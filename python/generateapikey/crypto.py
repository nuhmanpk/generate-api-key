"""Encrypt secrets at rest (TOTP secrets, webhook secrets...). ``pip install "generateapikey[crypto]"``.

TOTP secrets can't be hashed (the server needs them to compute codes), so
store them encrypted::

    from generateapikey.crypto import SecretBox, generate_encryption_key

    KEY = generate_encryption_key()            # once; keep in env / secret manager
    box = SecretBox(KEY)

    stored = box.encrypt(totp_secret, aad=str(user.id))   # bind ciphertext to the user
    totp_secret = box.decrypt(stored, aad=str(user.id))

AES-256-GCM, random 96-bit nonce per message, optional associated data.
Key rotation: ``SecretBox(new_key, old_keys=[old_key])`` decrypts with any of
them and always encrypts with the new one; ``box.needs_rotation(stored)`` tells
you when to re-encrypt.

Format: ``v1.<key-id>.<base64url(nonce + ciphertext + tag)>``.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Sequence
from typing import Optional

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as e:  # pragma: no cover
    raise ImportError('Encryption needs: pip install "generateapikey[crypto]"') from e

__all__ = ["DecryptionError", "SecretBox", "generate_encryption_key"]

_VERSION = "v1"


class DecryptionError(ValueError):
    """Ciphertext is malformed, was tampered with, or no key matches."""


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def generate_encryption_key() -> str:
    """New random 256-bit key as URL-safe base64 (store it in env / a secret manager)."""
    return _b64e(secrets.token_bytes(32))


def _load_key(key: str) -> bytes:
    try:
        raw = _b64d(key) if isinstance(key, str) else b""
    except ValueError:
        raw = b""
    if len(raw) != 32:
        raise ValueError("encryption key must be 32 bytes, URL-safe base64 (use generate_encryption_key()).")
    return raw


def _key_id(raw: bytes) -> str:
    return _b64e(hashlib.sha256(b"generateapikey.v1.keyid" + raw).digest()[:6])


class SecretBox:
    """AES-256-GCM encryption with key rotation."""

    def __init__(self, key: str, old_keys: Sequence[str] = ()):
        if isinstance(old_keys, str):
            raise TypeError("old_keys must be a sequence of keys, not a string.")
        raw = _load_key(key)
        self._current_id = _key_id(raw)
        self._keys: dict[str, AESGCM] = {self._current_id: AESGCM(raw)}
        for old in old_keys:
            old_raw = _load_key(old)
            self._keys.setdefault(_key_id(old_raw), AESGCM(old_raw))

    def __repr__(self) -> str:  # never show key material
        return f"SecretBox(key_id={self._current_id!r}, keys={len(self._keys)})"

    def encrypt(self, plaintext: str, aad: Optional[str] = None) -> str:
        """Encrypt ``plaintext``. ``aad`` (e.g. user id) must match on decrypt."""
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be a string.")
        nonce = secrets.token_bytes(12)
        ct = self._keys[self._current_id].encrypt(nonce, plaintext.encode(), _aad(aad))
        return f"{_VERSION}.{self._current_id}.{_b64e(nonce + ct)}"

    def decrypt(self, token: str, aad: Optional[str] = None) -> str:
        """Decrypt a value from :meth:`encrypt`. Raises :class:`DecryptionError`."""
        if not isinstance(token, str) or not token.isascii():
            raise DecryptionError("invalid ciphertext")
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != _VERSION:
            raise DecryptionError("invalid ciphertext")
        aes = self._keys.get(parts[1])
        if aes is None:
            raise DecryptionError("no key for this ciphertext (was it rotated out?)")
        try:
            blob = _b64d(parts[2])
            if len(blob) < 12 + 16:
                raise DecryptionError("invalid ciphertext")
            return aes.decrypt(blob[:12], blob[12:], _aad(aad)).decode()
        except (InvalidTag, ValueError, UnicodeDecodeError):
            raise DecryptionError("invalid ciphertext or associated data") from None

    def needs_rotation(self, token: str) -> bool:
        """True if ``token`` was encrypted with an old key; re-encrypt it."""
        parts = token.split(".") if isinstance(token, str) else []
        return len(parts) == 3 and parts[1] != self._current_id

    def rotate(self, token: str, aad: Optional[str] = None) -> str:
        """Re-encrypt ``token`` under the current key (no-op if already current)."""
        if not self.needs_rotation(token):
            return token
        return self.encrypt(self.decrypt(token, aad), aad)


def _aad(aad: Optional[str]) -> Optional[bytes]:
    if aad is None:
        return None
    if not isinstance(aad, str):
        raise TypeError("aad must be a string.")
    return aad.encode("utf-8", "surrogatepass")
