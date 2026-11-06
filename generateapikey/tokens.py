"""Signed, self-expiring tokens for magic links, email verification and password resets.

Format: ``<base64url(json payload)>.<base64url(HMAC-SHA256)>``. The payload is
readable (not encrypted), so don't put secrets in it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
import time
from typing import Any, Optional

from .utils import safe_equals, subkey

__all__ = ["generate_signed_token", "verify_signed_token"]


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


MIN_SECRET_LENGTH = 16
_MAX_TOKEN_LENGTH = 8192


def _check_secret(secret: str) -> None:
    if not isinstance(secret, str) or len(secret) < MIN_SECRET_LENGTH:
        raise ValueError(
            f"secret must be a string of at least {MIN_SECRET_LENGTH} characters; "
            "a short secret can be brute-forced from any token."
        )


def _sign(secret: str, body: str, context: Optional[str] = None) -> str:
    # Per-purpose subkey: reusing one secret as a hash pepper can't forge tokens.
    msg = body.encode()
    if context is not None:
        # Bound tokens sign an extra, never-transmitted value (session id, device id...).
        msg += b"\x1f" + hashlib.sha256(context.encode("utf-8", "surrogatepass")).digest()
    return _b64e(hmac.new(subkey(secret, "token"), msg, hashlib.sha256).digest())


def generate_signed_token(
    secret: str,
    data: Optional[dict[str, Any]] = None,
    *,
    purpose: str = "default",
    expiry: Optional[float] = 15,
    context: Optional[str] = None,
) -> str:
    """Return a URL-safe signed token.

    Args:
        secret: Server secret, at least 16 characters (keep it out of the database).
        data: JSON-serialisable dict, e.g. ``{"uid": 42}``.
        purpose: Binds the token to one use (``"login"``, ``"reset"``...), so
            a token made for one flow is rejected by another.
        expiry: Lifetime in minutes (default 15). ``None`` = never expires.
        context: Optional value the token is *bound* to, such as the session
            id or a device cookie. It is signed but not stored in the token, so
            a leaked link only works where the same ``context`` is presented at
            verification. Don't bind to IP addresses; mobile IPs change.

    Each token carries a random ``jti`` id; store used ids if a token must
    work only once.
    """
    _check_secret(secret)
    if not isinstance(purpose, str):
        raise TypeError("purpose must be a string.")
    if expiry is not None and (not math.isfinite(expiry) or expiry <= 0):
        raise ValueError("expiry must be a positive, finite number of minutes.")
    payload: dict[str, Any] = {"p": purpose, "jti": secrets.token_urlsafe(12), "d": data or {}}
    if expiry is not None:
        payload["exp"] = int(time.time() + expiry * 60)
    body = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    if context is not None and not isinstance(context, str):
        raise TypeError("context must be a string.")
    return f"{body}.{_sign(secret, body, context)}"


def verify_signed_token(
    token: str,
    secret: str,
    *,
    purpose: str = "default",
    with_meta: bool = False,
    context: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Return the token's ``data`` if the signature, purpose and expiry check out, else None.

    With ``with_meta=True`` returns ``{"data", "jti", "exp"}`` instead.
    ``context`` must equal the value the token was generated with (if any).
    """
    _check_secret(secret)
    if not isinstance(token, str) or len(token) > _MAX_TOKEN_LENGTH or not token.isascii() or token.count(".") != 1:
        return None
    body, sig = token.split(".")
    if context is not None and not isinstance(context, str):
        return None
    if not safe_equals(_sign(secret, body, context), sig):
        return None
    try:
        payload = json.loads(_b64d(body))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict) or not safe_equals(str(payload.get("p", "")), purpose):
        return None
    exp = payload.get("exp")
    if exp is not None and (not isinstance(exp, (int, float)) or time.time() >= exp):
        return None
    if with_meta:
        return {"data": payload.get("d", {}), "jti": payload.get("jti"), "exp": exp}
    data: dict[str, Any] = payload.get("d", {})
    return data
