"""Low-level helpers: charsets, unbiased sampling, derivation, checksums, hashing."""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import secrets
import string
import zlib
from typing import Callable, Optional

# Named character sets available via the ``charset`` option.
CHARSETS = {
    "alphanumeric": string.ascii_letters + string.digits,
    "base62": string.digits + string.ascii_uppercase + string.ascii_lowercase,
    "alphabetic": string.ascii_letters,
    "numeric": string.digits,
    "hex": string.digits + "abcdef",
    "base16": string.digits + "ABCDEF",
    "base32": string.ascii_uppercase + "234567",
    "crockford": "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
    "base64url": string.ascii_letters + string.digits + "-_",
    # base58 = base62 minus the ambiguous chars 0, O, I and l
    "base58": "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    # letters and digits that are hard to confuse when read aloud or by eye
    "unambiguous": "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz",
}

_AMBIGUOUS = set("0O1Il")
_NO_AMBIGUOUS = {"base58", "unambiguous", "crockford"}

CHECKSUM_LENGTH = 6
_CHECKSUM_ALPHABET = CHARSETS["base62"]


def build_charset(charset: str, case: str = "mixed") -> str:
    """Resolve a preset name (or a literal string of characters) and apply ``case``.

    Duplicate characters are removed so every character is equally likely.
    Presets that exclude look-alike characters keep excluding them after a
    case change (e.g. ``base58`` lower-cased never contains ``l``).
    """
    if not isinstance(charset, str):
        raise TypeError("charset must be a string.")
    chars = CHARSETS.get(charset, charset)

    if case == "lower":
        chars = chars.lower()
    elif case == "upper":
        chars = chars.upper()
    elif case != "mixed":
        raise ValueError("case must be one of 'mixed', 'lower', 'upper'.")

    if charset in _NO_AMBIGUOUS and case != "mixed":
        chars = "".join(c for c in chars if c not in _AMBIGUOUS)

    chars = "".join(dict.fromkeys(chars))  # dedupe, keep order
    if len(chars) < 2:
        raise ValueError(f"charset must contain at least 2 distinct characters: {charset!r}")
    return chars


def entropy_bits(length: int, charset: str = "alphanumeric", case: str = "mixed") -> float:
    """Bits of entropy in a random key of ``length`` drawn from ``charset``."""
    return length * math.log2(len(build_charset(charset, case)))


# ---------------------------------------------------------------------------
# Unbiased mapping of a byte stream onto an alphabet
# ---------------------------------------------------------------------------

_TABLE_CACHE: dict[str, Optional[tuple[bytes, bytes]]] = {}


def _byte_table(chars: str) -> Optional[tuple[bytes, bytes]]:
    """Return (translate_table, delete_bytes) for fast ASCII rejection sampling.

    Bytes below the largest multiple of ``len(chars)`` map uniformly onto
    ``chars``; the rest are rejected. ``None`` when the fast path can't apply.
    """
    cached = _TABLE_CACHE.get(chars)
    if cached is not None or chars in _TABLE_CACHE:
        return cached
    n = len(chars)
    if n > 256 or not chars.isascii():
        result = None
    else:
        limit = 256 - (256 % n)
        table = bytes(ord(chars[b % n]) if b < limit else 0 for b in range(256))
        result = (table, bytes(range(limit, 256)))
    if len(_TABLE_CACHE) < 256:
        _TABLE_CACHE[chars] = result
    return result


def _sample(source: Callable[[int], bytes], length: int, chars: str) -> str:
    """Draw ``length`` unbiased characters from ``chars`` using ``source(n) -> bytes``."""
    fast = _byte_table(chars)
    if fast is not None:
        table, reject = fast
        out = b""
        # Over-request a little so one round almost always suffices.
        want = length + (length >> 1) + 8
        while len(out) < length:
            out += source(want).translate(table, reject)
        return out[:length].decode("ascii")

    # Generic path: any alphabet size, any characters.
    n = len(chars)
    nbytes = (n.bit_length() + 7) // 8
    space = 1 << (8 * nbytes)
    limit = space - (space % n)
    result: list[str] = []
    while len(result) < length:
        chunk = source(nbytes * (length - len(result) + 8))
        for i in range(0, len(chunk) - nbytes + 1, nbytes):
            v = int.from_bytes(chunk[i : i + nbytes], "big")
            if v < limit:
                result.append(chars[v % n])
                if len(result) == length:
                    break
    return "".join(result)


def random_key(length: int, chars: str) -> str:
    """Cryptographically secure, unbiased random string of ``length`` from ``chars``."""
    return _sample(secrets.token_bytes, length, chars)


def derived_key(  # noqa: PLR0917 - internal helper
    secret: str,
    seed: str,
    include: Optional[str],
    length: int,
    chars: str,
    salt: bytes = b"",
) -> str:
    """Derive a key from ``secret``/``seed`` with HMAC-SHA256 in counter mode.

    Without ``salt`` the output is deterministic: the same inputs always give
    the same key. Pass a random ``salt`` to get a fresh key every call.
    """
    key = subkey(secret, "derive")
    # Length-prefixed fields so ("ab", "c") and ("a", "bc") never collide.
    parts = [seed.encode(), (include or "").encode(), salt]
    message = b"".join(len(p).to_bytes(4, "big") + p for p in parts)
    counter = 0

    def stream(n: int) -> bytes:
        nonlocal counter
        buf = bytearray()
        while len(buf) < n:
            buf += hmac.new(key, message + counter.to_bytes(8, "big"), hashlib.sha256).digest()
            counter += 1
        return bytes(buf)

    return _sample(stream, length, chars)


def add_dashes(key: str, group: int, sep: str = "-") -> str:
    """Insert ``sep`` every ``group`` characters, e.g. ``ABCD-EFGH-IJKL``."""
    if group < 1:
        raise ValueError("dash_group must be a positive integer.")
    return sep.join(key[i : i + group] for i in range(0, len(key), group))


# ---------------------------------------------------------------------------
# Checksums (GitHub-token style: CRC32 encoded as 6 base62 chars)
# ---------------------------------------------------------------------------


def compute_checksum(data: str) -> str:
    """Return a 6-character base62 CRC32 checksum of ``data``."""
    value = zlib.crc32(data.encode())
    out = []
    for _ in range(CHECKSUM_LENGTH):
        value, rem = divmod(value, 62)
        out.append(_CHECKSUM_ALPHABET[rem])
    return "".join(reversed(out))


def verify_checksum(key: str) -> bool:
    """True if ``key`` ends with a valid checksum produced by ``checksum=True``.

    Cheap, offline sanity check (catches typos and truncation); it is not a
    substitute for looking the key up.
    """
    if not isinstance(key, str) or len(key) <= CHECKSUM_LENGTH:
        return False
    body, check = key[:-CHECKSUM_LENGTH], key[-CHECKSUM_LENGTH:]
    return safe_equals(compute_checksum(body), check)


# ---------------------------------------------------------------------------
# Constant-time comparison and key separation
# ---------------------------------------------------------------------------


def safe_equals(a: str, b: str) -> bool:
    """Constant-time string comparison that never raises on attacker input.

    ``hmac.compare_digest`` raises ``TypeError`` for non-ASCII ``str``; comparing
    UTF-8 bytes avoids that while staying constant-time.
    """
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a.encode("utf-8", "surrogatepass"), b.encode("utf-8", "surrogatepass"))


def subkey(secret: str, label: str) -> bytes:
    """Derive an independent HMAC key per purpose from one server secret.

    Domain separation: a secret reused for tokens, hashing and derivation can
    never produce a value valid in another context.
    """
    return hmac.new(secret.encode(), b"generateapikey.v1." + label.encode(), hashlib.sha256).digest()


def _check_pepper(pepper: Optional[str]) -> None:
    if pepper is not None and (not isinstance(pepper, str) or not pepper):
        # Usually an unset environment variable; failing loudly beats silently
        # storing un-peppered hashes.
        raise ValueError("pepper must be a non-empty string (or None).")


# ---------------------------------------------------------------------------
# Storage hashing
# ---------------------------------------------------------------------------

_HASH_PREFIX = "sha256$"
_HMAC_PREFIX = "hmac-sha256$"


def hash_api_key(key: str, pepper: Optional[str] = None) -> str:
    """Hash ``key`` for storage. Store this, never the raw key.

    API keys are long random strings, so a fast hash is the right tool (a slow
    password hash like bcrypt would only slow down every request). Pass a
    server-side ``pepper`` to use HMAC-SHA256 so a leaked database alone is
    not enough to check guesses.

    Returns a self-describing string such as ``"sha256$<hex>"``.
    """
    _check_pepper(pepper)
    data = str(key).encode("utf-8", "surrogatepass")
    if pepper is not None:
        return _HMAC_PREFIX + hmac.new(subkey(pepper, "hash"), data, hashlib.sha256).hexdigest()
    return _HASH_PREFIX + hashlib.sha256(data).hexdigest()


def verify_api_key(key: str, hashed: str, pepper: Optional[str] = None) -> bool:
    """Constant-time check that ``key`` matches a value from :func:`hash_api_key`."""
    _check_pepper(pepper)
    if not isinstance(key, str) or not isinstance(hashed, str):
        return False
    if hashed.startswith(_HMAC_PREFIX) and pepper is None:
        return False
    if hashed.startswith(_HASH_PREFIX) and pepper is not None:
        return False
    return safe_equals(hash_api_key(key, pepper), hashed)


# ---------------------------------------------------------------------------
# Slow, salted hashing for short codes (recovery codes, OTPs)
# ---------------------------------------------------------------------------

_KDF_PREFIX = "pbkdf2-sha256"
KDF_ITERATIONS = 100_000


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _kdf(code: str, salt: bytes, iterations: int, pepper: Optional[str]) -> bytes:
    data = code.encode("utf-8", "surrogatepass")
    if pepper is not None:
        data = hmac.new(subkey(pepper, "code"), data, hashlib.sha256).digest()
    return hashlib.pbkdf2_hmac("sha256", data, salt, iterations)


def hash_code(code: str, pepper: Optional[str] = None, iterations: int = KDF_ITERATIONS) -> str:
    """Salted PBKDF2 hash for short, low-entropy codes.

    Short codes can't be protected by a fast hash: a leaked SHA-256 of a
    6-digit code reverses instantly. Per-record salt + 100k iterations makes
    each guess expensive and stops parallel cracking; a ``pepper`` makes a DB
    leak alone useless.

    Format: ``pbkdf2-sha256$<iterations>$<salt>$<hash>``.
    """
    _check_pepper(pepper)
    salt = secrets.token_bytes(16)
    digest = _kdf(code, salt, iterations, pepper)
    return f"{_KDF_PREFIX}${iterations}${_b64e(salt)}${_b64e(digest)}"


def verify_code(code: str, hashed: str, pepper: Optional[str] = None) -> bool:
    """Check ``code`` against a value from :func:`hash_code`. Never raises on bad input."""
    _check_pepper(pepper)
    if not isinstance(code, str) or not isinstance(hashed, str):
        return False
    parts = hashed.split("$")
    if len(parts) != 4 or parts[0] != _KDF_PREFIX:
        return False
    try:
        iterations = int(parts[1])
        salt, expected = _b64d(parts[2]), _b64d(parts[3])
    except ValueError:
        return False
    if not 1_000 <= iterations <= 10_000_000:  # refuse absurd stored values
        return False
    return hmac.compare_digest(_kdf(code, salt, iterations, pepper), expected)
