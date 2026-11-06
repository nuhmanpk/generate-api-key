"""Multi-factor authentication helpers. Standard library only.

* TOTP / HOTP (RFC 6238 / RFC 4226): authenticator-app codes.
* Recovery codes: single-use backup codes, stored hashed.
* One-time codes: short numeric codes for email/SMS with expiry.
* AttemptLimiter: in-memory brute-force guard for code checks.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import secrets
import struct
import threading
import time
from collections import OrderedDict
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, Optional, Union
from urllib.parse import quote, urlencode

if TYPE_CHECKING:
    from . import ApiKey

from .utils import add_dashes, build_charset, hash_code, random_key, safe_equals, verify_code

__all__ = [
    "AttemptLimiter",
    "find_totp_step",
    "generate_otp",
    "generate_recovery_codes",
    "generate_totp_secret",
    "hash_otp",
    "hash_recovery_code",
    "hotp",
    "hotp_uri",
    "normalize_recovery_code",
    "totp",
    "totp_now",
    "totp_uri",
    "verify_hotp",
    "verify_otp",
    "verify_recovery_code",
    "verify_totp",
]

_ALGORITHMS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}


# ---------------------------------------------------------------------------
# HOTP / TOTP
# ---------------------------------------------------------------------------


def generate_totp_secret(num_bytes: int = 20) -> str:
    """Return a new random base32 secret (no padding) for an authenticator app.

    20 bytes (160 bits) is the RFC 4226 recommendation and the common default.
    """
    if num_bytes < 10:
        raise ValueError("num_bytes must be at least 10 (80 bits).")
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode().rstrip("=")


# RFC 4226 asks for >= 128 bits (160 recommended, our default); 80 is accepted
# so secrets from older issuers still verify. Anything shorter is rejected.
_MIN_SECRET_BYTES = 10


def _normalize_secret(secret: str) -> str:
    return secret.replace(" ", "").replace("-", "").upper().rstrip("=")


def _decode_secret(secret: Union[str, bytes]) -> bytes:
    if isinstance(secret, bytes):
        raw = secret
    elif isinstance(secret, str):
        s = _normalize_secret(secret)
        s += "=" * (-len(s) % 8)
        try:
            raw = base64.b32decode(s)
        except Exception as e:  # binascii.Error
            raise ValueError("secret must be a base32 string.") from e
    else:
        raise TypeError("secret must be a base32 str or bytes.")
    if len(raw) < _MIN_SECRET_BYTES:
        raise ValueError(f"secret must be at least {_MIN_SECRET_BYTES} bytes (80 bits).")
    return raw


def _check(digits: int, algorithm: str) -> Any:
    # RFC 4226 truncation yields 31 bits, so 9+ digits add no real strength.
    if not 6 <= digits <= 8:
        raise ValueError("digits must be between 6 and 8.")
    try:
        return _ALGORITHMS[algorithm.lower()]
    except KeyError:
        raise ValueError(f"algorithm must be one of {sorted(_ALGORITHMS)}.") from None


def _clean_code(code: object, digits: Optional[int] = None) -> Optional[str]:
    """Normalize user input to an ASCII string, or None if it can't be a code.

    Ints (e.g. from JSON) are zero-padded when ``digits`` is known, since
    ``str(4411)`` would silently drop the leading zeros of ``004411``.
    """
    if isinstance(code, bool):
        return None
    if isinstance(code, int):
        if code < 0 or digits is None:
            return None
        return str(code).zfill(digits)
    if not isinstance(code, str) or len(code) > 64:
        return None
    code = code.replace(" ", "").replace("-", "")
    return code if code.isascii() else None


def _valid_numeric(code: str, digits: int) -> bool:
    return len(code) == digits and code.isdigit()


def hotp(secret: Union[str, bytes], counter: int, *, digits: int = 6, algorithm: str = "sha1") -> str:
    """Return the HOTP code for ``counter`` (RFC 4226)."""
    digest = _check(digits, algorithm)
    if counter < 0:
        raise ValueError("counter must be non-negative.")
    mac = hmac.new(_decode_secret(secret), struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


def totp(
    secret: Union[str, bytes],
    at: Optional[float] = None,
    *,
    period: int = 30,
    digits: int = 6,
    algorithm: str = "sha1",
) -> str:
    """Return the TOTP code at unix time ``at`` (default: now). RFC 6238."""
    if period < 1:
        raise ValueError("period must be positive.")
    t = time.time() if at is None else at
    return hotp(secret, int(t // period), digits=digits, algorithm=algorithm)


def totp_now(secret: Union[str, bytes], **options: Any) -> str:
    """Current TOTP code. Same options as :func:`totp`."""
    return totp(secret, **options)


def find_totp_step(
    secret: Union[str, bytes],
    code: object,
    *,
    window: int = 1,
    period: int = 30,
    digits: int = 6,
    algorithm: str = "sha1",
    at: Optional[float] = None,
    last_used_step: Optional[int] = None,
) -> Optional[int]:
    """Return the time step ``code`` matches, or None.

    ``window`` steps either side are accepted to tolerate clock drift. Store
    the returned step and pass it back as ``last_used_step`` so the same code
    can't be replayed.
    """
    code = _clean_code(code, digits)
    if code is None or not _valid_numeric(code, digits):
        return None
    if period < 1:
        raise ValueError("period must be positive.")
    t = time.time() if at is None else at
    current = int(t // period)
    match = None
    for step in range(current - window, current + window + 1):
        if step < 0 or (last_used_step is not None and step <= last_used_step):
            continue
        # check all candidates; no early exit
        if safe_equals(hotp(secret, step, digits=digits, algorithm=algorithm), code):
            match = step
    return match


def verify_totp(secret: Union[str, bytes], code: object, **options: Any) -> bool:
    """True if ``code`` is valid now. Options as :func:`find_totp_step`."""
    return find_totp_step(secret, code, **options) is not None


def verify_hotp(
    secret: Union[str, bytes],
    code: object,
    counter: int,
    *,
    look_ahead: int = 0,
    digits: int = 6,
    algorithm: str = "sha1",
) -> Optional[int]:
    """Check an HOTP ``code`` against ``counter`` .. ``counter + look_ahead``.

    Returns the **next counter** to store (always >= 1, so truthy) or None.
    """
    code = _clean_code(code, digits)
    if code is None or not _valid_numeric(code, digits):
        return None
    match = None
    for c in range(counter, counter + look_ahead + 1):
        if safe_equals(hotp(secret, c, digits=digits, algorithm=algorithm), code) and match is None:
            match = c + 1
    return match


def _otpauth_uri(kind: str, secret: str, account: str, issuer: Optional[str], params: dict[str, Any]) -> str:
    if not account:
        raise ValueError("account is required (e.g. the user's email).")
    # ':' separates issuer and account in the label; inside either it is ambiguous.
    if ":" in account or (issuer and ":" in issuer):
        raise ValueError("account and issuer must not contain ':'.")
    _decode_secret(secret)  # validate
    label = quote(account, safe="@")
    if issuer:
        label = f"{quote(issuer, safe='@')}:{label}"
    query = {"secret": _normalize_secret(secret)}
    if issuer:
        query["issuer"] = issuer
    query.update(params)
    return f"otpauth://{kind}/{label}?{urlencode(query, quote_via=quote)}"


def totp_uri(
    secret: str,
    account: str,
    issuer: Optional[str] = None,
    *,
    period: int = 30,
    digits: int = 6,
    algorithm: str = "sha1",
    image: Optional[str] = None,
) -> str:
    """``otpauth://totp/...`` URI to show as a QR code in your MFA setup screen.

    Non-default ``period``/``digits``/``algorithm`` are included; note that
    some apps (e.g. Google Authenticator) ignore them.
    """
    _check(digits, algorithm)
    if period < 1:
        raise ValueError("period must be positive.")
    params: dict[str, Any] = {}
    if algorithm.lower() != "sha1":
        params["algorithm"] = algorithm.upper()
    if digits != 6:
        params["digits"] = digits
    if period != 30:
        params["period"] = period
    if image:
        params["image"] = image
    return _otpauth_uri("totp", secret, account, issuer, params)


def hotp_uri(
    secret: str,
    account: str,
    issuer: Optional[str] = None,
    *,
    counter: int = 0,
    digits: int = 6,
    algorithm: str = "sha1",
) -> str:
    """``otpauth://hotp/...`` URI for counter-based tokens."""
    _check(digits, algorithm)
    params: dict[str, Any] = {"counter": counter}
    if algorithm.lower() != "sha1":
        params["algorithm"] = algorithm.upper()
    if digits != 6:
        params["digits"] = digits
    return _otpauth_uri("hotp", secret, account, issuer, params)


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------

# Crockford base32: no I, L, O, U. Easy to read aloud and type.
_RECOVERY_CHARS = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_RECOVERY_FIX = str.maketrans({"O": "0", "I": "1", "L": "1"})


def generate_recovery_codes(count: int = 10, length: int = 10, group: int = 5) -> list[str]:
    """Return ``count`` single-use backup codes like ``7KQ2M-9XPAB``.

    Show them to the user once and store only :func:`hash_recovery_code` of each.
    Default: 10 chars of Crockford base32 = 50 bits each.
    """
    if count < 1 or length < 8:
        raise ValueError("count must be >= 1 and length >= 8 (40 bits).")
    codes: set[str] = set()
    while len(codes) < count:
        codes.add(random_key(length, _RECOVERY_CHARS))
    return [add_dashes(c, group) if group else c for c in codes]


def normalize_recovery_code(code: str) -> str:
    """Upper-case, drop spaces/dashes, map look-alikes (O->0, I/L->1)."""
    cleaned = _clean_code(code)
    if cleaned is None:
        raise ValueError("recovery code must be an ASCII string.")
    return cleaned.upper().translate(_RECOVERY_FIX)


def hash_recovery_code(code: str, pepper: Optional[str] = None) -> str:
    """Hash a recovery code for storage (normalized, salted PBKDF2).

    Each call gives a different string (random salt), so verify with
    :func:`verify_recovery_code`, never by comparing hashes.
    """
    return hash_code(normalize_recovery_code(code), pepper)


def verify_recovery_code(code: str, hashes: Iterable[str], pepper: Optional[str] = None) -> Optional[str]:
    """Return the stored hash that ``code`` matches, or None.

    Delete the returned hash afterwards so the code can't be reused.
    """
    cleaned = _clean_code(code)
    if cleaned is None:
        return None
    normalized = cleaned.upper().translate(_RECOVERY_FIX)
    match = None
    for h in hashes:  # check every hash; no early exit
        if verify_code(normalized, h, pepper) and match is None:
            match = h
    return match


# ---------------------------------------------------------------------------
# Email / SMS one-time codes
# ---------------------------------------------------------------------------


def generate_otp(digits: int = 6, expiry: Optional[float] = 10, *, charset: str = "0123456789") -> ApiKey:
    """Return a one-time code (an :class:`~generateapikey.ApiKey`) for email/SMS.

    ``expiry`` is in minutes (default 10); ``None`` for no expiry. Short codes
    are only safe with an attempt limit, see :class:`AttemptLimiter`.
    """
    from . import ApiKey  # avoid import cycle

    if not 4 <= digits <= 12:
        raise ValueError("digits must be between 4 and 12.")
    if expiry is not None and (not math.isfinite(expiry) or expiry <= 0):
        raise ValueError("expiry must be a positive, finite number of minutes.")
    code = random_key(digits, build_charset(charset))
    expires_at = None if expiry is None else int(time.time() + expiry * 60)
    return ApiKey(code, expires_at)


def hash_otp(code: str, pepper: Optional[str] = None) -> str:
    """Hash a one-time code for storage (salted PBKDF2).

    A 6-digit code has only 10**6 values, so anyone who can read the stored
    hash *and* knows the pepper can brute-force it. Use a ``pepper`` kept
    outside the database, and keep the expiry short.
    """
    cleaned = _clean_code(code)
    if cleaned is None:
        raise ValueError("code must be an ASCII string.")
    return hash_code(cleaned, pepper)


def verify_otp(
    code: object,
    hashed: str,
    expires_at: Optional[float] = None,
    *,
    pepper: Optional[str] = None,
) -> bool:
    """True if ``code`` matches ``hashed`` and ``expires_at`` hasn't passed."""
    if expires_at is not None and time.time() >= expires_at:
        return False
    cleaned = _clean_code(code)
    if cleaned is None:
        return False
    return verify_code(cleaned, hashed, pepper)


# ---------------------------------------------------------------------------
# Attempt limiting
# ---------------------------------------------------------------------------


class AttemptLimiter:
    """Thread-safe, in-memory attempt limiter.

    Use :meth:`hit` (atomic check-and-count) **before** verifying::

        limiter = AttemptLimiter(max_attempts=5, window=15 * 60)

        if not limiter.hit(user_id):
            return "Too many attempts"
        if verify_totp(secret, code):
            limiter.reset(user_id)

    ``hit`` counts the attempt before the (slow) verification runs, so parallel
    requests can't all slip past the limit.

    Memory is bounded by ``max_keys``: expired entries are dropped first, then
    the oldest ones. Single-process only; with several workers keep the
    counter in Redis or your database instead.
    """

    def __init__(self, max_attempts: int = 5, window: float = 900, max_keys: int = 100_000):
        if max_attempts < 1 or window <= 0 or max_keys < 1:
            raise ValueError("max_attempts, window and max_keys must be positive.")
        self.max_attempts = max_attempts
        self.window = window
        self.max_keys = max_keys
        self._lock = threading.Lock()
        # key -> (count, window_start); insertion order == window_start order
        self._entries: OrderedDict[str, tuple[int, float]] = OrderedDict()

    def _purge(self, now: float) -> None:
        """Drop expired entries from the front. Amortized O(1)."""
        entries = self._entries
        while entries:
            _, (_, start) = next(iter(entries.items()))
            if now - start < self.window:
                break
            entries.popitem(last=False)

    def _count(self, key: str, now: float) -> int:
        entry = self._entries.get(key)
        if entry is None:
            return 0
        if now - entry[1] >= self.window:
            del self._entries[key]
            return 0
        return entry[0]

    def _add(self, key: str, now: float) -> int:
        count = self._count(key, now)
        if count:
            self._entries[key] = (count + 1, self._entries[key][1])
        else:
            self._entries[key] = (1, now)
            while len(self._entries) > self.max_keys:
                self._entries.popitem(last=False)
        return count + 1

    def hit(self, key: str) -> bool:
        """Atomically record an attempt. Returns False if the key is over the limit."""
        with self._lock:
            now = time.monotonic()
            self._purge(now)
            if self._count(key, now) >= self.max_attempts:
                return False
            self._add(key, now)
            return True

    def fail(self, key: str) -> int:
        """Record a failed attempt. Returns the number of attempts left."""
        with self._lock:
            now = time.monotonic()
            self._purge(now)
            return max(0, self.max_attempts - self._add(key, now))

    def is_blocked(self, key: str) -> bool:
        with self._lock:
            return self._count(key, time.monotonic()) >= self.max_attempts

    def remaining(self, key: str) -> int:
        with self._lock:
            return max(0, self.max_attempts - self._count(key, time.monotonic()))

    def reset(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)
