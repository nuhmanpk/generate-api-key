"""generateapikey — fast, secure API keys and MFA helpers.

Quick start::

    from generateapikey import generate_api_key, hash_api_key, verify_api_key

    key = generate_api_key()                          # 32 random chars
    key = generate_api_key(prefix="sk", checksum=True) # sk-xxxx...<checksum>
    key = generate_api_key(expiry=60)                 # expires in 60 minutes

    stored = hash_api_key(key)          # store this, never the raw key
    verify_api_key(key, stored)         # True

Everything is synchronous. :func:`generate_api_key_async` and the legacy
:func:`generateApiKey` exist for awaitable call sites.
"""

from __future__ import annotations

import datetime as _dt
import math
import time
import warnings
from secrets import token_bytes
from typing import Any, Optional, Union

from .utils import (
    CHARSETS,
    CHECKSUM_LENGTH,
    add_dashes,
    build_charset,
    compute_checksum,
    derived_key,
    entropy_bits,
    hash_api_key,
    random_key,
    verify_api_key,
    verify_checksum,
)

__version__ = "0.6.0"

__all__ = [
    "CHARSETS",
    "CHECKSUM_LENGTH",
    "ApiKey",
    "AttemptLimiter",
    "WeakKeyWarning",
    "__version__",
    "decode_jwt",
    "decode_jwt_jwks",
    "encode_jwt",
    "entropy_bits",
    "find_keys",
    "generateApiKey",
    "generate_api_key",
    "generate_api_key_async",
    "generate_api_keys",
    "generate_otp",
    "generate_recovery_codes",
    "generate_signed_token",
    # MFA (see generateapikey.mfa / generateapikey.tokens)
    "generate_totp_secret",
    "google_migration_uri",
    "has_all_scopes",
    "has_any_scope",
    "has_scope",
    "hash_api_key",
    "hash_otp",
    "hash_recovery_code",
    "is_expired",
    "is_token_valid",
    "key_pattern",
    "parse_scopes",
    "steam_code",
    "totp_now",
    "totp_uri",
    "verify_api_key",
    "verify_checksum",
    "verify_otp",
    "verify_recovery_code",
    "verify_signed_token",
    "verify_steam_code",
    "verify_totp",
]

#: Random keys below this many bits of entropy trigger a :class:`WeakKeyWarning`.
RECOMMENDED_ENTROPY = 128

Expiry = Union[int, float, _dt.timedelta]


class WeakKeyWarning(UserWarning):
    """Emitted when a random key has less than 128 bits of entropy."""


class ApiKey(str):
    """An API key.

    Behaves exactly like a ``str`` (headers, f-strings, comparisons, JSON)
    while carrying optional expiry metadata::

        key = generate_api_key(expiry=60)
        headers = {"Authorization": key}   # it's a str
        key.expires_at                     # unix timestamp (int) or None
        key.expires_in                     # seconds left, or None
        key.is_expired                     # bool

    Expiry lives only on this object. Persist ``expires_at`` alongside the
    key's hash if you need it later.
    """

    __slots__ = ("expires_at",)
    expires_at: Optional[int]

    def __new__(cls, value: str, expires_at: Optional[int] = None) -> ApiKey:
        obj = super().__new__(cls, value)
        obj.expires_at = expires_at
        return obj

    def __getnewargs__(self) -> tuple[str, Optional[int]]:  # type: ignore[override]
        return (str(self), self.expires_at)

    def __reduce__(self) -> tuple[type[ApiKey], tuple[str, Optional[int]]]:
        return (self.__class__, (str(self), self.expires_at))

    def __repr__(self) -> str:
        # Redacted so keys don't leak into logs, tracebacks and debuggers.
        # str(key) / f"{key}" still give the full value.
        value = str(self)
        shown = f"{value[:4]}…{value[-4:]}" if len(value) >= 16 else "…"
        if self.expires_at is None:
            return f"ApiKey('{shown}')"
        return f"ApiKey('{shown}', expires_at={self.expires_at})"

    @property
    def is_expired(self) -> bool:
        """True if an expiry was set and it is now in the past."""
        return self.expires_at is not None and time.time() >= self.expires_at

    @property
    def expires_in(self) -> Optional[float]:
        """Seconds until expiry (negative once expired), or None."""
        if self.expires_at is None:
            return None
        return self.expires_at - time.time()

    @property
    def expires_at_datetime(self) -> Optional[_dt.datetime]:
        """Expiry as a timezone-aware UTC ``datetime``, or None."""
        if self.expires_at is None:
            return None
        return _dt.datetime.fromtimestamp(self.expires_at, tz=_dt.timezone.utc)

    def hash(self, pepper: Optional[str] = None) -> str:
        """Shortcut for :func:`hash_api_key`."""
        return hash_api_key(self, pepper)


def _expiry_seconds(expiry: Expiry) -> float:
    if isinstance(expiry, bool):
        raise TypeError("expiry must be minutes (int/float) or a timedelta.")
    if isinstance(expiry, _dt.timedelta):
        seconds = expiry.total_seconds()
    elif isinstance(expiry, (int, float)):
        seconds = expiry * 60
    else:
        raise TypeError("expiry must be minutes (int/float) or a timedelta.")
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("expiry must be a positive, finite duration.")
    return seconds


def generate_api_key(
    secret: Optional[str] = None,
    seed: Optional[str] = None,
    *,
    length: int = 32,
    charset: str = "alphanumeric",
    case: str = "mixed",
    prefix: Optional[str] = None,
    separator: str = "-",
    dashes: bool = False,
    dash_group: int = 4,
    dash_char: str = "-",
    include: Optional[str] = None,
    expiry: Optional[Expiry] = None,
    checksum: bool = False,
    min_entropy: Optional[float] = None,
) -> ApiKey:
    """Generate an API key.

    With no ``secret``/``seed`` the key is cryptographically random. With both,
    it is derived from them via HMAC-SHA256 and is **deterministic**: the same
    inputs always give the same key (handy for reproducible test fixtures or
    keys you can re-derive instead of storing).

    Args:
        secret: Secret for derived keys. Requires ``seed``.
        seed: Per-key value for derived keys (e.g. a user id). Requires ``secret``.
        length: Characters in the key body (excluding prefix/dashes/checksum).
        charset: Preset name (see ``CHARSETS``) or a literal string of characters.
        case: ``"mixed"`` (default), ``"lower"`` or ``"upper"``.
        prefix: Optional prefix joined with ``separator`` (e.g. ``sk-...``).
        separator: String between prefix and body. Default ``"-"``.
        dashes: Group the body for readability, e.g. ``ABCD-EFGH``.
        dash_group: Group size when ``dashes`` is True. Default 4.
        dash_char: Character placed between groups. Default ``"-"``.
        include: Extra context mixed into a derived key (requires secret + seed).
        expiry: Lifetime in minutes, or a ``timedelta``. Sets ``.expires_at``.
        checksum: Append a 6-char base62 CRC32 so :func:`verify_checksum` can
            reject typos/truncated keys without a database lookup.
        min_entropy: Raise ``ValueError`` if a random key would carry fewer bits.

    Returns:
        An :class:`ApiKey` (a ``str`` subclass).

    Raises:
        ValueError / TypeError: on invalid arguments.

    Warns:
        WeakKeyWarning: random key with < 128 bits of entropy.
    """
    if isinstance(length, bool) or not isinstance(length, int) or length < 1:
        raise ValueError("length must be a positive integer.")
    if (secret is None) != (seed is None):
        raise ValueError("Provide both 'secret' and 'seed', or neither.")
    if secret is not None and (not secret or not seed):
        raise ValueError("'secret' and 'seed' must be non-empty strings.")
    if include is not None and secret is None:
        raise ValueError("'include' only applies to derived keys; pass 'secret' and 'seed' too.")

    chars = build_charset(charset, case)

    if secret is None:
        bits = length * math.log2(len(chars))
        if min_entropy is not None and bits < min_entropy:
            raise ValueError(f"key has {bits:.0f} bits of entropy, below min_entropy={min_entropy}.")
        if bits < RECOMMENDED_ENTROPY:
            warnings.warn(
                f"API key has only {bits:.0f} bits of entropy "
                f"(recommended >= {RECOMMENDED_ENTROPY}); increase length or use a larger charset.",
                WeakKeyWarning,
                stacklevel=2,
            )
        body = random_key(length, chars)
    else:
        if seed is None:  # unreachable: validated above; narrows the type
            raise ValueError("Provide both 'secret' and 'seed', or neither.")
        body = derived_key(secret, seed, include, length, chars)

    if dashes:
        body = add_dashes(body, dash_group, dash_char)

    key = f"{prefix}{separator}{body}" if prefix else body
    if checksum:
        key += compute_checksum(key)

    expires_at = None if expiry is None else int(time.time() + _expiry_seconds(expiry))
    return ApiKey(key, expires_at)


def generate_api_keys(count: int, **options: Any) -> list[ApiKey]:
    """Generate ``count`` random keys with the same options as :func:`generate_api_key`.

    Raises ValueError if ``secret``/``seed`` are passed (derived keys would all be equal).
    """
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("count must be a non-negative integer.")
    if "secret" in options or "seed" in options:
        raise ValueError("generate_api_keys only makes random keys; drop secret/seed.")
    if count == 0:
        return []
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", WeakKeyWarning)
        keys = [generate_api_key(**options) for _ in range(count)]
    if caught:
        warnings.warn(caught[0].message, WeakKeyWarning, stacklevel=2)
    return keys


async def generate_api_key_async(*args: Any, **kwargs: Any) -> ApiKey:
    """Awaitable version of :func:`generate_api_key` with the same signature."""
    return generate_api_key(*args, **kwargs)


def is_expired(key: Union[ApiKey, str]) -> bool:
    """True if ``key`` is an :class:`ApiKey` whose expiry has passed."""
    return bool(getattr(key, "is_expired", False))


# ---------------------------------------------------------------------------
# Backwards-compatible legacy API (async). Prefer generate_api_key above.
# ---------------------------------------------------------------------------


async def generateApiKey(  # noqa: PLR0917 - legacy positional signature
    secret: str,
    seed: str,
    include: Optional[str] = None,
    add_dashes: bool = False,
    prefix: Optional[str] = None,
    length: Optional[int] = None,
    expiry: Optional[int] = None,
) -> ApiKey:
    """Legacy async entry point, kept for backwards compatibility.

    Unlike :func:`generate_api_key`, every call returns a *new* key even for
    identical inputs (a random salt is mixed in), matching the old behaviour.
    """
    if not secret or not seed:
        raise ValueError("Secret and seed cannot be empty strings.")
    length = length or 32
    if length < 1:
        raise ValueError("length must be a positive integer.")

    chars = build_charset("alphanumeric")
    body = derived_key(secret, seed, include, length, chars, salt=token_bytes(16))
    if add_dashes:
        body = _add_dashes(body, 4)
    key = f"{prefix}-{body}" if prefix else body
    expires_at = None if not expiry else int(time.time() + _expiry_seconds(expiry))
    return ApiKey(key, expires_at)


_add_dashes = add_dashes  # the legacy signature shadows the helper's name


async def is_token_valid(token: str) -> bool:
    """Deprecated. Checked a ``_<timestamp>`` suffix that no API ever produced.

    Use ``ApiKey.is_expired`` / :func:`is_expired` instead.
    """
    warnings.warn(
        "is_token_valid is deprecated; use ApiKey.is_expired or is_expired().",
        DeprecationWarning,
        stacklevel=2,
    )
    if "_" not in token:
        return False
    try:
        return int(time.time()) < int(token.rsplit("_", 1)[1])
    except ValueError:
        return False


# MFA helpers re-exported for convenience (imported last: mfa uses ApiKey).
from . import mfa, tokens  # noqa: E402, F401  (make submodules available as attributes)
from .mfa import (  # noqa: E402
    AttemptLimiter,
    generate_otp,
    generate_recovery_codes,
    generate_totp_secret,
    google_migration_uri,
    hash_otp,
    hash_recovery_code,
    steam_code,
    totp_now,
    totp_uri,
    verify_otp,
    verify_recovery_code,
    verify_steam_code,
    verify_totp,
)
from .scanning import find_keys, key_pattern  # noqa: E402
from .scopes import has_all_scopes, has_any_scope, has_scope, parse_scopes  # noqa: E402
from .tokens import decode_jwt, decode_jwt_jwks, encode_jwt, generate_signed_token, verify_signed_token  # noqa: E402
