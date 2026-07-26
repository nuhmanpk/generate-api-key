"""generateApiKey — simple, secure API key generation.

Quick start::

    from generateApiKey import generate_api_key

    key = generate_api_key()                       # secure random, 32 chars
    key = generate_api_key(length=48, prefix="sk") # sk-xxxxxxxx...
    key = generate_api_key(expiry=60)              # expires in 60 minutes

Everything is synchronous by default. Use :func:`generate_api_key_async`
when you need an awaitable, or the legacy :func:`generateApiKey`.
"""

import time

from .utils import (
    CHARSETS,
    build_charset,
    random_key,
    derived_key,
    add_dashes,
)

__all__ = [
    "generate_api_key",
    "generate_api_key_async",
    "generateApiKey",
    "ApiKey",
    "is_expired",
    "is_token_valid",
    "CHARSETS",
]


class ApiKey(str):
    """An API key.

    Behaves exactly like a ``str`` (usable in headers, f-strings, comparisons)
    while carrying optional expiry metadata::

        key = generate_api_key(expiry=60)
        headers = {"Authorization": key}   # works, it's a str
        key.expires_at                     # unix timestamp or None
        key.is_expired                     # bool
    """

    expires_at = None

    def __new__(cls, value: str, expires_at: int = None) -> "ApiKey":
        obj = super().__new__(cls, value)
        obj.expires_at = expires_at
        return obj

    @property
    def is_expired(self) -> bool:
        """True if an expiry was set and it is now in the past."""
        return self.expires_at is not None and time.time() >= self.expires_at


def generate_api_key(
    secret: str = None,
    seed: str = None,
    *,
    length: int = 32,
    charset: str = "alphanumeric",
    case: str = "mixed",
    prefix: str = None,
    separator: str = "-",
    dashes: bool = False,
    dash_group: int = 4,
    include: str = None,
    expiry: int = None,
) -> ApiKey:
    """Generate a secure API key.

    With no arguments it returns a cryptographically random key. Pass both
    ``secret`` and ``seed`` to derive the key from them via HMAC-SHA256 instead.

    Args:
        secret: Optional secret. If given with ``seed``, the key is HMAC-derived.
        seed: Optional per-key value used together with ``secret``.
        length: Number of characters in the key body (before prefix/dashes). Default 32.
        charset: A preset name (see ``CHARSETS``) or a literal string of allowed
            characters. Presets: alphanumeric, base62, base58, base64url,
            alphabetic, numeric, hex, base16.
        case: ``"mixed"`` (default), ``"lower"`` or ``"upper"``.
        prefix: Optional prefix, joined with ``separator`` (e.g. ``sk-...``).
        separator: String used between prefix and key. Default ``"-"``.
        dashes: If True, group the key body with dashes for readability.
        dash_group: Group size when ``dashes`` is True. Default 4.
        include: Extra value mixed into a derived key (requires secret + seed).
        expiry: Optional expiry in minutes. Sets ``ApiKey.expires_at``.

    Returns:
        An :class:`ApiKey` (a ``str`` subclass).

    Raises:
        ValueError: If ``length`` < 1, or a bad ``charset``/``case`` is given, or
            only one of ``secret``/``seed`` is supplied.
    """
    if length < 1:
        raise ValueError("length must be a positive integer.")
    if (secret is None) != (seed is None):
        raise ValueError("Provide both 'secret' and 'seed', or neither.")

    chars = build_charset(charset, case)

    if secret and seed:
        body = derived_key(secret, seed, include, length, chars)
    else:
        body = random_key(length, chars)

    if dashes:
        body = add_dashes(body, dash_group)

    key = f"{prefix}{separator}{body}" if prefix else body

    expires_at = int(time.time()) + expiry * 60 if expiry else None
    return ApiKey(key, expires_at)


async def generate_api_key_async(*args, **kwargs) -> ApiKey:
    """Async wrapper around :func:`generate_api_key` with the same signature."""
    return generate_api_key(*args, **kwargs)


def is_expired(key: "ApiKey") -> bool:
    """Return True if ``key`` is an expired :class:`ApiKey`."""
    return getattr(key, "is_expired", False)


# ---------------------------------------------------------------------------
# Backwards-compatible legacy API (async). Prefer generate_api_key above.
# ---------------------------------------------------------------------------

async def generateApiKey(
    secret: str,
    seed: str,
    include: str = None,
    add_dashes: bool = False,
    prefix: str = None,
    length: int = None,
    expiry: int = None,
) -> ApiKey:
    """Legacy async entry point. Kept for backwards compatibility.

    New code should use :func:`generate_api_key` (synchronous, more options).
    """
    if not secret or not seed:
        raise ValueError("Secret and seed cannot be empty strings.")

    return generate_api_key(
        secret,
        seed,
        length=length or 32,
        include=include,
        prefix=prefix,
        dashes=add_dashes,
        dash_group=4,
        expiry=expiry,
    )


async def is_token_valid(token: str) -> bool:
    """Legacy check for the ``_<timestamp>`` expiry token format."""
    if "_" not in token:
        return False
    try:
        expiration_time = int(token.split("_")[1])
        return int(time.time()) < expiration_time
    except (IndexError, ValueError):
        return False
