import hmac
import time
import hashlib
import string
from secrets import choice, token_bytes

# Named character sets available via the ``charset`` option.
CHARSETS = {
    "alphanumeric": string.ascii_letters + string.digits,
    "base62": string.ascii_letters + string.digits,
    "alphabetic": string.ascii_letters,
    "numeric": string.digits,
    "hex": string.digits + "abcdef",
    "base16": string.digits + "ABCDEF",
    "base64url": string.ascii_letters + string.digits + "-_",
    # base58 = base62 minus the ambiguous chars 0, O, I and l
    "base58": "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
}


def build_charset(charset: str, case: str) -> str:
    """Resolve a charset name (or a custom literal string) and apply a case rule.

    Args:
        charset: A named preset in ``CHARSETS`` or a literal string of characters.
        case: One of ``"mixed"``, ``"lower"`` or ``"upper"``. Only affects letters.

    Returns:
        The final string of characters to draw from.
    """
    chars = CHARSETS.get(charset, charset)
    if not chars:
        raise ValueError(f"Unknown or empty charset: {charset!r}")

    if case == "lower":
        chars = "".join(dict.fromkeys(chars.lower()))
    elif case == "upper":
        chars = "".join(dict.fromkeys(chars.upper()))
    elif case != "mixed":
        raise ValueError("case must be one of 'mixed', 'lower', 'upper'.")
    return chars


def random_key(length: int, chars: str) -> str:
    """Return a cryptographically secure random string of ``length`` from ``chars``."""
    return "".join(choice(chars) for _ in range(length))


def derived_key(secret: str, seed: str, include: str, length: int, chars: str) -> str:
    """Derive a key from ``secret``/``seed`` using HMAC-SHA256 as a byte stream.

    A fresh random salt keeps every generated key unique even for identical
    inputs. The HMAC output is mapped onto ``chars`` to honour the charset.
    """
    salt = token_bytes(16)
    message = f"{seed}{include or ''}{int(time.time())}".encode()
    material = bytearray()
    counter = 0
    while len(material) < length:
        block = hmac.new(
            secret.encode(),
            message + salt + counter.to_bytes(4, "big"),
            hashlib.sha256,
        ).digest()
        material.extend(block)
        counter += 1
    return "".join(chars[b % len(chars)] for b in material[:length])


def add_dashes(key: str, group: int, sep: str = "-") -> str:
    """Insert ``sep`` every ``group`` characters, e.g. ``ABCD-EFGH-IJKL``."""
    if group < 1:
        return key
    return sep.join(key[i : i + group] for i in range(0, len(key), group))


def generate_expiration_token(minutes: int) -> str:
    """Return a stateless expiry token of the form ``_<unix_timestamp>``.

    Kept for backwards compatibility with :func:`generateApiKey`.
    """
    return f"_{int(time.time()) + minutes * 60}"
