# generateapikey for Python: API reference

Reference for the Python package [`generateapikey`](https://pypi.org/project/generateapikey/) **0.6.0**. It covers the high-level API (keys, hashing, scopes, rotation, framework auth, MFA, tokens, JWT) and the lower-level building blocks underneath it.

- Python 3.9 or newer. The core has **no runtime dependencies**. QR codes, asymmetric JWT, encryption, Redis and the framework adapters are optional extras that are imported only when you use them.
- Everything is synchronous unless the name says otherwise (`generate_api_key_async`, `APIKeyAuth.aauthenticate`, `AsyncRedisAttemptLimiter`).
- The package is fully typed (`py.typed`).
- Python is the normative implementation of the [wire-format spec](https://github.com/nuhmanpk/generate-api-key/blob/main/spec/SPEC.md). The npm package `@nuhmanpk/generateapikey` produces and accepts the same bytes. See [Cross-language compatibility](#cross-language-compatibility).

Placeholder secrets in this document (`"change-me-…"`) are examples only. In production, generate real values with `secrets.token_urlsafe(32)` and load them from the environment or a secret manager.

## Contents

1. [Install and extras](#install-and-extras)
2. [Quick start](#quick-start)
3. [API keys](#api-keys)
4. [Storage hashing](#storage-hashing)
5. [Scopes](#scopes)
6. [Rotation and KeyStore](#rotation-and-keystore)
7. [Leak detection](#leak-detection)
8. [Framework integrations](#framework-integrations)
9. [MFA](#mfa)
10. [Signed tokens](#signed-tokens)
11. [JWT](#jwt)
12. [SecretBox: encryption at rest](#secretbox-encryption-at-rest)
13. [QR codes](#qr-codes)
14. [CLI](#cli)
15. [Low-level building blocks](#low-level-building-blocks)
16. [Cross-language compatibility](#cross-language-compatibility)
17. [Errors reference](#errors-reference)

---

## Install and extras

```bash
pip install generateapikey
```

| Extra | Installs | Needed for |
|---|---|---|
| `qr` | `qrcode`, `pypng` | `generateapikey.qr`, `generate-api-key totp --qr` |
| `crypto` | `cryptography>=42` | `generateapikey.crypto.SecretBox`, RS/PS/ES/EdDSA JWTs, `decode_jwt_jwks` |
| `redis` | `redis` | `generateapikey.limiters` |
| `fastapi` | `fastapi>=0.100` | `generateapikey.integrations.fastapi` |
| `starlette` | `starlette>=0.27` | `generateapikey.integrations.starlette` |
| `django` | `django` (4.2+ on 3.9, 5.2+ otherwise) | `generateapikey.integrations.django` |
| `drf` | `django`, `djangorestframework>=3.14` | `generateapikey.integrations.drf` |
| `flask` | `flask>=2.2` | `generateapikey.integrations.flask` |
| `litestar` | `litestar>=2.0` | `generateapikey.integrations.litestar` |
| `sanic` | `sanic>=23.3` | `generateapikey.integrations.sanic` |
| `aiohttp` | `aiohttp>=3.8` | `generateapikey.integrations.aiohttp` |
| `quart` | `quart>=0.19` | `generateapikey.integrations.quart` |
| `falcon` | `falcon>=3.1` | `generateapikey.integrations.falcon` |
| `all` | every extra above | |

```bash
pip install "generateapikey[fastapi,crypto,redis]"
```

Importing a module whose extra is missing raises `ImportError` with the exact `pip install` command to run. The import name is lowercase `generateapikey`. The old `import generateApiKey` still works but emits a deprecation warning.

## Quick start

```python
from generateapikey import generate_api_key, hash_api_key, verify_api_key, verify_checksum

PEPPER = "change-me-pepper"  # server-side, from the environment

key = generate_api_key(prefix="sk", checksum=True)  # 'sk-…' + 32 random chars + 6-char checksum
stored = hash_api_key(key, pepper=PEPPER)  # 'hmac-sha256$…': save this, never the key

# On each request:
incoming = str(key)
assert verify_checksum(incoming)  # cheap offline typo/truncation check
assert verify_api_key(incoming, stored, pepper=PEPPER)  # constant-time
```

For web apps, use [`APIKeyAuth`](#apikeyauth) and a [framework adapter](#adapters) instead of wiring this by hand.

---

## API keys

### `generate_api_key`

```text
generate_api_key(
    secret: str | None = None,
    seed: str | None = None,
    *,
    length: int = 32,
    charset: str = "alphanumeric",
    case: str = "mixed",
    prefix: str | None = None,
    separator: str = "-",
    dashes: bool = False,
    dash_group: int = 4,
    dash_char: str = "-",
    include: str | None = None,
    expiry: int | float | datetime.timedelta | None = None,
    checksum: bool = False,
    min_entropy: float | None = None,
) -> ApiKey
```

Returns an [`ApiKey`](#apikey), which is a `str` subclass.

| Parameter | Meaning |
|---|---|
| `secret`, `seed` | Pass both to get a [derived key](#derived-keys). Pass neither for a random key. |
| `length` | Characters in the body. Excludes the prefix, separator, dashes and checksum. Must be a positive `int`. |
| `charset` | A [preset name](#charsets) or a literal string of characters. Duplicates are removed. At least 2 distinct characters are required. |
| `case` | `"mixed"`, `"lower"` or `"upper"`. Applied to the charset before sampling. |
| `prefix` | Joined as `prefix + separator + body`. Ignored when empty. |
| `separator` | String between prefix and body. |
| `dashes`, `dash_group`, `dash_char` | Split the body into groups, for example `ABCD-EFGH`. |
| `include` | Extra context mixed into a derived key. Only valid together with `secret` and `seed`. |
| `expiry` | Minutes (`int`/`float`) or a `timedelta`. Must be positive and finite. Sets `ApiKey.expires_at`. It is **not** encoded in the key text. |
| `checksum` | Append a 6-character base62 CRC32 over everything before it. See [Checksums](#checksums). |
| `min_entropy` | Raise `ValueError` if a random key would carry fewer bits. Ignored for derived keys. |

**Raises:** `ValueError` or `TypeError` on invalid arguments (see [Errors reference](#errors-reference)).
**Warns:** `WeakKeyWarning` when a random key has under 128 bits of entropy. Derived keys never warn.

```python
from datetime import timedelta
from generateapikey import generate_api_key

generate_api_key()  # 32 alphanumeric chars, about 190 bits
generate_api_key(length=48)
generate_api_key(prefix="sk")  # 'sk-…'
generate_api_key(prefix="myapp_live", separator="_")  # 'myapp_live_…'
generate_api_key(dashes=True)  # 'AEpx-VKcN-…'
generate_api_key(dashes=True, dash_group=8, dash_char=".")
generate_api_key(charset="hex", length=32)  # exactly 128 bits
generate_api_key(charset="base58")  # no 0 O I l
generate_api_key(charset="alphabetic", case="upper", length=40)
generate_api_key(charset="ABCDEFGHJKLMNPQRSTUVWXYZ23456789", length=30)  # your own alphabet
generate_api_key(prefix="sk", checksum=True)
generate_api_key(expiry=60)  # 60 minutes
generate_api_key(expiry=timedelta(days=30))
```

**Layout:** `[prefix + separator] + body (optionally dashed) + [checksum]`. Sampling uses `secrets.token_bytes` with rejection sampling, so every character in the charset is exactly equally likely. There is no `byte % n` bias.

### Derived keys

With both `secret` and `seed` the key is **deterministic**. The same inputs always give the same key, so you can re-derive a key instead of storing it, or build reproducible fixtures. The derivation is HMAC-SHA256 in counter mode, keyed with `subkey(secret, "derive")`, over length-prefixed `seed` and `include` fields.

```python
from generateapikey import generate_api_key

SECRET = "change-me-derivation-secret"

a = generate_api_key(SECRET, "user-42")
b = generate_api_key(SECRET, "user-42")
c = generate_api_key(SECRET, "user-42", include="prod")
assert a == b and a != c
```

A derived key is only as strong as `secret`. Use a long random secret, and keep it out of the database.

### Batch and async

```text
generate_api_keys(count: int, **options) -> list[ApiKey]
async generate_api_key_async(*args, **kwargs) -> ApiKey
```

`generate_api_keys` makes `count` random keys with the same options as `generate_api_key`. `count=0` returns `[]`. It raises `ValueError` if `count` is negative or not an `int`, or if `secret`/`seed` are passed, since every derived key would be identical. If the options produce weak keys, it emits a single `WeakKeyWarning` rather than one per key.

`generate_api_key_async` is an awaitable wrapper with the same signature. It does no I/O.

```python
import asyncio
from generateapikey import generate_api_key_async, generate_api_keys

keys = generate_api_keys(100, prefix="sk", length=40)
assert len(set(keys)) == 100

key = asyncio.run(generate_api_key_async(prefix="sk"))
```

### `ApiKey`

```text
class ApiKey(str):
    ApiKey(value: str, expires_at: int | None = None)
    expires_at: int | None                       # Unix timestamp (seconds)
    is_expired: bool                             # property
    expires_in: float | None                     # property: seconds left, negative once expired
    expires_at_datetime: datetime | None         # property: timezone-aware UTC
    hash(pepper: str | None = None) -> str       # same as hash_api_key(self, pepper)

is_expired(key: ApiKey | str) -> bool            # False for plain str
```

An `ApiKey` behaves like a `str` everywhere: headers, f-strings, JSON, comparisons. It survives `pickle` and `copy` with its expiry.

**`repr` is redacted.** `repr(key)` shows only the first and last 4 characters, for example `ApiKey('sk-B…bPtL')`, so keys don't leak into logs, tracebacks or debuggers. `str(key)` and `f"{key}"` give the full value.

```python
import pickle
from generateapikey import generate_api_key, is_expired

key = generate_api_key(prefix="sk", expiry=60)
print(repr(key))  # ApiKey('sk-x…AbCd', expires_at=…)
assert key.expires_at is not None and not key.is_expired
assert 0 < key.expires_in <= 3600
print(key.expires_at_datetime.isoformat())
assert is_expired(key) is False and is_expired("plain string") is False
assert pickle.loads(pickle.dumps(key)).expires_at == key.expires_at
headers = {"Authorization": f"Bearer {key}"}
```

Expiry lives only on the Python object. Persist `key.expires_at` next to the key's hash.

### Checksums

With `checksum=True`, a 6-character base62 encoding of CRC32 is appended, in the style of GitHub tokens. It is computed over the prefix, separator, dashes and body. `verify_checksum(key)` checks it offline, so you can reject typos, truncated keys and random garbage **before** touching the database. A checksum is not a security control: anyone can compute one. It only makes keys self-validating and [easy for secret scanners to find](#leak-detection).

```text
verify_checksum(key: str) -> bool     # never raises; False for non-str or too-short input
CHECKSUM_LENGTH = 6
```

```python
from generateapikey import generate_api_key, verify_checksum

key = generate_api_key(prefix="sk", checksum=True)
assert verify_checksum(key)
assert not verify_checksum(key[:-1])
assert not verify_checksum(None)
```

`compute_checksum` is listed under [Low-level building blocks](#low-level-building-blocks).

### Entropy

```text
entropy_bits(length: int, charset: str = "alphanumeric", case: str = "mixed") -> float
RECOMMENDED_ENTROPY = 128
class WeakKeyWarning(UserWarning)
```

`entropy_bits` returns `length * log2(len(build_charset(charset, case)))`.

```python
import warnings
import pytest
from generateapikey import WeakKeyWarning, entropy_bits, generate_api_key

assert round(entropy_bits(32), 1) == 190.5
assert entropy_bits(32, "hex") == 128.0

with pytest.raises(ValueError):
    generate_api_key(length=16, min_entropy=128)

with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always")
    generate_api_key(length=8)
assert caught[0].category is WeakKeyWarning
```

If you need a short key on purpose, you can silence the warning with `warnings.simplefilter("ignore", WeakKeyWarning)`. Increasing `length` is usually the better fix.

### Charsets

`CHARSETS` is a dict of the presets below. Any other string is used as a literal alphabet.

| Preset | Characters | Size | Bits/char | 32 chars |
|---|---|--:|--:|--:|
| `alphanumeric` (default) | `A-Z a-z 0-9` | 62 | 5.95 | 190.5 |
| `base62` | `0-9 A-Z a-z` (same set, sorted order) | 62 | 5.95 | 190.5 |
| `base58` | base62 minus `0 O I l` | 58 | 5.86 | 187.5 |
| `unambiguous` | base62 minus `0 O 1 I l o` | 56 | 5.81 | 185.8 |
| `base64url` | `A-Z a-z 0-9 - _` | 64 | 6.00 | 192.0 |
| `base32` | `A-Z 2-7` (RFC 4648) | 32 | 5.00 | 160.0 |
| `crockford` | `0-9 A-Z` minus `I L O U` | 32 | 5.00 | 160.0 |
| `alphabetic` | `A-Z a-z` | 52 | 5.70 | 182.4 |
| `hex` | `0-9 a-f` | 16 | 4.00 | 128.0 |
| `base16` | `0-9 A-F` | 16 | 4.00 | 128.0 |
| `numeric` | `0-9` | 10 | 3.32 | 106.3 (warns) |

Case handling has a few rules worth knowing:

- `case="lower"` or `"upper"` is applied, then duplicates are removed. For example, `alphanumeric` with `case="lower"` has 36 characters.
- For the look-alike-free presets (`base58`, `unambiguous`, `crockford`), any non-mixed `case` also removes `0 O 1 I l`. As a result, `crockford` with `case="upper"` has 30 characters (no `0` or `1`), even though the preset is already upper case.

```python
from generateapikey import CHARSETS, entropy_bits
from generateapikey.utils import build_charset

assert len(CHARSETS["base58"]) == 58
assert len(build_charset("alphanumeric", "lower")) == 36
assert "l" not in build_charset("base58", "lower")
assert len(build_charset("crockford", "upper")) == 30
print({name: round(entropy_bits(32, name), 1) for name in CHARSETS})
```

### Legacy API

The pre-0.5 async API still works for old code. Don't use it in new code.

```text
async generateApiKey(secret, seed, include=None, add_dashes=False, prefix=None, length=None, expiry=None) -> ApiKey
async is_token_valid(token: str) -> bool        # deprecated, emits DeprecationWarning
```

Unlike `generate_api_key(secret, seed)`, `generateApiKey` mixes in a random salt, so **every call returns a new key**. This matches its historical behaviour. `length` defaults to 32 and `expiry` is in minutes. `is_token_valid` checks a `_<timestamp>` suffix that no API ever produced. Use `ApiKey.is_expired` or `is_expired()` instead.

```python
import asyncio
from generateapikey import generateApiKey

k1 = asyncio.run(generateApiKey("change-me-secret", "user-1", prefix="sk"))
k2 = asyncio.run(generateApiKey("change-me-secret", "user-1", prefix="sk"))
assert k1 != k2 and k1.startswith("sk-")
```

---

## Storage hashing

```text
hash_api_key(key: str, pepper: str | None = None) -> str
verify_api_key(key: str, hashed: str, pepper: str | None = None) -> bool
```

| | Output | Algorithm |
|---|---|---|
| No pepper | `sha256$<64 hex>` | SHA-256 of the UTF-8 key |
| With pepper | `hmac-sha256$<64 hex>` | HMAC-SHA256 keyed with `subkey(pepper, "hash")` |

Security notes:

- **Store the hash, never the key.** Show the key to its owner once. On each request, either recompute the hash and look it up (an indexed column, which is what `APIKeyAuth` does) or call `verify_api_key` against a known hash.
- **A fast hash is correct here.** API keys are long and random, so bcrypt or argon2 would slow down every request without adding security. Short, human-sized codes are different: they use [`hash_code`](#low-level-building-blocks) (salted PBKDF2).
- **Use a pepper.** With a pepper kept outside the database, a leaked table alone isn't enough to test guesses. `pepper` must be a non-empty string or `None`. An empty string, usually an unset environment variable, raises `ValueError` rather than silently storing unpeppered hashes.
- `verify_api_key` is constant-time and never raises on bad input. A peppered hash only verifies with a pepper, and an unpeppered hash only verifies without one.

```python
from generateapikey import generate_api_key, hash_api_key, verify_api_key

PEPPER = "change-me-pepper"
key = generate_api_key(prefix="sk", checksum=True)

plain = hash_api_key(key)
peppered = hash_api_key(key, pepper=PEPPER)
assert plain.startswith("sha256$") and peppered.startswith("hmac-sha256$")
assert key.hash(PEPPER) == peppered

assert verify_api_key(key, peppered, pepper=PEPPER)
assert not verify_api_key(key, peppered)  # pepper required
assert not verify_api_key(key, plain, pepper=PEPPER)  # wrong scheme
assert not verify_api_key(None, plain)  # never raises
```

---

## Scopes

Permission scopes for keys, with wildcards. Scopes are not secrets, so they are compared normally.

```text
parse_scopes(scopes: str | Iterable[str] | None) -> frozenset[str]
has_scope(granted, required: str) -> bool
has_all_scopes(granted, required: Iterable[str] | str) -> bool   # empty required -> True
has_any_scope(granted, required: Iterable[str] | str) -> bool
```

`granted` may be a space- or comma-separated string, any iterable of strings, or `None`. Wildcard rules:

- `*` grants everything.
- `read:*` grants `read`, `read:users` and `read:users:list`.
- `read:users` grants only `read:users`.

```python
from generateapikey import has_all_scopes, has_any_scope, has_scope, parse_scopes

assert parse_scopes("read:users, write:users") == {"read:users", "write:users"}
assert has_scope(["read:*"], "read:users:list")
assert has_scope("read:*", "read")
assert not has_scope(["read:users"], "read:orders")
assert has_scope("*", "admin")
assert has_all_scopes("read:* write:users", ["read:orders", "write:users"])
assert has_all_scopes([], [])
assert has_any_scope(["read:users"], ["admin", "read:users"])
```

To enforce scopes per request, use `APIKeyAuth(required_scopes=[...])` or `auth.authenticate(key, scopes=[...])`. The record's `scopes` field is checked, and failures raise `AuthError(403)`. See [APIKeyAuth](#apikeyauth).

---

## Rotation and KeyStore

### `rotate_api_key`

```text
rotate_api_key(*, grace_minutes: float = 1440, pepper: str | None = None, **options) -> Rotation

@dataclass(frozen=True)
class Rotation:
    key: ApiKey            # give to the client once
    hashed: str            # store for the new key
    old_expires_at: int    # Unix time: set this as the OLD record's expires_at
```

This function issues a replacement key with any `generate_api_key` options (`checksum` defaults to `True`) and computes when the old key should stop working. Clients then have `grace_minutes` to switch with no downtime. It raises `ValueError` if `grace_minutes < 0`. It doesn't touch any storage: you update your own database.

```python
from generateapikey.keystore import rotate_api_key

PEPPER = "change-me-pepper"
db = {"old": {"hashed": "…", "expires_at": None}}

rot = rotate_api_key(grace_minutes=24 * 60, pepper=PEPPER, prefix="sk")
db["old"]["expires_at"] = rot.old_expires_at
db["new"] = {"hashed": rot.hashed, "expires_at": rot.key.expires_at}
print(rot)  # Rotation(old_expires_at=…, hashed=hmac-sha256$…): no raw key
```

### `KeyStore`

`generateapikey.keystore.KeyStore` is a small SQLite store that uses only the standard library. It suits CLIs, internal tools and small services. It stores hashes, never keys, and is thread-safe (one connection guarded by a lock). For a real application database, use [`issue_api_key`](#issue_api_key) or `rotate_api_key` with your own table.

```text
KeyStore(path: str = ":memory:", *, pepper: str | None = None, touch: bool = True, table_check: bool = True)

.create(name, *, scopes=(), meta=None, expiry=None, **options) -> Created
.lookup(hashed) -> KeyRecord | None          # APIKeyAuth lookup callback; updates last_used_at if touch
.get(key_id) -> KeyRecord | None
.list(*, active_only=False) -> list[KeyRecord]
.revoke(key_id) -> bool                      # True if a key was revoked now
.rotate(key_id, *, grace_minutes=1440, **options) -> Created
.close()                                     # also usable as a context manager
```

- `create` passes `options` to `generate_api_key`. `checksum` defaults to `True`, and `expiry` is in minutes. `name` must be a non-empty string, or `ValueError` is raised.
- `rotate` issues a replacement with the same name, scopes and meta. The old key's `expires_at` becomes the earlier of its current expiry and now + `grace_minutes`. It raises `KeyError` if `key_id` doesn't refer to an active key. **Key format options aren't stored.** Pass `prefix=` (and any other options) again, or the replacement will be an unprefixed key, which an `APIKeyAuth(prefix=...)` would reject.
- `table_check=True` creates the `api_keys` table if it doesn't exist.
- `lookup` returns revoked and expired records too. `APIKeyAuth` rejects them through `record_is_active`, which reads `KeyRecord.revoked`, `is_active` and `expires_at`.

```text
@dataclass(frozen=True)
class KeyRecord:
    id: int; name: str; hint: str; scopes: frozenset[str]
    created_at: int; expires_at: int | None; revoked: bool
    last_used_at: int | None; meta: dict
    is_active: bool  # property: not revoked and not expired

@dataclass(frozen=True)
class Created:
    id: int; key: ApiKey; record: KeyRecord     # repr hides the key
```

```python
from generateapikey.integrations import APIKeyAuth
from generateapikey.keystore import KeyStore

PEPPER = "change-me-pepper"

with KeyStore(":memory:", pepper=PEPPER) as store:  # or KeyStore("keys.db", ...)
    made = store.create("ci-bot", scopes=["read:*"], prefix="sk", expiry=60 * 24 * 90, meta={"team": "infra"})
    raw = str(made.key)  # show once
    print(made.record.hint)  # 'sk-AbCd…wXyZ'

    auth = APIKeyAuth(store.lookup, pepper=PEPPER, prefix="sk", required_scopes=["read:users"])
    record = auth.authenticate(raw)
    assert record.name == "ci-bot"

    new = store.rotate(made.id, grace_minutes=24 * 60, prefix="sk")  # old key works for 24 h more
    assert auth.authenticate(str(new.key)).id == new.id
    assert store.revoke(made.id)
    assert [r.id for r in store.list(active_only=True)] == [new.id]
```

For Django, `AbstractAPIKey.rotate(grace=...)` provides the same flow. For **pepper** rotation, see `previous_peppers` and `on_rehash` in [APIKeyAuth](#apikeyauth).

---

## Leak detection

`generateapikey.scanning` (`key_pattern` and `find_keys` are also importable from the top level). These functions build regexes that match keys you issue. Keys with a distinctive prefix and a checksum are easy for GitHub secret scanning, gitleaks or trufflehog to detect, and the checksum removes false positives.

```text
key_pattern(prefix: str, *, length=32, separator="-", charset="alphanumeric", case="mixed", checksum=True) -> str
find_keys(text: str, prefix: str, *, validate=True, **options) -> list[str]
gitleaks_rule(prefix: str, rule_id: str, *, description="", **options) -> str
```

- Pass the same `prefix`, `length`, `separator`, `charset`, `case` and `checksum` you issue keys with. Note that `checksum` defaults to `True` here but to `False` in `generate_api_key`. Keys issued with `dashes=True` aren't matched.
- `key_pattern` uses lookarounds, so it doesn't match inside longer tokens. `prefix` must be non-empty, or `ValueError` is raised.
- `find_keys` returns unique matches in order. With `validate=True` and `checksum=True`, each match must also pass `verify_checksum`. Non-`str` text returns `[]`.
- `gitleaks_rule` returns a `[[rules]]` TOML block for `.gitleaks.toml`. The lookarounds are removed because Go RE2 doesn't support them. `rule_id` must match `[A-Za-z0-9_.-]+`, or `ValueError` is raised.

```python
import re
from generateapikey import find_keys, generate_api_key, key_pattern
from generateapikey.scanning import gitleaks_rule

key = generate_api_key(prefix="sk", checksum=True)
log = f"user=42 auth={key} other=sk-{'A' * 38}"

assert re.search(key_pattern("sk"), log)
assert find_keys(log, "sk") == [str(key)]  # the look-alike fails its checksum
assert len(find_keys(log, "sk", validate=False)) == 2
print(gitleaks_rule("sk", "acme-api-key", description="Acme API key"))
```

---

## Framework integrations

`generateapikey.integrations` contains a framework-agnostic core, `APIKeyAuth`. Ten thin adapters map a request onto it and map `AuthError` onto a response, so behaviour is identical everywhere.

```text
from generateapikey.integrations import (
    APIKeyAuth, AuthError, IssuedKey, issue_api_key, record_is_active, path_excluded,
)
```

### `issue_api_key`

```text
issue_api_key(*, pepper: str | None = None, checksum: bool = True, **options) -> IssuedKey

@dataclass(frozen=True)
class IssuedKey:
    key: ApiKey     # give to the client once
    hashed: str     # store; put a unique index on it
    hint: str       # store and show in your UI: first 7 + '…' + last 4 chars, e.g. 'sk-AbCd…wXyZ'
```

`issue_api_key` generates a key plus everything you need to store for it. It accepts every `generate_api_key` option. `repr(IssuedKey)` never shows the raw key.

```python
from generateapikey.integrations import issue_api_key

PEPPER = "change-me-pepper"
issued = issue_api_key(prefix="sk", pepper=PEPPER, expiry=60 * 24 * 365)
row = {"hashed": issued.hashed, "hint": issued.hint, "expires_at": issued.key.expires_at, "scopes": ["read:*"]}
print(issued)  # IssuedKey(hint='sk-…', hashed=hmac-sha256$…)
```

### `APIKeyAuth`

```text
APIKeyAuth(
    lookup,                                  # lookup(hashed) -> record | None; sync or async
    *,
    pepper=None,
    header="X-API-Key",
    bearer=True,
    query_param=None,
    prefix=None,
    require_checksum=False,
    validate=record_is_active,
    limiter=None,
    on_success=None,
    previous_peppers=(),
    on_rehash=None,
    required_scopes=(),
)
```

| Option | Default | Meaning |
|---|---|---|
| `lookup` | required | `lookup(hashed) -> record or None`. It receives `hash_api_key(key, pepper)`, never the raw key, so query an indexed column. May be `async`, but only with `aauthenticate` and the async adapters. Raises `TypeError` if not callable. |
| `pepper` | `None` | The pepper used when the keys were issued. |
| `header` | `"X-API-Key"` | Header to read (case-insensitive). |
| `bearer` | `True` | Also accept `Authorization: Bearer <key>`. Also selects the `WWW-Authenticate` challenge. |
| `query_param` | `None` | Also accept `?<name>=<key>`. Discouraged, because URLs end up in logs. |
| `prefix` | `None` | Reject keys that don't start with this string, before any lookup. |
| `require_checksum` | `False` | Reject keys whose checksum fails, before any lookup. Use it when keys were issued with `checksum=True`, which `issue_api_key` does by default. |
| `validate` | `record_is_active` | `validate(record) -> bool`. Records that fail get 401. |
| `limiter` | `None` | An `AttemptLimiter`, `RedisAttemptLimiter` or `AsyncRedisAttemptLimiter`, keyed by client (IP). Each invalid key counts a failure; a blocked client gets 429 before any lookup. |
| `on_success` | `None` | `on_success(record)` after a successful check, for example to update `last_used_at`. May be async with `aauthenticate`. |
| `previous_peppers` | `()` | Old peppers still accepted during a pepper rotation. Lookups use the current pepper first, then each old one in order. A plain `str` raises `TypeError`. |
| `on_rehash` | `None` | `on_rehash(record, new_hashed)`, called when a key matched under an old pepper, so you can store its hash under the new pepper. |
| `required_scopes` | `()` | Scopes every key must hold, checked with `has_all_scopes(record.scopes, ...)`. Failing keys get 403. A plain `str` raises `TypeError`. |

Methods:

```text
.extract(headers, query=None) -> str | None
.authenticate(key, client=None, scopes=None) -> record        # sync; raises AuthError
async .aauthenticate(key, client=None, scopes=None) -> record # lookup/hooks/limiter may be sync or async
.challenge() -> str        # 'Bearer realm="api"' if bearer else 'ApiKey header="<header>"'
```

- **`extract`** reads `header` first, then `Authorization: Bearer` (if `bearer`), then `query_param` (if set). The value is trimmed, and an empty value becomes `None`. `headers` can be a dict or any framework's header object. Non-`str` values are treated as "no key".
- **`authenticate`** runs the full check in this order:
  1. If `client` is set and the limiter has blocked it, raise 429.
  2. If no key, raise 401 `Missing API key.`
  3. Pre-checks: at most 512 characters, ASCII only, `prefix` and checksum if configured.
  4. Look up the hash under each pepper.
  5. `validate(record)`. A failure counts against the limiter and raises 401 `Invalid API key.`
  6. Check scopes. Failure raises 403 `Insufficient scope.`
  7. Call `on_rehash` (if matched under an old pepper), then `on_success`.

  `scopes=` overrides `required_scopes` for one call. An async `lookup`, limiter or hook raises `TypeError` in the sync method.
- The limiter is consulted only when `client` is truthy. Valid keys don't count against it.

```python
import asyncio
import pytest
from generateapikey import AttemptLimiter
from generateapikey.integrations import APIKeyAuth, AuthError, issue_api_key

PEPPER = "change-me-pepper"
issued = issue_api_key(prefix="sk", pepper=PEPPER)
db = {issued.hashed: {"name": "ci", "scopes": ["read:*"], "revoked": False, "expires_at": None}}

auth = APIKeyAuth(
    lookup=db.get,
    pepper=PEPPER,
    prefix="sk",
    require_checksum=True,
    limiter=AttemptLimiter(max_attempts=10, window=60),
    required_scopes=["read:users"],
)

key = auth.extract({"Authorization": f"Bearer {issued.key}"})
assert auth.authenticate(key, client="203.0.113.7")["name"] == "ci"


async def lookup_async(hashed):
    return db.get(hashed)


async_auth = APIKeyAuth(lookup_async, pepper=PEPPER)
assert asyncio.run(async_auth.aauthenticate(str(issued.key)))["name"] == "ci"

with pytest.raises(AuthError) as err:
    auth.authenticate(key, scopes=["write:users"])  # per-call override
assert err.value.status == 403

with pytest.raises(AuthError) as err:
    auth.authenticate("sk-not-a-real-key", client="203.0.113.7")
assert (err.value.status, err.value.detail) == (401, "Invalid API key.")
print(auth.challenge())  # Bearer realm="api"
```

**Pepper rotation** moves keys to a new pepper as they are used:

```python
from generateapikey import hash_api_key
from generateapikey.integrations import APIKeyAuth

OLD, NEW = "change-me-old-pepper", "change-me-new-pepper"
key = "sk-example-key-for-docs"
db = {hash_api_key(key, OLD): {"id": 1}}


def on_rehash(record, new_hashed):
    old = next(h for h, r in db.items() if r is record)
    db[new_hashed] = db.pop(old)


auth = APIKeyAuth(db.get, pepper=NEW, previous_peppers=[OLD], on_rehash=on_rehash)
auth.authenticate(key)
assert hash_api_key(key, NEW) in db  # moved to the new pepper
```

Once every active key has been re-hashed, remove the old pepper.

### `record_is_active`, `path_excluded`, `AuthError`

```text
record_is_active(record) -> bool
path_excluded(path: str, exclude: Sequence[str]) -> bool
class AuthError(Exception): status: int; detail: str
```

`record_is_active` works on objects or mappings. It returns `False` if `record` is `None`, `revoked` is truthy, `is_active` is exactly `False`, or `expires_at` is in the past. `expires_at` can be a `datetime` (aware or naive) or a Unix timestamp in seconds. An `expires_at` of any other type fails closed.

`path_excluded` is the segment-aware prefix match used by the `exclude=` options. `/health` matches `/health` and `/health/live`, but not `/healthz` or `/health-admin`.

`AuthError.status` is one of the following. 401 responses carry `WWW-Authenticate: <auth.challenge()>`.

| status | detail |
|---|---|
| 401 | `Missing API key.` |
| 401 | `Invalid API key.` |
| 403 | `Insufficient scope.` |
| 429 | `Too many invalid API keys. Try again later.` |

```python
from datetime import datetime, timedelta, timezone
from generateapikey.integrations import path_excluded, record_is_active

assert record_is_active({"expires_at": datetime.now(timezone.utc) + timedelta(hours=1)})
assert not record_is_active({"revoked": True})
assert not record_is_active({"is_active": False})
assert not record_is_active({"expires_at": "2030-01-01"})  # unknown type: fail closed
assert path_excluded("/health/live", ["/health"]) and not path_excluded("/healthz", ["/health"])
```

### Adapters

| Framework | Module | API | Record ends up at | Missing key | sync/async `lookup` |
|---|---|---|---|---|---|
| FastAPI | `integrations.fastapi` | `APIKeyDependency(auth, *, scheme_name="APIKey")` | return value of the dependency, and `request.state.api_key` | 401 | both |
| Starlette | `integrations.starlette` | `APIKeyBackend(auth, scopes=None)`, `on_auth_error`, `APIKeyUser` | `request.user.record` (`request.auth.scopes` holds the scopes) | passes as unauthenticated (use `@requires`) | both |
| Django | `integrations.django` | `api_key_required(auth)`, `APIKeyMiddleware`, `AbstractAPIKey`, `model_lookup`, `touch_last_used`, `rehash_model` | `request.api_key` | decorator: 401; middleware: `request.api_key = None` | both (sync lookups run via `sync_to_async` in async views) |
| DRF | `integrations.drf` | `APIKeyAuthentication`, `HasAPIKey`, `APIKeyUser` | `request.auth` (and `request.user` = `record.user` or `APIKeyUser`) | `None` (other authenticators and permissions decide) | sync |
| Flask | `integrations.flask` | `require_api_key(auth)`, `FlaskAPIKey(app=None, auth=None)` | `flask.g.api_key` | 401 | sync views: sync; async views: both |
| Litestar | `integrations.litestar` | `api_key_middleware(auth, *, exclude=None, exclude_from_auth_key="exclude_from_auth")`, `APIKeyMiddleware` | `request.auth` (and `request.user` = `record.user` or the record) | 401 | both |
| Sanic | `integrations.sanic` | `require_api_key(auth)` | `request.ctx.api_key` | 401 | both |
| aiohttp | `integrations.aiohttp` | `api_key_middleware(auth, exclude=None)`, `require_api_key(auth)` | `request["api_key"]` | 401 | both |
| Quart | `integrations.quart` | `require_api_key(auth)` | `quart.g.api_key` | 401 | both |
| Falcon | `integrations.falcon` | `APIKeyMiddleware(auth, exclude=None)` (WSGI), `AsyncAPIKeyMiddleware(auth, exclude=None)` (ASGI), `require_api_key(auth)` hook | `req.context.api_key` | 401 | WSGI: sync; ASGI: both |

The client used for the limiter is the peer address each framework reports, for example `request.client.host`, `REMOTE_ADDR`, `request.remote_addr` or `request.ip`. Behind a proxy, that is the proxy's address unless the framework is configured to trust forwarded headers.

> **Status codes:** FastAPI, Starlette, Django, Flask, Sanic, aiohttp and Quart return the `AuthError` status as-is: 401, 403 or 429. In 0.6.0, the **Litestar, Falcon and DRF** adapters only special-case 429. A scope failure (403) reaches the client as **401** there.

Every adapter example below uses this shared setup (shown once):

```python
# myapp/auth.py (shared setup for the adapter examples)
from generateapikey.integrations import APIKeyAuth, issue_api_key

PEPPER = "change-me-pepper"
issued = issue_api_key(prefix="sk", pepper=PEPPER)
KEYS = {issued.hashed: {"name": "demo", "scopes": ["read:*"]}}  # your table, keyed by hash


def find_key_by_hash(hashed):
    return KEYS.get(hashed)


auth = APIKeyAuth(lookup=find_key_by_hash, pepper=PEPPER, prefix="sk", require_checksum=True)
```

#### FastAPI

```python
from fastapi import Depends, FastAPI, Request
from generateapikey.integrations import APIKeyAuth
from generateapikey.integrations.fastapi import APIKeyDependency

auth = APIKeyAuth(lookup=lambda hashed: None, pepper="change-me-pepper", prefix="sk")
require_key = APIKeyDependency(auth)  # adds the "Authorize" button to /docs
app = FastAPI()


@app.get("/items")
async def items(request: Request, key=Depends(require_key)):
    assert request.state.api_key is key
    return {"name": key["name"]}
```

The dependency registers an `APIKeyHeader` security scheme and, when `bearer=True`, an `HTTPBearer` scheme named `<scheme_name>Bearer`. Failures raise `HTTPException(status, detail)`, with `WWW-Authenticate` on 401.

#### Starlette

```python
from starlette.applications import Starlette
from starlette.authentication import requires
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from generateapikey.integrations import APIKeyAuth
from generateapikey.integrations.starlette import APIKeyBackend, on_auth_error

auth = APIKeyAuth(lookup=lambda hashed: None, pepper="change-me-pepper", prefix="sk")


@requires("authenticated")
async def items(request):
    return JSONResponse({"name": request.user.display_name, "scopes": request.auth.scopes})


app = Starlette(
    routes=[Route("/items", items)],
    middleware=[Middleware(AuthenticationMiddleware, backend=APIKeyBackend(auth), on_error=on_auth_error)],
)
```

Requests without a key pass through as unauthenticated, so `@requires` decides. Requests with a bad key get a JSON 401/403/429 from `on_auth_error`. By default the granted Starlette scopes are `["authenticated", *record.scopes]`. Pass `scopes=callable(record)` to change that. `APIKeyUser.display_name` is the record's `name`, or `"api-key"` if it has none.

#### Django

```python
# myapp/models.py
from django.conf import settings
from django.db import models
from generateapikey.integrations.django import AbstractAPIKey


class APIKey(AbstractAPIKey):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_keys")
```

```python
# myapp/keyauth.py
from generateapikey.integrations.django import APIKeyAuth, model_lookup, rehash_model, touch_last_used
from myapp.models import APIKey

auth = APIKeyAuth(
    lookup=model_lookup(APIKey, select_related=("user",)),
    pepper="change-me-pepper",  # e.g. settings.API_KEY_PEPPER, loaded from the environment
    prefix="sk",
    require_checksum=True,
    on_success=touch_last_used,
    on_rehash=rehash_model(APIKey),  # only matters with previous_peppers=[...]
)
```

```python
# myapp/views.py
from datetime import timedelta
from django.http import JsonResponse
from generateapikey.integrations.django import api_key_required
from myapp.keyauth import auth
from myapp.models import APIKey


@api_key_required(auth)  # sync or async views
def whoami(request):
    return JsonResponse({"user": request.api_key.user.username, "key": request.api_key.hint})


def create_key(request):  # behind your normal login
    obj, raw = APIKey.objects.create_key(
        pepper="change-me-pepper", key_options={"expiry": 60 * 24 * 90}, name="CLI", user=request.user
    )
    return JsonResponse({"api_key": raw, "hint": obj.hint})  # raw is shown once


def rotate_key(request, pk):
    old = APIKey.objects.get(pk=pk, user=request.user)
    new, raw = old.rotate(pepper="change-me-pepper", grace=timedelta(hours=24))
    return JsonResponse({"api_key": raw, "hint": new.hint})
```

Site-wide handling:

```python
# settings.py
GENERATEAPIKEY_AUTH = "myapp.keyauth.auth"  # dotted path to an APIKeyAuth instance
MIDDLEWARE = [
    # ...
    "generateapikey.integrations.django.APIKeyMiddleware",
]
```

Django API:

| Name | Signature / fields |
|---|---|
| `AbstractAPIKey` | Abstract model with `name`, `hashed_key` (unique), `hint`, `created_at`, `expires_at`, `last_used_at`, `revoked`. It has **no** `scopes` field: add one (for example a `JSONField`) if you use `required_scopes`. |
| `APIKey.objects.create_key` | `(*, pepper=None, key_options=None, **fields) -> (obj, raw_key)`. `key_options` go to `generate_api_key`; the default prefix is `"sk"`, with a checksum. An `expiry` in `key_options` fills `expires_at`. |
| `obj.revoke()` | Sets `revoked=True`. |
| `obj.rotate` | `(*, pepper=None, grace=None, key_options=None, **fields) -> (new_obj, raw_key)`. Copies the other fields (name, FKs). With `grace` (a `timedelta`) the old key expires after it; without it, the old key is revoked immediately. |
| `model_lookup` | `(model, *, field="hashed_key", select_related=()) -> lookup` |
| `touch_last_used` | `on_success` hook. Updates `last_used_at` with a single `UPDATE`. |
| `rehash_model` | `(model, *, field="hashed_key") -> on_rehash` hook |
| `api_key_required(auth)` | View decorator. Sets `request.api_key`, or returns a JSON 401/403/429. |
| `APIKeyMiddleware(get_response, auth=None)` | Sets `request.api_key` (the record, or `None` when no key was sent) and rejects bad keys. `auth` defaults to `settings.GENERATEAPIKEY_AUTH`, and `ImproperlyConfigured` is raised if that setting is missing. |
| `APIKeyAuth` | Re-exported for convenience. |

#### Django REST Framework

```python
# settings.py
GENERATEAPIKEY_AUTH = "myapp.keyauth.auth"
REST_FRAMEWORK = {"DEFAULT_AUTHENTICATION_CLASSES": ["generateapikey.integrations.drf.APIKeyAuthentication"]}
```

```python
# myapp/api.py
from rest_framework.response import Response
from rest_framework.views import APIView
from generateapikey.integrations.drf import APIKeyAuthentication, HasAPIKey
from myapp.keyauth import auth


class Items(APIView):
    permission_classes = [HasAPIKey]  # or IsAuthenticated

    def get(self, request):
        return Response({"hint": request.auth.hint})  # request.user = record.user, or an APIKeyUser


class ScopedAuth(APIKeyAuthentication):  # skip the setting by subclassing
    auth = auth
```

`APIKeyAuthentication.authenticate` returns `None` when no key is sent, so other authenticators can run. It raises `AuthenticationFailed` (401) for a bad key and `Throttled` (429) when the limiter blocks a client. `HasAPIKey` allows only requests authenticated by `APIKeyAuthentication`. `APIKeyUser` is an authenticated, non-staff stand-in user that holds `.record`. The DRF adapter uses the sync `authenticate`, so `lookup` must be sync.

#### Flask

```python
from flask import Flask, g
from generateapikey.integrations import APIKeyAuth
from generateapikey.integrations.flask import FlaskAPIKey, require_api_key

auth = APIKeyAuth(lookup=lambda hashed: None, pepper="change-me-pepper", prefix="sk")
app = Flask(__name__)


@app.get("/items")
@require_api_key(auth)  # async views (Flask[async]) work too
def items():
    return {"name": g.api_key["name"]}


api_key = FlaskAPIKey(app, auth)  # or FlaskAPIKey() + api_key.init_app(app, auth)


@app.get("/other")
@api_key.required
def other():
    return {"ok": True}
```

`FlaskAPIKey.init_app` raises `ValueError` without an `APIKeyAuth`, and `.required` raises `ValueError` before `init_app`. The extension registers itself as `app.extensions["generateapikey"]`.

#### Litestar

```python
from litestar import Litestar, Request, get
from generateapikey.integrations import APIKeyAuth
from generateapikey.integrations.litestar import api_key_middleware

auth = APIKeyAuth(lookup=lambda hashed: None, pepper="change-me-pepper", prefix="sk")


@get("/items")
async def items(request: Request) -> dict:
    return {"name": request.auth["name"]}


@get("/health", opt={"exclude_from_auth": True})
async def health() -> dict:
    return {"ok": True}


app = Litestar([items, health], middleware=[api_key_middleware(auth, exclude=["/docs"])])
```

Every route that isn't excluded requires a key. `exclude` is passed to Litestar's `AbstractAuthenticationMiddleware`, which treats each entry as a regex pattern; it isn't `path_excluded`. Failures raise `NotAuthorizedException` (401 with `WWW-Authenticate`) or `TooManyRequestsException` (429).

#### Sanic

```python
from sanic import Sanic
from sanic.response import json
from generateapikey.integrations import APIKeyAuth
from generateapikey.integrations.sanic import require_api_key

auth = APIKeyAuth(lookup=lambda hashed: None, pepper="change-me-pepper", prefix="sk")
app = Sanic("docs_example")


@app.get("/items")
@require_api_key(auth)
async def items(request):
    return json({"name": request.ctx.api_key["name"]})
```

#### aiohttp

```python
from aiohttp import web
from generateapikey.integrations import APIKeyAuth
from generateapikey.integrations.aiohttp import api_key_middleware, require_api_key

auth = APIKeyAuth(lookup=lambda hashed: None, pepper="change-me-pepper", prefix="sk")


async def items(request):
    return web.json_response({"name": request["api_key"]["name"]})


async def health(request):
    return web.json_response({"ok": True})


app = web.Application(middlewares=[api_key_middleware(auth, exclude=["/health"])])  # segment-aware
app.router.add_get("/items", items)
app.router.add_get("/health", health)


@require_api_key(auth)  # per-handler alternative to the middleware
async def single(request):
    return web.json_response({"name": request["api_key"]["name"]})
```

#### Quart

```python
from quart import Quart, g
from generateapikey.integrations import APIKeyAuth
from generateapikey.integrations.quart import require_api_key

auth = APIKeyAuth(lookup=lambda hashed: None, pepper="change-me-pepper", prefix="sk")
app = Quart(__name__)


@app.get("/items")
@require_api_key(auth)
async def items():
    return {"name": g.api_key["name"]}
```

#### Falcon

```python
import falcon
import falcon.asgi
from generateapikey.integrations import APIKeyAuth
from generateapikey.integrations.falcon import APIKeyMiddleware, AsyncAPIKeyMiddleware, require_api_key

auth = APIKeyAuth(lookup=lambda hashed: None, pepper="change-me-pepper", prefix="sk")


class Items:
    def on_get(self, req, resp):
        resp.media = {"name": req.context.api_key["name"]}


app = falcon.App(middleware=[APIKeyMiddleware(auth, exclude=["/health"])])  # WSGI
app.add_route("/items", Items())

asgi_app = falcon.asgi.App(middleware=[AsyncAPIKeyMiddleware(auth)])  # ASGI; async lookup allowed


@falcon.before(require_api_key(auth))  # per resource or responder; WSGI and ASGI
class Guarded:
    def on_get(self, req, resp):
        resp.media = {"name": req.context.api_key["name"]}
```

Failures raise `falcon.HTTPUnauthorized` (with the challenge) or `falcon.HTTPTooManyRequests`. Unrouted paths (no resource) are skipped by the middleware. For repeated query parameters, the first value is used.

#### Any other framework

```python
from generateapikey.integrations import APIKeyAuth, AuthError

auth = APIKeyAuth(lookup=lambda hashed: None, pepper="change-me-pepper")


def handle(headers, query, client_ip):
    key = auth.extract(headers, query)
    try:
        record = auth.authenticate(key, client=client_ip)  # or: await auth.aauthenticate(...)
    except AuthError as e:
        extra = {"WWW-Authenticate": auth.challenge()} if e.status == 401 else {}
        return e.status, {"detail": e.detail}, extra
    return 200, {"name": record["name"]}, {}


assert handle({}, {}, "198.51.100.1")[0] == 401
```

---

## MFA

`generateapikey.mfa` uses only the standard library. The most common names are re-exported from `generateapikey`. The low-level `hotp`, `totp`, `find_totp_step`, `verify_hotp`, `hotp_uri` and `normalize_recovery_code` are imported from `generateapikey.mfa`.

### TOTP and HOTP

```text
generate_totp_secret(num_bytes: int = 20) -> str           # base32, no padding; num_bytes >= 10

mfa.hotp(secret, counter, *, digits=6, algorithm="sha1") -> str                     # RFC 4226
mfa.totp(secret, at=None, *, period=30, digits=6, algorithm="sha1") -> str          # RFC 6238
totp_now(secret, **options) -> str                         # = totp(secret, **options)

mfa.find_totp_step(secret, code, *, window=1, period=30, digits=6, algorithm="sha1",
                   at=None, last_used_step=None) -> int | None
verify_totp(secret, code, **options) -> bool               # find_totp_step(...) is not None
mfa.verify_hotp(secret, code, counter, *, look_ahead=0, digits=6, algorithm="sha1") -> int | None
```

- `secret` is a base32 `str` (case, spaces, dashes and `=` padding are ignored) or raw `bytes`. It must decode to at least 10 bytes (80 bits). The default of 20 bytes is the RFC recommendation.
- `digits` must be 6–8 and `algorithm` must be `"sha1"`, `"sha256"` or `"sha512"`. Anything else raises `ValueError`.
- `code` can be a `str`, which may contain spaces or dashes, or an `int`. Ints are zero-padded to `digits`, so `4411` matches `"004411"`. Malformed codes return `None`/`False` and never raise.
- `window=1` accepts one step either side of now to allow for clock drift. Every candidate is checked, with no early exit.
- **Replay protection:** store the step returned by `find_totp_step` and pass it back as `last_used_step`. Steps at or before it are refused, so the same code can't be used twice.
- `verify_hotp` returns the **next counter to store** (always ≥ 1, so truthy) or `None`. It checks `counter … counter + look_ahead`.
- **Rate-limit every check.** A 6-digit code has a million values. Call [`AttemptLimiter.hit`](#attemptlimiter) **before** verifying.
- TOTP secrets can't be hashed, because the server needs them. Encrypt them at rest with [`SecretBox`](#secretbox-encryption-at-rest).

```python
import base64
from generateapikey import AttemptLimiter, generate_totp_secret, totp_now, totp_uri, verify_totp
from generateapikey.mfa import find_totp_step, hotp, totp, verify_hotp

# RFC 4226 / RFC 6238 test vectors
rfc = base64.b32encode(b"12345678901234567890").decode()
assert hotp(rfc, 0) == "755224"
assert totp(rfc, 59, digits=8) == "94287082"

# Enrolment
secret = generate_totp_secret()
uri = totp_uri(secret, "alice@example.com", issuer="MyApp")  # render as a QR code

# Login, with brute-force limit and replay protection
limiter = AttemptLimiter(max_attempts=5, window=15 * 60)
user = {"id": "alice", "last_totp_step": None}
code = totp_now(secret)  # what the user types

if limiter.hit(user["id"]):
    step = find_totp_step(secret, code, last_used_step=user["last_totp_step"])
    if step is not None:
        user["last_totp_step"] = step
        limiter.reset(user["id"])
assert user["last_totp_step"] is not None
assert find_totp_step(secret, code, last_used_step=user["last_totp_step"]) is None  # replay refused
assert verify_totp(secret, code) and not verify_totp(secret, "abc")

# HOTP: store the returned counter
counter = 0
nxt = verify_hotp(secret, hotp(secret, 2), counter, look_ahead=3)
assert nxt == 3
```

### otpauth URIs

```text
totp_uri(secret: str, account: str, issuer=None, *, period=30, digits=6, algorithm="sha1", image=None) -> str
mfa.hotp_uri(secret: str, account: str, issuer=None, *, counter=0, digits=6, algorithm="sha1") -> str
```

These build `otpauth://totp/Issuer:account?secret=…&issuer=…` URIs. Non-default `period`, `digits` and `algorithm` are included, but some apps, Google Authenticator among them, ignore them. `image` adds a logo URL parameter for apps that support it. `account` is required and neither `account` nor `issuer` may contain `:`. The secret is validated, and each of these raises `ValueError` if it fails.

```python
from generateapikey import totp_uri
from generateapikey.mfa import hotp_uri

secret = "JBSWY3DPEHPK3PXP"  # public test value
assert totp_uri(secret, "alice@example.com", "MyApp") == (
    "otpauth://totp/MyApp:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp"
)
print(totp_uri(secret, "alice@example.com", "MyApp", digits=8, algorithm="sha256", period=60))
print(hotp_uri(secret, "alice@example.com", "MyApp", counter=5))
```

### Steam Guard codes

```text
steam_code(secret, at=None) -> str                                     # 5 chars from 23456789BCDFGHJKMNPQRTVWXY
verify_steam_code(secret, code, *, window=1, at=None) -> bool          # case-insensitive, no early exit
```

These generate Steam Guard style codes (HMAC-SHA1, 30-second steps).

```python
from generateapikey import generate_totp_secret, steam_code, verify_steam_code

secret = generate_totp_secret()
code = steam_code(secret)
assert len(code) == 5 and verify_steam_code(secret, code.lower())
```

### Google Authenticator migration

```text
google_migration_uri(accounts: Iterable[dict]) -> str     # 'otpauth-migration://offline?data=…'
```

Each account is a dict with `secret` (base32) and `name`, plus optional `issuer`, `digits` (6 or 8) and `algorithm` (`sha1`, `sha256` or `sha512`). All accounts are TOTP. Render the URI as a QR code so users can import several accounts at once. Large batches should be split across several URIs, since one QR code holds only so much. **Keep the URI private:** it contains the secrets. It raises `ValueError` for an empty list or unsupported `digits` or `algorithm`, and `KeyError` if `secret` or `name` is missing.

```python
from generateapikey import generate_totp_secret, google_migration_uri

uri = google_migration_uri([
    {"secret": generate_totp_secret(), "name": "alice@example.com", "issuer": "MyApp"},
    {"secret": generate_totp_secret(), "name": "alice-admin", "digits": 8, "algorithm": "sha256"},
])
assert uri.startswith("otpauth-migration://offline?data=")
```

### Recovery codes

```text
generate_recovery_codes(count: int = 10, length: int = 10, group: int = 5) -> list[str]
hash_recovery_code(code: str, pepper: str | None = None) -> str
verify_recovery_code(code: str, hashes: Iterable[str], pepper: str | None = None) -> str | None
mfa.normalize_recovery_code(code: str) -> str
```

- Codes are Crockford base32 (no `I L O U`), 10 characters = 50 bits by default, and grouped with a dash every `group` characters (`group=0` disables grouping). The codes in one batch are unique, but they come back in no particular order. `count` must be ≥ 1 and `length` ≥ 8.
- Show the codes to the user once, and store only `hash_recovery_code` of each. The hash is salted PBKDF2-SHA256 with 100,000 iterations, so each call gives a different string. Never compare hashes directly; always use `verify_recovery_code`.
- Input is normalized: upper-cased, spaces and dashes dropped, and `O→0`, `I/L→1`.
- `verify_recovery_code` returns the **stored hash** that matched, or `None`. **Delete that hash** so the code is single-use. It checks every hash with no early exit and never raises on bad input.

```python
from generateapikey import generate_recovery_codes, hash_recovery_code, verify_recovery_code
from generateapikey.mfa import normalize_recovery_code

PEPPER = "change-me-pepper"
codes = generate_recovery_codes()  # ['7KQ2M-9XPAB', …] x10
stored = [hash_recovery_code(c, PEPPER) for c in codes]

typed = codes[3].lower().replace("-", " ")  # sloppy user input still works
used = verify_recovery_code(typed, stored, PEPPER)
assert used == stored[3]
stored.remove(used)  # single use
assert verify_recovery_code(typed, stored, PEPPER) is None
assert normalize_recovery_code("7kq2m-9xpab o") == "7KQ2M9XPAB0"
```

### One-time codes (email and SMS)

```text
generate_otp(digits: int = 6, expiry: float | None = 10, *, charset: str = "0123456789") -> ApiKey
hash_otp(code: str, pepper: str | None = None) -> str
verify_otp(code, hashed: str, expires_at: float | None = None, *, pepper: str | None = None) -> bool
```

- `generate_otp` returns an `ApiKey` whose `expires_at` is set from `expiry` (minutes; `None` means no expiry). `digits` must be 4–12. `charset` accepts a preset name or literal characters, like `generate_api_key`.
- `hash_otp` uses salted PBKDF2. A 6-digit code has only 10⁶ values, so anyone holding the hash *and* the pepper can brute-force it. Use a pepper kept outside the database, a short expiry, and an attempt limit.
- `verify_otp` returns `False` once `expires_at` has passed. It never raises on bad input. Pass the code as a string: an `int` returns `False` here (and `hash_otp` raises `ValueError` for one), because leading zeros can't be recovered without knowing `digits`.

```python
from generateapikey import AttemptLimiter, generate_otp, hash_otp, verify_otp

PEPPER = "change-me-pepper"
limiter = AttemptLimiter()

code = generate_otp()  # '583920', valid for 10 minutes
row = {"hash": hash_otp(code, pepper=PEPPER), "expires_at": code.expires_at}
# send_email(user, f"Your code is {code}")

user_input = str(code)
assert limiter.hit("alice@example.com")
assert verify_otp(user_input, row["hash"], row["expires_at"], pepper=PEPPER)
assert not verify_otp(user_input, row["hash"], 0, pepper=PEPPER)  # expired
```

### `AttemptLimiter`

```text
AttemptLimiter(max_attempts: int = 5, window: float = 900, max_keys: int = 100_000)
.hit(key) -> bool         # atomically count an attempt; False if already at the limit (not counted)
.fail(key) -> int         # count a failure; returns attempts left
.is_blocked(key) -> bool
.remaining(key) -> int
.reset(key) -> None
```

This is a thread-safe, in-memory, fixed-window limiter. The window starts at a key's first attempt and uses a monotonic clock. Memory is capped by `max_keys`: expired entries are dropped first, then the oldest. All three arguments must be positive, or `ValueError` is raised.

**Call `hit()` before verifying.** It checks and counts the attempt in one atomic step, so parallel requests can't all slip past the limit. A separate `is_blocked()` followed by `fail()` has a race. Call `reset()` after a success. The limiter lives in one process. With several workers or servers, use the [Redis limiters](#redis-limiters).

```python
from generateapikey import AttemptLimiter, generate_totp_secret, verify_totp

limiter = AttemptLimiter(max_attempts=3, window=15 * 60)
secret = generate_totp_secret()

for _ in range(3):
    assert limiter.hit("alice")
    assert not verify_totp(secret, "000000x")  # malformed: always False
assert not limiter.hit("alice")  # blocked
assert limiter.is_blocked("alice") and limiter.remaining("alice") == 0
limiter.reset("alice")
assert limiter.remaining("alice") == 3
```

### Redis limiters

`generateapikey.limiters` (extra `redis`):

```text
RedisAttemptLimiter(client, max_attempts=5, window=900, prefix="gak:attempts:")
AsyncRedisAttemptLimiter(client, max_attempts=5, window=900, prefix="gak:attempts:")   # redis.asyncio client; coroutine methods
.hit(key) / .fail(key) / .is_blocked(key) / .remaining(key) / .reset(key)
```

These have the same interface as `AttemptLimiter`. Counts are shared by every process. Each `hit` and `fail` is a single atomic Lua script, so counts stay exact under concurrency. Counters expire on their own: a fixed window from the first attempt, set with `PEXPIRE`. The Redis key is `prefix + sha256(key).hexdigest()`, so arbitrary user input can't create odd keys, and the counters are shared with the npm package. Both classes plug into `APIKeyAuth(limiter=...)`. `AsyncRedisAttemptLimiter` requires `aauthenticate`, which every async adapter uses. `max_attempts` and `window` must be positive.

```python
import asyncio
import fakeredis  # for this example only; in production: redis.Redis(...) / redis.asyncio.Redis(...)
from generateapikey.integrations import APIKeyAuth
from generateapikey.limiters import AsyncRedisAttemptLimiter, RedisAttemptLimiter

limiter = RedisAttemptLimiter(fakeredis.FakeRedis(), max_attempts=5, window=900)
assert limiter.hit("alice") and limiter.remaining("alice") == 4
limiter.reset("alice")

auth = APIKeyAuth(lookup=lambda hashed: None, pepper="change-me-pepper", limiter=limiter)


async def main():
    alimiter = AsyncRedisAttemptLimiter(fakeredis.FakeAsyncRedis(), max_attempts=2, window=60)
    assert await alimiter.hit("bob") and await alimiter.hit("bob")
    assert not await alimiter.hit("bob")


asyncio.run(main())
```

---

## Signed tokens

`generateapikey.tokens`: URL-safe, signed, self-expiring tokens for magic links, email verification and password resets. They need no database lookup.

```text
generate_signed_token(secret: str, data: dict | None = None, *, purpose="default", expiry: float | None = 15,
                      context: str | None = None) -> str
verify_signed_token(token: str, secret: str, *, purpose="default", with_meta=False,
                    context: str | None = None) -> dict | None
tokens.MIN_SECRET_LENGTH = 16
```

- The format is `base64url(json payload).base64url(HMAC-SHA256)`, signed with `subkey(secret, "token")`. The payload is **readable, not encrypted**, so don't put secrets in it.
- `secret` must be a `str` of at least 16 characters, or `ValueError` is raised (in both functions). Use `secrets.token_urlsafe(32)` and keep it out of the database.
- `purpose` binds a token to one flow, so a reset token can't be used to log in. `expiry` is in minutes; `None` means the token never expires.
- `context` binds the token to a value that isn't transmitted, such as a session ID or device cookie. The value is signed but not stored in the token, so a forwarded or leaked link only works where the same `context` is presented. Don't bind to IP addresses, because mobile IPs change.
- `verify_signed_token` returns `data`, or `None` for a bad signature, purpose, expiry or format. Tokens over 8192 characters are rejected. With `with_meta=True` it returns `{"data", "jti", "exp"}`.
- Every token carries a random `jti`. **For single-use links, store used `jti` values** and reject repeats.

```python
from generateapikey import generate_signed_token, verify_signed_token

SECRET = "change-me-signing-secret-32-chars"
session_id = "session-abc"

token = generate_signed_token(SECRET, {"uid": 42}, purpose="login", expiry=15, context=session_id)
link = f"https://myapp.example/magic?token={token}"

assert verify_signed_token(token, SECRET, purpose="login", context=session_id) == {"uid": 42}
assert verify_signed_token(token, SECRET, purpose="reset", context=session_id) is None  # wrong flow
assert verify_signed_token(token, SECRET, purpose="login") is None  # wrong/missing context

meta = verify_signed_token(token, SECRET, purpose="login", context=session_id, with_meta=True)
used_jtis = {meta["jti"]}  # reject this jti next time
```

---

## JWT

Standard RFC 7519 JWTs that interoperate with PyJWT and other libraries in both directions.

```text
encode_jwt(claims: dict, secret: str | bytes, *, algorithm="HS256", expiry: float | None = 15,
           issuer=None, audience=None, headers: dict | None = None) -> str
decode_jwt(token: str, secret: str | bytes, *, algorithms: tuple[str, ...] = ("HS256",),
           issuer=None, audience=None, leeway: float = 0, require_exp: bool = True) -> dict | None
decode_jwt_jwks(token: str, jwks: dict, *, algorithms: tuple[str, ...] = ("RS256",), **options) -> dict | None
```

| Algorithms | `secret` for encode | `secret` for decode | Extra |
|---|---|---|---|
| `HS256`, `HS384`, `HS512` | shared secret, `str`, at least 16 characters | same secret | none |
| `RS256/384/512`, `PS256/384/512` | RSA private key PEM, at least 2048 bits | RSA public key PEM (or the private PEM) | `crypto` |
| `ES256`, `ES384`, `ES512` | EC private key PEM on P-256 / P-384 / P-521 respectively | EC public key PEM on the matching curve | `crypto` |
| `EdDSA` | Ed25519 private key PEM | Ed25519 public key PEM | `crypto` |

**Key formats:** keys are PEM as `str` or `bytes`. Private keys must be unencrypted (PKCS#8 or traditional OpenSSL). For verification, any PEM public key (SubjectPublicKeyInfo, or PKCS#1 for RSA) works, and so does a private key PEM, from which the public half is derived. HS secrets must be `str`. A `bytes` HS secret raises `ValueError`, despite the `Union[str, bytes]` annotation. JWKs (`kty` `RSA`, `EC` with `P-256/384/521`, or `OKP` with `Ed25519`) are accepted by `decode_jwt_jwks`.

**`encode_jwt`** adds `iat`, `exp` (from `expiry` in minutes, unless `expiry=None`), `iss` and `aud` to `claims` unless they're already set. `headers` adds header fields such as `kid`, but `alg` and `typ` can't be overridden. `alg: none` can be neither created nor accepted.

**`decode_jwt`** returns the claims, or `None` for an invalid, expired or not-yet-valid token. Security behaviour:

- **The accepted algorithms are pinned by you**, never taken from the token header. `algorithms` must be a tuple of known names; a bare string raises `ValueError`.
- HS* and asymmetric algorithms can't be mixed in one call. Mixing them is the classic algorithm-confusion attack, and it raises `ValueError`.
- It checks the signature, `exp` and `nbf` (both with `leeway` seconds), and `iss` and `aud` when you pass them. `aud` may be a string or a list. `require_exp=True` rejects tokens without an `exp`.
- A key that doesn't fit the algorithm (for example an RSA key with `ES256`) raises `ValueError`, because it's a configuration error. **Pin algorithms of a single key type per call.** With `algorithms=("RS256", "ES256")` and an RSA key, a token whose header says `ES256` raises `ValueError` instead of returning `None`.

**`decode_jwt_jwks`** verifies an asymmetric token against a JWKS document (`{"keys": [...]}`). If the token has a `kid`, only the key with that `kid` is tried. A token whose `kid` matches no key is rejected. Without a `kid`, every key is tried. The algorithm is still pinned by `algorithms`, and other `options` (`issuer`, `audience`, `leeway`, `require_exp`) are passed to `decode_jwt`. Fetching and caching the JWKS is up to you; it's just JSON from your identity provider's `/.well-known/jwks.json`. JWKs that can't be parsed are skipped. Because a key of the wrong type raises (see above), use tokens with a `kid` when the JWKS mixes RSA and EC keys.

```python
from generateapikey import decode_jwt, encode_jwt

SECRET = "change-me-jwt-secret-32-characters"

token = encode_jwt({"sub": "42", "role": "admin"}, SECRET, expiry=15, issuer="myapp", audience="api")
claims = decode_jwt(token, SECRET, issuer="myapp", audience="api")
assert claims["sub"] == "42" and {"iat", "exp", "iss", "aud"} <= claims.keys()

assert decode_jwt(token, SECRET, audience="other") is None
assert decode_jwt(token + "x", SECRET) is None  # never raises on a bad token

t512 = encode_jwt({"sub": "1"}, SECRET, algorithm="HS512", expiry=None)
assert decode_jwt(t512, SECRET, algorithms=("HS512",), require_exp=False)["sub"] == "1"
```

Asymmetric algorithms and JWKS (extra `crypto`):

```python
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from generateapikey import decode_jwt, decode_jwt_jwks, encode_jwt


def pem_pair(private_key):
    priv = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pub = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv, pub


rsa_priv, rsa_pub = pem_pair(rsa.generate_private_key(public_exponent=65537, key_size=2048))
ec_priv, ec_pub = pem_pair(ec.generate_private_key(ec.SECP256R1()))
ed_priv, ed_pub = pem_pair(ed25519.Ed25519PrivateKey.generate())

for alg, priv, pub in [("RS256", rsa_priv, rsa_pub), ("PS384", rsa_priv, rsa_pub),
                       ("ES256", ec_priv, ec_pub), ("EdDSA", ed_priv, ed_pub)]:
    token = encode_jwt({"sub": "42"}, priv, algorithm=alg)
    assert decode_jwt(token, pub, algorithms=(alg,))["sub"] == "42"

# JWKS: the kid selects one of the keys you already trust
def b64u(n):
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode().rstrip("=")


numbers = serialization.load_pem_public_key(rsa_pub).public_numbers()
jwks = {"keys": [{"kty": "RSA", "kid": "2026-01", "n": b64u(numbers.n), "e": b64u(numbers.e)}]}

token = encode_jwt({"sub": "42"}, rsa_priv, algorithm="RS256", audience="api", headers={"kid": "2026-01"})
assert decode_jwt_jwks(token, jwks, algorithms=("RS256",), audience="api")["sub"] == "42"
```

---

## SecretBox: encryption at rest

`generateapikey.crypto` (extra `crypto`). Use it for secrets the server must read back, such as TOTP secrets and webhook signing secrets, which can't be hashed.

```text
generate_encryption_key() -> str                       # 32 random bytes, URL-safe base64
SecretBox(key: str, old_keys: Sequence[str] = ())
.encrypt(plaintext: str, aad: str | None = None) -> str
.decrypt(token: str, aad: str | None = None) -> str     # raises DecryptionError
.needs_rotation(token: str) -> bool
.rotate(token: str, aad: str | None = None) -> str     # re-encrypt under the current key (no-op if current)
class DecryptionError(ValueError)
```

- The cipher is AES-256-GCM with a random 96-bit nonce per message. The format is `v1.<key-id>.<base64url(nonce ‖ ciphertext ‖ tag)>`, where `key-id` is derived from the key, so the right key is chosen on decrypt.
- `aad` (associated data, for example the user ID) is authenticated but not stored. A ciphertext copied to another user's row fails to decrypt.
- **Key rotation:** `SecretBox(new_key, old_keys=[old_key])` decrypts with any of the keys and always encrypts with the new one. Re-encrypt rows where `needs_rotation()` is true, then drop the old key.
- The key must decode to exactly 32 bytes, or `ValueError` is raised. `repr(box)` never shows key material.

```python
import pytest
from generateapikey import generate_totp_secret
from generateapikey.crypto import DecryptionError, SecretBox, generate_encryption_key

OLD_KEY = generate_encryption_key()  # once; keep in env / a secret manager
NEW_KEY = generate_encryption_key()

box = SecretBox(OLD_KEY)
totp_secret = generate_totp_secret()
stored = box.encrypt(totp_secret, aad="user:42")
assert box.decrypt(stored, aad="user:42") == totp_secret

with pytest.raises(DecryptionError):
    box.decrypt(stored, aad="user:43")  # bound to user 42

box = SecretBox(NEW_KEY, old_keys=[OLD_KEY])
assert box.needs_rotation(stored)
stored = box.rotate(stored, aad="user:42")
assert not box.needs_rotation(stored) and box.decrypt(stored, aad="user:42") == totp_secret
```

---

## QR codes

`generateapikey.qr` (extra `qr`). Use it to show an `otpauth://` URI in an MFA setup screen. Error correction is level M, with a 2-module border.

```text
qr_svg(data: str) -> str                      # inline SVG markup
qr_png(data: str) -> bytes                    # PNG bytes (pypng)
qr_ascii(data: str, invert: bool = False) -> str   # for terminals
```

```python
from generateapikey import generate_totp_secret, totp_uri
from generateapikey.qr import qr_ascii, qr_png, qr_svg

uri = totp_uri(generate_totp_secret(), "alice@example.com", "MyApp")
svg = qr_svg(uri)  # embed in your HTML
png = qr_png(uri)
assert "<svg" in svg and png[:8] == b"\x89PNG\r\n\x1a\n"
print(qr_ascii(uri))
```

---

## CLI

The package installs `generate-api-key` and the alias `generateapikey`. `python -m generateapikey` works too. Errors print `error: …` to stderr and exit with status 2.

### Keys (default command)

```text
generate-api-key [-n COUNT] [-l LENGTH] [-c CHARSET] [--case {mixed,lower,upper}]
                 [-p PREFIX] [--separator SEP] [-d] [--dash-group N] [--checksum]
                 [--expiry MINUTES] [--secret S --seed S [--include I]]
                 [--hash [--pepper P]] [--json] [--entropy] [--llms] [--agent-rules] [-V]
```

| Flag | Default | Meaning |
|---|---|---|
| `-n`, `--count` | 1 | Number of random keys. Ignored for derived keys, which always produce exactly one. |
| `-l`, `--length` | 32 | Body length. |
| `-c`, `--charset` | `alphanumeric` | Preset or literal characters. |
| `--case` | `mixed` | `mixed`, `lower` or `upper`. |
| `-p`, `--prefix` | none | Prefix, for example `sk`. |
| `--separator` | `-` | Between prefix and body. |
| `-d`, `--dashes` | off | Group the body with dashes. |
| `--dash-group` | 4 | Group size. |
| `--checksum` | off | Append the 6-character checksum. |
| `--expiry` | none | Minutes. Shown as `expires_at` in `--json`. |
| `--secret`, `--seed`, `--include` | none | Derive one key deterministically. `--secret -` reads stdin. Without `--secret`, `$GENERATEAPIKEY_SECRET` is used (only when `--seed` is given). |
| `--hash` | off | Also print the storage hash (`key<TAB>hash`, or a `hash` field in JSON). |
| `--pepper` | none | Pepper for `--hash`. `-` reads stdin; otherwise `$GENERATEAPIKEY_PEPPER`. |
| `--json` | off | Output JSON: an object for one key, a list for several. |
| `--entropy` | off | Print the entropy bits of the format (for example `190.5`) and exit. |
| `--llms` | off | Print the bundled LLM usage guide (`llms-full.txt`) and exit. |
| `--agent-rules` | off | Print a snippet for `AGENTS.md`, `CLAUDE.md` or `.cursor/rules` and exit. |
| `-V`, `--version` | | Print the version. |

Weak-key warnings are printed to stderr as `warning: …`.

```bash
generate-api-key
generate-api-key -n 5 -p sk --checksum
generate-api-key --charset hex --length 64
generate-api-key -p sk --checksum --expiry 60 --hash --json
GENERATEAPIKEY_PEPPER=change-me-pepper generate-api-key --hash
echo change-me-derivation-secret | generate-api-key --secret - --seed user-42 --include prod
generate-api-key --entropy -c base58 -l 24
generate-api-key --agent-rules
generate-api-key -V
```

### MFA and token commands

Every subcommand accepts `--json`.

| Command | Options | Output |
|---|---|---|
| `totp` | `-a/--account` (required), `-i/--issuer`, `--digits` (6), `--period` (30), `--algorithm` (`sha1`, `sha256` or `sha512`), `--qr` | New secret and `otpauth://` URI. `--qr` prints an ASCII QR code (needs the `qr` extra), to stderr when combined with `--json`. |
| `code` | positional `SECRET` (or `-` for stdin, or `$GENERATEAPIKEY_TOTP_SECRET`), `--digits`, `--period`, `--algorithm` | Current code and seconds left. JSON: `{"code", "valid_for"}`. |
| `recovery` | `-n/--count` (10), `-l/--length` (10), `--hash`, `--pepper` (`-` or `$GENERATEAPIKEY_PEPPER`) | One code per line, or `code<TAB>hash`. |
| `otp` | `--digits` (6), `--expiry` minutes (10), `--hash`, `--pepper` | Code (and hash). JSON includes `expires_at`. |
| `token` | `-s/--secret` (or `-` for stdin, or `$GENERATEAPIKEY_SECRET`), `--purpose` (`default`), `--expiry` minutes (15), `--data` JSON object (`{}`) | A signed token, as from `generate_signed_token`. |

```bash
generate-api-key totp -a alice@example.com -i MyApp --json
generate-api-key totp -a alice@example.com -i MyApp --qr
echo JBSWY3DPEHPK3PXP | generate-api-key code -
GENERATEAPIKEY_TOTP_SECRET=JBSWY3DPEHPK3PXP generate-api-key code --json
GENERATEAPIKEY_PEPPER=change-me-pepper generate-api-key recovery -n 3 --hash
generate-api-key otp --digits 8 --expiry 5 --json
GENERATEAPIKEY_SECRET=change-me-signing-secret-32-chars generate-api-key token --purpose login --data '{"uid": 42}'
```

### Environment variables

Secrets passed as arguments leak through `ps`, shell history and CI logs. Prefer these variables or stdin (`-`):

| Variable | Used by |
|---|---|
| `GENERATEAPIKEY_SECRET` | `--secret` for derived keys (only with `--seed`), and `token --secret` |
| `GENERATEAPIKEY_PEPPER` | `--pepper` for `--hash`, `recovery --hash` and `otp --hash` |
| `GENERATEAPIKEY_TOTP_SECRET` | The `code` command's secret |

An empty variable counts as unset.

---

## Low-level building blocks

These live in `generateapikey.utils` and `generateapikey.mfa`. The high-level API is built from them, and they follow the [spec](https://github.com/nuhmanpk/generate-api-key/blob/main/spec/SPEC.md) byte for byte.

### `generateapikey.utils`

```text
CHARSETS: dict[str, str]
CHECKSUM_LENGTH = 6
KDF_ITERATIONS = 100_000

build_charset(charset: str, case: str = "mixed") -> str
entropy_bits(length: int, charset="alphanumeric", case="mixed") -> float
random_key(length: int, chars: str) -> str
derived_key(secret: str, seed: str, include: str | None, length: int, chars: str, salt: bytes = b"") -> str
add_dashes(key: str, group: int, sep: str = "-") -> str
subkey(secret: str, label: str) -> bytes
safe_equals(a: str, b: str) -> bool
compute_checksum(data: str) -> str
verify_checksum(key: str) -> bool
hash_api_key(key, pepper=None) -> str
verify_api_key(key, hashed, pepper=None) -> bool
hash_code(code: str, pepper: str | None = None, iterations: int = KDF_ITERATIONS) -> str
verify_code(code: str, hashed: str, pepper: str | None = None) -> bool
```

| Function | Notes |
|---|---|
| `build_charset` | Resolves a preset or literal, applies `case`, removes look-alikes for `base58`, `unambiguous` and `crockford` when the case isn't mixed, and dedupes while keeping order. Cached. Raises `TypeError` for a non-`str` charset and `ValueError` for a bad `case` or fewer than 2 distinct characters. |
| `random_key` | A CSPRNG string with unbiased rejection sampling. Pass `chars` from `build_charset`. |
| `derived_key` | HMAC-SHA256 counter-mode stream keyed by `subkey(secret, "derive")` over the length-prefixed `seed`, `include` and `salt`, then mapped with the same rejection sampling. Deterministic for an empty `salt`. A random salt gives a fresh key, which is what the legacy `generateApiKey` does. |
| `add_dashes` | Inserts `sep` every `group` characters. Raises `ValueError` if `group < 1`. |
| `subkey` | `HMAC-SHA256(secret, "generateapikey.v1." + label)`. Provides domain separation, so one server secret reused for hashing, tokens and derivation can't produce a value valid in another context. Labels used internally are `"derive"`, `"hash"`, `"code"` and `"token"`. |
| `safe_equals` | Constant-time comparison of the UTF-8 bytes. Unlike `hmac.compare_digest` on `str`, it **never raises** on non-ASCII or non-`str` input (it returns `False`). Use it for every secret comparison. |
| `compute_checksum` | CRC32 of the UTF-8 data as 6 base62 characters (alphabet `0-9A-Za-z`), most significant first. |
| `hash_code` | `pbkdf2-sha256$<iterations>$<b64url salt>$<b64url hash>` with a 16-byte random salt. With a pepper, the code is first HMAC'd with `subkey(pepper, "code")`. Use it for short, low-entropy codes. `verify_code` accepts only iteration counts from 1,000 to 10,000,000, so a hash made with `iterations` below 1,000 will never verify. |
| `verify_code` | Never raises on malformed input. Returns `False`. |

```python
from generateapikey.utils import (
    KDF_ITERATIONS, add_dashes, build_charset, compute_checksum, derived_key,
    hash_code, random_key, safe_equals, subkey, verify_checksum, verify_code,
)

chars = build_charset("crockford")
token = random_key(20, chars)
assert len(token) == 20 and set(token) <= set(chars)

d1 = derived_key("change-me-secret", "user-42", None, 24, build_charset("base58"))
assert d1 == derived_key("change-me-secret", "user-42", None, 24, build_charset("base58"))
assert d1 != derived_key("change-me-secret", "user-42", None, 24, build_charset("base58"), salt=b"x")

assert add_dashes("ABCDEFGHIJ", 4) == "ABCD-EFGH-IJ"
assert len(subkey("change-me-secret", "hash")) == 32
assert safe_equals("é", "é") and not safe_equals("a", None)

body = "sk-" + random_key(32, build_charset("alphanumeric"))
assert verify_checksum(body + compute_checksum(body))

h = hash_code("123456", pepper="change-me-pepper")
assert h.startswith(f"pbkdf2-sha256${KDF_ITERATIONS}$")
assert verify_code("123456", h, pepper="change-me-pepper") and not verify_code("123456", "garbage")
```

### `generateapikey.mfa` primitives

`hotp`, `totp`, `find_totp_step`, `verify_hotp`, `hotp_uri` and `normalize_recovery_code` are documented in [MFA](#mfa). They aren't re-exported from the top-level package, so import them from `generateapikey.mfa`. Implementation details that matter for interop:

- HOTP is RFC 4226 dynamic truncation: a 31-bit value modulo `10**digits`, zero-padded. TOTP uses `counter = floor(t / period)`.
- `find_totp_step` skips negative steps and steps `<= last_used_step`.
- `steam_code` uses the same truncation, then 5 base-26 digits over `23456789BCDFGHJKMNPQRTVWXY`, least significant first.
- `google_migration_uri` encodes the protobuf `MigrationPayload` by hand (version 1, batch size 1, batch index 0, random batch ID).

### `generateapikey.tokens` internals

Useful when you implement a verifier elsewhere:

- The signed-token payload is compact, sorted-key JSON: `{"d": data, "exp": int, "jti": str, "p": purpose}`. `exp` is omitted when `expiry=None`. The signature is `HMAC-SHA256(subkey(secret, "token"), body)`. With a `context`, the signed message is `body ‖ 0x1F ‖ SHA-256(utf8(context))`.
- HS JWTs are signed with the raw UTF-8 secret, as in standard JWT, not with a subkey. That is what keeps them interoperable with PyJWT and others.
- Tokens longer than 8192 characters, or containing non-ASCII, are rejected before any crypto runs.

---

## Cross-language compatibility

The Python package and the npm package [`@nuhmanpk/generateapikey`](https://www.npmjs.com/package/@nuhmanpk/generateapikey) implement the same [wire-format specification](https://github.com/nuhmanpk/generate-api-key/blob/main/spec/SPEC.md). Both test suites run the shared `vectors.json`, which is generated from the Python implementation. Python is normative.

In practice, any of these produced by one language verifies in the other:

- Charsets, unbiased sampling and **derived keys**: `generate_api_key(secret, seed)` gives the identical key in both languages.
- Checksums, `hash_api_key` hashes (with or without a pepper), and `hash_code` hashes for OTPs and recovery codes.
- HOTP, TOTP and Steam codes, and otpauth and migration URIs.
- Scopes, leak-detection patterns, and `APIKeyAuth` behaviour (pre-checks, status codes, messages and `WWW-Authenticate`).
- Signed tokens (the signature must match; the payload is verify-compatible), JWTs and `SecretBox` ciphertexts.
- Redis limiter keys and the Lua script, so Python and Node workers can share one set of counters.

This means you can issue keys in a Python service and authenticate them in a Node service with the same pepper, or the other way round. JavaScript API reference: [docs/js.md](https://github.com/nuhmanpk/generate-api-key/blob/main/docs/js.md).

---

## Errors reference

Verification functions **never raise on attacker-controlled input**. They return `False` or `None`: `verify_api_key`, `verify_checksum`, `verify_totp`, `find_totp_step`, `verify_hotp`, `verify_steam_code`, `verify_recovery_code`, `verify_otp`, `verify_code`, `verify_signed_token`, `decode_jwt` and `decode_jwt_jwks` (but see the JWT note on mixed key types). Exceptions signal programming or configuration errors.

| Raised by | Exception | When |
|---|---|---|
| `generate_api_key` | `ValueError` | `length` isn't a positive `int`; only one of `secret`/`seed` is given; either is empty; `include` without `secret`/`seed`; `min_entropy` not met; `dash_group < 1` |
| `generate_api_key`, `build_charset`, `entropy_bits` | `TypeError` / `ValueError` | `charset` isn't a `str` (`TypeError`); bad `case` or fewer than 2 distinct characters (`ValueError`) |
| `generate_api_key`, `generateApiKey` | `TypeError` / `ValueError` | `expiry` isn't a number or `timedelta` (`bool` is rejected); not positive or not finite |
| `generate_api_keys` | `ValueError` | `count` is negative or not an `int`; `secret`/`seed` passed |
| `generateApiKey` (legacy) | `ValueError` | `secret` or `seed` empty; `length < 1` |
| `hash_api_key`, `verify_api_key`, `hash_code`, `verify_code`, `hash_otp`, `hash_recovery_code`, `verify_recovery_code`, `verify_otp`, `issue_api_key`, `APIKeyAuth` | `ValueError` | `pepper` is not `None` and not a non-empty `str` |
| `APIKeyAuth(...)` | `TypeError` / `ValueError` | `lookup` not callable; `previous_peppers` or `required_scopes` passed as a `str` (`TypeError`); a `None` or empty previous pepper (`ValueError`) |
| `APIKeyAuth.authenticate` | `AuthError` | 401 missing or invalid key, 403 insufficient scope, 429 limiter blocked |
| `APIKeyAuth.authenticate` | `TypeError` | async `lookup`, limiter or hook used with the sync method |
| `rotate_api_key`, `KeyStore.rotate` | `ValueError` | `grace_minutes < 0` |
| `KeyStore.create` | `ValueError` | empty or non-`str` `name` |
| `KeyStore.rotate` | `KeyError` | no active key with that ID |
| `key_pattern`, `find_keys`, `gitleaks_rule` | `ValueError` | empty `prefix`, bad `length`, bad `rule_id` |
| `generate_totp_secret` | `ValueError` | `num_bytes < 10` |
| `hotp`, `totp`, `totp_now`, `verify_totp`, `find_totp_step`, `verify_hotp`, `steam_code`, `verify_steam_code`, `totp_uri`, `hotp_uri`, `google_migration_uri` | `ValueError` / `TypeError` | secret not base32 or shorter than 10 bytes; secret not `str`/`bytes` (`TypeError`); `digits` not 6–8; unknown `algorithm`; `period < 1`; negative `counter`. Verifiers check the code's shape first, so a malformed code returns `False`/`None` before the secret is examined. |
| `totp_uri`, `hotp_uri` | `ValueError` | empty `account`; `:` in `account` or `issuer` |
| `google_migration_uri` | `ValueError` / `KeyError` | empty list; `digits` not 6 or 8; unknown `algorithm` / missing `secret` or `name` |
| `generate_recovery_codes` | `ValueError` | `count < 1` or `length < 8` |
| `normalize_recovery_code`, `hash_recovery_code`, `hash_otp` | `ValueError` | code isn't an ASCII string |
| `generate_otp` | `ValueError` | `digits` not 4–12; `expiry` not positive and finite |
| `AttemptLimiter`, `RedisAttemptLimiter`, `AsyncRedisAttemptLimiter` | `ValueError` | non-positive `max_attempts`, `window` (or `max_keys`) |
| `generate_signed_token`, `verify_signed_token` | `ValueError` | `secret` isn't a `str` of at least 16 characters; `expiry` not positive and finite |
| `generate_signed_token` | `TypeError` | `purpose` or `context` isn't a `str` |
| `encode_jwt` | `ValueError` | unknown `algorithm`; HS secret shorter than 16 characters or not a `str`; bad `expiry`; RSA key under 2048 bits; key type or curve doesn't fit `algorithm` |
| `decode_jwt` | `ValueError` | `algorithms` empty, a `str`, unknown, or mixing HS and asymmetric; bad HS secret; unusable PEM or key of the wrong type |
| `decode_jwt_jwks` | `ValueError` | `algorithms[0]` isn't asymmetric |
| asymmetric JWT, `generateapikey.crypto` | `ImportError` | the `crypto` extra isn't installed |
| `SecretBox(...)` | `ValueError` / `TypeError` | key isn't 32 bytes of URL-safe base64 / `old_keys` is a `str` |
| `SecretBox.encrypt`, `decrypt` | `TypeError` | `plaintext` or `aad` isn't a `str` |
| `SecretBox.decrypt`, `rotate` | `DecryptionError` (a `ValueError`) | malformed or tampered ciphertext, wrong `aad`, or no matching key |
| `generateapikey.qr`, `generateapikey.limiters` users, `generateapikey.integrations.<framework>` | `ImportError` | the extra isn't installed (the message names it) |
| `FlaskAPIKey` | `ValueError` | `init_app` without an `APIKeyAuth`; `.required` before `init_app` |
| Django `APIKeyMiddleware`, DRF `APIKeyAuthentication` | `ImproperlyConfigured` | `GENERATEAPIKEY_AUTH` missing or not pointing to an `APIKeyAuth` |
| CLI | exit status 2 | any of the above, printed as `error: …` |

Warnings:

| Warning | When |
|---|---|
| `WeakKeyWarning` (`UserWarning`) | a random key has under 128 bits of entropy |
| `DeprecationWarning` | `is_token_valid()`; `import generateApiKey` |
