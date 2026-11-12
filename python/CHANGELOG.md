# Changelog

## Unreleased

No change to the package's API or behaviour.

### Repository
- The repository is now a monorepo: this package lives in `python/`, and its JavaScript/TypeScript
  sibling is published to npm as [`@nuhmanpk/generateapikey`](https://www.npmjs.com/package/@nuhmanpk/generateapikey)
  under the same version number. Both are wire-compatible: keys, hashes, codes, tokens, JWTs and
  ciphertexts made in one language verify in the other.
- `spec/SPEC.md` documents every format and algorithm (spec v1). `spec/vectors.json` is generated
  from this package by `scripts/gen_vectors.py`, and `tests/test_vectors.py` runs it. CI fails if
  the file is out of date. `scripts/interop.py` checks values made by the JS package.
- Releases are tag-driven (`py-v*`) and published with PyPI Trusted Publishing.
- README links are absolute, so they also work on the PyPI page.

### Notes found while writing the spec (not changed, documented in `spec/SPEC.md`)
- `decode_jwt` decodes base64url leniently, so a signature with characters outside the alphabet
  inserted, or with `+`/`/`, can still verify. This is not a forgery: the signature bytes must
  still be correct.
- `decode_jwt_jwks` raises `ValueError` instead of returning `None` when a token without a `kid`
  meets a JWKS that also contains a key of another type.

## 0.6.0

### Added
- `encode_jwt` / `decode_jwt`: standard JWTs with pinned algorithms, `exp`/`nbf`/`iss`/`aud` checks and no `alg: none`. Supports HS256/384/512, and RS256/384/512 and ES256/384/512 with PEM keys via the `crypto` extra. HS* and RS*/ES* can't be mixed in one decode (algorithm-confusion guard). Interoperates with PyJWT.
- Key scopes: `has_scope`, `has_all_scopes`, `has_any_scope`, `parse_scopes`, and `APIKeyAuth(required_scopes=...)` / `authenticate(key, scopes=...)` (403 when a valid key lacks a scope).
- `generateapikey.keystore`: `KeyStore` (SQLite, standard library) with create, lookup, list, revoke, last-used and rotation, plus `rotate_api_key` for your own database.
- Leak detection: `key_pattern`, `find_keys` and `scanning.gitleaks_rule`.
- JWT: PS256/384/512, EdDSA and `decode_jwt_jwks` (JWKS verification, `kid` only selects among trusted keys).
- MFA: `steam_code` / `verify_steam_code` (Steam Guard style codes) and `google_migration_uri` (Google Authenticator import).
- Tests: Hypothesis property and fuzz tests, a chi-square uniformity test (with a modulo-bias control), coverage reporting in CI.
- `generate-api-key --agent-rules` prints a snippet for `AGENTS.md` / `CLAUDE.md` / `.cursor/rules` that tells coding agents to use this library. Agent-facing docs (`llms.txt`, the LLM guide, the skill, `context7.json`) now include a "when to use" decision table, and PyPI keywords cover agent and JWT/scopes searches.
- New animated product tour `assets/tour.svg`, shown in the README.
- `benchmarks/compare.py` and a feature and speed comparison against secrets, pyotp, itsdangerous, PyJWT, shortuuid and nanoid in the README.

### Performance
- `generate_api_key()` is about 2× faster (5.8 → 2.8 µs): the resolved alphabet is now cached instead of rebuilt on every call.

### Fixed
- CI: Django extras on Python 3.9, UTF-8 doc reads on Windows, import-order lint.

## 0.5.0

### Renamed
- The package is now **`generateapikey`** (lowercase), both on PyPI and as the import name. PyPI treats names case-insensitively, so `pip install generateApiKey` still works. `import generateApiKey` (including submodules) keeps working through an alias module that emits a `DeprecationWarning`.

### Security
Fixes from an internal review. The issues below were found in this release's code before it was published:
- **Attacker input could crash verification.** `verify_totp`, `verify_hotp`, `verify_checksum` and `verify_signed_token` raised `TypeError` on non-ASCII input (e.g. `١٢٣٤٥٦`), which surfaced as an HTTP 500. All verifiers now return False/None on any input.
- **`AttemptLimiter` could be bypassed with parallel requests.** The new atomic `hit()` counts an attempt before verification, and the docs now use it.
- **`AttemptLimiter` memory and CPU DoS.** It was O(n) per call after 100k keys and unbounded. It is now capped by `max_keys` with O(1) amortized eviction (expired entries first).
- **Short codes were stored with fast unsalted SHA-256.** OTPs reversed instantly from a leaked hash. OTPs and recovery codes now use salted PBKDF2-SHA256 (100k iterations, format `pbkdf2-sha256$...`).
- **Domain separation.** Tokens, hash peppers and derived keys use independent subkeys, so reusing one server secret can't forge across features.
- **Stricter inputs:**
  - Empty peppers are rejected (they silently disabled the pepper before).
  - TOTP secrets under 80 bits are rejected.
  - Token secrets must be at least 16 characters.
  - TOTP/HOTP `digits` is capped at 8, per the RFC.
  - `:` is rejected in otpauth issuer/account.
  - `inf`/`NaN` expiry is rejected.
  - OTP `charset` is validated.
  - Integer codes keep their leading zeros.
  - Recovery codes must be at least 8 characters.
- **`repr(ApiKey)` is redacted** so keys don't leak into logs and tracebacks.
- **CLI secrets** can be passed via stdin (`-`) or `GENERATEAPIKEY_SECRET`, `GENERATEAPIKEY_PEPPER` and `GENERATEAPIKEY_TOTP_SECRET`, instead of argv.
- **CI hardening:**
  - Read-only default permissions.
  - The release workflow runs the full test suite and `twine check` before uploading.
  - A bandit scan runs on every push.
  - Dependabot is enabled.
  - `SECURITY.md` has been added.

### Added: production extras
- **More frameworks:** Sanic, aiohttp, Quart and Falcon (WSGI and ASGI), each tested against the real framework.
- **Rotation:**
  - Django `AbstractAPIKey.rotate(grace=...)` keeps the old key valid during a grace period.
  - Pepper rotation via `APIKeyAuth(previous_peppers=..., on_rehash=...)`, plus the Django `rehash_model()` hook.
- **Session-bound tokens:** `generate_signed_token(..., context=session_id)` and the matching `verify_signed_token(..., context=...)`. A leaked link fails outside the session that requested it.
- **`generateapikey.crypto`** (`[crypto]`): `SecretBox` encrypts TOTP and other secrets at rest. AES-256-GCM, associated data, key rotation.
- **`generateapikey.limiters`** (`[redis]`): `RedisAttemptLimiter` and `AsyncRedisAttemptLimiter` share atomic counters across processes. `APIKeyAuth` accepts sync or async limiters.
- **Segment-aware `exclude` matching:** `/health` no longer also excludes `/healthz`.
- **Tooling:**
  - Strict mypy across the core and ruff lint and format.
  - pre-commit config, plus a `dev` extra.
  - CI tests Python 3.9–3.14 on Linux, macOS and Windows, adds a zero-dependency job, and runs ruff, mypy and bandit.
- **Repo:** `examples/` (a full FastAPI app run in CI, and a Django quickstart), `benchmarks/bench.py`, CONTRIBUTING.md, and issue/PR templates.

### Added: framework integrations
- `generateapikey.integrations` holds the framework-agnostic core:
  - `APIKeyAuth` handles header/Bearer extraction, prefix and checksum pre-checks, hash-only lookup, revoked/expired checks, optional rate limiting and an `on_success` hook. Lookups can be sync or async.
  - `issue_api_key()` returns the key, its hash and a display hint.
- Adapters, each as an optional extra:
  - **FastAPI**: `APIKeyDependency`, with an OpenAPI security scheme.
  - **Starlette**: `APIKeyBackend`.
  - **Django**: `AbstractAPIKey` model with `create_key`, `api_key_required` for sync and async views, `APIKeyMiddleware`, `model_lookup` and `touch_last_used`.
  - **Django REST Framework**: `APIKeyAuthentication` and `HasAPIKey`.
  - **Flask**: `require_api_key` and `FlaskAPIKey`.
  - **Litestar**: `api_key_middleware`.
- Each adapter is tested against the real framework.

### Added: MFA
- **TOTP / HOTP** (RFC 6238 / 4226) in `generateapikey.mfa`: `generate_totp_secret`, `totp`, `totp_now`, `verify_totp`, `find_totp_step` (replay protection), `hotp`, `verify_hotp`, `totp_uri` and `hotp_uri` (`otpauth://` URIs for QR setup). Supports SHA-1/256/512, 6–10 digits and custom periods. Tested against the official RFC test vectors.
- **Recovery codes**: `generate_recovery_codes`, `hash_recovery_code`, `verify_recovery_code`. Crockford base32, single use, tolerant of case, dashes and look-alike characters.
- **Email/SMS one-time codes**: `generate_otp`, `hash_otp`, `verify_otp`.
- **Signed tokens** for magic links, email verification and password resets, in `generateapikey.tokens`: `generate_signed_token`, `verify_signed_token`. HMAC-SHA256, with expiry, purpose binding and a unique `jti`.
- **`AttemptLimiter`**: thread-safe, in-memory brute-force guard.
- **QR codes** (`pip install "generateapikey[qr]"`): `qr_svg`, `qr_png`, `qr_ascii` in `generateapikey.qr`.
- CLI subcommands: `totp` (with `--qr`), `code`, `recovery`, `otp`, `token`. A `generateapikey` command alias is also installed.

### Added: AI coding agent support
- `llms.txt` index and a full `llms-full.txt` guide. The guide ships in the wheel and is printed by `generate-api-key --llms`.
- A drop-in Agent Skill (`skills/generateapikey/SKILL.md`), `AGENTS.md` for contributors, and `context7.json`.
- Tests that fail if the documented imports drift from the real API.

### Added: API keys
- `checksum=True`: appends a 6-char CRC32 (base62) to the key. Check it offline with `verify_checksum()`.
- `hash_api_key()` / `verify_api_key()`: SHA-256 storage hashing, with optional HMAC pepper and constant-time verification. `ApiKey.hash()` is a shortcut.
- `generate_api_keys(count, ...)` for batches.
- `entropy_bits()`, the `min_entropy=` option, and `WeakKeyWarning` for random keys below 128 bits.
- `expiry` accepts a `timedelta` or fractional minutes.
- `ApiKey.expires_in` and `ApiKey.expires_at_datetime`. `ApiKey` now pickles with its expiry and has an informative `repr`.
- `dash_char=` option.
- New charsets: `base32`, `crockford`, `unambiguous`.
- `generate-api-key` command-line tool (also `python -m generateApiKey`).
- `__version__`, `py.typed`, a test CI matrix (3.9–3.13, Linux/macOS/Windows), and `pyproject.toml`.

### Changed
- **Derived keys (`secret` + `seed`) are now deterministic**: the same inputs give the same key. Previously a random salt and a timestamp made every call different, so the secret had no effect on the result. The legacy `generateApiKey()` keeps its old one-key-per-call behaviour.
- Character sampling uses rejection sampling, so it is unbiased. It is also about 20× faster.
- Removed the unused `cryptography` dependency. The package now has zero dependencies.

### Fixed
- Modulo bias in derived keys: some characters were about 25% more likely.
- Duplicate characters in a custom charset skewed the output.
- `expiry=0` was silently ignored, and negative expiry was accepted.
- Empty `secret`/`seed` strings silently fell back to random keys.
- `include` without `secret`/`seed` was silently ignored.
- `case="lower"`/`"upper"` on `base58` re-introduced look-alike characters.

### Deprecated
- `is_token_valid()`: no API ever produced the token format it checks. Use `ApiKey.is_expired` instead.
