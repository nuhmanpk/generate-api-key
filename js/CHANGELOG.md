# Changelog

The npm package shares its version number with the Python package on PyPI. Both implement the same
wire-format spec, so a version of one is compatible with the same version of the other.

## 0.6.0

The first npm release, published as `@nuhmanpk/generateapikey` (npm reserves the unscoped name): a TypeScript port of the Python `generateapikey` 0.6.0 with the same features
and wire formats (spec v1).

### Added
- API keys: `generateApiKey` (sync), `generateApiKeys`, `deriveApiKey` (secret + seed, identical to
  Python), `ApiKey` (value + `expiresAt`), checksums, 11 charsets, `entropyBits`, weak-key warnings.
- Storage: `hashApiKey` / `verifyApiKey` (SHA-256 / HMAC-SHA256 + pepper), `hashCode` / `verifyCode`
  (PBKDF2-SHA256), `timingSafeEqual`.
- Auth: `APIKeyAuth`, `issueApiKey`, `rotateApiKey`, `recordIsActive`, `pathExcluded`, scopes, and the
  adapters `@nuhmanpk/generateapikey/web`, `/hono`, `/express`, `/fastify`, `/koa`, `/next`. None of them
  imports its framework at runtime.
- `KeyStore` with `MemoryKeyStorage` and `SqlKeyStorage` (works with D1, better-sqlite3, node:sqlite and
  libSQL; same table as the Python `KeyStore`).
- MFA: TOTP/HOTP, Steam Guard, `totpUri` / `hotpUri`, `googleMigrationUri`, recovery codes, OTPs,
  `AttemptLimiter`, and `RedisAttemptLimiter` (same Lua script and keys as Python).
- Tokens: `generateSignedToken` / `verifySignedToken`, and `encodeJwt` / `decodeJwt` / `decodeJwtJwks`
  with HS, RS, PS, ES and EdDSA. Keys can be PEM (PKCS#8, SPKI, PKCS#1, SEC1), JWK or `CryptoKey`.
- `SecretBox` (AES-256-GCM with key rotation) and `generateEncryptionKey`.
- `@nuhmanpk/generateapikey/qr`: a zero-dependency QR encoder (`qrMatrix`, `qrAscii`, `qrSvg`, `qrPng`) whose
  output is identical to Python's `qrcode`.
- Leak detection: `keyPattern` (the same regex text as Python), `keyRegExp`, `findKeys`, `gitleaksRule`.
- CLI: `npx @nuhmanpk/generateapikey`, with the same commands and flags as the Python CLI. `llms.txt` is a guide for
  AI coding agents (`--llms`).
- ESM and CJS builds with type declarations, `sideEffects: false`, and only Web Crypto (Node 20+,
  Bun, Deno, Cloudflare Workers, Vercel Edge, browsers).

### Differences from Python
- Functions that hash, sign or verify are `async` (Web Crypto is). `SecretBox` is created with
  `await SecretBox.create(key, oldKeys)`.
- `decodeJwt` decodes base64url strictly, whereas Python accepts some malformed encodings.
  `decodeJwtJwks` skips JWKs of the wrong type instead of raising.
- `generateApiKey` only makes random keys; derived keys come from `deriveApiKey`. The legacy
  Python `generateApiKey()` coroutine has no JS counterpart.
