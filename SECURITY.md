# Security

This page covers both packages: `generateapikey` on [PyPI](https://pypi.org/project/generateapikey/)
and on [npm](https://www.npmjs.com/package/@nuhmanpk/generateapikey). They implement the same algorithms
([spec](https://github.com/nuhmanpk/generate-api-key/blob/main/spec/SPEC.md)), so everything
below applies to both.

## Reporting a vulnerability

Please **do not** open a public issue. Report privately through
[GitHub Security Advisories](https://github.com/nuhmanpk/generate-api-key/security/advisories/new).
You should get a reply within 7 days. Fixes are released as soon as possible, for both packages
together, and credited unless you prefer otherwise.

## Supported versions

Only the latest release of each package receives security fixes. Both packages share one version
number.

---

## Why reading the source code doesn't help an attacker

The library is open source, and everything about how it works is published here and in the
[spec](https://github.com/nuhmanpk/generate-api-key/blob/main/spec/SPEC.md). That is deliberate.
The design follows Kerckhoffs's principle: **security rests only on secret values (random bytes, your
server secrets), never on the algorithm being hidden.** Knowing exactly how a key is built tells an
attacker the *format* of a key (prefix, length, alphabet, checksum), which is public anyway because
it's printed on every key. It doesn't narrow down *which* key.

The numbers, for a default key (`generate_api_key()` / `generateApiKey()`: 32 characters from 62):

| | |
|---|---|
| Possible keys | 62³² ≈ 2.27 × 10⁵⁷ (≈ 190 bits) |
| Guesses at 10¹² per second (a very large GPU farm against an offline hash) | ≈ 3.6 × 10³⁷ years on average |
| Online guesses against your API | limited by your rate limit; each wrong key costs a request |

For comparison, AES-128 is considered unbreakable at 128 bits. Every random key under 128 bits
triggers a warning, and `min_entropy` / `minEntropy` turns that into an error.

---

## Attacks, one by one

Each row is something an attacker could try, and what stops it. "Both" means the Python and JS
packages behave the same way.

### Guessing or predicting keys

| Attack | Why it fails |
|---|---|
| **Predict the next key from earlier keys** (as with `Math.random()` or Python's `random`) | All randomness comes from the operating system's CSPRNG: Python's `secrets` module, and `crypto.getRandomValues` (Web Crypto) in JS. Their output is computationally independent of everything seen before, so a million leaked keys reveal nothing about the next one. `Math.random` and `random` are never used. |
| **Exploit modulo bias** (`byte % 62` makes some characters more likely) | Characters are chosen by **rejection sampling**: bytes that would skew the distribution are thrown away, so every character in the alphabet is exactly equally likely. Tests check the distribution statistically. |
| **Read leftover random bytes from memory** (JS) | JS draws random bytes in 4 KiB batches for speed. Each byte is handed out once and the pool slot is zeroed straight after it's used. |
| **Brute-force a key** | See the numbers above. The real limit is your rate limit: `APIKeyAuth(limiter=…)` answers 429 after repeated bad keys from one client. |
| **Recompute a derived key** (`generate_api_key(secret, seed)` / `deriveApiKey`) | Derived keys are HMAC-SHA256 of your server `secret`. Without the secret this is as hard as breaking HMAC-SHA256. Inputs are length-prefixed, so `("ab","c")` and `("a","bc")` can't collide. **The secret is the whole security**: keep it out of the database and the repo, and use a long random one (`generate_api_key(length=64)`). |

### Stolen database

| Attack | Why it fails |
|---|---|
| **Read API keys from a database dump** | Only `hash_api_key(key)` is stored, never the key. SHA-256 is one-way: there is no "decrypt". |
| **Crack the stored hashes offline** | Keys have about 190 bits of entropy, so a fast hash is enough (see the numbers above). Slow password hashes such as bcrypt exist for low-entropy human passwords; for random keys they would only slow down every request. With a **pepper** (`hash_api_key(key, pepper)`), hashes are HMAC-SHA256 under a secret that isn't in the database, so a dump alone can't even be checked against a guess. |
| **Crack OTP and recovery-code hashes** (only 10⁶ six-digit codes) | Short codes use **salted PBKDF2-SHA256 with 100,000 iterations**. The per-record random salt stops precomputed tables and stops one guess being tested against every row at once; the iterations make each guess expensive. Add a pepper and a leaked database alone is useless. Codes also expire (OTP, default 10 minutes) or are deleted after use (recovery codes). |
| **Read TOTP secrets** | TOTP secrets can't be hashed (the server needs them), so `SecretBox` encrypts them with AES-256-GCM. The encryption key lives in your environment or secret manager, not the database. `aad` binds each ciphertext to its user, so swapping encrypted values between rows fails decryption. |
| **Swap a hash between rows or algorithms** | Hashes are self-describing (`sha256$…`, `hmac-sha256$…`, `pbkdf2-sha256$…`). An un-peppered hash is never accepted when a pepper is configured, and the other way round, so an attacker can't downgrade a row. |

### Attacks on verification

| Attack | Why it fails |
|---|---|
| **Timing attack** (measure how long a compare takes to learn the key byte by byte) | Every comparison of a secret value is constant-time: `hmac.compare_digest` on bytes in Python, an XOR-accumulate loop with no early exit in JS. Loops that check several candidates (TOTP window, recovery-code list, HOTP look-ahead) check **all** of them, never stopping at the first match. |
| **Crash or confuse the verifier with odd input** (non-strings, Unicode, huge values) | Every `verify_*` / `verify*` function returns false for malformed input instead of raising, so it can't be turned into an oracle. Keys over 512 characters or with non-ASCII characters are rejected before any hashing or database lookup. |
| **Probe the database with junk keys** | `APIKeyAuth` checks prefix, length, ASCII and (optionally) the checksum *before* any lookup. A typo or a random string never reaches your database. |
| **Race the attempt limit** (send 100 parallel guesses before the counter updates) | `AttemptLimiter.hit()` counts the attempt **before** verification, as one atomic step (a lock in Python, a single synchronous call in JS). The Redis limiter is one atomic Lua script. Python and JS processes share Redis counters, because the key layout and script are identical. |
| **Replay a TOTP code** | `find_totp_step` / `findTotpStep` returns the matched time step. Store it and pass it back as `last_used_step` / `lastUsedStep`, and the same code (or an older one) is refused. |
| **Reuse a recovery code** | `verify_recovery_code` returns the matched hash. Delete it, and the code is gone. |

### Tokens and JWTs

| Attack | Why it fails |
|---|---|
| **Forge a magic-link or reset token** | Tokens are signed with HMAC-SHA256 under a purpose-specific subkey of your secret, which must be at least 16 characters. Changing one byte of the payload breaks the signature. |
| **Use a login token as a password-reset token** | Each token carries a `purpose` that verification checks, so a token made for one flow is rejected by another. |
| **Use a leaked link from another browser** | Pass `context` (session id, device cookie): it's signed into the token but never sent, so the link only works where that context is presented. |
| **`alg: none`** | It can never be created or accepted. |
| **Algorithm confusion** (HMAC-sign a token with the server's *public* RSA key) | The algorithms are pinned by your code, never read from the token header, and HMAC and RSA/EC algorithms can't be mixed in one call. A key of the wrong type or curve is an error, not a quiet failure. |
| **Small RSA keys** | Signing refuses RSA keys under 2048 bits. |
| **Expired or not-yet-valid JWTs** | `exp` is required by default and `nbf` is checked; `iss` and `aud` are checked when you pass them. `leeway` only allows the clock skew you choose. |
| **Swap a JWKS key** | The `kid` only *selects* among keys you already trust. A token whose `kid` matches nothing is rejected. |

### One secret, many uses

| Attack | Why it fails |
|---|---|
| **Use a value from one feature in another** (for example, a key hash as a token signature) | One server secret is split into independent keys per purpose: `HMAC(secret, "generateapikey.v1." + purpose)` for `derive`, `hash`, `code` and `token`. Reusing one secret everywhere is safe: a value computed for one purpose is useless for any other. |

### Supply chain

| Attack | Why it fails |
|---|---|
| **Compromise a dependency** | Neither package has runtime dependencies. Python uses only the standard library (the `cryptography` package is needed only for the opt-in `crypto` extra). JS uses only Web Crypto, which is built into every runtime. |
| **Tamper with a release** | Releases are built and published from GitHub Actions: PyPI through Trusted Publishing, npm with `--provenance`. Anyone can check that a published package came from this repository's workflow. |
| **Ship test keys** | No private key exists in the repository. Asymmetric test vectors are signed with throw-away keys that only ever exist in memory, and only the public keys are stored. Tests make fresh keys each run. |

---

## What this library can't protect you from

To use it safely, know where its responsibility ends:

- **Leaked server secrets.** Anyone with your `secret` can mint derived keys and tokens, and anyone
  with your pepper plus your database can test guesses offline. Keep both in an environment
  variable or secret manager, never in the database or the repo. Rotate them with
  `previous_peppers` / `previousPeppers` and `SecretBox(new_key, old_keys=[…])`.
- **A key that leaks on the client side** (committed to git, pasted in a log, sent over plain HTTP).
  A stolen key works until it's revoked. Give keys a recognizable prefix and a checksum so secret
  scanners find them (`key_pattern`, `gitleaks_rule`). Give them an expiry and scopes, and revoke
  them with the key store. Serve your API only over HTTPS.
- **Short codes without a rate limit.** A 6-digit code has a million values. Always put
  `AttemptLimiter` (or the Redis limiter) in front of OTP, TOTP and recovery-code checks.
- **A spoofed client IP.** The limiter keys on whatever client id you give it. `X-Forwarded-For` is
  set by the client unless a proxy you trust overwrites it. The adapters default to
  platform-provided values (`request.client`, `req.ip`, `CF-Connecting-IP`); configure your proxy
  settings (`trust proxy` in Express) to match your deployment.
- **The payload of signed tokens is readable.** It's signed, not encrypted. Don't put secrets in it.
- **A compromised server or runtime.** If an attacker can run code in your process, they can read
  secrets from memory. No library can prevent that.

## Primitives used

| Purpose | Primitive |
|---|---|
| Randomness | OS CSPRNG: Python `secrets`, JS `crypto.getRandomValues` |
| Key hashing | SHA-256; HMAC-SHA256 with a pepper |
| Key derivation, subkeys, tokens | HMAC-SHA256 |
| Short-code hashing | PBKDF2-HMAC-SHA256, 16-byte salt, 100,000 iterations |
| TOTP / HOTP | HMAC-SHA1/256/512 per RFC 4226 and RFC 6238 |
| Encryption at rest | AES-256-GCM, random 96-bit nonce, optional associated data |
| JWT | HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, EdDSA (Ed25519) |
| Checksum (typo detection only, not security) | CRC-32 |

These are standard, widely reviewed primitives, provided by Python's standard library and the
runtime's Web Crypto. Neither package implements its own hash or cipher.
