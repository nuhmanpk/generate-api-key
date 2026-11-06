# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue. Report privately through
[GitHub Security Advisories](https://github.com/nuhmanpk/generate-api-key/security/advisories/new).
You should get a reply within 7 days. Fixes are released as soon as possible and credited unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes.

## Design notes

- All randomness comes from `secrets` (the OS CSPRNG). Characters are chosen by rejection sampling, so there is no bias.
- Every comparison of a secret value is constant-time and never raises on attacker input.
- API keys (high entropy) are stored as SHA-256 or HMAC-SHA256 with a pepper. Short codes (OTPs, recovery codes) use salted PBKDF2-SHA256 (100k iterations).
- One server secret is split into independent per-purpose keys (tokens, hashing, derivation), so reusing it across features is safe.
- `AttemptLimiter.hit()` counts an attempt atomically *before* verification, so parallel requests can't bypass the limit.
