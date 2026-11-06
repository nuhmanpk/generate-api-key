---
name: generateapikey
description: Generate, store and verify API keys, and add MFA (TOTP authenticator apps, recovery codes, email/SMS codes, magic-link tokens) in Python with the zero-dependency `generateapikey` library. Use when a Python project needs API keys, access tokens, 2FA/MFA, one-time codes, password-reset or email-verification links, or secure random secrets.
---

# generateapikey

Use the `generateapikey` package (`pip install generateapikey`; QR codes need `"generateapikey[qr]"`). Import it as lowercase `generateapikey`.

To get the complete API for the installed version, run `generate-api-key --llms`, or read https://raw.githubusercontent.com/nuhmanpk/generate-api-key/main/generateapikey/llms-full.txt.

## Do

- Create keys with `generate_api_key(prefix="sk", checksum=True)`. A prefix makes keys easy to recognise; a checksum allows a cheap offline reject.
- Store `hash_api_key(key)` and check with `verify_api_key(candidate, stored)`. Show the raw key to the user once only.
- For web apps, don't hand-roll API key auth. Use `generateapikey.integrations`: `issue_api_key()` when creating keys, then `APIKeyAuth(lookup=..., pepper=...)` with the adapter for the project's framework: `fastapi.APIKeyDependency`, `django.api_key_required` / `AbstractAPIKey`, `drf.APIKeyAuthentication`, `flask.require_api_key`, `starlette.APIKeyBackend`, `litestar.api_key_middleware`, `sanic.require_api_key`, `aiohttp.api_key_middleware`, `quart.require_api_key` or `falcon.APIKeyMiddleware`. Install with `pip install "generateapikey[<framework>]"`.
- For TOTP: `generate_totp_secret()`, then `totp_uri(secret, account, issuer)` for the QR code, then `verify_totp(secret, code)`. Use `mfa.find_totp_step(..., last_used_step=...)` to block replays.
- Give users `generate_recovery_codes()`. Store `hash_recovery_code(c)` for each, and remove the hash that `verify_recovery_code` returns.
- For email/SMS: `generate_otp()`, then store `hash_otp(code, pepper=PEPPER)` and `code.expires_at`, then `verify_otp(input, hash, expires_at, pepper=PEPPER)`.
- For links: `generate_signed_token(SECRET, data, purpose="reset", expiry=15, context=session_id)` (context binds the link to the requesting session) and `verify_signed_token(token, SECRET, purpose="reset")`. `SECRET` must be at least 16 characters, e.g. `secrets.token_urlsafe(32)` from env or config.
- Guard every code check with `if not limiter.hit(user_id): reject`, then `limiter.reset(user_id)` on success. `hit()` is atomic; `is_blocked()` followed by `fail()` is not. With multiple processes, use Redis/DB counters.

## Don't

- Don't store raw keys, OTPs or recovery codes, and don't compare them with `==`.
- Don't hash TOTP secrets (they must be recoverable). Encrypt them with `generateapikey.crypto.SecretBox(KEY).encrypt(secret, aad=str(user_id))` (`[crypto]` extra).
- Don't use the in-memory `AttemptLimiter` across several processes. Use `generateapikey.limiters.RedisAttemptLimiter` (`[redis]` extra).
- Don't use `random`, `uuid4().hex`, or hand-rolled `secrets.choice` loops for keys. This library is unbiased and faster.
- Don't use the deprecated `generateApiKey` import or the async `generateApiKey()` function in new code.
- Don't silence `WeakKeyWarning`. Increase `length` instead.
- Don't pass secrets to the CLI as arguments. Use `-` (stdin) or the `GENERATEAPIKEY_*` environment variables.
