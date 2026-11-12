# generateapikey wire-format specification, v1

This document is the contract between the Python package (`python/`, PyPI
`generateapikey` ≥ 0.6.0) and the JavaScript package (`js/`, npm `@nuhmanpk/generateapikey`).
It describes what the Python code does today. **Python is normative**: where this
text and the Python code disagree, the code wins and this text is the bug.

Every rule here is exercised by [`vectors.json`](vectors.json), which is generated
from the Python implementation by `python/scripts/gen_vectors.py` and run by both
test suites. Never edit the vectors by hand.

Notation: `‖` is byte concatenation, `utf8(s)` is the UTF-8 encoding of a string,
`HMAC-H(k, m)` is RFC 2104 HMAC, `be32(n)` / `be64(n)` are big-endian unsigned
integers, `b64url` is the RFC 4648 §5 alphabet **without padding**, `hex` is
lowercase hexadecimal.

Compatibility levels used below:

- **MUST match**: both implementations produce and accept byte-identical values.
- **Verify-compatible**: values produced by one verify in the other, but the bytes
  of freshly generated values may differ (randomness, JSON formatting).
- **Python-only (non-normative)**: a Python quirk that the JavaScript package does
  not reproduce; no interoperable producer emits such values.

---

## 1. Charsets

### 1.1 Presets

| name | characters (in order) |
|---|---|
| `alphanumeric` | `a–z A–Z 0–9` → `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789` |
| `base62` | `0–9 A–Z a–z` |
| `alphabetic` | `a–z A–Z` |
| `numeric` | `0–9` |
| `hex` | `0–9 a–f` |
| `base16` | `0–9 A–F` |
| `base32` | `A–Z 2–7` |
| `crockford` | `0123456789ABCDEFGHJKMNPQRSTVWXYZ` |
| `base64url` | `a–z A–Z 0–9 - _` |
| `base58` | `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` |
| `unambiguous` | `23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz` |

`alphanumeric` and `base62` contain the same characters in a different order;
order matters for derived keys (§2.2).

### 1.2 `build_charset(charset, case)` — MUST match

1. `chars = PRESETS[charset]` if `charset` names a preset, else `charset` itself
   (a literal string of characters).
2. `case`: `"mixed"` leaves it unchanged, `"lower"` / `"upper"` apply full Unicode
   lower/upper-casing to the whole string. Any other value is an error.
3. If `charset` is one of `base58`, `unambiguous`, `crockford` **and** case is not
   `mixed`, remove every character in `0 O 1 I l`.
4. Remove duplicates, keeping the first occurrence.
5. Fewer than 2 distinct characters is an error.

Characters are **Unicode code points** (not UTF-16 code units). Unicode case
mapping of non-ASCII characters can differ between language runtimes; only ASCII
charsets are guaranteed to case-map identically.

`entropy_bits(length, charset, case) = length × log2(|build_charset(charset, case)|)`.

---

## 2. API keys

### 2.1 Layout

```
key  = [prefix ‖ separator] ‖ body ‖ [checksum]
body = sample(length chars)            with dashes: groups of dash_group joined by dash_char
```

- `prefix` is only used when non-empty. `separator` defaults to `-`.
- Dashes: `body` is split into consecutive groups of `dash_group` code points
  (the last may be shorter) joined with `dash_char` (default `-`, group 4).
- `checksum` (§3) is computed over everything before it (prefix, separator,
  dashes included) and appended with no separator.
- Defaults: `length = 32`, `charset = "alphanumeric"`, `case = "mixed"`.
- Random keys below 128 bits of entropy trigger a weak-key warning; `min_entropy`
  turns a shortfall into an error. Derived keys never warn.

### 2.2 Unbiased sampling — MUST match

Given a byte source and alphabet `C` of `n` code points:

- **Fast path** (`n ≤ 256` and every character is ASCII): read bytes one at a
  time; with `limit = 256 − (256 mod n)`, a byte `b < limit` yields `C[b mod n]`,
  any other byte is discarded.
- **Generic path** (otherwise): `w = ceil(bitlen(n) / 8)` bytes per draw,
  `space = 2^(8w)`, `limit = space − (space mod n)`. Read big-endian `w`-byte
  integers `v`; `v < limit` yields `C[v mod n]`, others are discarded. The
  source is consumed in chunks of `w × (remaining + 8)` bytes; trailing bytes of a
  chunk that don't fill a whole `w`-byte draw are discarded (only reachable for
  `w ≥ 3`, i.e. alphabets of more than 65,536 characters). Drawing stops as soon
  as `length` characters are produced.

Random keys feed this from a CSPRNG. Their exact bytes are not interoperable;
their shape is.

### 2.3 Derived (deterministic) keys — MUST match

Inputs: non-empty `secret`, non-empty `seed`, optional `include`.

```
K       = subkey(secret, "derive")
message = be32(len a) ‖ a ‖ be32(len b) ‖ b ‖ be32(len c) ‖ c
          with a = utf8(seed), b = utf8(include or ""), c = salt (empty for derived keys)
stream  = HMAC-SHA256(K, message ‖ be64(0)) ‖ HMAC-SHA256(K, message ‖ be64(1)) ‖ …
body    = sample(stream)                                     (§2.2)
```

The stream is one continuous sequence of 32-byte blocks; sampling consumes it in
order regardless of how it is chunked. The legacy Python `generateApiKey()` uses
the same construction with a random 16-byte `salt` (one vector pins it).

Errors: only one of `secret`/`seed` given, either empty, `include` without both,
`length < 1`, bad charset or case, `dash_group < 1`.

### 2.4 Subkeys

```
subkey(secret, label) = HMAC-SHA256(utf8(secret), utf8("generateapikey.v1." ‖ label))
labels: "derive", "hash", "code", "token"
```

---

## 3. Checksums — MUST match

```
v        = CRC-32/ISO-HDLC(utf8(data))          (zlib.crc32: reflected 0xEDB88320, init/xorout 0xFFFFFFFF)
checksum = 6 base62 digits of v, most significant first, alphabet 0-9A-Za-z (zero-padded)
```

`verify_checksum(key)`: false unless `key` is a string longer than 6 code points;
then constant-time compare `checksum(key[:-6])` with `key[-6:]`.

---

## 4. Key storage hashes — MUST match

```
hash_api_key(key)          = "sha256$"      ‖ hex(SHA-256(utf8(key)))
hash_api_key(key, pepper)  = "hmac-sha256$" ‖ hex(HMAC-SHA256(subkey(pepper, "hash"), utf8(key)))
```

- `pepper`, when given, must be a non-empty string (empty → error).
- `verify_api_key(key, hashed, pepper)`: false if either argument isn't a string,
  if `hashed` starts with `hmac-sha256$` and no pepper is given, or starts with
  `sha256$` and a pepper is given; otherwise constant-time compare against
  `hash_api_key(key, pepper)`. Never raises except for an invalid pepper.
- Hints for display: `key[:7] ‖ "…" ‖ key[-4:]` when the key has ≥ 16 code points,
  else `"…"` (U+2026).

Strings must be well-formed Unicode. (Python encodes lone surrogates with
`surrogatepass`; JavaScript has no equivalent. Lone surrogates are not
interoperable.)

---

## 5. Code hashes (OTP and recovery codes) — MUST match

```
password = utf8(code)                                         without pepper
password = HMAC-SHA256(subkey(pepper, "code"), utf8(code))    with pepper
dk       = PBKDF2-HMAC-SHA256(password, salt, iterations, 32 bytes)
hashed   = "pbkdf2-sha256$" ‖ iterations ‖ "$" ‖ b64url(salt) ‖ "$" ‖ b64url(dk)
```

- New hashes: 16-byte random salt, 100,000 iterations.
- Verify: split on `$`; exactly 4 parts, first `pbkdf2-sha256`; iterations is a
  decimal integer in `[1000, 10_000_000]`; salt and dk decode as base64url
  (padding optional); constant-time compare. Any malformed input → false.
- Cloudflare Workers limits PBKDF2 to 100,000 iterations, so hashes with more
  iterations can't be verified there (the JS package throws a clear error).

### 5.1 Recovery codes

- Alphabet: Crockford base32 `0123456789ABCDEFGHJKMNPQRSTVWXYZ`. Default 10 codes
  × 10 characters, grouped by 5 with `-` (`group = 0` disables grouping).
  `count ≥ 1`, `length ≥ 8`. Codes in one batch are distinct.
- Normalization: input must be a string of ≤ 64 code points; remove spaces and
  `-`; must then be ASCII; upper-case; map `O→0`, `I→1`, `L→1`.
- `hash_recovery_code(code) = hash_code(normalize(code))`.
- `verify_recovery_code(code, hashes)` returns the first matching stored hash
  (checks every hash, no early exit), or none.

### 5.2 One-time codes (email/SMS)

- `generate_otp(digits=6, expiry=10 min)`: `digits ∈ [4, 12]`, alphabet
  `0123456789` by default, `expires_at = floor(now + expiry × 60)`.
- Cleaning (`_clean_code`): booleans → invalid; non-negative integers → decimal
  string zero-padded to `digits` when known (else invalid); strings longer than
  64 → invalid; remove spaces and `-`; non-ASCII → invalid.
- `hash_otp(code)` = `hash_code(clean(code))`; `verify_otp(code, hashed,
  expires_at)` is false when `now ≥ expires_at`.

---

## 6. HOTP / TOTP / Steam — MUST match

- **Secrets** (base32 string): remove spaces and `-`, upper-case, strip trailing
  `=`, re-pad to a multiple of 8 with `=`, decode RFC 4648 base32 (invalid →
  error). Raw bytes are also accepted. Decoded secret must be ≥ 10 bytes.
  New secrets: 20 random bytes, base32 without padding.
- **HOTP** (RFC 4226): `mac = HMAC-H(secret, be64(counter))`, `H ∈ {sha1, sha256,
  sha512}` (lower-case names only), `off = mac[-1] & 0x0f`,
  `v = be32(mac[off:off+4]) & 0x7fffffff`, code = `v mod 10^digits` zero-padded.
  `digits ∈ [6, 8]`, `counter ≥ 0`.
- **TOTP** (RFC 6238): `counter = floor(t / period)`, default period 30.
- **find_totp_step**: clean the code (§5.2, digits known); must be exactly
  `digits` ASCII digits. Check every step in `[cur − window, cur + window]`
  (default window 1), skipping negative steps and steps `≤ last_used_step`; no
  early exit; return the **last** matching step, or none.
- **verify_hotp**: check counters `counter … counter + look_ahead`; return the
  first matching `c + 1` (the next counter to store), or none.
- **Steam Guard**: HMAC-SHA1 over `be64(floor(t / 30))`, dynamic truncation as
  HOTP, then 5 times `v, r = divmod(v, 26)` appending
  `23456789BCDFGHJKMNPQRTVWXY[r]`. Verify: case-insensitive, 5 characters,
  window ±1 step.

### 6.1 otpauth URIs — MUST match

```
otpauth://{totp|hotp}/{label}?{query}
label  = quote(issuer, safe="@") ":" quote(account, safe="@")     (issuer part only when issuer is non-empty)
query  = secret=<normalized secret>[&issuer=<issuer>][&algorithm=SHA256][&digits=8][&period=60][&image=…]    (totp)
         secret=…[&issuer=…]&counter=<n>[&algorithm=…][&digits=…]                                            (hotp)
```

`quote` is Python's `urllib.parse.quote`: percent-encode UTF-8 bytes of every
character except `A–Z a–z 0–9 _ . - ~` and the listed safe characters. Query
values use `safe=""`. Parameters only appear when non-default; `algorithm` is
upper-cased. `account` is required; `:` in account or issuer is an error.

### 6.2 Google Authenticator migration URI — MUST match

Protobuf (`MigrationPayload`) built by hand: per account a field-1 message of
`secret`(1, bytes) `name`(2) `issuer`(3) `algorithm`(4: sha1=1, sha256=2,
sha512=3) `digits`(5: 6→1, 8→2) `type`(6: TOTP=2); then `version`(2)=1,
`batch_size`(3)=1, `batch_index`(4)=0, `batch_id`(5)=31 random bits. URI:
`otpauth-migration://offline?data=` ‖ quote(standard base64 with padding, safe="").

---

## 7. Scopes — MUST match

- Parse: a string is split on the regex `[\s,]+` (empty parts dropped); an
  iterable keeps its non-empty string items; `None` → empty set.
- `has_scope(granted, required)`: false if `required` is empty or not a string;
  true if `*` or `required` is granted; true if, for any proper prefix of the
  `:`-separated parts, `prefix ‖ ":*"` is granted; true if `required ‖ ":*"`
  is granted (`read:*` grants `read`).
- `has_all_scopes` (empty `required` → true) / `has_any_scope`; a bare string
  `required` is treated as one scope.

Whitespace is ASCII whitespace in practice; the two regex engines differ on a few
exotic Unicode spaces.

---

## 8. Leak detection patterns — MUST match (pattern text)

```
(?<![0-9A-Za-z_-]){escape(prefix ‖ separator)}[{class(chars)}]{length}[0-9A-Za-z]{6}(?![0-9A-Za-z_-])
```

The checksum part is omitted when `checksum=False`. `escape` is Python's
`re.escape` (escapes every character other than ASCII letters, digits and `_`
that is special; see vectors), and inside the class only `\ ] ^ - [` are
backslash-escaped. `find_keys` returns unique matches in order of first
appearance, filtered by `verify_checksum` when validating. `gitleaks_rule` drops
the lookarounds (RE2 has none) and renders a fixed TOML block.

---

## 9. Signed tokens — MUST match (signature), verify-compatible (payload JSON)

```
payload = {"p": purpose, "jti": b64url(12 random bytes), "d": data or {}, ["exp": floor(now + expiry×60)]}
body    = b64url(JSON(payload))        JSON: sorted keys, separators "," ":", non-ASCII escaped as \uXXXX
msg     = ascii(body)                              without context
msg     = ascii(body) ‖ 0x1f ‖ SHA-256(utf8(context))   with context (context is never transmitted)
token   = body "." b64url(HMAC-SHA256(subkey(secret, "token"), msg))
```

- `secret` must be ≥ 16 code points. Default purpose `"default"`, expiry 15 min
  (`None` = no `exp`).
- Verify: token is an ASCII string ≤ 8192 characters with exactly one `.`;
  constant-time **string** comparison of the signature; payload must decode to a
  JSON object; `str(payload.p)` must equal purpose; `exp` (if present) must be a
  number with `now < exp`. Returns `d` (or `{data, jti, exp}` with meta).
- JSON serialisation details (key order, `\u` escapes, `1.0` vs `1`) only affect
  the bytes of new tokens; verification signs the transmitted body, so tokens are
  verify-compatible either way. The JS package emits sorted keys and ASCII
  escapes, so integer/string/boolean/null/nested payloads are byte-identical.

---

## 10. JWT (RFC 7519) — MUST match

- Header: `{...headers, "alg": alg, "typ": "JWT"}` (caller headers first; `alg`
  and `typ` always override). Payload: claims plus `iat = floor(now)` and
  `exp = floor(now + expiry×60)` (default 15 min), `iss`/`aud` when given — each
  only if not already in the claims. JSON: compact separators, insertion order,
  non-ASCII escaped. Segments are b64url.
- HS256/384/512: HMAC over `ascii(header_b64 "." payload_b64)` keyed by
  `utf8(secret)` (≥ 16 code points).
- RS*: RSASSA-PKCS1-v1_5; PS*: RSASSA-PSS, MGF1 with the same hash, salt length =
  hash length; RSA keys ≥ 2048 bits. ES256/384/512: ECDSA P-256/P-384/P-521 with
  SHA-256/384/512, signature is raw `r ‖ s`, each left-padded to 32/48/66 bytes.
  EdDSA: Ed25519.
- Keys: private keys as PEM PKCS#8, PKCS#1 (`RSA PRIVATE KEY`) or SEC1 (`EC
  PRIVATE KEY`); public keys as PEM SPKI or PKCS#1 (`RSA PUBLIC KEY`); a private
  key may be passed to verify. A key of the wrong type or curve is an **error**,
  not a failed verification.
- Decode: `algorithms` is pinned by the caller (default `["HS256"]`), non-empty,
  drawn from the known set, and can't mix HS and asymmetric algorithms (error).
  Token: ASCII, ≤ 8192 chars, exactly two `.`. Header and payload must be JSON
  objects; header `alg` must be a string in `algorithms`. Then: signature;
  `exp` required unless `require_exp=False`, must be a non-boolean number with
  `now < exp + leeway`; `nbf` (if present) a non-boolean number with
  `now ≥ nbf − leeway`; `iss` must equal `issuer` when given; `aud` must equal
  `audience` or be a list containing it. Returns the claims.
- `alg: none` is never produced or accepted.
- JWKS: the header `kid` selects keys (all keys when there is no `kid`); RSA, EC
  (P-256/384/521) and OKP/Ed25519 JWKs; first key that verifies wins; none → null.
- **Python-only (non-normative):** Python's base64url decoder ignores characters
  outside the alphabet and accepts `+`/`/`, so some malformed signature
  encodings still verify in Python. JavaScript decodes strictly. When a JWKS has
  no `kid` match and contains a key of a different type than the algorithm,
  Python raises `ValueError`; JavaScript skips such keys and returns null (or the
  claims, if another key verifies). Likewise, when `algorithms` lists several
  asymmetric algorithms and the token's header picks one the key doesn't fit,
  Python raises `ValueError` while JavaScript returns null (the header is
  attacker-controlled). With a single pinned algorithm both raise.

---

## 11. SecretBox (encryption at rest) — MUST match

```
key     = 32 bytes, b64url (padding optional)
key_id  = b64url(SHA-256("generateapikey.v1.keyid" ‖ key)[:6])        (8 chars)
token   = "v1." ‖ key_id ‖ "." ‖ b64url(nonce(12) ‖ AES-256-GCM(key, nonce, utf8(plaintext), aad=utf8(aad)) ‖ tag(16))
```

No `aad` and an empty `aad` are equivalent. Decrypt picks the key by `key_id`
(current key or any old key) and fails with a decryption error on any problem.
`needs_rotation(token)`: three `.`-parts whose key id is not the current one.

---

## 12. API key authentication — MUST match (behaviour)

- **Extract**: header (default `X-API-Key`, case-insensitive); else, when bearer is
  enabled (default), `Authorization` split at the first space after trimming, scheme
  compared case-insensitively with `bearer`; else the query parameter if
  configured. The value is trimmed; empty → none.
- **Pre-checks** (no lookup): length ≤ 512, ASCII, starts with `prefix` if set,
  valid checksum if `require_checksum`.
- **Lookup** with `hash_api_key(key, pepper)`, then each previous pepper in order;
  a match under an old pepper calls `on_rehash(record, current_hash)`.
- **Validity** (`record_is_active`): none → inactive; `revoked` truthy → inactive;
  `is_active` exactly `false` → inactive; `expires_at` absent/null → active;
  number → active while `now < expires_at` (**Unix seconds**); datetime → compared
  with now; anything else → inactive.
  (JavaScript only, non-normative: a number above 10¹¹ can only be a millisecond
  timestamp from `Date.now()`, so JS reads it as milliseconds. Python reads every
  number as seconds; store seconds when both languages share a table.)
- **Scopes**: required scopes (per call, else configured) checked with
  `has_all_scopes(record.scopes, …)` → 403.
- **Errors**: `401 "Missing API key."`, `401 "Invalid API key."`,
  `403 "Insufficient scope."`, `429 "Too many invalid API keys. Try again later."`
  (limiter blocked; failed attempts are counted per client).
  401 responses carry `WWW-Authenticate: Bearer realm="api"` (bearer enabled) or
  `ApiKey header="<header>"`.
- **path_excluded**: `path` equals the entry, equals it without trailing `/`, or
  starts with `entry-without-trailing-slash ‖ "/"`.
- **Redis limiter** (shared counters across both languages): key
  `"gak:attempts:" ‖ hex(SHA-256(utf8(id)))`, the Lua script in the vectors, window
  in milliseconds.

---

## 13. Versioning

This is spec **v1** (`vectors.json` → `spec_version: 1`). Any change to a
MUST-match rule bumps the version, regenerates the vectors, and lands in both
packages together with CHANGELOG entries.
