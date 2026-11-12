# generateapikey for JavaScript and TypeScript

API reference for the npm package [`@nuhmanpk/generateapikey`](https://www.npmjs.com/package/@nuhmanpk/generateapikey) **0.6.0**.

It covers API keys, checksums, storage hashing, scopes, key rotation and a key store, leak detection, API key auth middleware, TOTP/HOTP, recovery codes, one-time codes, attempt limiting, signed tokens, JWT, AES-GCM encryption at rest and QR codes. It has no runtime dependencies: everything uses Web Crypto (`globalThis.crypto`). It is written in TypeScript and ships its own types, as both ESM and CommonJS.

Its wire formats are compatible with the [Python package](https://github.com/nuhmanpk/generate-api-key/blob/main/docs/python.md). Hashes, codes, tokens, ciphertexts and database rows made in one language verify in the other. The formats are specified in [spec/SPEC.md](https://github.com/nuhmanpk/generate-api-key/blob/main/spec/SPEC.md).

## Contents

1. [Install and runtimes](#1-install-and-runtimes)
2. [Quick start](#2-quick-start)
3. [API keys](#3-api-keys)
4. [Storage hashing](#4-storage-hashing)
5. [Scopes](#5-scopes)
6. [Issuing, rotation and KeyStore](#6-issuing-rotation-and-keystore)
7. [Leak detection](#7-leak-detection)
8. [Framework adapters](#8-framework-adapters)
9. [MFA](#9-mfa)
10. [Signed tokens](#10-signed-tokens)
11. [JWT](#11-jwt)
12. [SecretBox (encryption at rest)](#12-secretbox-encryption-at-rest)
13. [QR codes](#13-qr-codes)
14. [CLI](#14-cli)
15. [Units and differences from Python](#15-units-and-differences-from-python)
16. [Cross-language compatibility](#16-cross-language-compatibility)
17. [Errors reference](#17-errors-reference)

---

## 1. Install and runtimes

```sh
npm install @nuhmanpk/generateapikey
# pnpm add @nuhmanpk/generateapikey · yarn add @nuhmanpk/generateapikey · bun add @nuhmanpk/generateapikey
# Deno: import { generateApiKey } from "npm:@nuhmanpk/generateapikey";
```

### Entry points

| Import | Contents |
|---|---|
| `@nuhmanpk/generateapikey` | Everything except QR codes and the framework adapters |
| `@nuhmanpk/generateapikey/qr` | `qrMatrix`, `qrAscii`, `qrSvg`, `qrPng` |
| `@nuhmanpk/generateapikey/web` | Adapter for any Fetch handler, `(Request) => Response` |
| `@nuhmanpk/generateapikey/hono` | Hono middleware |
| `@nuhmanpk/generateapikey/express` | Express 4/5 (and Connect-style) middleware |
| `@nuhmanpk/generateapikey/fastify` | Fastify plugin and `preHandler` hook |
| `@nuhmanpk/generateapikey/koa` | Koa middleware |
| `@nuhmanpk/generateapikey/next` | Next.js `middleware.ts` and App Router route handlers |
| `@nuhmanpk/generateapikey/llms.txt` | Usage guide for AI coding agents (also printed by `npx @nuhmanpk/generateapikey --llms`) |

Each code entry point has ESM (`import`) and CommonJS (`require`) builds with types. The adapters never import their framework at runtime. They are typed against the framework's request shape only, so installing `@nuhmanpk/generateapikey` does not pull in Express, Hono, or any other framework.

```js
// CommonJS
const { generateApiKey } = require("@nuhmanpk/generateapikey");
const { withApiKey } = require("@nuhmanpk/generateapikey/web");
```

### Runtime support

| Runtime | Supported | Notes |
|---|---|---|
| Node.js 20+ | Yes | `engines: { node: ">=20" }`. The CLI needs Node. |
| Bun | Yes | |
| Deno | Yes | `npm:@nuhmanpk/generateapikey` |
| Cloudflare Workers | Yes | PBKDF2 is capped at 100,000 iterations (see below). Random values can't be generated at global scope. |
| Vercel Edge / Next.js middleware | Yes | Use `@nuhmanpk/generateapikey/next` or `@nuhmanpk/generateapikey/web`. |
| Browsers | Yes | Needs a secure context (HTTPS or localhost) for `crypto.subtle`. |

The only requirement is `globalThis.crypto` with `subtle` and `getRandomValues`. If it is missing, every function that needs it throws `Error("generateapikey needs the Web Crypto API (globalThis.crypto). …")`.

**Cloudflare Workers caveats**

- **PBKDF2 iteration cap.** Production Workers reject PBKDF2 with more than 100,000 iterations. `KDF_ITERATIONS` is exactly 100,000, so default hashes work everywhere. A hash made elsewhere with more iterations, such as `hashCode(code, pepper, 200_000)` in Node, can't be verified on Workers. `verifyCode` then throws `Error("This runtime refused PBKDF2 with … iterations (Cloudflare Workers allows at most 100,000). …")`. The local Miniflare/workerd runtime does not enforce this cap, so test against a deployed Worker.
- **No randomness at global scope.** Workers forbid generating random values at module top level. Call `generateApiKey()`, `generateTotpSecret()`, `store.create()` and similar functions inside a handler, never at the top of the module.

### Sync vs async

Web Crypto's `crypto.subtle` is promise-based, so anything that hashes, signs or encrypts is `async`. Pure random generation uses the synchronous `crypto.getRandomValues`, so it is synchronous.

| Synchronous | Asynchronous (returns a `Promise`) |
|---|---|
| `generateApiKey`, `generateApiKeys`, `randomKey`, `buildCharset`, `entropyBits`, `addDashes`, `computeChecksum`, `verifyChecksum`, `isExpired`, `parseScopes`, `hasScope`, `hasAllScopes`, `hasAnyScope`, `keyPattern`, `keyRegExp`, `findKeys`, `gitleaksRule`, `generateTotpSecret`, `totpUri`, `hotpUri`, `googleMigrationUri`, `generateRecoveryCodes`, `normalizeRecoveryCode`, `generateOtp`, `generateEncryptionKey`, `keyHint`, `recordIsActive`, `pathExcluded`, `isKeyActive`, `timingSafeEqual`, `clearKeyCache`, `AttemptLimiter` methods, `qr*`, `APIKeyAuth#extract` | `deriveApiKey`, `subkey`, `hashApiKey`, `verifyApiKey`, `hashCode`, `verifyCode`, `hotp`, `totp`, `totpNow`, `findTotpStep`, `verifyTotp`, `verifyHotp`, `steamCode`, `verifySteamCode`, `hashRecoveryCode`, `verifyRecoveryCode`, `hashOtp`, `verifyOtp`, `RedisAttemptLimiter` methods, `generateSignedToken`, `verifySignedToken`, `encodeJwt`, `decodeJwt`, `decodeJwtJwks`, `SecretBox.create` and its `encrypt`/`decrypt`/`rotate`, `issueApiKey`, `rotateApiKey`, `APIKeyAuth#authenticate`, all `KeyStore` methods, all adapters |

---

## 2. Quick start

```ts
import { generateApiKey, hashApiKey, verifyApiKey } from "@nuhmanpk/generateapikey";

const key = generateApiKey({ prefix: "sk", checksum: true }); // sync: "sk-…" + 6-char checksum
const stored = await hashApiKey(key); // "sha256$…" (store this, never the raw key)

console.log(await verifyApiKey(key, stored)); // true (constant-time)
console.log(await verifyApiKey("sk-wrong", stored)); // false
```

The same thing, complete with storage, scopes, and HTTP middleware for any Fetch runtime (Workers, Bun, Deno, Vercel Edge):

```ts
import { APIKeyAuth, KeyStore, MemoryKeyStorage, type KeyRecord } from "@nuhmanpk/generateapikey";
import { withApiKey } from "@nuhmanpk/generateapikey/web";

const PEPPER = "change-me-pepper"; // server-side secret, e.g. from env
const store = new KeyStore(new MemoryKeyStorage(), { pepper: PEPPER });

const { key } = await store.create("ci-bot", { prefix: "sk", scopes: ["read:*"] });
// Show `key` to the user once. Only its hash is stored.

const auth = new APIKeyAuth<KeyRecord>({ lookup: store.lookup, pepper: PEPPER, prefix: "sk", requireChecksum: true });
const handler = withApiKey(auth, async (_req, record) => Response.json({ hello: record?.name }));

const res = await handler(new Request("https://api.example.com/items", { headers: { "X-API-Key": key } }));
console.log(res.status, await res.json()); // 200 { hello: "ci-bot" }
console.log((await handler(new Request("https://api.example.com/items"))).status); // 401
```

---

## 3. API keys

### `generateApiKey(options?)`: random keys (sync)

```ts
function generateApiKey(options?: KeyOptions & { expiry?: undefined }): string;
function generateApiKey(options: ExpiringKeyOptions): ApiKey; // when `expiry` (minutes) is given
```

The function is **synchronous**. It returns a plain `string`, or an [`ApiKey`](#apikey) object when `expiry` is set. Each body character is drawn from `crypto.getRandomValues` with rejection sampling, so the output is unbiased (no `byte % n`).

| Option | Type | Default | Meaning |
|---|---|---|---|
| `length` | `number` | `32` | Characters in the body, excluding prefix, dashes and checksum. Positive integer. |
| `charset` | `CharsetName \| string` | `"alphanumeric"` | A [preset](#charsets) or a literal string of characters. |
| `case` | `"mixed" \| "lower" \| "upper"` | `"mixed"` | Case mapping applied to the charset. |
| `prefix` | `string \| null` | none | Joined with `separator`, e.g. `sk-…`. Recommended: it makes leaked keys [detectable](#7-leak-detection). |
| `separator` | `string` | `"-"` | Placed between prefix and body. |
| `dashes` | `boolean` | `false` | Group the body for readability: `ABCD-EFGH-…`. |
| `dashGroup` | `number` | `4` | Group size when `dashes` is set. |
| `dashChar` | `string` | `"-"` | Character placed between groups. |
| `checksum` | `boolean` | `false` | Append a 6-character base62 CRC32 of everything before it. |
| `minEntropy` | `number` | none | Throw `RangeError` if the key would have fewer bits of entropy than this. |
| `onWeakKey` | `(msg: string) => void \| false` | `console.warn` | Called for keys under 128 bits (`RECOMMENDED_ENTROPY`). Pass `false` to silence it. |
| `expiry` | `number` | none | Lifetime in **minutes**. When set, an `ApiKey` is returned. |

**Throws:** `RangeError` for a bad `length`, `case`, `dashGroup`, a charset with fewer than 2 distinct characters, `minEntropy` not met, or a non-positive or non-finite `expiry`. `TypeError` if `expiry` is not a number, if `charset` is not a string, or if you pass `secret`/`seed`; use [`deriveApiKey`](#deriveapikeyoptions-deterministic-keys-async) for those.

```ts
import { generateApiKey } from "@nuhmanpk/generateapikey";

generateApiKey(); // "q3Xk…" (32 alphanumeric chars, ~190 bits)
generateApiKey({ prefix: "sk_live", separator: "_", checksum: true }); // "sk_live_…" + checksum
generateApiKey({ length: 26, charset: "crockford", dashes: true }); // "7KQ2-M9XP-…" (130 bits)
generateApiKey({ length: 8, onWeakKey: false }); // 48 bits, no warning

const expiring = generateApiKey({ prefix: "tmp", expiry: 60 }); // ApiKey
console.log(expiring.expiresAt); // unix seconds, one hour from now
console.log(`${expiring}`.startsWith("tmp-")); // true

try {
  generateApiKey({ length: 10, minEntropy: 128 });
} catch (e) {
  console.log(e instanceof RangeError); // true: "key has 60 bits of entropy, below minEntropy=128."
}
```

> **Security.** The default (32 alphanumeric characters, 190.5 bits) is far above the 128-bit recommendation. Keys under 128 bits trigger `onWeakKey` / `console.warn`. Use `minEntropy` to enforce a floor in code paths where the length or charset comes from configuration.

### `ApiKey`

The value returned when `expiry` is given, and by [`generateOtp`](#one-time-codes-for-email-and-sms). It wraps the raw string plus an expiry. It is **not** a `string` subclass. Use `String(key)`, `` `${key}` ``, `key.value` or `JSON.stringify` to get the raw value. `key == "…"` coerces through `valueOf`; `key === "…"` is always `false`.

```ts
class ApiKey {
  constructor(value: string, expiresAt?: number | null);
  readonly value: string;
  readonly expiresAt: number | null; // unix SECONDS (same as Python), or null
  get isExpired(): boolean; // true once now >= expiresAt
  get expiresIn(): number | null; // seconds left (negative once expired)
  get expiresAtDate(): Date | null;
  hash(pepper?: string | null): Promise<string>; // = hashApiKey(this.value, pepper)
  redacted(): string; // "ApiKey('abcd…wxyz', expiresAt=…)"
  toString(): string; toJSON(): string; valueOf(): string; // raw value
}
function isExpired(key: unknown): boolean; // true only for an ApiKey whose expiry has passed
```

`console.log(apiKey)` and `util.inspect` in Node show the **redacted** form, the same as Python's `repr`, so keys don't leak into logs by accident. Template literals and `String()` still give the full value.

```ts
import { ApiKey, generateApiKey, isExpired } from "@nuhmanpk/generateapikey";

const k = generateApiKey({ expiry: 15 });
console.log(k); // ApiKey('Xk3q…9fPa', expiresAt=…) (redacted)
console.log(k.isExpired, Math.round(k.expiresIn!)); // false 900
console.log(JSON.stringify({ key: k })); // {"key":"<full raw key>"}
console.log(await k.hash()); // "sha256$…"
console.log(isExpired(new ApiKey("old", 1_000_000_000))); // true
console.log(isExpired("plain string")); // false
```

### `generateApiKeys(count, options?)`: batches (sync)

```ts
function generateApiKeys(count: number, options?: KeyOptions): string[];
```

Generates `count` keys with the same options as `generateApiKey`. It warns about weak options at most once per batch. It returns plain strings, or `ApiKey` objects when you pass `expiry` (minutes). `count` must be a non-negative integer, otherwise it throws `RangeError`.

```ts
import { generateApiKeys } from "@nuhmanpk/generateapikey";

const keys = generateApiKeys(3, { prefix: "sk", checksum: true });
console.log(keys.length, new Set(keys).size); // 3 3
```

### `deriveApiKey(options)`: deterministic keys (async)

```ts
function deriveApiKey(options: DeriveOptions & { expiry?: undefined }): Promise<string>;
function deriveApiKey(options: DeriveOptions & { expiry: number }): Promise<ApiKey>;

interface DeriveOptions extends KeyFormatOptions {
  secret: string; // server secret (non-empty)
  seed: string; // per-key value, e.g. a user id (non-empty)
  include?: string | null; // extra context mixed in
  expiry?: number; // minutes. Note that expiresAt is based on *now*, so it isn't deterministic
}
```

The same `secret`, `seed`, `include` and format options always produce the same key, in JS and in Python. The derivation is HMAC-SHA256 in counter mode, keyed by `subkey(secret, "derive")`, and its output goes through the same unbiased sampler ([spec §2.3](https://github.com/nuhmanpk/generate-api-key/blob/main/spec/SPEC.md#23-derived-deterministic-keys--must-match)). It is async because HMAC uses `crypto.subtle`. The format options (`KeyFormatOptions`) are `length`, `charset`, `case`, `prefix`, `separator`, `dashes`, `dashGroup`, `dashChar` and `checksum`. There is no `minEntropy` or `onWeakKey`.

**Throws:** `RangeError` if `secret` or `seed` is missing or empty, and for bad format options (as above).

```ts
import { deriveApiKey } from "@nuhmanpk/generateapikey";

const a = await deriveApiKey({ secret: "change-me-derive-secret", seed: "user-42", prefix: "dk", checksum: true });
const b = await deriveApiKey({ secret: "change-me-derive-secret", seed: "user-42", prefix: "dk", checksum: true });
console.log(a === b); // true
console.log(a === (await deriveApiKey({ secret: "change-me-derive-secret", seed: "user-42", include: "v2", prefix: "dk", checksum: true }))); // false
```

> **Security.** A derived key is only as secret as `secret`. Anyone who knows the secret and the seed can recompute the key. To revoke one derived key, change `include` (for example, a per-user version counter) or deny-list it in your database.

### Checksums

```ts
const CHECKSUM_LENGTH = 6;
function computeChecksum(data: string): string; // 6 base62 chars of CRC-32 (zlib) of utf8(data)
function verifyChecksum(key: unknown): boolean; // false for non-strings and keys of <= 6 chars
```

`checksum: true` appends `computeChecksum(<everything before it>)`, with prefix, separator and dashes included. `verifyChecksum` recomputes it and compares in constant time. It is an **offline typo and truncation check**, not authentication: anyone can compute a CRC. Its job is to reject garbage before you touch the database. That is what `requireChecksum` in [`APIKeyAuth`](#apikeyauth) does. It also gives secret scanners [a way to confirm a match](#7-leak-detection).

```ts
import { computeChecksum, generateApiKey, verifyChecksum } from "@nuhmanpk/generateapikey";

const key = generateApiKey({ prefix: "sk", checksum: true });
console.log(verifyChecksum(key)); // true
console.log(verifyChecksum(key.slice(0, -1) + (key.endsWith("A") ? "B" : "A"))); // false
console.log(computeChecksum("sk-abc").length); // 6
console.log(verifyChecksum(42)); // false (never throws)
```

### Entropy

```ts
const RECOMMENDED_ENTROPY = 128;
function entropyBits(length: number, charset?: CharsetName | string, caseMode?: Case): number;
```

Returns `length × log2(number of distinct characters after case mapping)`. Prefix, separator, dashes and checksum add no entropy.

```ts
import { entropyBits } from "@nuhmanpk/generateapikey";

console.log(entropyBits(32).toFixed(1)); // "190.5" (default key)
console.log(entropyBits(20, "hex")); // 80
console.log(entropyBits(26, "crockford")); // 130
```

### Charsets

`CHARSETS` is a frozen object with these presets. Characters are listed in order; for derived keys the order matters.

| Name | Characters | Size | Bits/char |
|---|---|---|---|
| `alphanumeric` (default) | `a–z A–Z 0–9` | 62 | 5.95 |
| `base62` | `0–9 A–Z a–z` (same set, different order) | 62 | 5.95 |
| `alphabetic` | `a–z A–Z` | 52 | 5.70 |
| `numeric` | `0–9` | 10 | 3.32 |
| `hex` | `0–9 a–f` | 16 | 4 |
| `base16` | `0–9 A–F` | 16 | 4 |
| `base32` | `A–Z 2–7` | 32 | 5 |
| `crockford` | `0123456789ABCDEFGHJKMNPQRSTVWXYZ` | 32 | 5 |
| `base64url` | `a–z A–Z 0–9 - _` | 64 | 6 |
| `base58` | `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` | 58 | 5.86 |
| `unambiguous` | `23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz` | 56 | 5.81 |

```ts
function buildCharset(charset?: CharsetName | string, caseMode?: Case): string; // default ("alphanumeric", "mixed")
function randomKey(length: number, chars: string): string; // sync, unbiased
function addDashes(key: string, group?: number, sep?: string): string; // default (4, "-")
type CharsetName = keyof typeof CHARSETS;
type Case = "mixed" | "lower" | "upper";
```

`buildCharset` resolves a preset name, or treats any other string as a literal set of characters, and returns the final alphabet that keys are drawn from ([spec §1.2](https://github.com/nuhmanpk/generate-api-key/blob/main/spec/SPEC.md#12-build_charsetcharset-case--must-match)):

1. `"lower"` / `"upper"` apply Unicode case mapping to the **whole** string.
2. For `base58`, `unambiguous` and `crockford` with a non-`mixed` case, the characters `0 O 1 I l` are removed **after** case mapping. So `buildCharset("base58", "lower")` still contains `i` and `o`, the lower-cased forms of `I` and `O`, which `base58` keeps under `mixed`. Only the exact characters `0 O 1 I l` are filtered.
3. Duplicates are removed (the first occurrence is kept), so every character is equally likely. `"aab"` becomes `"ab"`.
4. Fewer than 2 distinct characters throws `RangeError`. A bad `case` throws `RangeError`, and a non-string charset throws `TypeError`.

Characters are Unicode **code points**, so emoji and other astral characters count as one character each. `length`, `dashGroup` and the checksum boundary also count code points. ASCII alphabets of up to 256 characters use a fast byte-table path; any other alphabet uses multi-byte rejection sampling. Both are unbiased.

`randomKey(length, chars)` is the raw sampler: `chars` goes through the same resolution, so a preset name works too. Unlike `generateApiKey`, it does no length validation, formatting or entropy warnings. `addDashes` inserts `sep` every `group` code points and throws `RangeError` if `group < 1`.

```ts
import { CHARSETS, addDashes, buildCharset, generateApiKey, randomKey } from "@nuhmanpk/generateapikey";

console.log(Object.keys(CHARSETS).length); // 11
console.log(buildCharset("hex", "upper")); // "0123456789ABCDEF"
console.log(buildCharset("crockford", "lower")); // "23456789abcdefghjkmnpqrstvwxyz"
console.log(buildCharset("aab")); // "ab"
console.log(randomKey(6, "0123456789")); // e.g. "042917"
console.log(addDashes("ABCDEFGHIJ", 3, "_")); // "ABC_DEF_GHI_J"
console.log(Array.from(generateApiKey({ charset: "😀😁😂🤣", length: 70 })).length); // 70
```

---

## 4. Storage hashing

Never store raw keys. API keys are high-entropy, so a fast hash is enough. Short codes (OTP, recovery codes) are not, so they get salted PBKDF2. Every hashing function is async.

### `hashApiKey` / `verifyApiKey`

```ts
function hashApiKey(key: string | ApiKey, pepper?: string | null): Promise<string>;
function verifyApiKey(key: unknown, hashed: unknown, pepper?: string | null): Promise<boolean>;
```

- Without a pepper: `"sha256$" + hex(SHA-256(key))`.
- With a pepper: `"hmac-sha256$" + hex(HMAC-SHA256(subkey(pepper, "hash"), key))`.

The hash is deterministic, so you can put a **unique index** on the hash column and look keys up by it. `verifyApiKey` compares in constant time and returns `false`, without throwing, for non-string input. It also returns `false` when the hash kind and the pepper disagree: an `hmac-sha256$` hash with no pepper, or a `sha256$` hash with one.

**Throws:** `RangeError` if `pepper` is given but isn't a non-empty string (`""` is rejected).

```ts
import { generateApiKey, hashApiKey, verifyApiKey } from "@nuhmanpk/generateapikey";

const PEPPER = "change-me-pepper";
const key = generateApiKey({ prefix: "sk" });

const plain = await hashApiKey(key); // "sha256$…"
const peppered = await hashApiKey(key, PEPPER); // "hmac-sha256$…"
console.log(await verifyApiKey(key, peppered, PEPPER)); // true
console.log(await verifyApiKey(key, peppered)); // false (pepper missing)
console.log(await verifyApiKey(key, plain, PEPPER)); // false (kind mismatch)
console.log(await verifyApiKey(null, plain)); // false
```

> **Security: use a pepper.** With a pepper (a server-side secret kept in env or a secret manager, never in the database), a leaked `api_keys` table is useless on its own. To rotate a pepper without invalidating keys, use `APIKeyAuth`'s `previousPeppers` and `onRehash` ([§8](#apikeyauth)).

### `hashCode` / `verifyCode` / `KDF_ITERATIONS`

```ts
const KDF_ITERATIONS = 100_000;
function hashCode(code: string, pepper?: string | null, iterations?: number): Promise<string>;
function verifyCode(code: unknown, hashed: unknown, pepper?: string | null): Promise<boolean>;
```

Salted PBKDF2-HMAC-SHA256 for short, low-entropy secrets: `pbkdf2-sha256$<iterations>$<b64url salt(16)>$<b64url dk(32)>`. The format is the same as Python's. A pepper is applied as `HMAC(subkey(pepper, "code"), code)` before PBKDF2. You rarely call these directly; `hashOtp` and `hashRecoveryCode` use them.

- `hashCode` throws `RangeError` for a bad pepper or if `iterations` is not a positive integer.
- `verifyCode` returns `false` for malformed input and never throws for it. It does throw for a bad pepper, or when the runtime refuses the iteration count (Workers above 100,000).
- `verifyCode` only accepts stored iteration counts between **1,000 and 10,000,000**, as a guard against absurd stored values. `hashCode(code, pepper, 500)` succeeds, but the result **never verifies**. Don't go below 1,000, and stay at or below 100,000 if any verifier runs on Cloudflare Workers.

```ts
import { KDF_ITERATIONS, hashCode, verifyCode } from "@nuhmanpk/generateapikey";

const stored = await hashCode("493817", "change-me-pepper");
console.log(stored.startsWith(`pbkdf2-sha256$${KDF_ITERATIONS}$`)); // true
console.log(await verifyCode("493817", stored, "change-me-pepper")); // true
console.log(await verifyCode("000000", stored, "change-me-pepper")); // false
console.log(await verifyCode("493817", "garbage")); // false
```

### `subkey`

```ts
function subkey(secret: string, label: string): Promise<Uint8Array>; // 32 bytes
```

`HMAC-SHA256(utf8(secret), utf8("generateapikey.v1." + label))`. This derives an independent key per purpose from one server secret (domain separation). The library uses the labels `"derive"`, `"hash"`, `"code"` and `"token"`, so one pepper can safely back key hashing, code hashing and signed tokens. Use your own labels for your own HMACs. Results are cached per `(secret, label)` (up to 64 entries).

```ts
import { subkey } from "@nuhmanpk/generateapikey";

const k = await subkey("change-me-server-secret", "webhooks");
console.log(k.length); // 32
```

### `timingSafeEqual` and `clearKeyCache`

```ts
function timingSafeEqual(a: unknown, b: unknown): boolean; // constant-time over UTF-8 bytes; never throws
function clearKeyCache(): void;
```

`timingSafeEqual` is the comparison every `verify*` function uses internally. Non-strings are simply unequal. The length can leak; the contents can't. Use it for your own secret comparisons instead of `===`.

To avoid re-importing keys on every request, the library caches imported HMAC keys for **server secrets** (peppers, signing secrets, derive secrets), up to 64 each. User secrets such as TOTP secrets are never cached. Call `clearKeyCache()` after rotating a pepper or secret so the old key material is dropped from memory.

```ts
import { clearKeyCache, timingSafeEqual } from "@nuhmanpk/generateapikey";

console.log(timingSafeEqual("abc", "abc"), timingSafeEqual("abc", "abd"), timingSafeEqual("abc", 1)); // true false false
clearKeyCache();
```

---

## 5. Scopes

```ts
type Scopes = string | Iterable<unknown> | null | undefined;
function parseScopes(scopes: Scopes): Set<string>;
function hasScope(granted: Scopes, required: string): boolean;
function hasAllScopes(granted: Scopes, required: string | Iterable<string>): boolean; // empty required → true
function hasAnyScope(granted: Scopes, required: string | Iterable<string>): boolean; // empty required → false
```

Scopes are strings such as `read:users`. `granted` can be a space- or comma-separated string, an array, or a `Set`; non-string entries are ignored. Wildcards:

- `*` grants everything.
- `read:*` grants `read`, `read:users` and `read:users:list`.
- `read` does **not** grant `read:users`.

All of these are synchronous and never throw. Scopes aren't secrets, so plain comparison is fine. `APIKeyAuth` checks `requiredScopes` against the record's `scopes` field and responds **403** on failure.

```ts
import { hasAllScopes, hasAnyScope, hasScope, parseScopes } from "@nuhmanpk/generateapikey";

console.log(parseScopes("read:users, write:users admin")); // Set { "read:users", "write:users", "admin" }
console.log(hasScope("read:*", "read:users:list")); // true
console.log(hasScope("read", "read:users")); // false
console.log(hasScope(["*"], "anything")); // true
console.log(hasAllScopes(["read:*", "write:users"], ["read:users", "write:users"])); // true
console.log(hasAnyScope("read:*", ["admin", "read:orders"])); // true
```

---

## 6. Issuing, rotation and KeyStore

### `issueApiKey(options?)`

```ts
function issueApiKey(options?: IssueOptions): Promise<IssuedKey>;
interface IssueOptions extends KeyOptions { pepper?: string | null; expiry?: number /* minutes */ }
interface IssuedKey {
  key: string; // give to the client once; never store it
  hashed: string; // store (unique index) and look up by it
  hint: string; // store and show in your UI: "sk-AbCd…wXyZ"
  expiresAt: number | null; // unix seconds
}
function keyHint(key: string): string; // key[:7] + "…" + key[-4:] for keys of >= 16 code points, else "…"
```

This generates a key plus everything you need to store for it. **`checksum` defaults to `true`** here, unlike in `generateApiKey`. It accepts every `generateApiKey` option. Throws the same errors as `generateApiKey`, plus `RangeError` for a bad pepper.

```ts
import { issueApiKey, keyHint, verifyChecksum } from "@nuhmanpk/generateapikey";

const issued = await issueApiKey({ prefix: "sk", pepper: "change-me-pepper", expiry: 60 * 24 * 90 });
console.log(verifyChecksum(issued.key)); // true
console.log(issued.hashed.startsWith("hmac-sha256$"), issued.hint === keyHint(issued.key)); // true true
// INSERT INTO api_keys (hashed, hint, expires_at, …) VALUES (issued.hashed, issued.hint, issued.expiresAt, …)
```

### `rotateApiKey(options?)`

```ts
function rotateApiKey(options?: IssueOptions & { graceMinutes?: number }): Promise<Rotation>;
interface Rotation extends IssuedKey { oldExpiresAt: number } // set the OLD record's expires_at to this
```

This issues a replacement key and computes when the old key should stop working: `now + graceMinutes` (default 24 hours, so clients can switch without downtime). Throws `RangeError` if `graceMinutes` is negative.

```ts
import { rotateApiKey } from "@nuhmanpk/generateapikey";

const r = await rotateApiKey({ prefix: "sk", graceMinutes: 60 });
console.log(r.oldExpiresAt - Math.floor(Date.now() / 1000)); // ~3600
// UPDATE api_keys SET expires_at = MIN(COALESCE(expires_at, :old), :old) WHERE id = :oldId; INSERT the new one
```

### `KeyStore`

A small key store (create, look up, revoke, rotate) that stores **only hashes**. Storage is pluggable.

```ts
class KeyStore {
  constructor(storage?: KeyStorage /* default new MemoryKeyStorage() */, options?: { pepper?: string | null; touch?: boolean /* default true */ });
  readonly storage: KeyStorage;
  readonly pepper: string | null;
  create(name: string, options?: CreateOptions): Promise<CreatedKey>;
  lookup: (hashed: string) => Promise<KeyRecord | null>; // arrow property: pass `store.lookup` straight to APIKeyAuth
  find(key: string): Promise<KeyRecord | null>; // hashes the raw key with the store's pepper, then lookup
  get(id: number): Promise<KeyRecord | null>;
  list(options?: { activeOnly?: boolean }): Promise<KeyRecord[]>;
  revoke(id: number): Promise<boolean>; // false if missing or already revoked
  rotate(id: number, options?: Omit<CreateOptions, "scopes" | "meta"> & { graceMinutes?: number }): Promise<CreatedKey>;
}
interface CreateOptions extends Omit<IssueOptions, "pepper"> { scopes?: Scopes; meta?: Record<string, unknown> }
interface CreatedKey { id: number; key: string /* show once */; record: KeyRecord }
interface KeyRecord {
  id: number; name: string; hint: string;
  scopes: string[]; // sorted
  createdAt: number; expiresAt: number | null; lastUsedAt: number | null; // unix seconds
  revoked: boolean; meta: Record<string, unknown>;
}
function isKeyActive(record: KeyRecord): boolean; // not revoked and not expired
```

- `create` throws `RangeError` for an empty `name`, plus any `generateApiKey` error. Checksums are on by default. Storage errors, such as a duplicate hash, propagate.
- `lookup` updates `last_used_at` when `touch` is true, and the record it returns already holds the new value.
- `rotate` throws `Error("no active key with id …")` if the key is missing, revoked or expired. It copies the old key's name, scopes and meta, and sets the old key's expiry to the earlier of its current expiry and the end of the grace period. **Format options are not copied.** Pass the same `prefix` (and other format options) again, or the new key won't pass an `APIKeyAuth` that has `prefix` set.
- `KeyRecord` has `revoked` and `expiresAt`, so it works with the default `recordIsActive` check and with scope checks in `APIKeyAuth`.

```ts
import { APIKeyAuth, KeyStore, MemoryKeyStorage, isKeyActive, type KeyRecord } from "@nuhmanpk/generateapikey";

const store = new KeyStore(new MemoryKeyStorage(), { pepper: "change-me-pepper" });
const { id, key, record } = await store.create("billing-service", { prefix: "sk", scopes: "read:invoices write:invoices", meta: { team: "billing" } });
console.log(record.scopes, record.hint); // ["read:invoices", "write:invoices"] "sk-AbCd…wXyZ"

console.log((await store.find(key))?.name); // "billing-service"
const rotated = await store.rotate(id, { prefix: "sk", graceMinutes: 60 }); // same prefix again!
console.log(isKeyActive((await store.get(id))!), rotated.record.name); // true (in grace period) "billing-service"

console.log(await store.revoke(id), await store.revoke(id)); // true false
console.log((await store.list({ activeOnly: true })).map((r) => r.id)); // [rotated.id]

const auth = new APIKeyAuth<KeyRecord>({ lookup: store.lookup, pepper: store.pepper, prefix: "sk", requireChecksum: true });
console.log((await auth.authenticate(rotated.key)).id === rotated.id); // true
```

### Storage backends

```ts
interface KeyStorage {
  insert(row: Omit<KeyRow, "id" | "revoked_at" | "last_used_at">): Promise<number>; // returns the new id
  findByHash(hashed: string): Promise<KeyRow | null>;
  get(id: number): Promise<KeyRow | null>;
  all(): Promise<KeyRow[]>;
  update(id: number, patch: Partial<Pick<KeyRow, "expires_at" | "revoked_at" | "last_used_at">>): Promise<void>;
}
interface KeyRow { // same columns as the Python package's SQLite table
  id: number; hashed: string; name: string; hint: string;
  scopes: string; // JSON array
  created_at: number; expires_at: number | null; revoked_at: number | null; last_used_at: number | null;
  meta: string; // JSON object
}
```

- **`MemoryKeyStorage`**: a `Map`, for tests, prototypes and single processes. A duplicate hash throws `Error("UNIQUE constraint failed: api_keys.hashed")`.
- **`SqlKeyStorage`**: works over any SQLite-dialect driver that supports `?` placeholders. It needs two functions:

```ts
interface SqlDriver {
  all(sql: string, params: unknown[]): Promise<Record<string, unknown>[]>;
  run(sql: string, params: unknown[]): Promise<{ lastInsertRowid?: number | bigint | null } | void>;
}
class SqlKeyStorage implements KeyStorage {
  constructor(db: SqlDriver, table?: string /* default "api_keys"; must be a plain identifier, else RangeError */);
  migrate(): Promise<void>; // CREATE TABLE IF NOT EXISTS …
}
const KEYSTORE_SCHEMA: string; // the CREATE TABLE statement (identical to Python's KeyStore)
```

If `run` doesn't report `lastInsertRowid`, `insert` falls back to looking the row up by its hash.

**The table is the same one the Python `KeyStore` uses** (`api_keys`: `id`, `hashed UNIQUE`, `name`, `hint`, `scopes` JSON, `created_at`, `expires_at`, `revoked_at`, `last_used_at`, `meta` JSON; timestamps in unix seconds). A key created by Python's `KeyStore("keys.db", pepper=…)` authenticates through a JS `SqlKeyStorage` on the same database, and the other way round, as long as both sides use the same pepper.

#### node:sqlite (Node 22.5+, built in)

```ts
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { KeyStore, SqlKeyStorage, type SqlDriver } from "@nuhmanpk/generateapikey";

const db = new DatabaseSync("keys.db");
const driver: SqlDriver = {
  all: async (sql, params) => db.prepare(sql).all(...(params as SQLInputValue[])) as Record<string, unknown>[],
  run: async (sql, params) => db.prepare(sql).run(...(params as SQLInputValue[])),
};

const storage = new SqlKeyStorage(driver);
await storage.migrate();
const store = new KeyStore(storage, { pepper: "change-me-pepper" });
const { key } = await store.create("cron", { prefix: "sk", scopes: ["jobs:run"] });
console.log((await store.find(key))?.scopes); // ["jobs:run"]
db.close();
```

#### better-sqlite3

```ts
import Database from "better-sqlite3";
import { KeyStore, SqlKeyStorage, type SqlDriver } from "@nuhmanpk/generateapikey";

const db = new Database("keys.db");
const driver: SqlDriver = {
  all: async (sql, params) => db.prepare(sql).all(...params) as Record<string, unknown>[],
  run: async (sql, params) => db.prepare(sql).run(...params), // returns { changes, lastInsertRowid }
};

const storage = new SqlKeyStorage(driver);
await storage.migrate();
const store = new KeyStore(storage, { pepper: "change-me-pepper" });
const { key } = await store.create("worker", { prefix: "sk" });
console.log((await store.find(key))?.name); // "worker"
db.close();
```

#### Cloudflare D1

Create the table once with a migration that contains `KEYSTORE_SCHEMA`, or by calling `storage.migrate()` from an admin route.

```ts
// src/worker.ts (wrangler.toml: [[d1_databases]] binding = "DB")
import { APIKeyAuth, KeyStore, SqlKeyStorage, type KeyRecord, type SqlDriver } from "@nuhmanpk/generateapikey";
import { withApiKey } from "@nuhmanpk/generateapikey/web";

interface Env {
  DB: D1Database;
  API_KEY_PEPPER: string; // wrangler secret put API_KEY_PEPPER
}

export const d1 = (db: D1Database): SqlDriver => ({
  all: async (sql, params) => (await db.prepare(sql).bind(...params).all<Record<string, unknown>>()).results,
  run: async (sql, params) => ({ lastInsertRowid: (await db.prepare(sql).bind(...params).run()).meta.last_row_id }),
});

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const store = new KeyStore(new SqlKeyStorage(d1(env.DB)), { pepper: env.API_KEY_PEPPER });
    const auth = new APIKeyAuth<KeyRecord>({ lookup: store.lookup, pepper: env.API_KEY_PEPPER, prefix: "sk", requireChecksum: true });
    return withApiKey(auth, async (_req, record) => Response.json({ name: record?.name, scopes: record?.scopes }))(req);
  },
};
```

Any other database works the same way: implement the five `KeyStorage` methods, or map `SqlDriver` onto libSQL, Turso, Postgres (rewrite `?` to `$1`…) and so on.

---

## 7. Leak detection

Keys with a distinctive **prefix** and a **checksum** can be found reliably by GitHub secret scanning, gitleaks, trufflehog, or your own log scrubber: the checksum lets a scanner reject random lookalikes.

```ts
interface KeyPatternOptions {
  length?: number; // 32
  separator?: string; // "-"
  charset?: CharsetName | string; // "alphanumeric"
  case?: Case; // "mixed"
  checksum?: boolean; // TRUE by default here
}
function keyPattern(prefix: string, options?: KeyPatternOptions): string; // regex SOURCE, Python/PCRE syntax
function keyRegExp(prefix: string, options?: KeyPatternOptions): RegExp; // JS RegExp, flags "gu"
function findKeys(text: unknown, prefix: string, options?: KeyPatternOptions & { validate?: boolean /* true */ }): string[];
function gitleaksRule(prefix: string, ruleId: string, options?: KeyPatternOptions & { description?: string }): string;
```

The options must describe how your keys are generated: same length, charset, case, separator, and whether there is a checksum. **Note that `checksum` defaults to `true` here** but `false` in `generateApiKey`. Keys generated with `dashes: true` are not matched by these patterns.

**`keyPattern` vs `keyRegExp`**

- `keyPattern` returns a **string** byte-identical to Python's `key_pattern()`, escaped the way Python's `re.escape` does it (for example `sk\-`). Use it in tools that take PCRE/RE2/Python regexes: GitHub custom secret-scanning patterns, gitleaks, trufflehog, a Python service. It's not guaranteed to compile as a JavaScript `u`-mode regex.
- `keyRegExp` returns a ready-to-use JavaScript `RegExp` with flags `gu` that matches the same keys. Because of the `g` flag, it is **stateful** with `.test()` and `.exec()`, which advance `lastIndex`. Use `String.prototype.matchAll` or `match`, or reset `re.lastIndex = 0` between calls.
- Both anchor on `(?<![0-9A-Za-z_-])` … `(?![0-9A-Za-z_-])`, so keys embedded inside longer tokens don't match.

`findKeys` returns unique matches in order of appearance. With `validate` (the default) and checksums on, each candidate must also pass `verifyChecksum`. All four functions throw `RangeError` for an empty `prefix` or a bad `length`. `gitleaksRule` also throws `RangeError` if `ruleId` contains anything other than letters, digits, `.`, `_` and `-`.

```ts
import { findKeys, generateApiKey, gitleaksRule, keyPattern, keyRegExp } from "@nuhmanpk/generateapikey";

const key = generateApiKey({ prefix: "acme", checksum: true });
const log = `user pasted ${key} and acme-notARealKeyButLooksAlmostRight123456 into chat`;

console.log(findKeys(log, "acme")); // [key] (lookalike rejected by the checksum)
console.log(keyPattern("acme", { length: 4, charset: "hex" }));
// (?<![0-9A-Za-z_-])acme\-[0123456789abcdef]{4}[0-9A-Za-z]{6}(?![0-9A-Za-z_-])

const re = keyRegExp("acme");
console.log(log.replace(re, "[REDACTED]").includes(key)); // false

console.log(gitleaksRule("acme", "acme-api-key"));
// [[rules]]
// id = "acme-api-key"
// description = "acme API key"
// regex = '''acme\-[abc…789]{32}[0-9A-Za-z]{6}'''
// keywords = ["acme"]
```

---

## 8. Framework adapters

### `APIKeyAuth`

Every adapter is a thin wrapper around `APIKeyAuth`, so behaviour is identical across frameworks, and identical to the Python integrations ([spec §12](https://github.com/nuhmanpk/generate-api-key/blob/main/spec/SPEC.md#12-api-key-authentication--must-match-behaviour)).

```ts
class APIKeyAuth<R = unknown> {
  constructor(options: APIKeyAuthOptions<R>);
  extract(headers: HeadersLike | null | undefined, query?: QueryLike | null): string | null; // sync
  authenticate(key: string | null | undefined, client?: string | null, scopes?: readonly string[] | null): Promise<R>;
  challenge(): string; // WWW-Authenticate value
  errorHeaders(e: AuthError): Record<string, string>; // { "WWW-Authenticate": … } for 401, else {}
}
class AuthError extends Error { readonly status: 401 | 403 | 429; readonly detail: string }
const MAX_KEY_LENGTH = 512;
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `lookup` | `(hashed: string) => R \| null \| Promise<R \| null>` | **required** | Find the record by its stored hash (the unique-indexed column). Throws `TypeError` if missing. |
| `pepper` | `string \| null` | `null` | The pepper the keys were hashed with. |
| `header` | `string` | `"X-API-Key"` | Header to read the key from (case-insensitive). |
| `bearer` | `boolean` | `true` | Also accept `Authorization: Bearer <key>`. |
| `queryParam` | `string \| null` | `null` | Also accept `?<queryParam>=<key>`. Discouraged: URLs end up in logs. |
| `prefix` | `string \| null` | `null` | Reject keys that don't start with this, **before** any lookup. |
| `requireChecksum` | `boolean` | `false` | Reject keys with a bad checksum before any lookup. |
| `validate` | `(record: R) => boolean \| Promise<boolean>` | `recordIsActive` | Decide whether a found record is usable. |
| `limiter` | `LimiterLike \| null` | `null` | Anything with `isBlocked(client)` and `fail(client)`: `AttemptLimiter`, `RedisAttemptLimiter` or your own. Too many bad keys from one client gets **429**. |
| `onSuccess` | `(record: R) => unknown` | none | Called after a successful check, e.g. to record usage. |
| `previousPeppers` | `readonly string[]` | `[]` | Old peppers still accepted during a pepper rotation (tried in order after `pepper`). |
| `onRehash` | `(record: R, newHashed: string) => unknown` | none | Called when a key matched under an old pepper. Store `newHashed` to migrate the record. |
| `requiredScopes` | `readonly string[]` | `[]` | Scopes every key must hold (wildcards work). Failing keys get **403**. Checked against the record's `scopes` field. |

**What `authenticate(key, client, scopes)` does, in order:**

1. If a `limiter` is set **and `client` is truthy**, and `limiter.isBlocked(client)` is true: **429** `"Too many invalid API keys. Try again later."`.
2. If there is no key: **401** `"Missing API key."`.
3. Pre-checks that never touch the database: length ≤ 512, ASCII only, `prefix`, `requireChecksum`.
4. `lookup(hashApiKey(key, pepper))`, then each previous pepper in turn.
5. No record, or `validate(record)` is false: `limiter.fail(client)` is called, then **401** `"Invalid API key."`.
6. If `scopes` (the per-call argument) or else `requiredScopes` isn't covered by the record's `scopes`: **403** `"Insufficient scope."`.
7. `onRehash` (if matched under an old pepper), then `onSuccess`, then it returns the record.

Errors are thrown as `AuthError`. Every adapter turns them into a JSON `{"detail": "…"}` response with that status. 401 responses carry `WWW-Authenticate: Bearer realm="api"`, or `ApiKey header="<header>"` when `bearer` is false. Errors thrown by your `lookup`, `validate` or callbacks are passed through unchanged.

> **No client, no limiting.** The limiter only applies when a client id is available. If `client` is `null` or `""`, there is no 429 and no counting, and `APIKeyAuth` logs a one-time warning so this can't go unnoticed. Check that your adapter actually produces a client id in your deployment; see [client IPs](#client-ips-and-x-forwarded-for).

```ts
function recordIsActive(record: unknown): boolean;
function pathExcluded(path: string, exclude: readonly string[]): boolean;
type HeadersLike = Headers | Map<string, string | string[] | undefined> | Record<string, string | string[] | undefined | null> | { get(name: string): string | null | undefined };
type QueryLike = URLSearchParams | Map<string, unknown> | Record<string, unknown> | { get(name: string): unknown };
interface LimiterLike { isBlocked(client: string): boolean | Promise<boolean>; fail(client: string): unknown }
```

`recordIsActive` is the default `validate`. It accepts plain objects and `Map`s, with fields in **snake_case or camelCase**. It rejects `null`/`undefined`, a truthy `revoked`, `is_active`/`isActive` that is exactly `false`, and an `expires_at`/`expiresAt` in the past. A number there is **unix seconds**, as in Python. A number above 10¹¹ can only be milliseconds (`Date.now()`), so it's read as milliseconds rather than as a date that never comes. A `Date` is compared directly; anything else, such as a string, fails closed. Prefer seconds if Python services read the same table: Python always reads numbers as seconds.

`pathExcluded` does segment-aware prefix matching: `/health` matches `/health` and `/health/live` but not `/healthz`. Every adapter uses it for its `exclude` option.

Using `APIKeyAuth` directly, for example in a framework without an adapter:

```ts
import { APIKeyAuth, AttemptLimiter, AuthError, recordIsActive } from "@nuhmanpk/generateapikey";

type Row = { id: number; scopes: string[]; expires_at: number | null; revoked: boolean };
const rows = new Map<string, Row>(); // hashed -> row (your database)

const auth = new APIKeyAuth<Row>({
  lookup: (hashed) => rows.get(hashed) ?? null,
  pepper: "change-me-pepper",
  previousPeppers: ["change-me-old-pepper"],
  onRehash: (row, newHashed) => { /* UPDATE api_keys SET hashed = newHashed WHERE id = row.id */ },
  limiter: new AttemptLimiter({ maxAttempts: 10, window: 900 }),
  requiredScopes: ["read:*"],
});

const headers = new Headers({ authorization: "Bearer sk-not-a-real-key" });
try {
  await auth.authenticate(auth.extract(headers), "203.0.113.7");
} catch (e) {
  if (e instanceof AuthError) console.log(e.status, e.detail, auth.errorHeaders(e)); // 401 Invalid API key. { "WWW-Authenticate": 'Bearer realm="api"' }
}
console.log(recordIsActive({ expires_at: Math.floor(Date.now() / 1000) + 60 })); // true
```

### Adapter summary

| Import | Function(s) | Record ends up in | Default client id (for the limiter) |
|---|---|---|---|
| `@nuhmanpk/generateapikey/web` | `withApiKey`, `authenticateRequest`, `errorResponse`, `clientIp` | 2nd handler argument (`null` on excluded paths) | `CF-Connecting-IP`, then `X-Real-IP` |
| `@nuhmanpk/generateapikey/hono` | `apiKey` | `c.get("apiKey")` (option `key`) | `CF-Connecting-IP`, then `X-Real-IP`, then the Node socket (`@hono/node-server`) |
| `@nuhmanpk/generateapikey/express` | `apiKey` | `req.apiKey` (option `property`) | `req.ip`, then `req.socket.remoteAddress` |
| `@nuhmanpk/generateapikey/fastify` | `apiKeyPlugin`, `apiKey` | `request.apiKey` (option `property`) | `request.ip` |
| `@nuhmanpk/generateapikey/koa` | `apiKey` | `ctx.state.apiKey` (option `key`) | `ctx.ip` |
| `@nuhmanpk/generateapikey/next` | `apiKeyMiddleware`, `withApiKey`, `vercelClient` | middleware: request header `x-api-key-id` = `String(record.id)`; route handler: 2nd argument | `X-Real-IP`, then the first `X-Forwarded-For` hop |

Every adapter also takes `scopes` (overrides `requiredScopes` for that route), `exclude` (paths that skip auth) and `client` (a function returning the client id, or `null` to skip limiting). Every adapter module re-exports `AuthError`. Non-`AuthError` exceptions are re-thrown, or passed to `next(err)` in Express, so your normal error handling applies.

#### Client IPs and X-Forwarded-For

The client id is what the limiter counts failed attempts against. If an attacker can choose it, they get unlimited guesses, and they can also lock out other people's IPs.

- `X-Forwarded-For` is **set by the client** unless a proxy you control overwrites it. The web and Hono adapters deliberately read only `CF-Connecting-IP` (set by Cloudflare) and `X-Real-IP` (set by Vercel, and by many nginx configs). Behind a different proxy, pass `client` yourself.
- If neither header is present, for example Hono on Node without a proxy, the client id is `null` and **no limiting happens**. Pass `client`, for example `client: (c) => c.env?.incoming?.socket?.remoteAddress` on `@hono/node-server`.
- Express, Fastify and Koa use the framework's own `req.ip` / `request.ip` / `ctx.ip`. These honour `X-Forwarded-For` only when you enable `app.set("trust proxy", …)` (Express), `trustProxy` (Fastify) or `app.proxy = true` (Koa). Enable them only behind a proxy that overwrites the header, and configure the exact hop count or proxy addresses.
- `@nuhmanpk/generateapikey/next` uses `vercelClient`: `X-Real-IP`, or the first `X-Forwarded-For` hop. That is correct on Vercel, where the platform sets both headers. On a self-hosted Next.js server without a proxy that overwrites them, pass your own `client`.

### `@nuhmanpk/generateapikey/web`: Fetch handlers (Workers, Deno, Bun, Vercel, SvelteKit, Remix, Astro…)

```ts
interface WebOptions { scopes?: readonly string[]; exclude?: readonly string[]; client?: (req: Request) => string | null | undefined }
function withApiKey<R, A extends unknown[]>(auth: APIKeyAuth<R>, handler: (req: Request, record: R | null, ...rest: A) => Response | Promise<Response>, options?: WebOptions): (req: Request, ...rest: A) => Promise<Response>;
function authenticateRequest<R>(auth: APIKeyAuth<R>, req: Request, options?: WebOptions): Promise<R>; // throws AuthError
function errorResponse(auth: APIKeyAuth<unknown>, e: AuthError): Response; // JSON {"detail"} + WWW-Authenticate
function clientIp(req: Request): string | null; // CF-Connecting-IP ?? X-Real-IP
```

Extra handler arguments, such as Workers' `env` and `ctx`, are passed through. `record` is `null` only for excluded paths.

```ts
import { APIKeyAuth, AttemptLimiter, KeyStore, type KeyRecord } from "@nuhmanpk/generateapikey";
import { authenticateRequest, errorResponse, withApiKey } from "@nuhmanpk/generateapikey/web";
import { AuthError } from "@nuhmanpk/generateapikey/web";

const PEPPER = "change-me-pepper";
const store = new KeyStore(undefined, { pepper: PEPPER });
const { key } = await store.create("demo", { prefix: "sk", scopes: ["read:*"] });

const auth = new APIKeyAuth<KeyRecord>({ lookup: store.lookup, pepper: PEPPER, prefix: "sk", requireChecksum: true, limiter: new AttemptLimiter() });

// 1. Wrap a whole handler (Deno.serve(handler), Bun.serve({ fetch: handler }), export default { fetch: handler })
const handler = withApiKey(auth, async (req, record) => Response.json({ path: new URL(req.url).pathname, key: record?.name ?? null }), { exclude: ["/health"] });

// 2. Or authenticate inside your own routing
async function adminRoute(req: Request): Promise<Response> {
  try {
    const record = await authenticateRequest(auth, req, { scopes: ["admin"] });
    return Response.json({ admin: record.name });
  } catch (e) {
    if (e instanceof AuthError) return errorResponse(auth as APIKeyAuth<unknown>, e);
    throw e;
  }
}

console.log((await handler(new Request("https://x/items", { headers: { "X-API-Key": key } }))).status); // 200
console.log((await handler(new Request("https://x/health"))).status); // 200 (excluded, record = null)
console.log((await adminRoute(new Request("https://x/admin", { headers: { "X-API-Key": key } }))).status); // 403
```

### `@nuhmanpk/generateapikey/hono`

```ts
interface HonoOptions { scopes?: readonly string[]; exclude?: readonly string[]; key?: string /* "apiKey" */; client?: (c: Context) => string | null | undefined }
function apiKey<R>(auth: APIKeyAuth<R>, options?: HonoOptions): MiddlewareHandler;
```

The middleware reads the key from `c.req.raw` headers and the URL query, and stores the record with `c.set(key, record)`. Declare it in your `Variables` type so `c.get("apiKey")` is typed. `exclude` matches against `c.req.path`, the full path.

```ts
import { Hono } from "hono";
import { APIKeyAuth, KeyStore, MemoryKeyStorage, type KeyRecord } from "@nuhmanpk/generateapikey";
import { apiKey } from "@nuhmanpk/generateapikey/hono";

const PEPPER = "change-me-pepper";
const store = new KeyStore(new MemoryKeyStorage(), { pepper: PEPPER });
const auth = new APIKeyAuth<KeyRecord>({ lookup: store.lookup, pepper: PEPPER, prefix: "sk", requireChecksum: true });

const app = new Hono<{ Variables: { apiKey: KeyRecord } }>();
app.use("/api/*", apiKey(auth, { exclude: ["/api/health"] }));
app.get("/api/health", (c) => c.json({ ok: true }));
app.get("/api/items", (c) => c.json({ owner: c.get("apiKey").name }));
app.get("/api/admin", apiKey(auth, { scopes: ["admin"] }), (c) => c.json({ admin: true }));

const { key } = await store.create("hono-client", { prefix: "sk", scopes: ["read:*"] }); // (on Workers: inside a handler)
console.log(key);

export default app; // Bun / Deno / Cloudflare Workers; on Node use @hono/node-server
```

### `@nuhmanpk/generateapikey/express`

```ts
interface ExpressOptions { scopes?: readonly string[]; exclude?: readonly string[]; property?: string /* "apiKey" */; client?: (req) => string | null | undefined }
function apiKey<R>(auth: APIKeyAuth<R>, options?: ExpressOptions): (req, res, next) => void;
```

The middleware sets `req[property]` to the record, or responds with `res.status(…).json({ detail })`. `exclude` is matched against `req.path`, which is **relative to the mount point**: under `app.use("/api", …)`, write `exclude: ["/health"]` for `/api/health`.


```ts
import express from "express";
import { APIKeyAuth, KeyStore, type KeyRecord } from "@nuhmanpk/generateapikey";
import { apiKey } from "@nuhmanpk/generateapikey/express";

declare global {
  namespace Express {
    interface Request { apiKey?: KeyRecord }
  }
}

const PEPPER = "change-me-pepper";
const store = new KeyStore(undefined, { pepper: PEPPER });
const auth = new APIKeyAuth<KeyRecord>({ lookup: store.lookup, pepper: PEPPER, prefix: "sk", requireChecksum: true });
const requireKey = (scopes?: string[]) => apiKey(auth, { scopes, exclude: ["/health"] });

const app = express();
// app.set("trust proxy", 1); // only behind exactly one proxy that overwrites X-Forwarded-For
app.use("/api", requireKey());
app.get("/api/health", (_req, res) => void res.json({ ok: true }));
app.get("/api/items", (req, res) => void res.json({ owner: req.apiKey!.name }));
app.get("/api/admin", requireKey(["admin"]), (_req, res) => void res.json({ admin: true }));

const { key } = await store.create("express-client", { prefix: "sk" });
const server = app.listen(3000, () => console.log("listening on :3000", key));
```

### `@nuhmanpk/generateapikey/fastify`

```ts
interface FastifyOptions { scopes?: readonly string[]; exclude?: readonly string[]; property?: string /* "apiKey" */; client?: (req) => string | null | undefined }
const apiKeyPlugin: FastifyPlugin<FastifyOptions & { auth: APIKeyAuth<unknown> }>; // protects every route on the instance
function apiKey<R>(auth: APIKeyAuth<R>, options?: FastifyOptions): preHandlerHook; // one route
```

`apiKeyPlugin` adds a `preHandler` hook and decorates `request[property]` with `null`. It opts out of encapsulation, the same as `fastify-plugin` does, so registering it at the root protects **every** route. Register it inside a child plugin to protect only that scope. `exclude` is matched against the full URL path. On failure the reply is `{ detail }` with the status code.


```ts
import Fastify from "fastify";
import { APIKeyAuth, KeyStore, type KeyRecord } from "@nuhmanpk/generateapikey";
import { apiKey, apiKeyPlugin, type FastifyOptions } from "@nuhmanpk/generateapikey/fastify";

declare module "fastify" {
  interface FastifyRequest { apiKey: KeyRecord | null }
}

const PEPPER = "change-me-pepper";
const store = new KeyStore(undefined, { pepper: PEPPER });
const auth = new APIKeyAuth<KeyRecord>({ lookup: store.lookup, pepper: PEPPER, prefix: "sk", requireChecksum: true });

const app = Fastify(); // Fastify({ trustProxy: … }) only behind a proxy you control
await app.register(apiKeyPlugin, { auth, exclude: ["/health"] });
app.get("/health", async () => ({ ok: true }));
app.get("/items", async (req) => ({ owner: req.apiKey!.name }));
app.get("/admin", { preHandler: apiKey(auth, { scopes: ["admin"] }) }, async () => ({ admin: true }));

const { key } = await store.create("fastify-client", { prefix: "sk" });
await app.listen({ port: 3000 });
console.log("listening on :3000", key);
```

### `@nuhmanpk/generateapikey/koa`

```ts
interface KoaOptions { scopes?: readonly string[]; exclude?: readonly string[]; key?: string /* "apiKey" */; client?: (ctx) => string | null | undefined }
function apiKey<R>(auth: APIKeyAuth<R>, options?: KoaOptions): Koa.Middleware;
```

The middleware sets `ctx.state[key]` to the record, or sets `ctx.status` and `ctx.body = { detail }`. Koa has no built-in router, so use `exclude` for public paths and per-route middleware (for example, with `@koa/router`) for scopes.

```ts
import Koa from "koa";
import { APIKeyAuth, KeyStore, type KeyRecord } from "@nuhmanpk/generateapikey";
import { apiKey } from "@nuhmanpk/generateapikey/koa";

const PEPPER = "change-me-pepper";
const store = new KeyStore(undefined, { pepper: PEPPER });
const auth = new APIKeyAuth<KeyRecord>({ lookup: store.lookup, pepper: PEPPER, prefix: "sk", requireChecksum: true });

const app = new Koa(); // app.proxy = true only behind a proxy that overwrites X-Forwarded-For
app.use(apiKey(auth, { exclude: ["/health"] }));
app.use((ctx) => {
  const record = ctx.state.apiKey as KeyRecord | undefined;
  ctx.body = ctx.path === "/health" ? { ok: true } : { owner: record!.name };
});

const { key } = await store.create("koa-client", { prefix: "sk" });
const server = app.listen(3000, () => console.log("listening on :3000", key));
```

### `@nuhmanpk/generateapikey/next`

```ts
interface NextOptions extends WebOptions { forwardHeader?: string | false /* "x-api-key-id" */ }
function apiKeyMiddleware<R>(auth: APIKeyAuth<R>, options?: NextOptions): (req: Request) => Promise<Response>;
function withApiKey<R, A extends unknown[]>(auth: APIKeyAuth<R>, handler: (req: Request, record: R, ...rest: A) => Response | Promise<Response>, options?: WebOptions): (req: Request, ...rest: A) => Promise<Response>;
function vercelClient(req: Request): string | null; // X-Real-IP ?? first X-Forwarded-For hop
```

- **`apiKeyMiddleware`** is for `middleware.ts`, and runs on the Edge runtime. Bad keys get 401/403/429. Otherwise the request continues (`x-middleware-next`), and the record's `id` is forwarded to your route handlers as the request header `x-api-key-id`. The incoming value of that header is always stripped, so clients can't forge it. Pass `forwardHeader: false` to disable forwarding.
- **`withApiKey`** wraps an App Router route handler. The handler receives the record directly, typed as non-null (route handlers don't take `exclude`; use the middleware for public paths). Any extra arguments, such as `{ params }`, are passed through.

```ts
// lib/auth.ts
import { APIKeyAuth, KeyStore, MemoryKeyStorage, type KeyRecord } from "@nuhmanpk/generateapikey";

const PEPPER = process.env.API_KEY_PEPPER ?? "change-me-pepper";
export const store = new KeyStore(new MemoryKeyStorage(), { pepper: PEPPER }); // use SqlKeyStorage / your DB in production
export const auth = new APIKeyAuth<KeyRecord>({ lookup: store.lookup, pepper: PEPPER, prefix: "sk", requireChecksum: true });
```

```ts
// middleware.ts
import { apiKeyMiddleware } from "@nuhmanpk/generateapikey/next";
import { auth } from "./lib/auth";

export const middleware = apiKeyMiddleware(auth, { exclude: ["/api/health"] });
export const config = { matcher: "/api/:path*" };
```

```ts
// app/api/items/route.ts
import { withApiKey } from "@nuhmanpk/generateapikey/next";
import { auth } from "../../../lib/auth";

export const GET = withApiKey(auth, async (_req, record) => Response.json({ owner: record.name, scopes: record.scopes }));
export const DELETE = withApiKey(auth, async () => new Response(null, { status: 204 }), { scopes: ["admin"] });
// Behind apiKeyMiddleware, a plain handler can also read req.headers.get("x-api-key-id").
```

---

## 9. MFA

All TOTP/HOTP code follows RFC 4226 and RFC 6238, and the code passes the RFC test vectors. A secret (`OtpSecret`) is a base32 string, as shown to users (spaces, `-`, lower case and `=` padding are tolerated), or the raw bytes as a `Uint8Array`. It must decode to at least 10 bytes (80 bits). Otherwise `RangeError` is thrown: `"secret must be at least 10 bytes (80 bits)."` or `"secret must be a base32 string."`.

```ts
type OtpSecret = string | Uint8Array;
type OtpAlgorithm = "sha1" | "sha256" | "sha512";
interface HotpOptions { digits?: number /* 6, range 6-8 */; algorithm?: OtpAlgorithm /* "sha1" */ }
interface TotpOptions extends HotpOptions { period?: number /* 30 seconds */ }
interface VerifyTotpOptions extends TotpOptions { window?: number /* 1 */; at?: number | null /* unix seconds */; lastUsedStep?: number | null }
```

A bad `digits`, `algorithm` or `period` throws `RangeError` from every function that takes them.

### TOTP (authenticator apps)

```ts
function generateTotpSecret(numBytes?: number /* 20; min 10 */): string; // sync, base32 without padding
function totpUri(secret: string, account: string, issuer?: string | null, options?: TotpOptions & { image?: string | null }): string; // sync
function totp(secret: OtpSecret, at?: number | null, options?: TotpOptions): Promise<string>; // at = unix seconds, default now
function totpNow(secret: OtpSecret, options?: TotpOptions): Promise<string>;
function verifyTotp(secret: OtpSecret, code: unknown, options?: VerifyTotpOptions): Promise<boolean>;
function findTotpStep(secret: OtpSecret, code: unknown, options?: VerifyTotpOptions): Promise<number | null>;
```

- `totpUri` builds the `otpauth://totp/Issuer:account?secret=…&issuer=…` URI to render as a QR code. Non-default `algorithm`, `digits` and `period` are included in the URI, and so is `image`. The output is byte-identical to Python's `totp_uri`. Throws `RangeError` if `account` is empty, if `account` or `issuer` contains `:`, or if the secret is invalid.
- `verifyTotp` / `findTotpStep` accept codes within `window` steps either side of now, to allow for clock drift. They accept strings, with spaces and `-` ignored, or non-negative integers, which are zero-padded. Anything else returns `false`/`null` and never throws. Every candidate step is checked, with no early exit.
- **Replay protection:** `findTotpStep` returns the matched time step. Store it, and pass it back as `lastUsedStep`; that step and all earlier ones are then rejected.

```ts
import { findTotpStep, generateTotpSecret, totp, totpUri, verifyTotp } from "@nuhmanpk/generateapikey";

// Enrolment
const secret = generateTotpSecret(); // store encrypted (SecretBox), never in plain text
const uri = totpUri(secret, "alice@example.com", "Acme");
console.log(uri); // otpauth://totp/Acme:alice@example.com?secret=…&issuer=Acme  (render with @nuhmanpk/generateapikey/qr)

// Verification with replay protection
const code = await totp(secret); // what the user's app shows right now
let lastUsedStep: number | null = null; // persisted per user

const step = await findTotpStep(secret, code, { lastUsedStep });
console.log(step !== null); // true: accept, then save `step` as lastUsedStep
lastUsedStep = step;
console.log(await findTotpStep(secret, code, { lastUsedStep })); // null: same code replayed

console.log(await verifyTotp(secret, "000000")); // false (almost certainly)
console.log(await totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59, { digits: 8 })); // "94287082" (RFC 6238 vector)
```

> **Security.** Rate-limit every verification with [`AttemptLimiter`](#attemptlimiter-and-redisattemptlimiter): a 6-digit code has only 1,000,000 values. Encrypt TOTP secrets at rest with [`SecretBox`](#12-secretbox-encryption-at-rest).

### HOTP (counter based)

```ts
function hotp(secret: OtpSecret, counter: number | bigint, options?: HotpOptions): Promise<string>;
function verifyHotp(secret: OtpSecret, code: unknown, counter: number, options?: HotpOptions & { lookAhead?: number /* 0 */ }): Promise<number | null>;
function hotpUri(secret: string, account: string, issuer?: string | null, options?: HotpOptions & { counter?: number /* 0 */ }): string;
```

`verifyHotp` checks `counter … counter + lookAhead` and returns the **next counter to store** (the matched counter + 1), or `null`. A negative or non-integer counter throws `RangeError`.

```ts
import { generateTotpSecret, hotp, hotpUri, verifyHotp } from "@nuhmanpk/generateapikey";

const raw = new TextEncoder().encode("12345678901234567890"); // RFC 4226 test secret
console.log(await hotp(raw, 0), await hotp(raw, 1)); // "755224" "287082"

const secret = generateTotpSecret();
let counter = 0; // persisted per device
const next = await verifyHotp(secret, await hotp(secret, 2), counter, { lookAhead: 5 });
console.log(next); // 3: store it as the new counter
if (next !== null) counter = next;
console.log(hotpUri(secret, "alice@example.com", "Acme").startsWith("otpauth://hotp/Acme:alice@example.com?secret=")); // true
```

### Steam Guard codes

```ts
function steamCode(secret: OtpSecret, at?: number | null): Promise<string>; // 5 chars, HMAC-SHA1, 30 s steps
function verifySteamCode(secret: OtpSecret, code: unknown, options?: { window?: number /* 1 */; at?: number | null }): Promise<boolean>;
```

```ts
import { generateTotpSecret, steamCode, verifySteamCode } from "@nuhmanpk/generateapikey";

const secret = generateTotpSecret();
const code = await steamCode(secret); // e.g. "5CP98", alphabet 23456789BCDFGHJKMNPQRTVWXY
console.log(await verifySteamCode(secret, code.toLowerCase())); // true (case-insensitive)
```

### Google Authenticator migration URI

```ts
interface MigrationAccount { secret: string; name: string; issuer?: string; digits?: 6 | 8; algorithm?: OtpAlgorithm }
function googleMigrationUri(accounts: Iterable<MigrationAccount>): string; // sync
```

This builds an `otpauth-migration://offline?data=…` URI that Google Authenticator imports as a QR code, for bulk transfer of several accounts. Throws `RangeError` for an empty list, `digits` other than 6 or 8, or an unknown algorithm. **The URI contains the secrets**, so treat it like the secrets themselves.

```ts
import { generateTotpSecret, googleMigrationUri } from "@nuhmanpk/generateapikey";

const uri = googleMigrationUri([
  { secret: generateTotpSecret(), name: "alice@example.com", issuer: "Acme" },
  { secret: generateTotpSecret(), name: "alice@example.com", issuer: "Acme Staging", digits: 8, algorithm: "sha256" },
]);
console.log(uri.startsWith("otpauth-migration://offline?data=")); // true
```

### Recovery codes

```ts
const RECOVERY_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32: no I, L, O, U
function generateRecoveryCodes(count?: number /* 10 */, length?: number /* 10, min 8 */, group?: number /* 5; 0 = no dashes */): string[]; // sync
function normalizeRecoveryCode(code: string): string; // sync
function hashRecoveryCode(code: string, pepper?: string | null): Promise<string>;
function verifyRecoveryCode(code: unknown, hashes: Iterable<string>, pepper?: string | null): Promise<string | null>;
```

- `generateRecoveryCodes` returns distinct codes like `7KQ2M-9XPAB` (50 bits each by default). Throws `RangeError` if `count < 1` or `length < 8`.
- `normalizeRecoveryCode` upper-cases, removes spaces and `-`, and maps the lookalikes `O→0`, `I→1`, `L→1`. It throws `TypeError` for non-ASCII input or input over 64 characters. `hashRecoveryCode` normalizes first, then salted-PBKDF2-hashes the result.
- `verifyRecoveryCode` normalizes the input and checks it against **every** stored hash. It returns the matching hash, which you should **delete** so the code is single-use, or `null`. It never throws for bad input.

```ts
import { generateRecoveryCodes, hashRecoveryCode, verifyRecoveryCode } from "@nuhmanpk/generateapikey";

const codes = generateRecoveryCodes(); // show once, let the user download them
const stored = await Promise.all(codes.map((c) => hashRecoveryCode(c)));

const typed = codes[3]!.toLowerCase().replace("-", " "); // users type sloppily
const matched = await verifyRecoveryCode(typed, stored);
console.log(matched === stored[3]); // true: now delete stored[3]
console.log(await verifyRecoveryCode("AAAAA-AAAAA", stored)); // null
```

### One-time codes for email and SMS

```ts
function generateOtp(digits?: number /* 6, range 4-12 */, expiry?: number | null /* 10 minutes; null = none */, options?: { charset?: string /* "0123456789" */ }): ApiKey; // sync
function hashOtp(code: string | ApiKey, pepper?: string | null): Promise<string>;
function verifyOtp(code: unknown, hashed: string, expiresAt?: number | null, options?: { pepper?: string | null }): Promise<boolean>;
```

`generateOtp` returns an `ApiKey` with `value` and `expiresAt` (unix seconds). It throws `RangeError` for out-of-range `digits` or a non-positive `expiry`. `hashOtp` throws `TypeError` for non-ASCII codes. `verifyOtp` returns `false` once `expiresAt` has passed, and for malformed input.

```ts
import { AttemptLimiter, generateOtp, hashOtp, verifyOtp } from "@nuhmanpk/generateapikey";

const PEPPER = "change-me-pepper";
const otp = generateOtp(); // email otp.value to the user
const row = { hashed: await hashOtp(otp, PEPPER), expiresAt: otp.expiresAt };

const limiter = new AttemptLimiter({ maxAttempts: 5, window: 600 });
const userInput = ` ${otp.value.slice(0, 3)}-${otp.value.slice(3)} `; // spaces and dashes are ignored
if (!limiter.hit("otp:alice@example.com")) throw new Error("too many attempts");
console.log(await verifyOtp(userInput, row.hashed, row.expiresAt, { pepper: PEPPER })); // true
```

> **Security.** Short codes are only safe together with an attempt limit and a short expiry. Delete the stored hash after a successful verification.

### `AttemptLimiter` and `RedisAttemptLimiter`

```ts
class AttemptLimiter { // in memory, one process or isolate; all methods sync
  constructor(options?: { maxAttempts?: number /* 5 */; window?: number /* 900 seconds */; maxKeys?: number /* 100_000 */ });
  hit(key: string): boolean; // check-and-count; false = over the limit (attempt not counted)
  fail(key: string): number; // count a failure; returns attempts left
  isBlocked(key: string): boolean;
  remaining(key: string): number;
  reset(key: string): void; // e.g. after a successful login
}
class RedisAttemptLimiter { // same methods, all async; atomic Lua script
  constructor(client: RedisLike, options?: { maxAttempts?: number /* 5 */; window?: number /* 900 s */; prefix?: string /* "gak:attempts:" */ });
  redisKey(key: string): Promise<string>; // prefix + sha256 hex of key
}
interface RedisLike {
  eval(script: string, keys: string[], args: (string | number)[]): Promise<unknown>;
  get(key: string): Promise<string | number | null | undefined>;
  del(key: string): Promise<unknown>;
}
const REDIS_LIMITER_SCRIPT: string;
```

The window is fixed and starts at the first attempt. Call `hit` **before** verifying a code: it atomically checks and counts. Use `fail` plus `isBlocked` when only failures should count; `APIKeyAuth` does it that way. The constructors throw `RangeError` for non-positive values. `AttemptLimiter` memory is bounded by `maxKeys`, and the oldest entries are evicted first.

`RedisAttemptLimiter` uses the **same Lua script, key layout (`gak:attempts:<sha256 hex>`) and window units** as the Python `RedisAttemptLimiter`, so Python and JS processes share counters. It talks to Redis through the three-method `RedisLike` interface; wrap your client as shown below.

```ts
import { AttemptLimiter } from "@nuhmanpk/generateapikey";

const limiter = new AttemptLimiter({ maxAttempts: 3, window: 60 });
console.log(limiter.hit("login:alice"), limiter.hit("login:alice"), limiter.hit("login:alice")); // true true true
console.log(limiter.hit("login:alice"), limiter.isBlocked("login:alice"), limiter.remaining("login:alice")); // false true 0
limiter.reset("login:alice");
console.log(limiter.fail("login:bob")); // 2 attempts left
```

**ioredis**

```ts
import { Redis } from "ioredis";
import { RedisAttemptLimiter } from "@nuhmanpk/generateapikey";

const redis = new Redis(process.env.REDIS_URL ?? "redis://127.0.0.1:6379");
const limiter = new RedisAttemptLimiter(
  {
    eval: (script, keys, args) => redis.eval(script, keys.length, ...keys, ...args),
    get: (key) => redis.get(key),
    del: (key) => redis.del(key),
  },
  { maxAttempts: 5, window: 900 },
);

console.log(await limiter.hit("otp:alice"), await limiter.remaining("otp:alice")); // true 4
await limiter.reset("otp:alice");
redis.disconnect();
```

**node-redis (`redis` v4+)**: arguments must be strings, so map them with `String`.

```ts
import { createClient } from "redis";
import { RedisAttemptLimiter } from "@nuhmanpk/generateapikey";

const redis = await createClient({ url: process.env.REDIS_URL ?? "redis://127.0.0.1:6379" }).connect();
const limiter = new RedisAttemptLimiter({
  eval: (script, keys, args) => redis.eval(script, { keys, arguments: args }),
  get: (key) => redis.get(key),
  del: (key) => redis.del(key),
});

console.log(await limiter.fail("login:bob")); // 4
await limiter.reset("login:bob");
await redis.quit();
```

**Upstash (`@upstash/redis`, HTTP, works on edge runtimes)**

```ts
import { Redis } from "@upstash/redis";
import { RedisAttemptLimiter } from "@nuhmanpk/generateapikey";

const redis = Redis.fromEnv(); // UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
const limiter = new RedisAttemptLimiter({
  eval: (script, keys, args) => redis.eval(script, keys, args),
  get: (key) => redis.get<string | number>(key),
  del: (key) => redis.del(key),
});

console.log(await limiter.hit("otp:carol")); // true
await limiter.reset("otp:carol");
```

---

## 10. Signed tokens

Short-lived, URL-safe, HMAC-signed tokens for magic links, email verification and password resets. The format is `<base64url(JSON)>.<base64url(HMAC-SHA256)>`, signed with `subkey(secret, "token")`. **The payload is readable, not encrypted**, so don't put secrets in it.

```ts
const MIN_SECRET_LENGTH = 16;
interface SignedTokenOptions {
  purpose?: string; // "default"; binds the token to one flow ("login", "reset"…)
  expiry?: number | null; // minutes, default 15; null = never expires
  context?: string | null; // signed but NOT stored: the token only verifies when the same context is presented
}
function generateSignedToken(secret: string, data?: Record<string, unknown> | null, options?: SignedTokenOptions): Promise<string>;
function verifySignedToken<T>(token: unknown, secret: string, options?: { purpose?: string; context?: string | null; withMeta?: false }): Promise<T | null>;
function verifySignedToken<T>(token: unknown, secret: string, options: { purpose?: string; context?: string | null; withMeta: true }): Promise<TokenMeta<T> | null>;
interface TokenMeta<T> { data: T; jti: unknown; exp: number | null }
```

- `secret` must have at least 16 characters, otherwise both functions throw `RangeError`. `generateSignedToken` also throws `RangeError` for a bad `expiry` and `TypeError` for a non-string `purpose` or `context`.
- `verifySignedToken` returns `null` for a bad signature, purpose, context or expiry, or a malformed token (non-ASCII, or longer than 8192 characters). It never throws for those.
- Each token carries a random `jti`. For single-use links, verify `withMeta: true` and store used `jti`s until `exp`.
- Python and JS tokens verify in both directions.

```ts
import { generateSignedToken, verifySignedToken } from "@nuhmanpk/generateapikey";

const SECRET = "change-me-token-secret-0123456789";

const token = await generateSignedToken(SECRET, { uid: 42 }, { purpose: "login", expiry: 15, context: "session-abc" });
// https://app.example.com/magic?token=<token>

console.log(await verifySignedToken(token, SECRET, { purpose: "login", context: "session-abc" })); // { uid: 42 }
console.log(await verifySignedToken(token, SECRET, { purpose: "reset", context: "session-abc" })); // null (wrong purpose)
console.log(await verifySignedToken(token, SECRET, { purpose: "login" })); // null (context missing)

const meta = await verifySignedToken<{ uid: number }>(token, SECRET, { purpose: "login", context: "session-abc", withMeta: true });
console.log(meta?.data.uid, typeof meta?.jti, meta!.exp! > Date.now() / 1000); // 42 "string" true
```

> **Security.** Use `context`, for example a session id or a device cookie, so that a leaked link, from email forwarding or proxy logs, is useless on another device.

---

## 11. JWT

Standard RFC 7519 JWTs, readable by any JWT library. `alg: none` is never produced or accepted.

```ts
type HsAlg = "HS256" | "HS384" | "HS512";
type AsymAlg = "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" | "ES256" | "ES384" | "ES512" | "EdDSA";
type JwtAlgorithm = HsAlg | AsymAlg;
type AsymKey = string /* PEM */ | JsonWebKey | CryptoKey;

interface EncodeJwtOptions {
  algorithm?: JwtAlgorithm; // "HS256"
  expiry?: number | null; // minutes until exp, default 15; null = no exp
  issuer?: string | null; audience?: string | null;
  headers?: Record<string, unknown>; // extra header fields such as kid (alg/typ are always set by the library)
}
interface DecodeJwtOptions {
  algorithms?: readonly JwtAlgorithm[]; // pinned by YOU; default ["HS256"] (decodeJwtJwks: ["RS256"])
  issuer?: string | null; audience?: string | null; // aud may be a string or an array containing it
  leeway?: number; // seconds of clock skew for exp/nbf, default 0
  requireExp?: boolean; // default true
}
interface Jwks { keys: JsonWebKey[] }

function encodeJwt(claims: Record<string, unknown>, secret: string | AsymKey, options?: EncodeJwtOptions): Promise<string>;
function decodeJwt<T>(token: unknown, secret: string | AsymKey, options?: DecodeJwtOptions): Promise<T | null>;
function decodeJwtJwks<T>(token: unknown, jwks: Jwks, options?: DecodeJwtOptions): Promise<T | null>;
```

- `encodeJwt` adds `iat`, `exp`, `iss` and `aud`, unless they are already in `claims`.
- `decodeJwt` returns the claims, or `null` for any invalid token: bad signature, an `alg` not in `algorithms`, an expired token, a token used before `nbf`, a wrong `iss`/`aud`, a missing `exp` (unless `requireExp: false`), or a malformed token. It **throws only for programmer errors**: an empty or unknown `algorithms` list, or a plain string instead of an array (`RangeError`); a mix of HS and asymmetric algorithms in one call (`RangeError`, to protect against algorithm confusion); an HS secret shorter than 16 characters (`RangeError`); a key of the wrong type or curve for the algorithm (`RangeError`); or a runtime that can't import that key type (`Error`).
- **HS256/384/512** take a shared secret string of at least 16 characters.
- **RS\*** (RSASSA-PKCS1-v1_5), **PS\*** (RSA-PSS, salt = hash length), **ES256/384/512** (P-256/P-384/P-521, raw `r‖s` signatures) and **EdDSA** (Ed25519) take an asymmetric key. RSA keys must be at least 2048 bits.

**Accepted asymmetric key inputs** (the same PEM files Python's `cryptography` loads):

| Input | Sign (private) | Verify (public) |
|---|---|---|
| PEM PKCS#8 (label `PRIVATE KEY`) | yes | yes (its public half is used) |
| PEM SPKI (label `PUBLIC KEY`) | — | yes |
| PEM PKCS#1 (label `RSA PRIVATE KEY`) | yes | yes |
| PEM PKCS#1 (label `RSA PUBLIC KEY`) | — | yes |
| PEM SEC1 (label `EC PRIVATE KEY`) (e.g. `openssl ecparam -genkey`) | yes | yes |
| JWK object (`kty` RSA / EC / OKP-Ed25519; `d` required for signing) | yes | yes (private fields are dropped) |
| Web Crypto `CryptoKey` | yes, if imported for that algorithm with usage `sign` | yes, with usage `verify` |

A PEM or JWK of the wrong type or curve throws `RangeError`, for example `"ES384 requires a secp384r1 key."`. A public key passed for signing throws `RangeError("signing needs a private key.")`. `CryptoKey`s are used as given: make sure they were imported or generated for the same algorithm.

```ts
import { decodeJwt, encodeJwt } from "@nuhmanpk/generateapikey";

const SECRET = "change-me-jwt-secret-0123456789";
const token = await encodeJwt({ sub: "user-42", role: "admin" }, SECRET, { issuer: "auth.example.com", audience: "api", expiry: 60 });

console.log(await decodeJwt(token, SECRET, { issuer: "auth.example.com", audience: "api" })); // { sub, role, iat, exp, iss, aud }
console.log(await decodeJwt(token, SECRET, { audience: "other" })); // null
console.log(await decodeJwt(token, SECRET, { algorithms: ["HS512"] })); // null (alg pinned)
```

Asymmetric keys, in PEM, JWK and `CryptoKey` form:

```ts
import { readFileSync } from "node:fs";
import { decodeJwt, decodeJwtJwks, encodeJwt } from "@nuhmanpk/generateapikey";

// PEM files, e.g. from `openssl ecparam -name prime256v1 -genkey -noout -out ec-private.pem`
// and `openssl ec -in ec-private.pem -pubout -out ec-public.pem`
const privatePem = readFileSync("ec-private.pem", "utf8"); // SEC1 "EC PRIVATE KEY"
const publicPem = readFileSync("ec-public.pem", "utf8"); // SPKI "PUBLIC KEY"
const es = await encodeJwt({ sub: "svc-a" }, privatePem, { algorithm: "ES256", headers: { kid: "2026-01" } });
console.log((await decodeJwt(es, publicPem, { algorithms: ["ES256"] }))?.sub); // "svc-a"

// CryptoKey and JWK (Ed25519)
const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
const ed = await encodeJwt({ sub: "svc-b" }, pair.privateKey, { algorithm: "EdDSA", headers: { kid: "ed-1" } });
const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
console.log((await decodeJwt(ed, publicJwk, { algorithms: ["EdDSA"] }))?.sub); // "svc-b"

// JWKS: the token's kid only *selects* among keys you trust; the algorithm stays pinned
const jwks = { keys: [{ ...publicJwk, kid: "ed-1" }] };
console.log((await decodeJwtJwks(ed, jwks, { algorithms: ["EdDSA"] }))?.sub); // "svc-b"
```

`decodeJwtJwks` picks keys by the header `kid` (all keys if the token has none). It skips keys whose type doesn't fit the token's `alg`, as well as keys that fail to import, and returns the first set of claims that verifies, or `null`. It throws `RangeError` if `algorithms` is empty or starts with an HS algorithm. Fetching and caching the JWKS document is up to you, for example `await (await fetch(jwksUrl)).json()`.

---

## 12. SecretBox (encryption at rest)

AES-256-GCM with key rotation. Use it for secrets you must be able to read back, such as TOTP secrets and webhook signing secrets. Ciphertexts look like `v1.<keyId>.<b64url(nonce‖ciphertext‖tag)>` and decrypt in both JS and Python.

```ts
function generateEncryptionKey(): string; // 32 random bytes, base64url (store in env / a secret manager)
class SecretBox {
  static create(key: string, oldKeys?: readonly string[]): Promise<SecretBox>; // async: imports the keys
  get keyId(): string; // 8-char id of the current key, embedded in ciphertexts
  encrypt(plaintext: string, aad?: string | null): Promise<string>;
  decrypt(token: string, aad?: string | null): Promise<string>; // throws DecryptionError
  needsRotation(token: unknown): boolean; // encrypted with an old key?
  rotate(token: string, aad?: string | null): Promise<string>; // re-encrypt under the current key (no-op if current)
}
class DecryptionError extends Error {}
```

- The constructor is private. Use **`await SecretBox.create(key, oldKeys)`**, because Web Crypto key import is async. `key` encrypts and decrypts; `oldKeys` only decrypt.
- `create` throws `RangeError` for a key that isn't 32 bytes of base64url, and `TypeError` if `oldKeys` is a string instead of an array. `encrypt` throws `TypeError` for a non-string plaintext or `aad`.
- `decrypt` throws `DecryptionError` for a malformed or tampered ciphertext, a mismatched `aad`, or a key that is not loaded ("no key for this ciphertext (was it rotated out?)").
- `aad` (associated data) binds a ciphertext to a context, such as the user id, so a ciphertext can't be copied onto another user's row. No `aad` and `""` are equivalent.
- `String(box)` and `console.log(box)` never show key material.

```ts
import { DecryptionError, SecretBox, generateEncryptionKey, generateTotpSecret } from "@nuhmanpk/generateapikey";

const oldKey = generateEncryptionKey(); // normally: process.env.ENCRYPTION_KEY_OLD
const newKey = generateEncryptionKey(); // normally: process.env.ENCRYPTION_KEY

const before = await SecretBox.create(oldKey);
const stored = await before.encrypt(generateTotpSecret(), "user-42");

const box = await SecretBox.create(newKey, [oldKey]); // after rotating keys
const secret = await box.decrypt(stored, "user-42"); // still readable
console.log(secret.length, box.needsRotation(stored)); // 32 true
const migrated = await box.rotate(stored, "user-42"); // write back to the row
console.log(box.needsRotation(migrated), String(box)); // false "SecretBox(keyId='…', keys=2)"

try {
  await box.decrypt(migrated, "user-43");
} catch (e) {
  console.log(e instanceof DecryptionError); // true (aad mismatch)
}
```

---

## 13. QR codes

`@nuhmanpk/generateapikey/qr` is a zero-dependency QR encoder: error correction level M, smallest fitting version, a 2-module quiet zone. Its output is identical to the Python package's `qr` module, which uses the `qrcode` library. All functions are synchronous and use only `Uint8Array` and `TextEncoder`, so they run in browsers and on edge runtimes.

```ts
function qrMatrix(data: string): boolean[][]; // [row][col], true = dark, includes the border
function qrAscii(data: string, options?: { invert?: boolean }): string; // half-block characters for terminals
function qrSvg(data: string): string; // standalone SVG document; safe to inline in HTML
function qrPng(data: string, options?: { scale?: number /* 10 px per module */ }): Uint8Array; // PNG bytes (uncompressed, 1-bit)
```

Throws `RangeError` if the data doesn't fit in a version-40 code, or if `scale` is not a positive integer.

```ts
import { writeFileSync } from "node:fs";
import { generateTotpSecret, totpUri } from "@nuhmanpk/generateapikey";
import { qrAscii, qrMatrix, qrPng, qrSvg } from "@nuhmanpk/generateapikey/qr";

const uri = totpUri(generateTotpSecret(), "alice@example.com", "Acme");

console.log(qrAscii(uri)); // scan from the terminal
const svg = qrSvg(uri); // <img src={`data:image/svg+xml;utf8,${encodeURIComponent(svg)}`}> or inline it
writeFileSync("totp.png", qrPng(uri, { scale: 8 }));
console.log(qrMatrix(uri).length, svg.startsWith("<?xml")); // 41 true (37 modules + 2×2 border)
```

In a browser, `new Blob([qrPng(uri)], { type: "image/png" })` plus `URL.createObjectURL` gives you an `<img>` source. Never send TOTP setup QR codes to third-party QR services: the URI contains the secret.

---

## 14. CLI

The package installs two binaries, `generateapikey` and `generate-api-key` (so after a global install both commands work; `npx @nuhmanpk/generateapikey` runs `generateapikey`). They need Node.js 20 or later. The commands and flags are the same as the Python CLI's.

```sh
npx @nuhmanpk/generateapikey                                  # one 32-char key
npx @nuhmanpk/generateapikey -n 5 -p sk --checksum            # five sk-… keys with checksums
npx @nuhmanpk/generateapikey -p sk --checksum --hash          # key<TAB>sha256$…  (store the hash)
npx @nuhmanpk/generateapikey --length 20 --charset hex --entropy   # 80.0
npx @nuhmanpk/generateapikey totp -a alice@example.com -i Acme --qr
```

### Keys (default command)

| Flag | Meaning |
|---|---|
| `-n`, `--count N` | Number of keys (default 1). Ignored for derived keys. |
| `-l`, `--length N` | Body length (default 32). |
| `-c`, `--charset NAME` | Preset name or literal characters (default `alphanumeric`). |
| `--case CASE` | `mixed` / `lower` / `upper`. |
| `-p`, `--prefix PREFIX` | Prefix, e.g. `sk`. |
| `--separator S` | Between prefix and body (default `-`). |
| `-d`, `--dashes` | Group the body with dashes. |
| `--dash-group N` | Group size (default 4). |
| `--checksum` | Append the 6-character checksum. |
| `--expiry MINUTES` | Expiry; adds `expires_at` to `--json` output. |
| `--secret S` | Derive deterministically from secret plus seed. `-` reads it from stdin. Without the flag, `$GENERATEAPIKEY_SECRET` is used when `--seed` is given. |
| `--seed S` | Seed for derived keys (both `--secret` and `--seed` are needed). |
| `--include S` | Extra context for derived keys (requires `--secret` and `--seed`). |
| `--hash` | Also print the storage hash (tab-separated, or `hash` in JSON). |
| `--pepper P` | Pepper for `--hash`. `-` reads it from stdin; defaults to `$GENERATEAPIKEY_PEPPER`. |
| `--json` | JSON output: one object for one key, an array for several. Fields: `key`, `expires_at`, `hash`. |
| `--entropy` | Print the entropy in bits for the given length, charset and case, then exit. |
| `--llms` | Print the bundled usage guide for AI coding agents, then exit. |
| `--agent-rules` | Print a snippet for `AGENTS.md` / `CLAUDE.md` / `.cursor/rules`, then exit. |
| `-V`, `--version` | Print `generate-api-key 0.6.0`. |
| `-h`, `--help` | Help. |

### MFA commands

| Command | Flags | Output |
|---|---|---|
| `totp` | `-a/--account` (required), `-i/--issuer`, `--digits` (6), `--period` (30), `--algorithm` (sha1), `--qr`, `--json` | New secret plus `otpauth://` URI. `--qr` also draws the QR code (to stderr with `--json`). |
| `code SECRET` | `--digits`, `--period`, `--algorithm`, `--json` | Current TOTP code and seconds left. `SECRET` may be `-` (stdin); if omitted, `$GENERATEAPIKEY_TOTP_SECRET` is used. |
| `recovery` | `-n/--count` (10), `-l/--length` (10), `--hash`, `--pepper`, `--json` | Recovery codes, optionally with hashes. |
| `otp` | `--digits` (6), `--expiry` (10), `--hash`, `--pepper`, `--json` | One-time code (JSON: `code`, `expires_at`, `hash`). |
| `token` | `-s/--secret`, `--purpose` (default), `--data JSON` ({}), `--expiry` (15), `--json` | Signed token. The secret comes from `--secret`, `-` (stdin) or `$GENERATEAPIKEY_SECRET`. |

`<command> -h` prints a short usage line. Unknown flags, or invalid values such as a missing secret or a charset that is too small, print `error: …` to stderr and exit with status **2**. Weak-key warnings go to stderr.

> **Security.** Secrets passed on the command line leak through `ps`, shell history and CI logs. Prefer the environment variables (`GENERATEAPIKEY_SECRET`, `GENERATEAPIKEY_PEPPER`, `GENERATEAPIKEY_TOTP_SECRET`) or `-` with stdin.

```sh
echo "change-me-derive-secret" | npx @nuhmanpk/generateapikey --secret - --seed user-42 --prefix dk --checksum
GENERATEAPIKEY_PEPPER=change-me-pepper npx @nuhmanpk/generateapikey -p sk --checksum --hash --json
GENERATEAPIKEY_SECRET=change-me-token-secret-0123 npx @nuhmanpk/generateapikey token --purpose login --data '{"uid":42}'
npx @nuhmanpk/generateapikey recovery -n 8 --hash
```

---

## 15. Units and differences from Python

### Units

| Quantity | Unit | Examples |
|---|---|---|
| Lifetimes you pass in | **minutes** | `expiry` (keys, OTPs, tokens, JWTs), `graceMinutes` |
| Timestamps you get back or store | **unix seconds** (integers) | `ApiKey.expiresAt`, `IssuedKey.expiresAt`, `Rotation.oldExpiresAt`, `KeyRecord.*At`, `TokenMeta.exp`, JWT `iat`/`exp`, DB columns |
| Time inputs to TOTP/Steam | unix **seconds** | `totp(secret, at)`, `{ at }` |
| Limiter `window`, JWT `leeway`, TOTP `period` | seconds | |
| `recordIsActive` numeric `expires_at` | unix seconds (`Date` objects are also accepted) | values above 10¹¹ are read as milliseconds |

### Differences from the Python package

- **Naming:** camelCase functions and options (`generate_api_key` becomes `generateApiKey`, `last_used_step` becomes `lastUsedStep`). Keyword arguments become an options object.
- **Async:** anything that uses `crypto.subtle` returns a Promise (see [Sync vs async](#sync-vs-async)). Python's sync/async pairs, such as `authenticate`/`aauthenticate` or `RedisAttemptLimiter`/`AsyncRedisAttemptLimiter`, collapse into one async API.
- **Random vs derived keys** are two functions. Python's `generate_api_key(secret=…, seed=…)` is `await deriveApiKey({ secret, seed })` in JS.
- **`ApiKey`** is not a `string` subclass (Python's is `str`). `generateApiKey` returns a plain `string` unless `expiry` is set. `generateApiKeys` returns `string[]`.
- **Weak keys:** Python emits `WeakKeyWarning`; JS calls `onWeakKey` or `console.warn`.
- **`expiry`:** a number of minutes only (Python also accepts `timedelta`).
- **`SecretBox`:** `await SecretBox.create(key, oldKeys)` instead of a constructor; `keyId` getter.
- **`KeyStore`:** takes a pluggable `KeyStorage` instead of a SQLite path. There is no `close()`; close your driver yourself. JS adds `find(rawKey)`. `rotate` throws `Error` where Python raises `KeyError`. `KeyRecord.scopes` is a sorted `string[]` (Python: `frozenset`), and `isKeyActive(record)` replaces the `is_active` property.
- **Records:** `recordIsActive` and the scope check read fields in **snake_case or camelCase** (`expires_at` / `expiresAt`, `is_active` / `isActive`, `revoked`, `scopes`), from plain objects or `Map`s.
- **Scopes:** `parseScopes` returns a `Set` (Python: `frozenset`).
- **Leak detection:** JS adds `keyRegExp`, which returns a JS `RegExp`. `keyPattern` returns the Python-syntax pattern string.
- **QR:** built in, with no optional dependency. JS adds `qrMatrix`.
- **JWT keys:** JS also accepts JWK objects and `CryptoKey`s directly.
- **Python-only:** the legacy `generateApiKey()` coroutine and `is_token_valid()` (deprecated in Python) have no JS equivalent. Python's base64url decoder is more lenient with malformed JWT signatures; JS decodes strictly ([spec §10](https://github.com/nuhmanpk/generate-api-key/blob/main/spec/SPEC.md#10-jwt-rfc-7519--must-match)).

### Python → JavaScript name mapping

| Python (`generateapikey…`) | JavaScript (`@nuhmanpk/generateapikey`) | Async in JS? |
|---|---|---|
| `generate_api_key(...)` | `generateApiKey(options)` | no |
| `generate_api_key(secret=, seed=, include=)` | `deriveApiKey({ secret, seed, include })` | yes |
| `generate_api_key_async(...)` | `generateApiKey` / `deriveApiKey` | — |
| `generate_api_keys(count, **o)` | `generateApiKeys(count, options)` | no |
| `generateApiKey(...)` (legacy) | — | — |
| `is_token_valid` (deprecated) | — | — |
| `ApiKey`, `.expires_at`, `.expires_in`, `.is_expired`, `.expires_at_datetime`, `.hash()` | `ApiKey`, `.expiresAt`, `.expiresIn`, `.isExpired`, `.expiresAtDate`, `.hash()` | `.hash()` yes |
| `is_expired` | `isExpired` | no |
| `WeakKeyWarning` | `onWeakKey` option | — |
| `__version__` | `VERSION` (also `SPEC_VERSION`) | — |
| `CHARSETS`, `CHECKSUM_LENGTH`, `RECOMMENDED_ENTROPY` | same names | — |
| `utils.build_charset` | `buildCharset` | no |
| `entropy_bits` | `entropyBits` | no |
| `utils.random_key` | `randomKey` | no |
| `utils.add_dashes` | `addDashes` | no |
| `utils.compute_checksum` | `computeChecksum` | no |
| `verify_checksum` | `verifyChecksum` | no |
| `utils.safe_equals` | `timingSafeEqual` | no |
| `utils.subkey` | `subkey` (returns `Uint8Array`) | yes |
| `hash_api_key` / `verify_api_key` | `hashApiKey` / `verifyApiKey` | yes |
| `utils.hash_code` / `utils.verify_code` / `utils.KDF_ITERATIONS` | `hashCode` / `verifyCode` / `KDF_ITERATIONS` | yes |
| — | `clearKeyCache` | no |
| `parse_scopes`, `has_scope`, `has_all_scopes`, `has_any_scope` | `parseScopes`, `hasScope`, `hasAllScopes`, `hasAnyScope` | no |
| `key_pattern` | `keyPattern` (+ `keyRegExp`) | no |
| `find_keys` | `findKeys` | no |
| `scanning.gitleaks_rule(prefix, rule_id, description=)` | `gitleaksRule(prefix, ruleId, { description })` | no |
| `mfa.generate_totp_secret(num_bytes)` | `generateTotpSecret(numBytes)` | no |
| `mfa.hotp` | `hotp` | yes |
| `mfa.totp`, `totp_now` | `totp`, `totpNow` | yes |
| `mfa.find_totp_step`, `verify_totp` | `findTotpStep`, `verifyTotp` | yes |
| `mfa.verify_hotp(look_ahead=)` | `verifyHotp({ lookAhead })` | yes |
| `totp_uri`, `mfa.hotp_uri` | `totpUri`, `hotpUri` | no |
| `steam_code`, `verify_steam_code` | `steamCode`, `verifySteamCode` | yes |
| `google_migration_uri` | `googleMigrationUri` | no |
| `generate_recovery_codes`, `mfa.normalize_recovery_code` | `generateRecoveryCodes`, `normalizeRecoveryCode` | no |
| `hash_recovery_code`, `verify_recovery_code` | `hashRecoveryCode`, `verifyRecoveryCode` | yes |
| `generate_otp` | `generateOtp` | no |
| `hash_otp`, `verify_otp` | `hashOtp`, `verifyOtp` | yes |
| `AttemptLimiter(max_attempts, window, max_keys)` `.hit/.fail/.is_blocked/.remaining/.reset` | `AttemptLimiter({ maxAttempts, window, maxKeys })` `.hit/.fail/.isBlocked/.remaining/.reset` | no |
| `limiters.RedisAttemptLimiter`, `limiters.AsyncRedisAttemptLimiter` | `RedisAttemptLimiter` (+ `REDIS_LIMITER_SCRIPT`) | yes |
| `generate_signed_token`, `verify_signed_token(with_meta=)` | `generateSignedToken`, `verifySignedToken({ withMeta })` | yes |
| `encode_jwt`, `decode_jwt(require_exp=)`, `decode_jwt_jwks` | `encodeJwt`, `decodeJwt({ requireExp })`, `decodeJwtJwks` | yes |
| `tokens.MIN_SECRET_LENGTH` | `MIN_SECRET_LENGTH` | — |
| `crypto.SecretBox(key, old_keys)` `.encrypt/.decrypt/.needs_rotation/.rotate` | `await SecretBox.create(key, oldKeys)` `.encrypt/.decrypt/.needsRotation/.rotate` | yes (`needsRotation` no) |
| `crypto.generate_encryption_key`, `crypto.DecryptionError` | `generateEncryptionKey`, `DecryptionError` | no |
| `qr.qr_ascii`, `qr.qr_svg`, `qr.qr_png` | `qrAscii`, `qrSvg`, `qrPng` (+ `qrMatrix`) from `@nuhmanpk/generateapikey/qr` | no |
| `integrations.APIKeyAuth(...)` `.extract/.authenticate/.aauthenticate/.challenge` | `APIKeyAuth({...})` `.extract/.authenticate/.challenge/.errorHeaders` | `authenticate` yes |
| `integrations.AuthError(status, detail)` | `AuthError` (`.status`, `.detail`) | — |
| `integrations.issue_api_key` / `IssuedKey` | `issueApiKey` / `IssuedKey` (+ `expiresAt`) | yes |
| `integrations.record_is_active`, `integrations.path_excluded`, `integrations.MAX_KEY_LENGTH` | `recordIsActive`, `pathExcluded`, `MAX_KEY_LENGTH` | no |
| (internal hint) | `keyHint` | no |
| `keystore.rotate_api_key(grace_minutes=)` / `Rotation` | `rotateApiKey({ graceMinutes })` / `Rotation` (+ `hint`, `expiresAt`) | yes |
| `keystore.KeyStore(path, pepper=, touch=)` | `new KeyStore(storage, { pepper, touch })` with `MemoryKeyStorage` / `SqlKeyStorage` | yes |
| `KeyStore.create/lookup/get/list(active_only=)/revoke/rotate(grace_minutes=)/close` | `create/lookup/find/get/list({ activeOnly })/revoke/rotate({ graceMinutes })` | yes |
| `keystore.KeyRecord`, `.is_active`, `keystore.Created` | `KeyRecord`, `isKeyActive(record)`, `CreatedKey` | no |
| (schema string) | `KEYSTORE_SCHEMA` | — |
| `integrations.fastapi` / `starlette` / `flask` / `django` / `drf` / `litestar` / `sanic` / `aiohttp` / `quart` / `falcon` | `@nuhmanpk/generateapikey/web`, `/hono`, `/express`, `/fastify`, `/koa`, `/next` | — |

---

## 16. Cross-language compatibility

The JS package implements wire-format **spec v1** (`SPEC_VERSION === 1`). The contract between the two packages is [spec/SPEC.md](https://github.com/nuhmanpk/generate-api-key/blob/main/spec/SPEC.md), with test vectors generated from the Python implementation ([spec/vectors.json](https://github.com/nuhmanpk/generate-api-key/blob/main/spec/vectors.json)) that both test suites run. Python is normative.

What this means in practice:

- **Byte-identical:** charsets, derived keys, checksums, `hashApiKey` hashes (with or without pepper), PBKDF2 code hashes, TOTP/HOTP/Steam codes, `otpauth://` URIs, Google migration payloads, scope rules, leak-detection patterns (`keyPattern`), JWT signatures, SecretBox ciphertext format, the `api_keys` table, `APIKeyAuth` behaviour (status codes, messages, headers) and Redis limiter keys and script.
- **Verify-compatible:** signed tokens. Freshly generated tokens may differ byte-for-byte because of JSON formatting, but tokens from either language verify in the other.
- **Not interoperable:** lone UTF-16 surrogates in keys or codes. JavaScript can't encode them the way Python's `surrogatepass` does.

So you can, for example, issue keys from a Python admin tool and authenticate them in a Hono app on Cloudflare Workers, share one `api_keys` table and one Redis limiter between services in both languages, or encrypt TOTP secrets in Node and decrypt them in Django. The Python API is documented in [docs/python.md](https://github.com/nuhmanpk/generate-api-key/blob/main/docs/python.md).

---

## 17. Errors reference

| Error | Thrown by | When |
|---|---|---|
| `RangeError` | key generation (`generateApiKey`, `generateApiKeys`, `deriveApiKey`, `issueApiKey`, `rotateApiKey`, `KeyStore#create`), `buildCharset`, `entropyBits`, `randomKey`, `addDashes` | Bad `length`, `count`, `case`, `dashGroup` or `expiry`; a charset with fewer than 2 distinct characters; `minEntropy` not met; missing `secret`/`seed`; negative `graceMinutes`; empty `name` |
| `RangeError` | `hashApiKey`, `verifyApiKey`, `hashCode`, `verifyCode`, `APIKeyAuth` constructor, … | `pepper` given but not a non-empty string; `iterations` not a positive integer |
| `RangeError` | MFA functions | A secret under 10 bytes or not valid base32; `digits`/`algorithm`/`period` out of range; negative counter; empty or `:`-containing account/issuer; bad recovery or OTP parameters; bad migration accounts; limiter options ≤ 0 |
| `RangeError` | `generateSignedToken`, `verifySignedToken`, `encodeJwt`, `decodeJwt`, `decodeJwtJwks` | Secret shorter than `MIN_SECRET_LENGTH` (16); bad `expiry`; bad/empty/mixed `algorithms`; wrong key type or curve; public key for signing; RSA key under 2048 bits; malformed PEM |
| `RangeError` | `SecretBox.create`, `SqlKeyStorage`, scanning functions, `qr*` | Encryption key not 32 bytes of base64url; non-identifier table name; empty prefix or invalid rule id; data too large for a QR code or bad `scale` |
| `TypeError` | `generateApiKey`, `APIKeyAuth`, `SecretBox`, tokens, OTP/recovery hashing, `buildCharset` | `secret`/`seed` passed to `generateApiKey`; non-numeric `expiry`; `lookup` not a function; `previousPeppers`/`requiredScopes`/`oldKeys` given as a string; non-string plaintext/aad/purpose/context; non-ASCII code to `hashOtp` or `normalizeRecoveryCode`; non-string charset |
| `AuthError` | `APIKeyAuth#authenticate`, `authenticateRequest` (the adapters convert it into a response) | `status` 401 `"Missing API key."` / `"Invalid API key."`, 403 `"Insufficient scope."`, 429 `"Too many invalid API keys. Try again later."` |
| `DecryptionError` | `SecretBox#decrypt`, `SecretBox#rotate` | Malformed or tampered ciphertext, wrong `aad`, or a key that is not loaded |
| `Error` | `KeyStore#rotate` | `"no active key with id …"` |
| `Error` | `MemoryKeyStorage#insert` | `"UNIQUE constraint failed: api_keys.hashed"` |
| `Error` | any crypto function | No Web Crypto in the runtime; the runtime refused PBKDF2 above 100,000 iterations (Cloudflare Workers); the runtime can't import a JWT key type |

Functions that check untrusted input **return `false`/`null` instead of throwing**: `verifyApiKey`, `verifyChecksum`, `verifyCode`, `verifyTotp`, `findTotpStep`, `verifyHotp`, `verifySteamCode`, `verifyRecoveryCode`, `verifyOtp`, `verifySignedToken`, `decodeJwt`, `decodeJwtJwks`, `timingSafeEqual`, `findKeys`, `recordIsActive`. They only throw for programmer errors such as a bad pepper, a short secret, or bad options.
