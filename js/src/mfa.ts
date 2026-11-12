/**
 * Multi-factor authentication (spec §5-§6): TOTP/HOTP (RFC 6238/4226), Steam
 * Guard codes, otpauth URIs, Google Authenticator migration, recovery codes,
 * email/SMS one-time codes and an in-memory attempt limiter.
 */

import { alphabet } from "./charsets.js";
import { b32decodePadded, b32encode, b64std, be64, concat, isAscii, safeEquals, toHex, utf8 } from "./internal/bytes.js";
import { type Hash, digest, hmac, hmacKey, randomBytes } from "./internal/webcrypto.js";
import { ApiKey, addDashes, hashCode, randomKey, verifyCode } from "./keys.js";

export type OtpAlgorithm = "sha1" | "sha256" | "sha512";
const ALGORITHMS: Record<string, Hash> = { sha1: "SHA-1", sha256: "SHA-256", sha512: "SHA-512" };

/** A base32 secret (as stored/shown) or raw secret bytes. */
export type OtpSecret = string | Uint8Array;

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/** New random base32 secret (no padding) for an authenticator app. 20 bytes = 160 bits (RFC 4226). */
export function generateTotpSecret(numBytes = 20): string {
  if (!Number.isInteger(numBytes) || numBytes < 10) throw new RangeError("numBytes must be at least 10 (80 bits).");
  return b32encode(randomBytes(numBytes));
}

const MIN_SECRET_BYTES = 10;

function normalizeSecret(secret: string): string {
  return secret.replace(/[ -]/g, "").toUpperCase().replace(/=+$/, "");
}

/** @internal Decode a base32 secret like Python's ``_decode_secret``. */
export function decodeSecret(secret: OtpSecret): Uint8Array {
  let raw: Uint8Array | null;
  if (secret instanceof Uint8Array) raw = secret;
  else if (typeof secret === "string") {
    let s = normalizeSecret(secret);
    s += "=".repeat((8 - (s.length % 8)) % 8);
    raw = b32decodePadded(s);
    if (raw === null) throw new RangeError("secret must be a base32 string.");
  } else throw new TypeError("secret must be a base32 string or Uint8Array.");
  if (raw.length < MIN_SECRET_BYTES) throw new RangeError(`secret must be at least ${MIN_SECRET_BYTES} bytes (80 bits).`);
  return raw;
}

function check(digits: number, algorithm: string): Hash {
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) throw new RangeError("digits must be between 6 and 8.");
  const h = typeof algorithm === "string" ? ALGORITHMS[algorithm.toLowerCase()] : undefined;
  if (!h) throw new RangeError("algorithm must be one of ['sha1', 'sha256', 'sha512'].");
  return h;
}

/** @internal Normalize user input to an ASCII code string, or null (Python ``_clean_code``). */
export function cleanCode(code: unknown, digits?: number): string | null {
  if (typeof code === "boolean") return null;
  if (typeof code === "number" || typeof code === "bigint") {
    if (typeof code === "number" && !Number.isInteger(code)) return null;
    if (code < 0 || digits === undefined) return null;
    return code.toString().padStart(digits, "0");
  }
  if (typeof code !== "string" || Array.from(code).length > 64) return null;
  const c = code.replace(/[ -]/g, "");
  return isAscii(c) ? c : null;
}

const isNumeric = (code: string, digits: number): boolean => code.length === digits && /^[0-9]+$/.test(code);

// ---------------------------------------------------------------------------
// HOTP / TOTP
// ---------------------------------------------------------------------------

export interface HotpOptions {
  /** 6-8, default 6. */
  digits?: number;
  /** ``sha1`` (default), ``sha256`` or ``sha512``. */
  algorithm?: OtpAlgorithm;
}

export interface TotpOptions extends HotpOptions {
  /** Step in seconds, default 30. */
  period?: number;
}

function hmacKeyFor(secret: OtpSecret, hash: Hash): Promise<CryptoKey> {
  return hmacKey(decodeSecret(secret), hash, false);
}

function truncate(mac: Uint8Array): number {
  const off = mac[mac.length - 1]! & 0x0f;
  return ((mac[off]! << 24) | (mac[off + 1]! << 16) | (mac[off + 2]! << 8) | mac[off + 3]!) & 0x7fffffff;
}

async function hotpWithKey(key: CryptoKey, counter: number | bigint, digits: number): Promise<string> {
  const mac = await hmac(key, be64(counter));
  return String(truncate(mac) % 10 ** digits).padStart(digits, "0");
}

function checkCounter(counter: number | bigint): void {
  if (typeof counter === "number" ? !Number.isInteger(counter) || counter < 0 : counter < 0n) throw new RangeError("counter must be non-negative.");
}

/** HOTP code for ``counter`` (RFC 4226). */
export async function hotp(secret: OtpSecret, counter: number | bigint, options: HotpOptions = {}): Promise<string> {
  const digits = options.digits ?? 6;
  const hash = check(digits, options.algorithm ?? "sha1");
  checkCounter(counter);
  return hotpWithKey(await hmacKeyFor(secret, hash), counter, digits);
}

function checkPeriod(period: number): void {
  if (!(period >= 1)) throw new RangeError("period must be positive.");
}

const nowSeconds = (): number => Date.now() / 1000;

/** TOTP code at unix time ``at`` seconds (default: now). RFC 6238. */
export async function totp(secret: OtpSecret, at?: number | null, options: TotpOptions = {}): Promise<string> {
  const period = options.period ?? 30;
  checkPeriod(period);
  const t = at ?? nowSeconds();
  return hotp(secret, Math.floor(t / period), options);
}

/** Current TOTP code. */
export function totpNow(secret: OtpSecret, options: TotpOptions = {}): Promise<string> {
  return totp(secret, null, options);
}

export interface VerifyTotpOptions extends TotpOptions {
  /** Steps either side accepted for clock drift. Default 1. */
  window?: number;
  /** Unix time in seconds (default now). */
  at?: number | null;
  /** Reject this step and older ones (replay protection). */
  lastUsedStep?: number | null;
}

/**
 * The time step ``code`` matches, or null. Store it and pass it back as
 * ``lastUsedStep`` so the same code can't be replayed. All candidate steps are
 * checked (no early exit).
 */
export async function findTotpStep(secret: OtpSecret, code: unknown, options: VerifyTotpOptions = {}): Promise<number | null> {
  const digits = options.digits ?? 6;
  const c = cleanCode(code, digits);
  if (c === null || !isNumeric(c, digits)) return null;
  const period = options.period ?? 30;
  checkPeriod(period);
  const hash = check(digits, options.algorithm ?? "sha1");
  const key = await hmacKeyFor(secret, hash);
  const window = options.window ?? 1;
  const current = Math.floor((options.at ?? nowSeconds()) / period);
  const steps: number[] = [];
  for (let s = current - window; s <= current + window; s++) {
    if (s < 0 || (options.lastUsedStep != null && s <= options.lastUsedStep)) continue;
    steps.push(s);
  }
  const codes = await Promise.all(steps.map((s) => hotpWithKey(key, s, digits)));
  let match: number | null = null;
  for (let i = 0; i < steps.length; i++) if (safeEquals(codes[i], c)) match = steps[i]!;
  return match;
}

/** True if ``code`` is valid now. */
export async function verifyTotp(secret: OtpSecret, code: unknown, options: VerifyTotpOptions = {}): Promise<boolean> {
  return (await findTotpStep(secret, code, options)) !== null;
}

/**
 * Check an HOTP ``code`` against ``counter … counter + lookAhead``. Returns the
 * **next counter** to store (always >= 1) or null.
 */
export async function verifyHotp(secret: OtpSecret, code: unknown, counter: number, options: HotpOptions & { lookAhead?: number } = {}): Promise<number | null> {
  const digits = options.digits ?? 6;
  const c = cleanCode(code, digits);
  if (c === null || !isNumeric(c, digits)) return null;
  const key = await hmacKeyFor(secret, check(digits, options.algorithm ?? "sha1"));
  checkCounter(counter);
  const counters = Array.from({ length: (options.lookAhead ?? 0) + 1 }, (_, i) => counter + i);
  const codes = await Promise.all(counters.map((n) => hotpWithKey(key, n, digits)));
  let match: number | null = null;
  for (let i = 0; i < counters.length; i++) if (safeEquals(codes[i], c) && match === null) match = counters[i]! + 1;
  return match;
}

// ---------------------------------------------------------------------------
// Steam Guard
// ---------------------------------------------------------------------------

const STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY";

/** Steam Guard style 5-character code (HMAC-SHA1, 30 s steps). */
export async function steamCode(secret: OtpSecret, at?: number | null): Promise<string> {
  const t = at ?? nowSeconds();
  const mac = await hmac(await hmacKeyFor(secret, "SHA-1"), be64(Math.floor(t / 30)));
  let v = truncate(mac);
  let out = "";
  for (let i = 0; i < 5; i++) {
    out += STEAM_ALPHABET[v % 26];
    v = Math.floor(v / 26);
  }
  return out;
}

/** True if a Steam Guard style ``code`` is valid now (case-insensitive, no early exit). */
export async function verifySteamCode(secret: OtpSecret, code: unknown, options: { window?: number; at?: number | null } = {}): Promise<boolean> {
  if (typeof code !== "string" || Array.from(code).length !== 5) return false;
  const t = options.at ?? nowSeconds();
  const window = options.window ?? 1;
  const wanted = code.toUpperCase();
  const codes = await Promise.all(Array.from({ length: 2 * window + 1 }, (_, i) => steamCode(secret, t + (i - window) * 30)));
  let ok = false;
  for (const c of codes) if (safeEquals(c, wanted)) ok = true;
  return ok;
}

// ---------------------------------------------------------------------------
// otpauth:// URIs
// ---------------------------------------------------------------------------

/** Python's ``urllib.parse.quote``: keep ``A-Za-z0-9_.-~`` plus ``safe``, percent-encode UTF-8 bytes of the rest. */
export function pyQuote(s: string, safe = "/"): string {
  let out = "";
  for (const b of utf8(s)) {
    const ch = String.fromCharCode(b);
    if ((b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || "_.-~".includes(ch) || (b < 0x80 && safe.includes(ch))) out += ch;
    else out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}

function otpauthUri(kind: string, secret: string, account: string, issuer: string | null | undefined, params: [string, string | number][]): string {
  if (!account) throw new RangeError("account is required (e.g. the user's email).");
  if (account.includes(":") || (issuer && issuer.includes(":"))) throw new RangeError("account and issuer must not contain ':'.");
  decodeSecret(secret);
  let label = pyQuote(account, "@");
  if (issuer) label = `${pyQuote(issuer, "@")}:${label}`;
  const query: [string, string | number][] = [["secret", normalizeSecret(secret)]];
  if (issuer) query.push(["issuer", issuer]);
  query.push(...params);
  return `otpauth://${kind}/${label}?${query.map(([k, v]) => `${pyQuote(k, "")}=${pyQuote(String(v), "")}`).join("&")}`;
}

/**
 * ``otpauth://totp/...`` URI to show as a QR code in your MFA setup screen
 * (render it with ``@nuhmanpk/generateapikey/qr``). Byte-identical to Python's ``totp_uri``.
 */
export function totpUri(secret: string, account: string, issuer?: string | null, options: TotpOptions & { image?: string | null } = {}): string {
  const digits = options.digits ?? 6;
  const algorithm = options.algorithm ?? "sha1";
  const period = options.period ?? 30;
  check(digits, algorithm);
  checkPeriod(period);
  const params: [string, string | number][] = [];
  if (algorithm.toLowerCase() !== "sha1") params.push(["algorithm", algorithm.toUpperCase()]);
  if (digits !== 6) params.push(["digits", digits]);
  if (period !== 30) params.push(["period", period]);
  if (options.image) params.push(["image", options.image]);
  return otpauthUri("totp", secret, account, issuer, params);
}

/** ``otpauth://hotp/...`` URI for counter-based tokens. */
export function hotpUri(secret: string, account: string, issuer?: string | null, options: HotpOptions & { counter?: number } = {}): string {
  const digits = options.digits ?? 6;
  const algorithm = options.algorithm ?? "sha1";
  check(digits, algorithm);
  const params: [string, string | number][] = [["counter", options.counter ?? 0]];
  if (algorithm.toLowerCase() !== "sha1") params.push(["algorithm", algorithm.toUpperCase()]);
  if (digits !== 6) params.push(["digits", digits]);
  return otpauthUri("hotp", secret, account, issuer, params);
}

// --- Google Authenticator migration (hand-rolled protobuf) ------------------

function varint(n: number): number[] {
  const out: number[] = [];
  let v = n;
  for (;;) {
    const b = v % 128;
    v = Math.floor(v / 128);
    out.push(b | (v ? 0x80 : 0));
    if (!v) return out;
  }
}
const fieldBytes = (num: number, data: Uint8Array): Uint8Array => concat(Uint8Array.from(varint((num << 3) | 2)), Uint8Array.from(varint(data.length)), data);
const fieldInt = (num: number, value: number): Uint8Array => Uint8Array.from([...varint(num << 3), ...varint(value)]);

export interface MigrationAccount {
  secret: string;
  name: string;
  issuer?: string;
  digits?: 6 | 8;
  algorithm?: OtpAlgorithm;
}

/**
 * ``otpauth-migration://`` URI that Google Authenticator can import (as a QR
 * code). Keep it private: it contains the secrets.
 */
export function googleMigrationUri(accounts: Iterable<MigrationAccount>): string {
  const algs: Record<string, number> = { sha1: 1, sha256: 2, sha512: 3 };
  const parts: Uint8Array[] = [];
  for (const acc of accounts) {
    const digits = Number(acc.digits ?? 6);
    const alg = String(acc.algorithm ?? "sha1").toLowerCase();
    if ((digits !== 6 && digits !== 8) || !(alg in algs)) throw new RangeError("digits must be 6 or 8; algorithm must be sha1, sha256 or sha512.");
    const item = concat(
      fieldBytes(1, decodeSecret(acc.secret)),
      fieldBytes(2, utf8(String(acc.name))),
      fieldBytes(3, utf8(String(acc.issuer ?? ""))),
      fieldInt(4, algs[alg]!),
      fieldInt(5, digits === 6 ? 1 : 2),
      fieldInt(6, 2),
    );
    parts.push(fieldBytes(1, item));
  }
  if (!parts.length) throw new RangeError("accounts must not be empty.");
  const r = randomBytes(4);
  const batchId = ((r[0]! << 24) | (r[1]! << 16) | (r[2]! << 8) | r[3]!) & 0x7fffffff;
  const payload = concat(...parts, fieldInt(2, 1), fieldInt(3, 1), fieldInt(4, 0), fieldInt(5, batchId));
  return "otpauth-migration://offline?data=" + pyQuote(b64std(payload), "");
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

/** Crockford base32: no I, L, O, U. Easy to read aloud and type. */
export const RECOVERY_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const FIX: Record<string, string> = { O: "0", I: "1", L: "1" };

/**
 * ``count`` single-use backup codes like ``7KQ2M-9XPAB`` (default 10 × 10
 * chars = 50 bits each). Show once; store only {@link hashRecoveryCode}.
 */
export function generateRecoveryCodes(count = 10, length = 10, group = 5): string[] {
  if (!Number.isInteger(count) || !Number.isInteger(length) || !Number.isInteger(group) || count < 1 || length < 8 || group < 0) {
    throw new RangeError("count must be >= 1 and length >= 8 (40 bits), all integers.");
  }
  const codes = new Set<string>();
  while (codes.size < count) codes.add(randomKey(length, RECOVERY_ALPHABET));
  return [...codes].map((c) => (group ? addDashes(c, group) : c));
}

/** Upper-case, drop spaces/dashes, map look-alikes (O→0, I/L→1). */
export function normalizeRecoveryCode(code: string): string {
  const c = cleanCode(code);
  if (c === null) throw new TypeError("recovery code must be an ASCII string.");
  return c.toUpperCase().replace(/[OIL]/g, (ch) => FIX[ch]!);
}

/** Hash a recovery code for storage (normalized, salted PBKDF2). */
export function hashRecoveryCode(code: string, pepper?: string | null): Promise<string> {
  return hashCode(normalizeRecoveryCode(code), pepper);
}

/**
 * The stored hash that ``code`` matches, or null. Delete it afterwards so the
 * code can't be reused. Every hash is checked (no early exit).
 */
export async function verifyRecoveryCode(code: unknown, hashes: Iterable<string>, pepper?: string | null): Promise<string | null> {
  const c = cleanCode(code);
  if (c === null) return null;
  const normalized = c.toUpperCase().replace(/[OIL]/g, (ch) => FIX[ch]!);
  const list = [...hashes];
  const results = await Promise.all(list.map((h) => verifyCode(normalized, h, pepper)));
  let match: string | null = null;
  for (let i = 0; i < list.length; i++) if (results[i] && match === null) match = list[i]!;
  return match;
}

// ---------------------------------------------------------------------------
// Email / SMS one-time codes
// ---------------------------------------------------------------------------

/**
 * One-time code for email/SMS, as an {@link ApiKey} (``value`` + ``expiresAt``).
 * ``expiry`` is minutes (default 10; ``null`` = no expiry). Short codes are only
 * safe with an attempt limit ({@link AttemptLimiter}).
 */
export function generateOtp(digits = 6, expiry: number | null = 10, options: { charset?: string } = {}): ApiKey {
  if (!Number.isInteger(digits) || digits < 4 || digits > 12) throw new RangeError("digits must be between 4 and 12.");
  if (expiry !== null && (typeof expiry !== "number" || !Number.isFinite(expiry) || expiry <= 0)) throw new RangeError("expiry must be a positive, finite number of minutes.");
  const code = randomKey(digits, alphabet(options.charset ?? "0123456789").chars);
  return new ApiKey(code, expiry === null ? null : Math.floor(nowSeconds() + expiry * 60));
}

/** Hash a one-time code for storage (salted PBKDF2). */
export function hashOtp(code: string | ApiKey, pepper?: string | null): Promise<string> {
  const c = cleanCode(code instanceof ApiKey ? code.value : code);
  if (c === null) throw new TypeError("code must be an ASCII string.");
  return hashCode(c, pepper);
}

/** True if ``code`` matches ``hashed`` and ``expiresAt`` (unix seconds) hasn't passed. */
export async function verifyOtp(code: unknown, hashed: string, expiresAt?: number | null, options: { pepper?: string | null } = {}): Promise<boolean> {
  if (expiresAt != null && nowSeconds() >= expiresAt) return false;
  const c = cleanCode(code instanceof ApiKey ? code.value : code);
  if (c === null) return false;
  return verifyCode(c, hashed, options.pepper);
}

// ---------------------------------------------------------------------------
// Attempt limiting
// ---------------------------------------------------------------------------

const monotonic = (): number => (typeof performance !== "undefined" ? performance.now() / 1000 : Date.now() / 1000);

/**
 * In-memory attempt limiter (one process / isolate). Call ``hit`` **before**
 * verifying: it atomically checks and counts. Memory is bounded by ``maxKeys``.
 * For several processes use {@link RedisAttemptLimiter}.
 */
export class AttemptLimiter {
  readonly maxAttempts: number;
  /** Window in seconds. */
  readonly window: number;
  readonly maxKeys: number;
  private readonly entries = new Map<string, [count: number, start: number]>();

  constructor(options: { maxAttempts?: number; window?: number; maxKeys?: number } = {}) {
    this.maxAttempts = options.maxAttempts ?? 5;
    this.window = options.window ?? 900;
    this.maxKeys = options.maxKeys ?? 100_000;
    if (this.maxAttempts < 1 || this.window <= 0 || this.maxKeys < 1) throw new RangeError("maxAttempts, window and maxKeys must be positive.");
  }

  private purge(now: number): void {
    for (const [k, [, start]] of this.entries) {
      if (now - start < this.window) break;
      this.entries.delete(k);
    }
  }

  private count(key: string, now: number): number {
    const e = this.entries.get(key);
    if (!e) return 0;
    if (now - e[1] >= this.window) {
      this.entries.delete(key);
      return 0;
    }
    return e[0];
  }

  private add(key: string, now: number): number {
    const c = this.count(key, now);
    if (c) this.entries.get(key)![0] = c + 1;
    else {
      this.entries.set(key, [1, now]);
      while (this.entries.size > this.maxKeys) this.entries.delete(this.entries.keys().next().value as string);
    }
    return c + 1;
  }

  /** Record an attempt. False if the key is over the limit (attempt not counted). */
  hit(key: string): boolean {
    const now = monotonic();
    this.purge(now);
    if (this.count(key, now) >= this.maxAttempts) return false;
    this.add(key, now);
    return true;
  }

  /** Record a failed attempt. Returns attempts left. */
  fail(key: string): number {
    const now = monotonic();
    this.purge(now);
    return Math.max(0, this.maxAttempts - this.add(key, now));
  }

  isBlocked(key: string): boolean {
    return this.count(key, monotonic()) >= this.maxAttempts;
  }

  remaining(key: string): number {
    return Math.max(0, this.maxAttempts - this.count(key, monotonic()));
  }

  reset(key: string): void {
    this.entries.delete(key);
  }
}

/** Minimal Redis client surface; wrap ioredis / node-redis / Upstash in three lines. */
export interface RedisLike {
  /** Run a Lua script. ``args`` are strings (what every Redis client expects). */
  eval(script: string, keys: string[], args: string[]): Promise<unknown>;
  get(key: string): Promise<string | number | null | undefined>;
  del(key: string): Promise<unknown>;
}

/** Same Lua script and key layout as Python's ``limiters.py``: Python and JS processes share counters. */
export const REDIS_LIMITER_SCRIPT = `
local c = tonumber(redis.call('GET', KEYS[1]) or '0')
if ARGV[3] == 'hit' and c >= tonumber(ARGV[2]) then
  return -1
end
c = redis.call('INCR', KEYS[1])
if c == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return c
`;

/**
 * Redis-backed limiter with the same interface as {@link AttemptLimiter}
 * (async). Atomic Lua script; counters expire on their own.
 *
 * @example
 * // ioredis
 * new RedisAttemptLimiter({ eval: (s, k, a) => redis.eval(s, k.length, ...k, ...a), get: (k) => redis.get(k), del: (k) => redis.del(k) })
 * // node-redis v4+
 * new RedisAttemptLimiter({ eval: (s, keys, args) => redis.eval(s, { keys, arguments: args }), get: (k) => redis.get(k), del: (k) => redis.del(k) })
 */
export class RedisAttemptLimiter {
  readonly maxAttempts: number;
  readonly window: number;
  readonly prefix: string;

  constructor(
    private readonly client: RedisLike,
    options: { maxAttempts?: number; window?: number; prefix?: string } = {},
  ) {
    this.maxAttempts = options.maxAttempts ?? 5;
    this.window = options.window ?? 900;
    this.prefix = options.prefix ?? "gak:attempts:";
    if (this.maxAttempts < 1 || this.window <= 0) throw new RangeError("maxAttempts and window must be positive.");
  }

  /** Redis key for ``key``: prefix + sha256 hex (arbitrary input can't create odd keys). */
  async redisKey(key: string): Promise<string> {
    return this.prefix + toHex(await digest("SHA-256", utf8(String(key))));
  }

  private async run(key: string, mode: "hit" | "fail"): Promise<number> {
    return Number(await this.client.eval(REDIS_LIMITER_SCRIPT, [await this.redisKey(key)], [String(Math.trunc(this.window * 1000)), String(this.maxAttempts), mode]));
  }

  async hit(key: string): Promise<boolean> {
    return (await this.run(key, "hit")) !== -1;
  }

  async fail(key: string): Promise<number> {
    return Math.max(0, this.maxAttempts - (await this.run(key, "fail")));
  }

  private async count(key: string): Promise<number> {
    return Number((await this.client.get(await this.redisKey(key))) ?? 0);
  }

  async isBlocked(key: string): Promise<boolean> {
    return (await this.count(key)) >= this.maxAttempts;
  }

  async remaining(key: string): Promise<number> {
    return Math.max(0, this.maxAttempts - (await this.count(key)));
  }

  async reset(key: string): Promise<void> {
    await this.client.del(await this.redisKey(key));
  }
}
