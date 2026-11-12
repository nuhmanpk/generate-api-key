/** API keys: generation, derivation, checksums and storage hashing (spec §2-§5). */

import { type Alphabet, type Case, type CharsetName, alphabet } from "./charsets.js";
import { b64url, b64urlDecode, be32, be64, bytesEqual, concat, cpLength, cpSlice, crc32, safeEquals, toHex, utf8 } from "./internal/bytes.js";
import { digest, hmac, hmacKey, onClearKeyCache, pbkdf2, randomBytes } from "./internal/webcrypto.js";

// ---------------------------------------------------------------------------
// ApiKey value object
// ---------------------------------------------------------------------------

const inspectSymbol = Symbol.for("nodejs.util.inspect.custom");

/**
 * A key (or one-time code) with optional expiry. ``String(key)``, template
 * literals, ``JSON.stringify`` and ``key.value`` give the raw string; logging
 * the object itself shows a redacted form so keys don't leak into logs.
 */
export class ApiKey {
  /** The raw key. */
  readonly value: string;
  /** Unix timestamp in **seconds** (same as Python), or null. */
  readonly expiresAt: number | null;

  constructor(value: string, expiresAt: number | null = null) {
    this.value = value;
    this.expiresAt = expiresAt;
  }

  /** True if an expiry was set and it has passed. */
  get isExpired(): boolean {
    return this.expiresAt !== null && Date.now() / 1000 >= this.expiresAt;
  }

  /** Seconds until expiry (negative once expired), or null. */
  get expiresIn(): number | null {
    return this.expiresAt === null ? null : this.expiresAt - Date.now() / 1000;
  }

  /** Expiry as a ``Date``, or null. */
  get expiresAtDate(): Date | null {
    return this.expiresAt === null ? null : new Date(this.expiresAt * 1000);
  }

  /** Shortcut for {@link hashApiKey}. */
  hash(pepper?: string | null): Promise<string> {
    return hashApiKey(this.value, pepper);
  }

  toString(): string {
    return this.value;
  }

  toJSON(): string {
    return this.value;
  }

  valueOf(): string {
    return this.value;
  }

  [Symbol.toPrimitive](): string {
    return this.value;
  }

  /** Redacted, like Python's ``repr(ApiKey)``. */
  redacted(): string {
    const n = cpLength(this.value);
    const shown = n >= 16 ? `${cpSlice(this.value, 0, 4)}…${cpSlice(this.value, n - 4)}` : "…";
    return this.expiresAt === null ? `ApiKey('${shown}')` : `ApiKey('${shown}', expiresAt=${this.expiresAt})`;
  }

  [inspectSymbol](): string {
    return this.redacted();
  }
}

/** True if ``key`` is an {@link ApiKey} whose expiry has passed. */
export function isExpired(key: unknown): boolean {
  return key instanceof ApiKey && key.isExpired;
}

// ---------------------------------------------------------------------------
// Unbiased sampling (spec §2.2)
// ---------------------------------------------------------------------------

/** Rejection sampler that consumes chunks exactly like Python's ``utils._sample``. */
class Sampler {
  private readonly out: string[] = [];
  private readonly table: Int16Array | null;
  private readonly w: number;
  private readonly limit: number;

  constructor(
    private readonly length: number,
    private readonly a: Alphabet,
  ) {
    const n = a.points.length;
    if (a.ascii && n <= 256) {
      const limit = 256 - (256 % n);
      const t = new Int16Array(256).fill(-1);
      for (let b = 0; b < limit; b++) t[b] = a.chars.charCodeAt(b % n);
      this.table = t;
      this.w = 1;
      this.limit = limit;
    } else {
      this.table = null;
      this.w = Math.ceil(n.toString(2).length / 8);
      const space = 2 ** (8 * this.w);
      this.limit = space - (space % n);
    }
  }

  /** Bytes the next ``feed`` call should receive (Python's request size). */
  need(): number {
    const remaining = this.length - this.out.length;
    if (this.table) return this.length + (this.length >> 1) + 8;
    return this.w * (remaining + 8);
  }

  feed(chunk: Uint8Array): void {
    if (this.table) {
      const t = this.table;
      const out = this.out;
      const codes: number[] = [];
      const want = this.length - this.fastLen;
      for (let i = 0; i < chunk.length && codes.length < want; i++) {
        const c = t[chunk[i]!]!;
        if (c >= 0) codes.push(c);
      }
      for (let i = 0; i < codes.length; i += 4096) out.push(String.fromCharCode(...codes.slice(i, i + 4096)));
      // In fast mode `out` holds multi-char chunks, so the char count is tracked separately.
      this.fastLen += codes.length;
      return;
    }
    const { w, limit } = this;
    const n = this.a.points.length;
    for (let i = 0; i + w <= chunk.length; i += w) {
      let v = 0;
      for (let j = 0; j < w; j++) v = v * 256 + chunk[i + j]!;
      if (v < limit) {
        this.out.push(this.a.points[v % n]!);
        if (this.out.length === this.length) break;
      }
    }
  }

  private fastLen = 0;

  get isDone(): boolean {
    return this.table ? this.fastLen >= this.length : this.out.length >= this.length;
  }

  result(): string {
    return this.out.join("");
  }
}

/** Cryptographically secure, unbiased random string of ``length`` characters from ``chars``. */
export function randomKey(length: number, chars: string): string {
  return sampleRandom(length, alphabet(chars));
}

function sampleRandom(length: number, a: Alphabet): string {
  const s = new Sampler(length, a);
  while (!s.isDone) s.feed(randomBytes(s.need()));
  return s.result();
}

/** HMAC-SHA256 counter-mode byte stream; ``read(n)`` returns whole 32-byte blocks like Python's ``stream``. */
class HmacStream {
  private counter = 0;
  constructor(
    private readonly key: CryptoKey,
    private readonly message: Uint8Array,
  ) {}

  async read(n: number): Promise<Uint8Array> {
    const blocks = Math.max(1, Math.ceil(n / 32));
    const start = this.counter;
    this.counter += blocks;
    const parts = await Promise.all(
      Array.from({ length: blocks }, (_, i) => hmac(this.key, concat(this.message, be64(start + i)))),
    );
    return concat(...parts);
  }
}

/** @internal Raw derivation (spec §2.3); ``salt`` is only used by the legacy API. */
export async function derivedKey(secret: string, seed: string, include: string | null | undefined, length: number, chars: string, salt: Uint8Array = new Uint8Array()): Promise<string> {
  const key = await subkeyKey(secret, "derive");
  const parts = [utf8(seed), utf8(include ?? ""), salt];
  const message = concat(...parts.flatMap((p) => [be32(p.length), p]));
  const stream = new HmacStream(key, message);
  const s = new Sampler(length, alphabet(chars));
  while (!s.isDone) s.feed(await stream.read(s.need()));
  return s.result();
}

// ---------------------------------------------------------------------------
// Subkeys (spec §2.4)
// ---------------------------------------------------------------------------

const subkeyCache = new Map<string, Promise<Uint8Array>>();
const subkeyKeyCache = new Map<string, Promise<CryptoKey>>();

onClearKeyCache(() => {
  subkeyCache.clear();
  subkeyKeyCache.clear();
});

/** @internal Imported HMAC-SHA256 key for ``subkey(secret, label)``, cached (server secrets only). */
export function subkeyKey(secret: string, label: string): Promise<CryptoKey> {
  const id = label + "\u0000" + secret;
  let p = subkeyKeyCache.get(id);
  if (!p) {
    p = subkey(secret, label).then((raw) => hmacKey(raw, "SHA-256", false));
    subkeyKeyCache.set(id, p);
    p.catch(() => subkeyKeyCache.delete(id));
    if (subkeyKeyCache.size > 64) subkeyKeyCache.delete(subkeyKeyCache.keys().next().value as string);
  }
  return p;
}

/** Independent HMAC key per purpose from one server secret (domain separation). */
export function subkey(secret: string, label: string): Promise<Uint8Array> {
  const id = label + "\u0000" + secret;
  let p = subkeyCache.get(id);
  if (!p) {
    p = hmac(utf8(secret), utf8("generateapikey.v1." + label), "SHA-256", true);
    subkeyCache.set(id, p);
    p.catch(() => subkeyCache.delete(id));
    if (subkeyCache.size > 64) subkeyCache.delete(subkeyCache.keys().next().value as string);
  }
  return p;
}

// ---------------------------------------------------------------------------
// Key generation (spec §2.1)
// ---------------------------------------------------------------------------

/** Random keys below this many bits of entropy trigger a weak-key warning. */
export const RECOMMENDED_ENTROPY = 128;

export interface KeyFormatOptions {
  /** Characters in the key body (excluding prefix/dashes/checksum). Default 32. */
  length?: number;
  /** Preset name (see {@link CHARSETS}) or a literal string of characters. Default ``"alphanumeric"``. */
  charset?: CharsetName | (string & {});
  /** ``"mixed"`` (default), ``"lower"`` or ``"upper"``. */
  case?: Case;
  /** Optional prefix joined with ``separator`` (e.g. ``sk-...``). */
  prefix?: string | null;
  /** String between prefix and body. Default ``"-"``. */
  separator?: string;
  /** Group the body for readability, e.g. ``ABCD-EFGH``. */
  dashes?: boolean;
  /** Group size when ``dashes`` is true. Default 4. */
  dashGroup?: number;
  /** Character placed between groups. Default ``"-"``. */
  dashChar?: string;
  /** Append a 6-char base62 CRC32 so {@link verifyChecksum} can reject typos offline. */
  checksum?: boolean;
}

export interface KeyOptions extends KeyFormatOptions {
  /** Throw if a random key would carry fewer bits of entropy. */
  minEntropy?: number;
  /** Called instead of ``console.warn`` for keys under 128 bits; pass ``false`` to silence. */
  onWeakKey?: ((message: string) => void) | false;
}

export interface ExpiringKeyOptions extends KeyOptions {
  /** Lifetime in **minutes** (same unit as Python). Sets ``expiresAt``. */
  expiry: number;
}

export interface DeriveOptions extends KeyFormatOptions {
  /** Secret for derived keys. */
  secret: string;
  /** Per-key value for derived keys (e.g. a user id). */
  seed: string;
  /** Extra context mixed into the derivation. */
  include?: string | null;
  /** Lifetime in minutes. When set, an {@link ApiKey} is returned. */
  expiry?: number;
}

function checkLength(length: unknown): number {
  if (typeof length !== "number" || !Number.isInteger(length) || length < 1) throw new RangeError("length must be a positive integer.");
  return length;
}

/** Insert ``sep`` every ``group`` characters (code points), e.g. ``ABCD-EFGH-IJKL``. */
export function addDashes(key: string, group = 4, sep = "-"): string {
  if (!Number.isInteger(group) || group < 1) throw new RangeError("dashGroup must be a positive integer.");
  const pts = Array.from(key);
  const out: string[] = [];
  for (let i = 0; i < pts.length; i += group) out.push(pts.slice(i, i + group).join(""));
  return out.join(sep);
}

/** @internal Expiry in minutes → seconds (positive, finite). */
export function expirySeconds(expiry: unknown): number {
  if (typeof expiry !== "number" || typeof expiry === "boolean") throw new TypeError("expiry must be a number of minutes.");
  const seconds = expiry * 60;
  if (!Number.isFinite(seconds) || seconds <= 0) throw new RangeError("expiry must be a positive, finite duration.");
  return seconds;
}

function finish(body: string, o: KeyFormatOptions): string {
  let b = body;
  if (o.dashes) b = addDashes(b, o.dashGroup ?? 4, o.dashChar ?? "-");
  let key = o.prefix ? `${o.prefix}${o.separator ?? "-"}${b}` : b;
  if (o.checksum) key += computeChecksum(key);
  return key;
}

function warnWeak(bits: number, o: KeyOptions): void {
  if (o.onWeakKey === false) return;
  const msg =
    `API key has only ${Math.round(bits)} bits of entropy (recommended >= ${RECOMMENDED_ENTROPY}); ` +
    "increase length or use a larger charset.";
  if (typeof o.onWeakKey === "function") o.onWeakKey(msg);
  else console.warn(`[generateapikey] ${msg}`);
}

/**
 * Generate a cryptographically random API key. Synchronous.
 *
 * Returns a ``string``, or an {@link ApiKey} (string value + ``expiresAt``)
 * when ``expiry`` (minutes) is given. For deterministic keys use {@link deriveApiKey}.
 *
 * @example
 * generateApiKey()                                  // 32 random chars
 * generateApiKey({ prefix: "sk", checksum: true })  // sk-xxxx…<checksum>
 * generateApiKey({ expiry: 60 }).expiresAt          // unix seconds
 */
export function generateApiKey(options?: KeyOptions & { expiry?: undefined }): string;
export function generateApiKey(options: ExpiringKeyOptions): ApiKey;
export function generateApiKey(options: KeyOptions & { expiry?: number } = {}): string | ApiKey {
  const o = options;
  if ("secret" in o || "seed" in o) throw new TypeError("generateApiKey makes random keys; use deriveApiKey({ secret, seed }) for derived keys.");
  const length = checkLength(o.length ?? 32);
  const a = alphabet(o.charset ?? "alphanumeric", o.case ?? "mixed");
  const bits = length * Math.log2(a.points.length);
  if (o.minEntropy != null && bits < o.minEntropy) throw new RangeError(`key has ${Math.round(bits)} bits of entropy, below minEntropy=${o.minEntropy}.`);
  if (bits < RECOMMENDED_ENTROPY) warnWeak(bits, o);
  const exp = o.expiry === undefined ? null : Math.floor(Date.now() / 1000 + expirySeconds(o.expiry));
  const key = finish(sampleRandom(length, a), o);
  return exp === null ? key : new ApiKey(key, exp);
}

/**
 * Generate ``count`` random keys with the same options as {@link generateApiKey}
 * (``ApiKey`` objects when ``expiry`` is given). Warns at most once for weak options.
 */
export function generateApiKeys(count: number, options?: KeyOptions & { expiry?: undefined }): string[];
export function generateApiKeys(count: number, options: ExpiringKeyOptions): ApiKey[];
export function generateApiKeys(count: number, options: KeyOptions & { expiry?: number } = {}): (string | ApiKey)[] {
  if (!Number.isInteger(count) || count < 0) throw new RangeError("count must be a non-negative integer.");
  if (count === 0) return [];
  let warned = false;
  const opts: KeyOptions = {
    ...options,
    onWeakKey: (m) => {
      if (!warned && options.onWeakKey !== false) (typeof options.onWeakKey === "function" ? options.onWeakKey : (x: string) => console.warn(`[generateapikey] ${x}`))(m);
      warned = true;
    },
  };
  const out: (string | ApiKey)[] = new Array(count);
  const expiry = options.expiry;
  for (let i = 0; i < count; i++) out[i] = expiry === undefined ? generateApiKey({ ...opts, expiry: undefined }) : generateApiKey({ ...opts, expiry });
  return out;
}

/**
 * Derive a key from ``secret``/``seed`` with HMAC-SHA256 (deterministic: the
 * same inputs always give the same key, in Python and JS). Async (Web Crypto).
 */
export async function deriveApiKey(options: DeriveOptions & { expiry?: undefined }): Promise<string>;
export async function deriveApiKey(options: DeriveOptions & { expiry: number }): Promise<ApiKey>;
export async function deriveApiKey(options: DeriveOptions): Promise<string | ApiKey> {
  const { secret, seed } = options;
  if (typeof secret !== "string" || typeof seed !== "string" || !secret || !seed) throw new RangeError("'secret' and 'seed' must be non-empty strings.");
  const length = checkLength(options.length ?? 32);
  const a = alphabet(options.charset ?? "alphanumeric", options.case ?? "mixed");
  if (options.dashes) addDashes("", options.dashGroup ?? 4); // validate early
  const exp = options.expiry === undefined ? null : Math.floor(Date.now() / 1000 + expirySeconds(options.expiry));
  const key = finish(await derivedKey(secret, seed, options.include, length, a.chars), options);
  return exp === null ? key : new ApiKey(key, exp);
}

// ---------------------------------------------------------------------------
// Checksums (spec §3)
// ---------------------------------------------------------------------------

export const CHECKSUM_LENGTH = 6;
const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/** 6-character base62 CRC32 checksum of ``data`` (same as Python). */
export function computeChecksum(data: string): string {
  let v = crc32(utf8(data));
  let out = "";
  for (let i = 0; i < CHECKSUM_LENGTH; i++) {
    out = BASE62[v % 62]! + out;
    v = Math.floor(v / 62);
  }
  return out;
}

/**
 * True if ``key`` ends with a valid checksum (``checksum: true``). Cheap,
 * offline sanity check for typos and truncation, not a substitute for lookup.
 */
export function verifyChecksum(key: unknown): boolean {
  if (typeof key !== "string") return false;
  const pts = Array.from(key);
  if (pts.length <= CHECKSUM_LENGTH) return false;
  const body = pts.slice(0, -CHECKSUM_LENGTH).join("");
  const check = pts.slice(-CHECKSUM_LENGTH).join("");
  return safeEquals(computeChecksum(body), check);
}

// ---------------------------------------------------------------------------
// Storage hashing (spec §4)
// ---------------------------------------------------------------------------

const HASH_PREFIX = "sha256$";
const HMAC_PREFIX = "hmac-sha256$";

/** @internal */
export function checkPepper(pepper: unknown): void {
  if (pepper !== undefined && pepper !== null && (typeof pepper !== "string" || pepper === "")) {
    throw new RangeError("pepper must be a non-empty string (or undefined).");
  }
}

/**
 * Hash ``key`` for storage: ``"sha256$<hex>"``, or ``"hmac-sha256$<hex>"`` with a
 * server-side ``pepper``. Store this, never the raw key. Same output as Python.
 */
export async function hashApiKey(key: string | ApiKey, pepper?: string | null): Promise<string> {
  checkPepper(pepper);
  const data = utf8(String(key));
  if (pepper != null) return HMAC_PREFIX + toHex(await hmac(await subkeyKey(pepper, "hash"), data));
  return HASH_PREFIX + toHex(await digest("SHA-256", data));
}

/** Constant-time check that ``key`` matches a value from {@link hashApiKey}. */
export async function verifyApiKey(key: unknown, hashed: unknown, pepper?: string | null): Promise<boolean> {
  checkPepper(pepper);
  if (key instanceof ApiKey) key = key.value;
  if (typeof key !== "string" || typeof hashed !== "string") return false;
  if (hashed.startsWith(HMAC_PREFIX) && pepper == null) return false;
  if (hashed.startsWith(HASH_PREFIX) && pepper != null) return false;
  return safeEquals(await hashApiKey(key, pepper), hashed);
}

// ---------------------------------------------------------------------------
// Slow, salted hashing for short codes (spec §5)
// ---------------------------------------------------------------------------

const KDF_PREFIX = "pbkdf2-sha256";
/** PBKDF2 iterations for new code hashes (same as Python). */
export const KDF_ITERATIONS = 100_000;

async function kdf(code: string, salt: Uint8Array, iterations: number, pepper: string | null | undefined): Promise<Uint8Array> {
  let data = utf8(code);
  if (pepper != null) data = await hmac(await subkeyKey(pepper, "code"), data);
  return pbkdf2(data, salt, iterations);
}

/**
 * Salted PBKDF2-SHA256 hash for short, low-entropy codes:
 * ``pbkdf2-sha256$<iterations>$<salt>$<hash>``. Same format as Python.
 */
export async function hashCode(code: string, pepper?: string | null, iterations: number = KDF_ITERATIONS): Promise<string> {
  checkPepper(pepper);
  if (!Number.isInteger(iterations) || iterations < 1) throw new RangeError("iterations must be a positive integer.");
  const salt = randomBytes(16);
  const dk = await kdf(code, salt, iterations, pepper);
  return `${KDF_PREFIX}$${iterations}$${b64url(salt)}$${b64url(dk)}`;
}

/** Check ``code`` against a value from {@link hashCode}. Never throws on bad input. */
export async function verifyCode(code: unknown, hashed: unknown, pepper?: string | null): Promise<boolean> {
  checkPepper(pepper);
  if (typeof code !== "string" || typeof hashed !== "string") return false;
  const parts = hashed.split("$");
  if (parts.length !== 4 || parts[0] !== KDF_PREFIX) return false;
  if (!/^\s*[+-]?\d+(_\d+)*\s*$/.test(parts[1]!)) return false;
  const iterations = Number(parts[1]!.replace(/_/g, ""));
  const salt = b64urlDecode(parts[2]!);
  const expected = b64urlDecode(parts[3]!);
  if (!salt || !expected) return false;
  if (!(iterations >= 1_000 && iterations <= 10_000_000)) return false;
  return bytesEqual(await kdf(code, salt, iterations, pepper), expected);
}
