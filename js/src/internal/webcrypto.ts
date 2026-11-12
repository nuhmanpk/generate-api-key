/** Thin, cached wrapper over ``globalThis.crypto`` (Web Crypto). */

import { toHex } from "./bytes.js";

export type Hash = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";

export function webcrypto(): Crypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c || !c.subtle || typeof c.getRandomValues !== "function") {
    throw new Error(
      "generateapikey needs the Web Crypto API (globalThis.crypto). Use Node.js 20+, Deno, Bun, a modern browser or an edge runtime.",
    );
  }
  return c;
}

export function subtle(): SubtleCrypto {
  return webcrypto().subtle;
}

/** Copy into a fresh ArrayBuffer-backed view (Web Crypto rejects SharedArrayBuffer views in some runtimes). */
export function buf(b: Uint8Array): Uint8Array<ArrayBuffer> {
  return b.buffer instanceof ArrayBuffer && b.byteOffset === 0 && b.byteLength === b.buffer.byteLength
    ? (b as Uint8Array<ArrayBuffer>)
    : new Uint8Array(b);
}

// ---------------------------------------------------------------------------
// Random bytes: pooled getRandomValues (one syscall-ish call per 4 KiB)
// ---------------------------------------------------------------------------

const POOL_SIZE = 4096;
let pool: Uint8Array | null = null;
let poolOffset = POOL_SIZE;

let override: ((n: number) => Uint8Array) | null = null;

/**
 * @internal Test hook: replace the random source (used by the cross-language
 * vector tests to pin salts and nonces). Not exported from the package entry.
 */
export function _setRandomSource(fn: ((n: number) => Uint8Array) | null): void {
  override = fn;
  pool = null;
  poolOffset = POOL_SIZE;
}

/** ``n`` cryptographically secure random bytes. */
export function randomBytes(n: number): Uint8Array {
  if (override) return override(n);
  if (n > POOL_SIZE / 4) {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i += 65536) webcrypto().getRandomValues(out.subarray(i, Math.min(n, i + 65536)));
    return out;
  }
  if (pool === null || poolOffset + n > POOL_SIZE) {
    pool ??= new Uint8Array(POOL_SIZE);
    webcrypto().getRandomValues(pool);
    poolOffset = 0;
  }
  const out = pool.slice(poolOffset, poolOffset + n);
  // Wipe consumed bytes so they can't be handed out twice or read later.
  pool.fill(0, poolOffset, poolOffset + n);
  poolOffset += n;
  return out;
}

// ---------------------------------------------------------------------------
// HMAC with an LRU cache of imported keys for long-lived server secrets
// ---------------------------------------------------------------------------

const KEY_CACHE_MAX = 64;
const keyCache = new Map<string, Promise<CryptoKey>>();

function importHmac(key: Uint8Array, hash: Hash): Promise<CryptoKey> {
  return subtle().importKey("raw", buf(key), { name: "HMAC", hash }, false, ["sign"]);
}

/**
 * Imported HMAC key. ``cache`` is only for server secrets (peppers, signing
 * secrets) that are reused on every request; user secrets (TOTP) are never cached.
 */
export function hmacKey(key: Uint8Array, hash: Hash, cache = false): Promise<CryptoKey> {
  if (!cache) return importHmac(key, hash);
  const id = hash + ":" + toHex(key);
  let k = keyCache.get(id);
  if (k) {
    keyCache.delete(id);
    keyCache.set(id, k);
    return k;
  }
  k = importHmac(key, hash);
  keyCache.set(id, k);
  k.catch(() => keyCache.delete(id));
  if (keyCache.size > KEY_CACHE_MAX) keyCache.delete(keyCache.keys().next().value as string);
  return k;
}

export async function hmac(key: Uint8Array | CryptoKey, data: Uint8Array, hash: Hash = "SHA-256", cache = false): Promise<Uint8Array> {
  const k = key instanceof Uint8Array ? await hmacKey(key, hash, cache) : key;
  return new Uint8Array(await subtle().sign("HMAC", k, buf(data)));
}

export async function digest(hash: Hash, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest(hash, buf(data)));
}

export async function pbkdf2(password: Uint8Array, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const base = await subtle().importKey("raw", buf(password), "PBKDF2", false, ["deriveBits"]);
  try {
    const bits = await subtle().deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: buf(salt), iterations }, base, 256);
    return new Uint8Array(bits);
  } catch (e) {
    if (iterations > 100_000) {
      throw new Error(
        `This runtime refused PBKDF2 with ${iterations} iterations (Cloudflare Workers allows at most 100,000). ` +
          "Re-hash codes with the default iteration count.",
        { cause: e },
      );
    }
    throw e;
  }
}

/** Clear cached HMAC keys (e.g. after rotating a pepper). */
export function clearKeyCache(): void {
  keyCache.clear();
  for (const fn of clearHooks) fn();
}

const clearHooks: (() => void)[] = [];
/** @internal */
export function onClearKeyCache(fn: () => void): void {
  clearHooks.push(fn);
}
