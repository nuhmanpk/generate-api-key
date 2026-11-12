/**
 * Signed, self-expiring tokens (magic links, email verification, password
 * resets) and standard JWTs (spec §9-§10). Same wire formats as Python.
 */

import { b64url, b64urlDecode, bytesEqual, concat, cpLength, fromUtf8, isAscii, safeEquals, utf8 } from "./internal/bytes.js";
import { type AsymAlg, type AsymKey, ES_SIZES, signParams, signingKey, verifyingKey } from "./internal/pem.js";
import { pyDumps, pyStr } from "./internal/pyjson.js";
import { buf, digest, type Hash, hmac, randomBytes, subtle } from "./internal/webcrypto.js";
import { subkeyKey } from "./keys.js";

/** Minimum length (in characters) of HMAC secrets for tokens and HS* JWTs. */
export const MIN_SECRET_LENGTH = 16;
const MAX_TOKEN_LENGTH = 8192;

function checkSecret(secret: unknown): asserts secret is string {
  if (typeof secret !== "string" || cpLength(secret) < MIN_SECRET_LENGTH) {
    throw new RangeError(`secret must be a string of at least ${MIN_SECRET_LENGTH} characters; a short secret can be brute-forced from any token.`);
  }
}

const now = (): number => Date.now() / 1000;

function parseJson(seg: string): unknown {
  const raw = b64urlDecode(seg);
  if (raw === null) return undefined;
  try {
    return JSON.parse(fromUtf8(raw));
  } catch {
    return undefined;
  }
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isNum = (v: unknown): v is number => typeof v === "number";

// ---------------------------------------------------------------------------
// Signed tokens
// ---------------------------------------------------------------------------

async function sign(secret: string, body: string, context: string | null | undefined): Promise<string> {
  let msg = utf8(body);
  if (context != null) msg = concat(msg, Uint8Array.of(0x1f), await digest("SHA-256", utf8(context)));
  return b64url(await hmac(await subkeyKey(secret, "token"), msg));
}

export interface SignedTokenOptions {
  /** Binds the token to one flow (``"login"``, ``"reset"``…). Default ``"default"``. */
  purpose?: string;
  /** Lifetime in **minutes** (default 15). ``null`` = never expires. */
  expiry?: number | null;
  /**
   * Value the token is bound to (session id, device cookie). Signed but not
   * stored in the token: a leaked link only works where the same context is presented.
   */
  context?: string | null;
}

/**
 * URL-safe signed token: ``<base64url(json)>.<base64url(HMAC-SHA256)>``.
 * The payload is readable (not encrypted). Verifies in Python and JS.
 */
export async function generateSignedToken(secret: string, data: Record<string, unknown> | null = null, options: SignedTokenOptions = {}): Promise<string> {
  checkSecret(secret);
  const purpose = options.purpose ?? "default";
  if (typeof purpose !== "string") throw new TypeError("purpose must be a string.");
  const expiry = options.expiry === undefined ? 15 : options.expiry;
  if (expiry !== null && (typeof expiry !== "number" || !Number.isFinite(expiry) || expiry <= 0)) throw new RangeError("expiry must be a positive, finite number of minutes.");
  if (options.context != null && typeof options.context !== "string") throw new TypeError("context must be a string.");
  const payload: Record<string, unknown> = { p: purpose, jti: b64url(randomBytes(12)), d: data && Object.keys(data).length ? data : {} };
  if (expiry !== null) payload.exp = Math.floor(now() + expiry * 60);
  const body = b64url(utf8(pyDumps(payload, true)));
  return `${body}.${await sign(secret, body, options.context)}`;
}

export interface TokenMeta<T = Record<string, unknown>> {
  data: T;
  jti: unknown;
  exp: number | null;
}

/**
 * The token's ``data`` if signature, purpose and expiry check out, else null.
 * With ``withMeta: true`` returns ``{ data, jti, exp }``. Never throws on bad tokens.
 */
export async function verifySignedToken<T = Record<string, unknown>>(token: unknown, secret: string, options: { purpose?: string; context?: string | null; withMeta: true }): Promise<TokenMeta<T> | null>;
export async function verifySignedToken<T = Record<string, unknown>>(token: unknown, secret: string, options?: { purpose?: string; context?: string | null; withMeta?: false }): Promise<T | null>;
export async function verifySignedToken(token: unknown, secret: string, options: { purpose?: string; context?: string | null; withMeta?: boolean } = {}): Promise<unknown> {
  checkSecret(secret);
  if (typeof token !== "string" || token.length > MAX_TOKEN_LENGTH || !isAscii(token)) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts as [string, string];
  const context = options.context;
  if (context != null && typeof context !== "string") return null;
  if (!safeEquals(await sign(secret, body, context), sig)) return null;
  const payload = parseJson(body);
  if (!isObject(payload) || !safeEquals(pyStr(payload.p ?? ""), options.purpose ?? "default")) return null;
  const exp = payload.exp;
  if (exp !== undefined && exp !== null && (typeof exp !== "number" || now() >= exp)) return null;
  const data = "d" in payload ? payload.d : {};
  if (options.withMeta) return { data, jti: payload.jti ?? null, exp: exp ?? null };
  return data;
}

// ---------------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------------

export type HsAlg = "HS256" | "HS384" | "HS512";
export type JwtAlgorithm = HsAlg | AsymAlg;
export type { AsymAlg, AsymKey };

const HS: Record<HsAlg, Hash> = { HS256: "SHA-256", HS384: "SHA-384", HS512: "SHA-512" };
const ASYM: readonly AsymAlg[] = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"];
const KNOWN = [...Object.keys(HS), ...ASYM].sort();
const isAsym = (a: string): a is AsymAlg => (ASYM as readonly string[]).includes(a);
const isHs = (a: string): a is HsAlg => a in HS;

export interface EncodeJwtOptions {
  /** Default ``"HS256"``. RS/PS/ES/EdDSA take a private key. */
  algorithm?: JwtAlgorithm;
  /** Minutes until ``exp`` (default 15); ``null`` = no ``exp``. */
  expiry?: number | null;
  issuer?: string | null;
  audience?: string | null;
  /** Extra header fields (``alg``/``typ`` are always set by the library). */
  headers?: Record<string, unknown>;
}

/**
 * Standard JWT (RFC 7519), readable by any JWT library. ``iat``/``exp``/``iss``/``aud``
 * are added unless already in ``claims``. HS* take a shared secret (16+ chars);
 * RS/PS/ES/EdDSA take a PEM / JWK / CryptoKey private key. ``alg: none`` is impossible.
 */
export async function encodeJwt(claims: Record<string, unknown>, secret: string | AsymKey, options: EncodeJwtOptions = {}): Promise<string> {
  const algorithm = options.algorithm ?? "HS256";
  const asym = isAsym(algorithm);
  if (!asym) checkSecret(secret);
  if (!isHs(algorithm) && !asym) throw new RangeError(`algorithm must be one of ${JSON.stringify(KNOWN)}.`);
  const expiry = options.expiry === undefined ? 15 : options.expiry;
  if (expiry !== null && (typeof expiry !== "number" || !Number.isFinite(expiry) || expiry <= 0)) throw new RangeError("expiry must be a positive, finite number of minutes.");
  const t = Math.floor(now());
  const payload: Record<string, unknown> = { ...claims };
  if (!("iat" in payload)) payload.iat = t;
  if (expiry !== null && !("exp" in payload)) payload.exp = Math.floor(t + expiry * 60);
  if (options.issuer != null && !("iss" in payload)) payload.iss = options.issuer;
  if (options.audience != null && !("aud" in payload)) payload.aud = options.audience;
  const header: Record<string, unknown> = { ...(options.headers ?? {}) };
  delete header.alg;
  delete header.typ;
  const fullHeader = { ...header, alg: algorithm, typ: "JWT" };
  // Python dict update keeps the original key position for alg/typ overrides.
  const ordered = options.headers ? reorder(options.headers, fullHeader) : fullHeader;
  const input = `${b64url(utf8(pyDumps(ordered)))}.${b64url(utf8(pyDumps(payload)))}`;
  let sig: Uint8Array;
  if (asym) {
    const key = await signingKey(algorithm, secret as AsymKey);
    sig = new Uint8Array(await subtle().sign(signParams(algorithm), key, buf(utf8(input))));
  } else {
    sig = await hmac(utf8(secret as string), utf8(input), HS[algorithm as HsAlg], true);
  }
  return `${input}.${b64url(sig)}`;
}

/** ``{**headers, "alg": a, "typ": "JWT"}`` in Python keeps the first-seen position of every key. */
function reorder(original: Record<string, unknown>, merged: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(original)) out[k] = merged[k];
  for (const k of Object.keys(merged)) if (!(k in out)) out[k] = merged[k];
  return out;
}

export interface DecodeJwtOptions {
  /** Accepted algorithms, pinned by you (never taken from the token). Default ``["HS256"]``. */
  algorithms?: readonly JwtAlgorithm[];
  issuer?: string | null;
  audience?: string | null;
  /** Seconds of clock skew allowed for ``exp``/``nbf``. */
  leeway?: number;
  /** Reject tokens without ``exp`` (default true). */
  requireExp?: boolean;
}

/**
 * The claims if the JWT is valid, else null (never throws on bad tokens).
 * Throws only for programmer errors: bad ``algorithms``, a short secret, or a
 * key of the wrong type/curve for the algorithm. HS and asymmetric algorithms
 * can't be mixed (algorithm-confusion protection).
 */
export async function decodeJwt<T extends Record<string, unknown> = Record<string, unknown>>(token: unknown, secret: string | AsymKey, options: DecodeJwtOptions = {}): Promise<T | null> {
  const algorithms = options.algorithms ?? ["HS256"];
  if (typeof algorithms === "string" || !Array.isArray(algorithms) || !algorithms.length || !algorithms.every((a) => KNOWN.includes(a))) {
    throw new RangeError(`algorithms must be an array drawn from ${JSON.stringify(KNOWN)}.`);
  }
  const asym = isAsym(algorithms[0]!);
  if (algorithms.some((a) => isAsym(a) !== asym)) throw new RangeError("Don't mix HS* and RS*/ES* algorithms in one decodeJwt call.");
  if (!asym) checkSecret(secret);
  if (typeof token !== "string" || token.length > MAX_TOKEN_LENGTH || !isAscii(token)) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [head, body, sig] = parts as [string, string, string];
  const header = parseJson(head);
  const claims = parseJson(body);
  const given = b64urlDecode(sig);
  if (header === undefined || claims === undefined || given === null) return null;
  if (!isObject(header) || !isObject(claims)) return null;
  const alg = header.alg;
  if (typeof alg !== "string" || !algorithms.includes(alg as JwtAlgorithm)) return null;
  const input = utf8(`${head}.${body}`);
  if (asym) {
    let key: CryptoKey;
    try {
      key = await verifyingKey(alg as AsymAlg, secret as AsymKey);
    } catch (e) {
      // With one pinned algorithm a wrong key is the caller's mistake: throw (like Python).
      // With several, the token's header picked the algorithm, so a mismatch is just an
      // invalid token: return null instead of letting attacker input raise.
      if (algorithms.length > 1 && e instanceof RangeError) return null;
      throw e;
    }
    if (alg.startsWith("ES") && given.length !== 2 * ES_SIZES[alg]!) return null;
    let ok = false;
    try {
      ok = await subtle().verify(signParams(alg as AsymAlg), key, buf(given), buf(input));
    } catch {
      ok = false;
    }
    if (!ok) return null;
  } else if (!bytesEqual(await hmac(utf8(secret as string), input, HS[alg as HsAlg], true), given)) {
    return null;
  }
  const t = now();
  const leeway = options.leeway ?? 0;
  const { exp, nbf } = claims;
  if (exp === undefined || exp === null) {
    if (options.requireExp ?? true) return null;
  } else if (!isNum(exp) || t >= exp + leeway) return null;
  if (nbf !== undefined && nbf !== null && (!isNum(nbf) || t < nbf - leeway)) return null;
  if (options.issuer != null && claims.iss !== options.issuer) return null;
  if (options.audience != null) {
    const aud = claims.aud;
    if (aud !== options.audience && !(Array.isArray(aud) && aud.includes(options.audience))) return null;
  }
  return claims as T;
}

export interface Jwks {
  keys: JsonWebKey[];
}

function jwkMatches(alg: string, jwk: JsonWebKey & { kid?: string }): boolean {
  if (alg === "EdDSA") return jwk.kty === "OKP" && jwk.crv === "Ed25519";
  if (alg.startsWith("RS") || alg.startsWith("PS")) return jwk.kty === "RSA";
  return jwk.kty === "EC" && jwk.crv === { ES256: "P-256", ES384: "P-384", ES512: "P-521" }[alg];
}

/**
 * Verify an asymmetric JWT against a JWKS (``{ keys: [...] }``). The token's
 * ``kid`` only *selects* among keys you trust; the algorithm stays pinned.
 * Keys whose type doesn't fit the token's algorithm are skipped.
 */
export async function decodeJwtJwks<T extends Record<string, unknown> = Record<string, unknown>>(token: unknown, jwks: Jwks, options: DecodeJwtOptions = {}): Promise<T | null> {
  const algorithms = options.algorithms ?? ["RS256"];
  if (!algorithms.length || !isAsym(algorithms[0]!)) throw new RangeError("decodeJwtJwks only supports RS/PS/ES/EdDSA algorithms.");
  if (typeof token !== "string" || token.split(".").length !== 3 || !isAscii(token)) return null;
  const header = parseJson(token.split(".")[0]!);
  const kid = isObject(header) ? header.kid : undefined;
  const alg = isObject(header) ? header.alg : undefined;
  const keys = isObject(jwks) && Array.isArray(jwks.keys) ? jwks.keys : [];
  for (const jwk of keys as (JsonWebKey & { kid?: string })[]) {
    if (!isObject(jwk) || (kid !== undefined && kid !== null && jwk.kid !== kid)) continue;
    if (typeof alg !== "string" || !isAsym(alg) || !jwkMatches(alg, jwk)) continue;
    let claims: T | null = null;
    try {
      claims = await decodeJwt<T>(token, jwk, options);
    } catch {
      continue;
    }
    if (claims !== null) return claims;
  }
  return null;
}
