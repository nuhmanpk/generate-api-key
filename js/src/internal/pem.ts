/**
 * PEM / DER handling for asymmetric JWT keys. Web Crypto imports only PKCS#8
 * and SPKI, so PKCS#1 (``RSA PRIVATE KEY`` / ``RSA PUBLIC KEY``) and SEC1
 * (``EC PRIVATE KEY``) are re-wrapped here: the same PEM files Python's
 * ``cryptography`` loads work in JavaScript too.
 */

import { concat } from "./bytes.js";
import { buf, subtle } from "./webcrypto.js";

export type KeyKind = "rsa" | "ec" | "ed25519";
export type Curve = "P-256" | "P-384" | "P-521";

export interface ParsedKey {
  kind: KeyKind;
  curve?: Curve;
  private: boolean;
  /** PKCS#8 (private) or SPKI (public) DER. */
  der: Uint8Array;
}

const OID = {
  rsa: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
  ec: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
  ed25519: [0x2b, 0x65, 0x70],
  "P-256": [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
  "P-384": [0x2b, 0x81, 0x04, 0x00, 0x22],
  "P-521": [0x2b, 0x81, 0x04, 0x00, 0x23],
} as const;

// --- minimal DER ------------------------------------------------------------

interface Tlv {
  tag: number;
  start: number; // content start
  end: number; // content end
  next: number; // index after this TLV
}

function readTlv(d: Uint8Array, i: number): Tlv {
  if (i + 2 > d.length) throw new RangeError("invalid DER");
  const tag = d[i]!;
  let len = d[i + 1]!;
  let p = i + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4 || p + n > d.length) throw new RangeError("invalid DER");
    len = 0;
    for (let k = 0; k < n; k++) len = len * 256 + d[p++]!;
  }
  if (p + len > d.length) throw new RangeError("invalid DER");
  return { tag, start: p, end: p + len, next: p + len };
}

function children(d: Uint8Array, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let i = t.start; i < t.end; ) {
    const c = readTlv(d, i);
    out.push(c);
    i = c.next;
  }
  return out;
}

function lenBytes(n: number): number[] {
  if (n < 0x80) return [n];
  const out: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) out.unshift(v % 256);
  return [0x80 | out.length, ...out];
}

function tlv(tag: number, content: Uint8Array): Uint8Array {
  return concat(Uint8Array.from([tag, ...lenBytes(content.length)]), content);
}

const seq = (...parts: Uint8Array[]): Uint8Array => tlv(0x30, concat(...parts));
const oid = (o: readonly number[]): Uint8Array => tlv(0x06, Uint8Array.from(o));
const NULL = Uint8Array.from([0x05, 0x00]);
const INT0 = Uint8Array.from([0x02, 0x01, 0x00]);

const eq = (d: Uint8Array, t: Tlv, o: readonly number[]): boolean =>
  t.end - t.start === o.length && o.every((b, k) => d[t.start + k] === b);

function curveOf(d: Uint8Array, t: Tlv | undefined): Curve {
  if (t && t.tag === 0x06) for (const c of ["P-256", "P-384", "P-521"] as const) if (eq(d, t, OID[c])) return c;
  throw new RangeError("unsupported EC curve (use P-256, P-384 or P-521).");
}

/** Classify an AlgorithmIdentifier SEQUENCE. */
function algorithm(d: Uint8Array, alg: Tlv): { kind: KeyKind; curve?: Curve } {
  const [o, params] = children(d, alg);
  if (!o || o.tag !== 0x06) throw new RangeError("invalid key");
  if (eq(d, o, OID.rsa)) return { kind: "rsa" };
  if (eq(d, o, OID.ed25519)) return { kind: "ed25519" };
  if (eq(d, o, OID.ec)) return { kind: "ec", curve: curveOf(d, params) };
  throw new RangeError("unsupported key type (use RSA, EC or Ed25519).");
}

// --- PEM --------------------------------------------------------------------

function pemBody(pem: string): { label: string; der: Uint8Array } {
  const m = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(pem);
  if (!m) throw new RangeError("key must be a PEM string (-----BEGIN ...-----).");
  const b64 = m[2]!.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new RangeError("invalid PEM body");
  const bin = atob(b64);
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  return { label: m[1]!, der };
}

/** Parse a PEM key (PKCS#8, SPKI, PKCS#1 or SEC1) into normalized PKCS#8/SPKI DER. */
export function parsePem(pem: string): ParsedKey {
  const { label, der } = pemBody(pem);
  const top = readTlv(der, 0);
  const parts = children(der, top);
  switch (label) {
    case "PRIVATE KEY": {
      const alg = parts[1];
      if (!alg) throw new RangeError("invalid PKCS#8 key");
      return { ...algorithm(der, alg), private: true, der };
    }
    case "PUBLIC KEY": {
      const alg = parts[0];
      if (!alg) throw new RangeError("invalid SPKI key");
      return { ...algorithm(der, alg), private: false, der };
    }
    case "RSA PRIVATE KEY":
      return { kind: "rsa", private: true, der: seq(INT0, seq(oid(OID.rsa), NULL), tlv(0x04, der)) };
    case "RSA PUBLIC KEY":
      return { kind: "rsa", private: false, der: seq(seq(oid(OID.rsa), NULL), tlv(0x03, concat(Uint8Array.of(0), der))) };
    case "EC PRIVATE KEY": {
      const params = parts.find((p) => p.tag === 0xa0);
      const scalar = parts[1];
      // RFC 5915 makes the curve parameters optional; fall back to the private scalar's size.
      const bySize: Record<number, Curve> = { 32: "P-256", 48: "P-384", 66: "P-521" };
      const curve = params ? curveOf(der, readTlv(der, params.start)) : bySize[scalar ? scalar.end - scalar.start : 0];
      if (!curve) throw new RangeError("unsupported EC curve (use P-256, P-384 or P-521).");
      return { kind: "ec", curve, private: true, der: seq(INT0, seq(oid(OID.ec), oid(OID[curve])), tlv(0x04, der)) };
    }
    default:
      throw new RangeError(`unsupported PEM type: ${label}`);
  }
}

// --- import -----------------------------------------------------------------

export type AsymAlg = "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" | "ES256" | "ES384" | "ES512" | "EdDSA";

const HASHES = { "256": "SHA-256", "384": "SHA-384", "512": "SHA-512" } as const;
const ES_CURVES: Record<string, Curve> = { ES256: "P-256", ES384: "P-384", ES512: "P-521" };
export const ES_SIZES: Record<string, number> = { ES256: 32, ES384: 48, ES512: 66 };

export function importParams(alg: AsymAlg): RsaHashedImportParams | EcKeyImportParams | Algorithm {
  if (alg === "EdDSA") return { name: "Ed25519" };
  const hash = HASHES[alg.slice(2) as keyof typeof HASHES];
  if (alg.startsWith("RS")) return { name: "RSASSA-PKCS1-v1_5", hash };
  if (alg.startsWith("PS")) return { name: "RSA-PSS", hash };
  return { name: "ECDSA", namedCurve: ES_CURVES[alg]! };
}

export function signParams(alg: AsymAlg): Algorithm | RsaPssParams | EcdsaParams {
  if (alg === "EdDSA") return { name: "Ed25519" };
  const bits = alg.slice(2) as keyof typeof HASHES;
  const hash = HASHES[bits];
  if (alg.startsWith("RS")) return { name: "RSASSA-PKCS1-v1_5" };
  if (alg.startsWith("PS")) return { name: "RSA-PSS", saltLength: Number(bits) / 8 };
  return { name: "ECDSA", hash };
}

function checkKind(alg: AsymAlg, k: { kind: KeyKind; curve?: Curve | undefined }): void {
  if (alg === "EdDSA") {
    if (k.kind !== "ed25519") throw new RangeError("EdDSA requires an Ed25519 key.");
  } else if (alg.startsWith("RS") || alg.startsWith("PS")) {
    if (k.kind !== "rsa") throw new RangeError(`${alg} requires an RSA key.`);
  } else {
    if (k.kind !== "ec") throw new RangeError(`${alg} requires an EC key.`);
    const want = ES_CURVES[alg]!;
    if (k.curve !== want) throw new RangeError(`${alg} requires a ${{ "P-256": "secp256r1", "P-384": "secp384r1", "P-521": "secp521r1" }[want]} key.`);
  }
}

function unsupported(alg: AsymAlg, e: unknown): Error {
  return new Error(`This runtime's Web Crypto can't use ${alg} keys (${(e as Error)?.message ?? e}).`, { cause: e });
}

const cache = new Map<string, Promise<CryptoKey>>();

function cached(id: string, make: () => Promise<CryptoKey>): Promise<CryptoKey> {
  let p = cache.get(id);
  if (!p) {
    p = make();
    cache.set(id, p);
    p.catch(() => cache.delete(id));
    if (cache.size > 64) cache.delete(cache.keys().next().value as string);
  }
  return p;
}

/** Key material accepted for RS/PS/ES/EdDSA: PEM string, JWK object or a Web Crypto ``CryptoKey``. */
export type AsymKey = string | JsonWebKey | CryptoKey;

const isCryptoKey = (k: unknown): k is CryptoKey => typeof CryptoKey !== "undefined" && k instanceof CryptoKey;

function jwkKind(j: JsonWebKey): { kind: KeyKind; curve?: Curve } {
  if (j.kty === "RSA") return { kind: "rsa" };
  if (j.kty === "EC" && (j.crv === "P-256" || j.crv === "P-384" || j.crv === "P-521")) return { kind: "ec", curve: j.crv };
  if (j.kty === "OKP" && j.crv === "Ed25519") return { kind: "ed25519" };
  throw new RangeError(`unsupported JWK: kty=${JSON.stringify(j.kty)}`);
}

/** Private signing key for ``alg``; validates type, curve and (RSA) size >= 2048 bits. */
export async function signingKey(alg: AsymAlg, key: AsymKey): Promise<CryptoKey> {
  let k: CryptoKey;
  if (isCryptoKey(key)) k = key;
  else if (typeof key === "string") {
    const p = parsePem(key);
    if (!p.private) throw new RangeError("signing needs a private key.");
    checkKind(alg, p);
    k = await cached(`s:${alg}:${key}`, () => subtle().importKey("pkcs8", buf(p.der), importParams(alg), false, ["sign"]).catch((e) => Promise.reject(unsupported(alg, e))));
  } else {
    checkKind(alg, jwkKind(key));
    if (!key.d) throw new RangeError("signing needs a private key.");
    const { alg: _alg, key_ops: _ops, use: _use, ...material } = key;
    k = await subtle().importKey("jwk", material, importParams(alg), false, ["sign"]).catch((e) => Promise.reject(unsupported(alg, e)));
  }
  const algo = k.algorithm as RsaHashedKeyAlgorithm;
  if (algo.modulusLength !== undefined && algo.modulusLength < 2048) throw new RangeError("RSA keys must be at least 2048 bits.");
  return k;
}

/** Public verification key for ``alg``. A private PEM is accepted (its public half is used), like Python. */
export async function verifyingKey(alg: AsymAlg, key: AsymKey): Promise<CryptoKey> {
  if (isCryptoKey(key)) return key;
  if (typeof key !== "string") {
    checkKind(alg, jwkKind(key));
    const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, oth: _oth, key_ops: _ops, alg: _alg, use: _use, ...pub } = key;
    return subtle().importKey("jwk", pub, importParams(alg), false, ["verify"]).catch((e) => Promise.reject(unsupported(alg, e)));
  }
  const p = parsePem(key);
  checkKind(alg, p);
  return cached(`v:${alg}:${key}`, async () => {
    try {
      if (!p.private) return await subtle().importKey("spki", buf(p.der), importParams(alg), false, ["verify"]);
      const priv = await subtle().importKey("pkcs8", buf(p.der), importParams(alg), true, ["sign"]);
      const jwk = await subtle().exportKey("jwk", priv);
      const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, key_ops: _ops, alg: _alg, ...pub } = jwk;
      return await subtle().importKey("jwk", pub, importParams(alg), false, ["verify"]);
    } catch (e) {
      throw unsupported(alg, e);
    }
  });
}
