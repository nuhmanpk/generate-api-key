/**
 * Asymmetric JWT signing with keys generated fresh for each run (no key files
 * exist anywhere in the repo). Covers PKCS#8, SPKI, PKCS#1 and SEC1 PEMs, JWKs,
 * CryptoKeys, wrong-type keys and algorithm confusion.
 */

import { describe, expect, it } from "vitest";
import * as g from "../src/index.js";

const subtle = globalThis.crypto.subtle;

function pem(label: string, der: ArrayBuffer | Uint8Array): string {
  const bytes = der instanceof Uint8Array ? der : new Uint8Array(der);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64 = btoa(bin).replace(/.{1,64}/g, "$&\n");
  return `-----BEGIN ${label}-----\n${b64}-----END ${label}-----\n`;
}

/** Content of the last OCTET STRING / BIT STRING inside a PKCS#8 / SPKI SEQUENCE (the inner PKCS#1 / SEC1 key). */
function inner(der: Uint8Array, tag: number): Uint8Array {
  const read = (i: number): [number, number, number] => {
    let len = der[i + 1]!;
    let p = i + 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let k = 0; k < n; k++) len = len * 256 + der[p++]!;
    }
    return [der[i]!, p, p + len];
  };
  const [, start, end] = read(0);
  let i = start;
  let last: Uint8Array | null = null;
  while (i < end) {
    const [t, s, e] = read(i);
    if (t === tag) last = der.slice(tag === 0x03 ? s + 1 : s, e);
    i = e;
  }
  return last!;
}

type Kind = "rsa" | "p256" | "p384" | "p521" | "ed25519";
const PARAMS: Record<Kind, RsaHashedKeyGenParams | EcKeyGenParams | Algorithm> = {
  rsa: { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  p256: { name: "ECDSA", namedCurve: "P-256" },
  p384: { name: "ECDSA", namedCurve: "P-384" },
  p521: { name: "ECDSA", namedCurve: "P-521" },
  ed25519: { name: "Ed25519" },
};

async function keys(kind: Kind) {
  const pair = (await subtle.generateKey(PARAMS[kind], true, ["sign", "verify"])) as CryptoKeyPair;
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey));
  const spki = new Uint8Array(await subtle.exportKey("spki", pair.publicKey));
  const forms: Record<string, string> = { private_pkcs8: pem("PRIVATE KEY", pkcs8), public_spki: pem("PUBLIC KEY", spki) };
  if (kind === "rsa") {
    forms.private_pkcs1 = pem("RSA PRIVATE KEY", inner(pkcs8, 0x04));
    forms.public_pkcs1 = pem("RSA PUBLIC KEY", inner(spki, 0x03));
  } else if (kind !== "ed25519") {
    forms.private_sec1 = pem("EC PRIVATE KEY", inner(pkcs8, 0x04));
  }
  return { forms, jwkPub: await subtle.exportKey("jwk", pair.publicKey), jwkPriv: await subtle.exportKey("jwk", pair.privateKey) };
}

const ALGS: [g.AsymAlg, Kind][] = [
  ["RS256", "rsa"], ["RS384", "rsa"], ["RS512", "rsa"], ["PS256", "rsa"], ["PS384", "rsa"], ["PS512", "rsa"],
  ["ES256", "p256"], ["ES384", "p384"], ["ES512", "p521"], ["EdDSA", "ed25519"],
];

describe.each(ALGS)("%s", (alg, kind) => {
  it("signs with every private key form and verifies with every public form", async () => {
    const k = await keys(kind);
    const privs = Object.entries(k.forms).filter(([f]) => f.startsWith("private")).map(([, v]) => v);
    const pubs = [...Object.values(k.forms), k.jwkPub];
    for (const priv of [...privs, k.jwkPriv]) {
      const t = await g.encodeJwt({ sub: "42" }, priv, { algorithm: alg, headers: { kid: kind } });
      expect(JSON.parse(atob(t.split(".")[0]!))).toEqual({ kid: kind, alg, typ: "JWT" });
      for (const pub of pubs) expect(await g.decodeJwt(t, pub, { algorithms: [alg] }), alg).toMatchObject({ sub: "42" });
      const tampered = t.slice(0, -4) + (t.endsWith("AAAA") ? "BBBB" : "AAAA");
      expect(await g.decodeJwt(tampered, k.forms.public_spki!, { algorithms: [alg] })).toBeNull();
    }
    const jwks = { keys: [{ ...k.jwkPub, kid: kind }] };
    const t = await g.encodeJwt({ sub: "1" }, k.forms.private_pkcs8!, { algorithm: alg, headers: { kid: kind } });
    expect(await g.decodeJwtJwks(t, jwks, { algorithms: [alg] })).toMatchObject({ sub: "1" });
  });
});

describe("key validation", () => {
  it("rejects wrong key types, wrong curves and small RSA keys", async () => {
    const rsa = await keys("rsa");
    const p256 = await keys("p256");
    await expect(g.encodeJwt({}, p256.forms.private_pkcs8!, { algorithm: "RS256" })).rejects.toThrow(/RSA/);
    await expect(g.encodeJwt({}, p256.forms.private_pkcs8!, { algorithm: "ES384" })).rejects.toThrow(/secp384r1/);
    await expect(g.encodeJwt({}, rsa.forms.private_pkcs8!, { algorithm: "EdDSA" })).rejects.toThrow(/Ed25519/);
    await expect(g.encodeJwt({}, rsa.forms.public_spki!, { algorithm: "RS256" })).rejects.toThrow(/private/);
    const small = (await subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign"])) as CryptoKeyPair;
    const smallPem = pem("PRIVATE KEY", await subtle.exportKey("pkcs8", small.privateKey));
    await expect(g.encodeJwt({}, smallPem, { algorithm: "RS256" })).rejects.toThrow(/2048/);
  });
  it("blocks algorithm confusion", async () => {
    const rsa = await keys("rsa");
    // An attacker "signs" an HS256 token with the public key as the HMAC secret.
    const forged = await g.encodeJwt({ sub: "admin" }, rsa.forms.public_spki!, { algorithm: "HS256" });
    expect(await g.decodeJwt(forged, rsa.forms.public_spki!, { algorithms: ["RS256"] })).toBeNull();
    await expect(g.decodeJwt(forged, rsa.forms.public_spki!, { algorithms: ["RS256", "HS256"] })).rejects.toThrow(/mix/);
    const rs = await g.encodeJwt({ sub: "1" }, rsa.forms.private_pkcs8!, { algorithm: "RS256" });
    expect(await g.decodeJwt(rs, rsa.forms.public_spki!, { algorithms: ["PS256"] })).toBeNull();
  });
  it("a token's header can't make decodeJwt throw when several algorithms are allowed", async () => {
    const rsa = await keys("rsa");
    const ec = await keys("p256");
    const es = await g.encodeJwt({ sub: "1" }, ec.forms.private_pkcs8!, { algorithm: "ES256" });
    expect(await g.decodeJwt(es, rsa.forms.public_spki!, { algorithms: ["RS256", "ES256"] })).toBeNull();
    await expect(g.decodeJwt(es, rsa.forms.public_spki!, { algorithms: ["ES256"] })).rejects.toThrow(RangeError);
  });
  it("JWKS skips keys of the wrong type and unknown kids", async () => {
    const ed = await keys("ed25519");
    const rsa = await keys("rsa");
    const jwks = { keys: [{ ...rsa.jwkPub, kid: "r" }, { ...ed.jwkPub, kid: "e" }] };
    const noKid = await g.encodeJwt({ sub: "1" }, ed.forms.private_pkcs8!, { algorithm: "EdDSA" });
    expect(await g.decodeJwtJwks(noKid, jwks, { algorithms: ["EdDSA"] })).toMatchObject({ sub: "1" });
    const unknown = await g.encodeJwt({ sub: "1" }, ed.forms.private_pkcs8!, { algorithm: "EdDSA", headers: { kid: "zzz" } });
    expect(await g.decodeJwtJwks(unknown, jwks, { algorithms: ["EdDSA"] })).toBeNull();
  });
});
