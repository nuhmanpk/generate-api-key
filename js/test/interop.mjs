// Live cross-language interop (CI): JS makes values with fresh randomness and
// fresh keys, Python verifies them, and the other way round.
//   node test/interop.mjs make   > /tmp/js.json
//   node test/interop.mjs verify < /tmp/py.json
// Private keys exist only in memory; the JSON carries public keys and tokens.
import { readFileSync } from "node:fs";
import * as g from "../dist/index.js";

const PEPPER = "interop-pepper";
const SECRET = "interop-signing-secret-0123456789";
const subtle = globalThis.crypto.subtle;
const ALGS = { RS256: "rsa", PS384: "rsa", ES256: "p256", ES384: "p384", ES512: "p521", EdDSA: "ed25519" };
const GEN = {
  rsa: { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  p256: { name: "ECDSA", namedCurve: "P-256" },
  p384: { name: "ECDSA", namedCurve: "P-384" },
  p521: { name: "ECDSA", namedCurve: "P-521" },
  ed25519: { name: "Ed25519" },
};
const pem = (label, buf) => `-----BEGIN ${label}-----\n${btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/.{1,64}/g, "$&\n")}-----END ${label}-----\n`;

async function make() {
  const key = g.generateApiKey({ prefix: "sk", checksum: true });
  const totpSecret = g.generateTotpSecret();
  const at = Math.floor(Date.now() / 1000);
  const [recovery] = g.generateRecoveryCodes(1);
  const otp = g.generateOtp();
  const encKey = g.generateEncryptionKey();
  const box = await g.SecretBox.create(encKey);
  const jwt = {};
  const kinds = {};
  for (const [alg, kind] of Object.entries(ALGS)) {
    kinds[kind] ??= await subtle.generateKey(GEN[kind], true, ["sign", "verify"]);
    const priv = pem("PRIVATE KEY", await subtle.exportKey("pkcs8", kinds[kind].privateKey));
    jwt[alg] = { token: await g.encodeJwt({ sub: "js", n: 1 }, priv, { algorithm: alg }), public: pem("PUBLIC KEY", await subtle.exportKey("spki", kinds[kind].publicKey)) };
  }
  return {
    from: "js",
    key, hash: await g.hashApiKey(key), hmac: await g.hashApiKey(key, PEPPER),
    derived: { secret: "derive-secret", seed: "user-42", include: "ctx", key: await g.deriveApiKey({ secret: "derive-secret", seed: "user-42", include: "ctx", prefix: "dk", checksum: true }) },
    code: { code: "123456", hashed: await g.hashCode("123456", PEPPER) },
    recovery: { code: recovery, hashed: await g.hashRecoveryCode(recovery) },
    otp: { code: otp.value, hashed: await g.hashOtp(otp, PEPPER) },
    totp: { secret: totpSecret, at, code: await g.totp(totpSecret, at), sha512: await g.totp(totpSecret, at, { algorithm: "sha512", digits: 8 }) },
    signed: await g.generateSignedToken(SECRET, { uid: 42, name: "José ✓" }, { purpose: "login", context: "session-1" }),
    hs256: await g.encodeJwt({ sub: "js", roles: ["a"] }, SECRET, { algorithm: "HS512", issuer: "js", audience: "py" }),
    jwt,
    secretbox: { key: encKey, token: await box.encrypt("JBSWY3DPEHPK3PXP ✓", "user-42") },
  };
}

async function verify(d) {
  const results = {
    "hash": await g.verifyApiKey(d.key, d.hash),
    "hmac": await g.verifyApiKey(d.key, d.hmac, PEPPER),
    "checksum": g.verifyChecksum(d.key),
    "derived": (await g.deriveApiKey({ secret: d.derived.secret, seed: d.derived.seed, include: d.derived.include, prefix: "dk", checksum: true })) === d.derived.key,
    "pbkdf2": await g.verifyCode(d.code.code, d.code.hashed, PEPPER),
    "recovery": (await g.verifyRecoveryCode(d.recovery.code.toLowerCase(), [d.recovery.hashed])) === d.recovery.hashed,
    "otp": await g.verifyOtp(d.otp.code, d.otp.hashed, null, { pepper: PEPPER }),
    "totp": (await g.totp(d.totp.secret, d.totp.at)) === d.totp.code && (await g.totp(d.totp.secret, d.totp.at, { algorithm: "sha512", digits: 8 })) === d.totp.sha512,
    "signed token": g.verifySignedToken(d.signed, SECRET, { purpose: "login", context: "session-1" }).then((r) => r?.uid === 42 && r?.name === "José ✓"),
    "jwt HS512": g.decodeJwt(d.hs256, SECRET, { algorithms: ["HS512"], issuer: d.from, audience: d.from === "js" ? "py" : "js" }).then((r) => r?.sub === d.from),
    "secretbox": (await (await g.SecretBox.create(d.secretbox.key)).decrypt(d.secretbox.token, "user-42")) === "JBSWY3DPEHPK3PXP ✓",
  };
  for (const [alg, j] of Object.entries(d.jwt)) results[`jwt ${alg}`] = g.decodeJwt(j.token, j.public, { algorithms: [alg] }).then((r) => r?.sub === d.from);
  const out = Object.fromEntries(await Promise.all(Object.entries(results).map(async ([k, v]) => [k, await v])));
  const failed = Object.entries(out).filter(([, ok]) => !ok).map(([k]) => k);
  console.log(`JS verified ${Object.keys(out).length - failed.length}/${Object.keys(out).length} values made by ${d.from}`);
  if (failed.length) {
    console.error("FAILED:", failed.join(", "));
    process.exit(1);
  }
}

const mode = process.argv[2];
if (mode === "make") process.stdout.write(JSON.stringify(await make(), null, 1));
else if (mode === "verify") await verify(JSON.parse(readFileSync(process.argv[3] ?? 0, "utf8")));
else {
  console.error("usage: node test/interop.mjs make | verify [file]");
  process.exit(2);
}
