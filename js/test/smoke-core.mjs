// Shared smoke checks (see smoke.mjs). Exported as run() so it can also execute
// inside a request handler on Cloudflare Workers, where top-level crypto is not allowed.
import * as g from "../dist/index.js";
import { qrMatrix } from "../dist/qr.js";
import V from "../../spec/vectors.json" with { type: "json" };

export async function run() {
  const runtime = globalThis.Deno ? `deno ${Deno.version.deno}` : globalThis.Bun ? `bun ${Bun.version}` : globalThis.navigator?.userAgent === "Cloudflare-Workers" ? "cloudflare workerd" : `node ${globalThis.process?.version}`;
  let passed = 0;
  const failures = [];
  const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  function check(label, got, want) {
    if (eq(got, want)) passed++;
    else failures.push(`${label}\n    got:  ${JSON.stringify(got)}\n    want: ${JSON.stringify(want)}`);
  }
  const camel = (o) => Object.fromEntries(Object.entries(o ?? {}).map(([k, v]) => [k.replace(/_([a-z])/g, (_, c) => c.toUpperCase()), v]));
  const realNow = Date.now;
  const at = (s) => (Date.now = () => s * 1000);

  for (const d of V.derived_keys) {
    const { secret, seed, salt_hex, ...rest } = d.options;
    if (salt_hex || !("result" in d)) continue;
    check(`derive ${JSON.stringify(d.options)}`, await g.deriveApiKey({ secret, seed, ...camel(rest) }), d.result);
  }
  for (const c of V.checksums.compute) check(`checksum ${c.input}`, g.computeChecksum(c.input), c.checksum);
  for (const h of V.key_hashes.hash) check(`hash ${h.key}`, await g.hashApiKey(h.key, h.pepper), h.hashed);
  for (const c of V.code_hashes.verify) if ("result" in c) check(`verifyCode ${c.hashed}`, await g.verifyCode(c.code, c.hashed, c.pepper), c.result);
  for (const t of V.hotp_totp.totp) check(`totp ${t.at} ${t.algorithm}`, await g.totp(t.secret, t.at, camel(t)), t.code);
  for (const s of V.hotp_totp.steam) check(`steam ${s.at}`, await g.steamCode(s.secret, s.at), s.code);
  for (const u of V.otpauth.uris) if ("result" in u) check(`uri ${u.account}`, (u.kind === "totp" ? g.totpUri : g.hotpUri)(u.secret, u.account, u.issuer, camel(u.options)), u.result);
  for (const h of V.scopes.has_scope) check(`scope ${h.required}`, g.hasScope(h.granted, h.required), h.result);
  for (const f of V.scanning.find_keys) check(`findKeys`, g.findKeys(f.text, f.prefix, camel(f.options)), f.found);
  for (const t of V.signed_tokens.verify) {
    at(t.now);
    check(`signed token ${t.note ?? ""}`, await g.verifySignedToken(t.token, t.secret, camel(t.options)), t.result);
  }
  for (const d of V.jwt_hs.decode) {
    at(d.now);
    check(`jwt hs ${JSON.stringify(d.options)}`, await g.decodeJwt(d.token, d.secret, camel(d.options)), d.result);
  }
  const unsupported = new Set();
  for (const c of V.jwt_asym.verify) {
    if (!("result" in c)) continue;
    at(c.now);
    try {
      check(`jwt ${c.alg} ${c.key_form}`, await g.decodeJwt(c.token, V.jwt_asym.keys[c.key][c.key_form], { algorithms: c.algorithms }), c.result);
    } catch (e) {
      // Some runtimes lack an algorithm (e.g. P-521 or Ed25519); report, don't hide.
      if (/can't use/.test(e.message)) unsupported.add(c.alg);
      else throw e;
    }
  }
  Date.now = realNow;
  for (const d of V.secretbox.decrypt) {
    const box = await g.SecretBox.create(d.key, d.old_keys);
    let got;
    try {
      got = { result: await box.decrypt(d.token, d.aad) };
    } catch (e) {
      got = { error: e instanceof g.DecryptionError ? "DecryptionError" : String(e) };
    }
    check(`secretbox ${d.token.slice(0, 12)}`, got, "error" in d ? { error: d.error } : { result: d.result });
  }
  const key = g.generateApiKey({ prefix: "sk", checksum: true });
  check("random key round trip", [g.verifyChecksum(key), await g.verifyApiKey(key, await g.hashApiKey(key, "p"), "p")], [true, true]);
  check("qr", qrMatrix("hello").length, 25);

  return { runtime, passed, failures, unsupported: [...unsupported] };
}
