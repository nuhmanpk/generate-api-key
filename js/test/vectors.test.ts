/**
 * Runs spec/vectors.json (generated from the Python implementation) against
 * the JS package. This is the cross-language compatibility contract.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import V from "../../spec/vectors.json" with { type: "json" };
import * as g from "../src/index.js";
import { alphabet } from "../src/charsets.js";
import { fromHex, toHex } from "../src/internal/bytes.js";
import { _setRandomSource } from "../src/internal/webcrypto.js";
import { derivedKey, randomKey } from "../src/keys.js";
import { decodeSecret } from "../src/mfa.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any;
const v = V as Any;

/** Same semantics as the Python generator's ``frozen(rand=...)``: a repeating byte pool. */
function feed(bytes: Uint8Array): void {
  let pool: number[] = [];
  _setRandomSource((n) => {
    while (pool.length < n) pool.push(...bytes);
    const out = Uint8Array.from(pool.slice(0, n));
    pool = pool.slice(n);
    return out;
  });
}

function at(seconds: number): void {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(seconds * 1000);
}

afterEach(() => {
  _setRandomSource(null);
  vi.useRealTimers();
});

/** Python ValueError/TypeError ⇢ JS RangeError/TypeError: both count as "error". */
async function outcome(fn: () => unknown): Promise<{ result?: unknown; error?: string }> {
  try {
    return { result: await fn() };
  } catch (e) {
    if (e instanceof RangeError || e instanceof TypeError) return { error: "error" };
    throw e;
  }
}
const expectOutcome = (got: { result?: unknown; error?: string }, want: Any, label?: unknown): void => {
  if ("error" in want) expect(got, JSON.stringify(label)).toHaveProperty("error");
  else expect(got, JSON.stringify(label)).toEqual({ result: want.result });
};

/** Python snake_case options ⇢ JS camelCase. */
const camel = (o: Record<string, unknown>): Record<string, unknown> =>
  Object.fromEntries(Object.entries(o).map(([k, val]) => [k.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase()), val]));

it("implements spec v1", () => {
  expect(v.spec_version).toBe(g.SPEC_VERSION);
});

describe("charsets", () => {
  it("presets", () => {
    for (const [name, cases] of Object.entries<Record<string, string>>(v.charsets.presets)) {
      for (const [c, chars] of Object.entries(cases)) expect(g.buildCharset(name, c as g.Case)).toBe(chars);
      expect((g.CHARSETS as Record<string, string>)[name]).toBe(cases.mixed);
    }
  });
  it("custom + errors", async () => {
    for (const c of v.charsets.custom) expectOutcome(await outcome(() => g.buildCharset(c.charset, c.case)), c, c);
  });
  it("entropy", () => {
    for (const e of v.charsets.entropy_bits) expect(g.entropyBits(e.length, e.charset, e.case)).toBeCloseTo(e.bits, 9);
  });
});

it("random sampling consumes bytes exactly like Python", () => {
  for (const s of v.random_sampling) {
    feed(fromHex(s.stream_hex));
    expect(randomKey(s.length, s.chars)).toBe(s.result);
  }
});

describe("derived keys", () => {
  it("match Python byte for byte", async () => {
    for (const d of v.derived_keys) {
      const o = { ...d.options };
      if ("salt_hex" in o) {
        expect(await derivedKey(o.secret, o.seed, null, 32, alphabet("alphanumeric").chars, fromHex(o.salt_hex))).toBe(d.result);
        continue;
      }
      const { secret, seed, ...rest } = o;
      const got = await outcome(() => {
        if (secret == null || seed == null) throw new RangeError("both");
        if (rest.include !== undefined && secret == null) throw new RangeError("include");
        return g.deriveApiKey({ secret, seed, ...camel(rest) } as g.DeriveOptions & { expiry?: undefined });
      });
      expectOutcome(got, d, d.options);
    }
  });
});

describe("random key formats", () => {
  it("shape", () => {
    for (const f of v.random_key_formats) {
      if (!f.options) continue;
      const key = g.generateApiKey({ ...camel(f.options), onWeakKey: false } as g.KeyOptions);
      expect(Array.from(key).length).toBe(f.length_total);
      if (f.options.checksum) expect(g.verifyChecksum(key)).toBe(true);
      if (f.options.prefix) expect(key.startsWith(f.options.prefix + (f.options.separator ?? "-"))).toBe(true);
      const sampleChars = new Set(Array.from(f.sample as string));
      expect(sampleChars.size).toBeGreaterThan(1);
    }
  });
  it("weak-key warning threshold", () => {
    const weak = v.random_key_formats.find((x: Any) => x.weak_key_warning).weak_key_warning;
    for (const w of weak) {
      let warned = false;
      g.generateApiKey({ ...camel(w.options), onWeakKey: () => (warned = true) } as g.KeyOptions);
      expect(warned, JSON.stringify(w.options)).toBe(w.weak);
    }
    expect(() => g.generateApiKey({ length: 16, minEntropy: 128 })).toThrow(RangeError);
  });
});

describe("checksums", () => {
  it("compute + verify", () => {
    for (const c of v.checksums.compute) expect(g.computeChecksum(c.input)).toBe(c.checksum);
    for (const c of v.checksums.verify) expect(g.verifyChecksum(c.key)).toBe(c.valid);
  });
});

describe("key hashes", () => {
  it("hash", async () => {
    for (const h of v.key_hashes.hash) expect(await g.hashApiKey(h.key, h.pepper)).toBe(h.hashed);
  });
  it("verify", async () => {
    for (const c of v.key_hashes.verify) expectOutcome(await outcome(() => g.verifyApiKey(c.key, c.hashed, c.pepper)), c, c);
    for (const c of v.key_hashes.pepper_errors) await expect(g.hashApiKey("k", c.pepper)).rejects.toThrow(RangeError);
  });
  it("subkeys", async () => {
    for (const s of v.key_hashes.subkeys) expect(toHex(await g.subkey(s.secret, s.label))).toBe(s.hex);
  });
});

describe("code hashes (PBKDF2)", () => {
  it("hash with pinned salt", async () => {
    for (const h of v.code_hashes.hash) {
      feed(fromHex(h.salt_hex));
      expect(await g.hashCode(h.code, h.pepper, h.iterations)).toBe(h.hashed);
    }
  });
  it("verify", async () => {
    for (const c of v.code_hashes.verify) expectOutcome(await outcome(() => g.verifyCode(c.code, c.hashed, c.pepper)), c, c);
  });
});

describe("recovery codes", () => {
  const r = v.recovery_codes;
  it("normalize", async () => {
    for (const n of r.normalize) expectOutcome(await outcome(() => g.normalizeRecoveryCode(n.input)), n, n);
  });
  it("hash", async () => {
    for (const h of r.hash) {
      feed(fromHex(h.salt_hex));
      expect(await g.hashRecoveryCode(h.code, h.pepper)).toBe(h.hashed);
    }
  });
  it("verify", async () => {
    for (const c of r.verify) {
      const m = await g.verifyRecoveryCode(c.code, c.hashes, c.pepper);
      expect(m === null ? null : c.hashes.indexOf(m)).toBe(c.match_index);
    }
  });
  it("format + errors", () => {
    expect(g.RECOVERY_ALPHABET).toBe(r.alphabet);
    for (const f of r.format) {
      const codes = g.generateRecoveryCodes(f.count, f.length, f.group);
      expect(codes).toHaveLength(f.count);
      expect(codes[0]!.length).toBe(f.sample.length);
      expect(new Set(codes).size).toBe(f.count);
    }
    for (const e of r.errors) expect(() => g.generateRecoveryCodes(e.count, e.length)).toThrow(RangeError);
  });
});

describe("one-time codes", () => {
  it("hash", async () => {
    for (const h of v.otp.hash) {
      feed(fromHex(h.salt_hex));
      expect(await g.hashOtp(h.code, h.pepper)).toBe(h.hashed);
    }
  });
  it("verify", async () => {
    for (const c of v.otp.verify) {
      at(v.now);
      expect(await g.verifyOtp(c.code, c.hashed, c.expires_at, { pepper: c.pepper }), JSON.stringify(c.code)).toBe(c.valid);
    }
  });
  it("generate + errors", () => {
    at(v.otp.generate.now);
    const code = g.generateOtp(v.otp.generate.digits, v.otp.generate.expiry_minutes);
    expect(code.expiresAt).toBe(v.otp.generate.expires_at);
    expect(code.value).toMatch(/^\d{6}$/);
    for (const e of v.otp.errors) expect(() => g.generateOtp(e.digits, e.expiry === "Infinity" ? Infinity : e.expiry)).toThrow(RangeError);
  });
});

describe("HOTP / TOTP / Steam", () => {
  const o = v.hotp_totp;
  it("HOTP (RFC 4226 + more)", async () => {
    for (const h of o.hotp) expect(await g.hotp(h.secret, BigInt(h.counter_str), { digits: h.digits, algorithm: h.algorithm })).toBe(h.code);
  });
  it("TOTP (RFC 6238 + more)", async () => {
    for (const t of o.totp) expect(await g.totp(t.secret, t.at, { period: t.period, digits: t.digits, algorithm: t.algorithm })).toBe(t.code);
  });
  it("secret decoding", async () => {
    for (const s of o.secrets) {
      const got = await outcome(() => toHex(decodeSecret(s.secret)));
      expectOutcome(got, "bytes_hex" in s ? { result: s.bytes_hex } : { error: s.error }, s.secret);
    }
  });
  it("findTotpStep", async () => {
    for (const f of o.find_totp_step) expect(await g.findTotpStep(f.secret, f.code, { at: f.at, ...camel(f.options) }), JSON.stringify(f)).toBe(f.step);
  });
  it("verifyHotp", async () => {
    for (const h of o.verify_hotp) expect(await g.verifyHotp(h.secret, h.code, h.counter, { lookAhead: h.look_ahead })).toBe(h.next_counter);
  });
  it("Steam", async () => {
    for (const s of o.steam) expect(await g.steamCode(s.secret, s.at)).toBe(s.code);
    for (const s of o.verify_steam) expect(await g.verifySteamCode(s.secret, s.code, { window: s.window, at: s.at })).toBe(s.valid);
  });
  it("errors", async () => {
    for (const e of o.errors) {
      const a = e.args;
      const fn = e.fn === "hotp" ? () => g.hotp(a.secret, a.counter, camel(a) as g.HotpOptions) : () => g.totp(a.secret, a.at, camel(a) as g.TotpOptions);
      expectOutcome(await outcome(fn), e, e);
    }
  });
});

describe("otpauth URIs", () => {
  it("totp/hotp URIs are byte-identical", async () => {
    for (const u of v.otpauth.uris) {
      const fn = u.kind === "totp" ? g.totpUri : g.hotpUri;
      expectOutcome(await outcome(() => fn(u.secret, u.account, u.issuer, camel(u.options))), u, u);
    }
  });
  it("Google migration URI", async () => {
    for (const m of v.otpauth.google_migration) {
      const id = m.batch_id as number;
      feed(Uint8Array.from([id >>> 24, (id >>> 16) & 255, (id >>> 8) & 255, id & 255]));
      expectOutcome(await outcome(() => g.googleMigrationUri(m.accounts)), m, m.accounts);
    }
  });
});

describe("scopes", () => {
  it("parse / has / all / any", () => {
    for (const p of v.scopes.parse) expect([...g.parseScopes(p.input)].sort()).toEqual(p.result);
    for (const h of v.scopes.has_scope) expect(g.hasScope(h.granted, h.required), JSON.stringify(h)).toBe(h.result);
    for (const a of v.scopes.all_any) {
      expect(g.hasAllScopes(a.granted, a.required)).toBe(a.all);
      expect(g.hasAnyScope(a.granted, a.required)).toBe(a.any);
    }
  });
});

describe("leak scanning", () => {
  it("keyPattern is the same regex text", async () => {
    for (const p of v.scanning.key_pattern) expectOutcome(await outcome(() => g.keyPattern(p.prefix, camel(p.options))), p, p);
  });
  it("findKeys", () => {
    for (const f of v.scanning.find_keys) expect(g.findKeys(f.text, f.prefix, camel(f.options)), JSON.stringify(f)).toEqual(f.found);
  });
  it("gitleaksRule", async () => {
    for (const r of v.scanning.gitleaks_rule) expectOutcome(await outcome(() => g.gitleaksRule(r.prefix, r.rule_id, camel(r.options))), r, r);
  });
});

describe("signed tokens", () => {
  it("generate is byte-identical", async () => {
    for (const t of v.signed_tokens.generate) {
      at(t.now);
      feed(fromHex(t.jti_hex));
      expect(await g.generateSignedToken(t.secret, t.data, { purpose: t.purpose, expiry: t.expiry, context: t.context }), JSON.stringify(t.data)).toBe(t.token);
    }
  });
  it("verify", async () => {
    for (const t of v.signed_tokens.verify) {
      at(t.now);
      const o = camel(t.options) as Any;
      expect(await g.verifySignedToken(t.token, t.secret, o), t.note ?? JSON.stringify(t.options)).toEqual(t.result);
    }
  });
  it("errors", async () => {
    for (const e of v.signed_tokens.errors) {
      const p = g.generateSignedToken(e.secret, null, e.expiry === undefined ? {} : { expiry: e.expiry });
      if ("error" in e) await expect(p, e.secret).rejects.toThrow(RangeError);
      else await expect(p, e.secret).resolves.toMatch(/\./);
    }
  });
});

describe("JWT HS*", () => {
  it("encode is byte-identical", async () => {
    for (const e of v.jwt_hs.encode) {
      at(e.now);
      expect(await g.encodeJwt(e.claims, e.secret, camel(e.options)), JSON.stringify(e.options)).toBe(e.token);
    }
  });
  it("decode", async () => {
    for (const d of v.jwt_hs.decode) {
      at(d.now);
      expect(await g.decodeJwt(d.token, d.secret, camel(d.options)), JSON.stringify(d.options)).toEqual(d.result);
    }
  });
  it("decoding is strict where Python is lenient (non-normative)", async () => {
    for (const l of v.jwt_hs.python_lenient_non_normative) {
      at(v.now);
      expect(await g.decodeJwt(l.token, v.jwt_hs.encode[0].secret)).toBeNull();
    }
  });
  it("errors", async () => {
    const t = v.jwt_hs.encode[0].token;
    const secret = v.jwt_hs.encode[0].secret;
    await expect(g.encodeJwt({}, secret, { algorithm: "none" as never })).rejects.toThrow(RangeError);
    await expect(g.encodeJwt({}, "short")).rejects.toThrow(RangeError);
    await expect(g.decodeJwt(t, secret, { algorithms: ["none" as never] })).rejects.toThrow(RangeError);
    await expect(g.decodeJwt(t, secret, { algorithms: [] })).rejects.toThrow(RangeError);
    await expect(g.decodeJwt(t, secret, { algorithms: ["HS256", "RS256"] })).rejects.toThrow(RangeError);
  });
});

describe("JWT RS/PS/ES/EdDSA (verify-only vectors)", () => {
  const j = v.jwt_asym;
  it("no private key material is stored", () => {
    expect(JSON.stringify(j)).not.toMatch(/PRIVATE KEY/);
  });
  it("verify", async () => {
    for (const c of j.verify) {
      at(c.now);
      const got = await outcome(() => g.decodeJwt(c.token, j.keys[c.key][c.key_form], { algorithms: c.algorithms }));
      expectOutcome(got, c, `${c.alg} ${c.key}/${c.key_form}`);
    }
  });
  it("JWKS", async () => {
    for (const d of j.jwks_decode) {
      at(d.now);
      const got = await g.decodeJwtJwks(d.token, j.jwks, { algorithms: d.algorithms });
      if ("error" in d) {
        // Python raises when a no-kid token meets a JWK of another type; JS skips such keys (spec §10).
        const claims = await g.decodeJwt(d.token, j.keys.ed25519.public_spki, { algorithms: d.algorithms });
        const header = JSON.parse(atob(d.token.split(".")[0].replace(/-/g, "+").replace(/_/g, "/")));
        expect(got).toEqual(header.kid === undefined ? claims : null);
      } else expect(got).toEqual(d.result);
    }
  });
});

describe("SecretBox", () => {
  const sb = v.secretbox;
  it("encrypt is byte-identical", async () => {
    for (const e of sb.encrypt) {
      feed(fromHex(e.nonce_hex));
      expect(await (await g.SecretBox.create(e.key)).encrypt(e.plaintext, e.aad)).toBe(e.token);
    }
  });
  it("decrypt", async () => {
    for (const d of sb.decrypt) {
      const box = await g.SecretBox.create(d.key, d.old_keys);
      let got: Any;
      try {
        got = { result: await box.decrypt(d.token, d.aad) };
      } catch (e) {
        expect(e).toBeInstanceOf(g.DecryptionError);
        got = { error: "DecryptionError" };
      }
      expect(got, d.token).toEqual("error" in d ? { error: d.error } : { result: d.result });
    }
  });
  it("rotation, key ids, bad keys", async () => {
    for (const r of sb.rotation) expect((await g.SecretBox.create(r.key, r.old_keys)).needsRotation(r.token)).toBe(r.needs_rotation);
    for (const k of sb.key_ids) expect((await g.SecretBox.create(k.key)).keyId).toBe(k.key_id);
    for (const k of sb.key_errors) await expect(g.SecretBox.create(k.key)).rejects.toThrow(RangeError);
  });
});

describe("APIKeyAuth", () => {
  const a = v.auth;
  it("constants", () => {
    expect(g.MAX_KEY_LENGTH).toBe(a.max_key_length);
  });
  it("extract", () => {
    for (const e of a.extract) {
      const auth = new g.APIKeyAuth({ lookup: () => null, ...camel(e.options) });
      expect(auth.extract(e.headers, e.query), JSON.stringify(e)).toBe(e.key);
    }
  });
  it("well-formed pre-checks", () => {
    for (const w of a.well_formed) expect(new g.APIKeyAuth({ lookup: () => null, ...camel(w.options) }).wellFormed(w.key)).toBe(w.well_formed);
  });
  it("recordIsActive / pathExcluded / hints / challenge", () => {
    for (const r of a.record_is_active) {
      at(r.now);
      expect(g.recordIsActive(r.record), JSON.stringify(r.record)).toBe(r.active);
    }
    for (const p of a.path_excluded) expect(g.pathExcluded(p.path, p.exclude), JSON.stringify(p)).toBe(p.excluded);
    for (const h of a.hints) expect(g.keyHint(h.key)).toBe(h.hint);
    for (const c of a.challenge) expect(new g.APIKeyAuth({ lookup: () => null, ...camel(c.options) }).challenge()).toBe(c.challenge);
  });
  it("authenticate flows (peppers, rehash, scopes, status codes)", async () => {
    const f = a.authenticate;
    for (const flow of f.flows) {
      at(v.now);
      const rehashed: unknown[] = [];
      const opts = flow.options;
      const auth = new g.APIKeyAuth<Any>({
        lookup: (h) => f.table[h] ?? null,
        pepper: f.pepper,
        previousPeppers: f.previous_peppers,
        requireChecksum: f.require_checksum,
        onRehash: (r, h) => void rehashed.push([r.id, h]),
        ...(opts.required_scopes ? { requiredScopes: opts.required_scopes } : {}),
        ...(opts.prefix ? { prefix: opts.prefix } : {}),
      });
      let got: Any;
      try {
        got = { record_id: (await auth.authenticate(flow.key, null, opts.scopes)).id };
      } catch (e) {
        got = { status: (e as g.AuthError).status, detail: (e as g.AuthError).detail };
      }
      const want = Object.fromEntries(["record_id", "status", "detail"].filter((k) => k in flow).map((k) => [k, flow[k]]));
      expect(got, JSON.stringify(flow.options)).toEqual(want);
      expect(rehashed).toEqual(flow.rehashed);
    }
  });
  it("issueApiKey with pinned randomness", async () => {
    for (const i of a.issue_api_key) {
      feed(fromHex(i.rand_hex));
      const issued = await g.issueApiKey({ prefix: i.options.prefix, pepper: i.options.pepper });
      expect(issued.key).toBe(i.key);
      expect(issued.hashed).toBe(i.hashed);
      expect(issued.hint).toBe(i.hint);
    }
  });
  it("Redis limiter keys + script are shared with Python", async () => {
    const r = a.redis_limiter_keys;
    expect(g.REDIS_LIMITER_SCRIPT).toBe(r.script);
    const lim = new g.RedisAttemptLimiter({ eval: async () => 1, get: async () => null, del: async () => 1 }, { prefix: r.prefix });
    for (const k of r.keys) expect(await lim.redisKey(k.key)).toBe(k.redis_key);
  });
});
