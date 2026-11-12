/** Unit tests for behaviour the shared vectors don't pin (randomness, API ergonomics, limits). */

import { afterEach, describe, expect, it, vi } from "vitest";
import pkg from "../package.json" with { type: "json" };
import * as g from "../src/index.js";

afterEach(() => vi.useRealTimers());

describe("generateApiKey", () => {
  it("defaults: 32 alphanumeric chars, ~190 bits", () => {
    const k = g.generateApiKey();
    expect(k).toMatch(/^[A-Za-z0-9]{32}$/);
    expect(g.entropyBits(32)).toBeCloseTo(190.53, 1);
  });

  it("is unbiased (chi-square over 200k hex chars)", () => {
    const counts = new Map<string, number>();
    const s = g.generateApiKeys(1000, { length: 200, charset: "hex" }).join("");
    for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
    const expected = s.length / 16;
    let chi = 0;
    for (const n of counts.values()) chi += (n - expected) ** 2 / expected;
    expect(counts.size).toBe(16);
    expect(chi).toBeLessThan(60); // df=15; p ≈ 1e-7 for a false failure
  });

  it("is unbiased for alphabets that don't divide 256 (62 chars)", () => {
    const counts = new Map<string, number>();
    const s = g.generateApiKeys(2000, { length: 100 }).join("");
    for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
    const expected = s.length / 62;
    let chi = 0;
    for (const n of counts.values()) chi += (n - expected) ** 2 / expected;
    expect(chi).toBeLessThan(140); // df=61
  });

  it("never repeats", () => {
    const keys = g.generateApiKeys(10_000);
    expect(new Set(keys).size).toBe(10_000);
  });

  it("prefix, separator, dashes, checksum", () => {
    const k = g.generateApiKey({ prefix: "sk_live", separator: "_", dashes: true, checksum: true });
    expect(k).toMatch(/^sk_live_([A-Za-z0-9]{4}-){7}[A-Za-z0-9]{4}[0-9A-Za-z]{6}$/);
    expect(g.verifyChecksum(k)).toBe(true);
    expect(g.verifyChecksum(k.slice(0, -1) + (k.endsWith("A") ? "B" : "A"))).toBe(false);
  });

  it("non-ASCII and large alphabets", () => {
    expect(Array.from(g.generateApiKey({ charset: "αβγδεζηθ", length: 50, onWeakKey: false }))).toHaveLength(50);
    const big = Array.from({ length: 300 }, (_, i) => String.fromCodePoint(0x4e00 + i)).join("");
    expect(Array.from(g.generateApiKey({ charset: big, length: 30 }))).toHaveLength(30);
    expect(Array.from(g.generateApiKey({ charset: "😀😁😂🤣", length: 70 })).every((c) => "😀😁😂🤣".includes(c))).toBe(true);
  });

  it("expiry returns an ApiKey with unix-second expiresAt", () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(1_700_000_000_000);
    const k = g.generateApiKey({ expiry: 60 });
    expect(k).toBeInstanceOf(g.ApiKey);
    expect(k.expiresAt).toBe(1_700_003_600);
    expect(k.isExpired).toBe(false);
    expect(`${k}`).toBe(k.value);
    expect(JSON.stringify({ k })).toBe(JSON.stringify({ k: k.value }));
    expect(k.redacted()).toMatch(/^ApiKey\('.{4}….{4}', expiresAt=1700003600\)$/);
    vi.setSystemTime(1_700_003_600_000);
    expect(k.isExpired).toBe(true);
    expect(g.isExpired(k)).toBe(true);
  });

  it("weak keys warn once per batch, minEntropy throws", () => {
    const warn = vi.fn();
    g.generateApiKeys(5, { length: 10, onWeakKey: warn });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(() => g.generateApiKey({ length: 10, minEntropy: 128 })).toThrow(RangeError);
  });

  it("rejects bad options", () => {
    expect(() => g.generateApiKey({ length: 0 })).toThrow(RangeError);
    expect(() => g.generateApiKey({ length: 1.5 })).toThrow(RangeError);
    expect(() => g.generateApiKey({ charset: "a" })).toThrow(RangeError);
    expect(() => g.generateApiKey({ case: "title" as never })).toThrow(RangeError);
    expect(() => g.generateApiKey({ dashes: true, dashGroup: 0 })).toThrow(RangeError);
    expect(() => g.generateApiKey({ expiry: 0 } as never)).toThrow(RangeError);
    expect(() => g.generateApiKey({ secret: "x", seed: "y" } as never)).toThrow(TypeError);
  });
});

describe("deriveApiKey", () => {
  it("is deterministic and input-separated", async () => {
    const a = await g.deriveApiKey({ secret: "s3cret", seed: "user-1" });
    expect(await g.deriveApiKey({ secret: "s3cret", seed: "user-1" })).toBe(a);
    expect(await g.deriveApiKey({ secret: "s3cret", seed: "user-2" })).not.toBe(a);
    expect(await g.deriveApiKey({ secret: "ab", seed: "c" })).not.toBe(await g.deriveApiKey({ secret: "a", seed: "bc" }));
    await expect(g.deriveApiKey({ secret: "", seed: "x" })).rejects.toThrow(RangeError);
  });
});

describe("hashing never throws on attacker input", () => {
  it("verifyApiKey / verifyCode / verifyChecksum", async () => {
    for (const bad of [null, undefined, 1, {}, [], "", "\u0000", "é".repeat(1000)]) {
      expect(await g.verifyApiKey(bad, "sha256$00")).toBe(false);
      expect(await g.verifyApiKey("k", bad)).toBe(false);
      expect(await g.verifyCode(bad, "pbkdf2-sha256$1000$AA$AA")).toBe(false);
      expect(await g.verifyCode("1", bad)).toBe(false);
      expect(g.verifyChecksum(bad)).toBe(false);
    }
    expect(await g.verifyCode("1", "pbkdf2-sha256$100000000$AA$AA")).toBe(false);
  });
  it("hash round trip + ApiKey.hash", async () => {
    const k = g.generateApiKey({ expiry: 5 });
    const h = await k.hash("pepper");
    expect(h.startsWith("hmac-sha256$")).toBe(true);
    expect(await g.verifyApiKey(k, h, "pepper")).toBe(true);
    expect(await g.verifyApiKey(k.value, h)).toBe(false);
  });
  it("code hashes are salted", async () => {
    const a = await g.hashCode("123456", null, 1000);
    const b = await g.hashCode("123456", null, 1000);
    expect(a).not.toBe(b);
    expect(await g.verifyCode("123456", a)).toBe(true);
  });
});

describe("MFA", () => {
  it("TOTP round trip with replay protection", async () => {
    const secret = g.generateTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    const code = await g.totpNow(secret);
    const step = await g.findTotpStep(secret, code);
    expect(step).not.toBeNull();
    expect(await g.verifyTotp(secret, code, { lastUsedStep: step })).toBe(false);
  });
  it("recovery codes round trip with look-alikes", async () => {
    const [code] = g.generateRecoveryCodes(1);
    const hashes = [await g.hashRecoveryCode(code!)];
    expect(await g.verifyRecoveryCode(code!.toLowerCase().replace("-", " "), hashes)).toBe(hashes[0]);
  });
  it("OTP expiry", async () => {
    const code = g.generateOtp(6, 1);
    const h = await g.hashOtp(code);
    expect(await g.verifyOtp(code.value, h, code.expiresAt)).toBe(true);
    expect(await g.verifyOtp(code.value, h, Date.now() / 1000 - 1)).toBe(false);
  });
  it("AttemptLimiter counts before verification", () => {
    const lim = new g.AttemptLimiter({ maxAttempts: 3, window: 60 });
    expect([lim.hit("u"), lim.hit("u"), lim.hit("u"), lim.hit("u")]).toEqual([true, true, true, false]);
    expect(lim.isBlocked("u")).toBe(true);
    expect(lim.remaining("u")).toBe(0);
    lim.reset("u");
    expect(lim.fail("u")).toBe(2);
    const small = new g.AttemptLimiter({ maxKeys: 2 });
    small.hit("a");
    small.hit("b");
    small.hit("c");
    expect(small.remaining("a")).toBe(5);
  });
});

describe("signed tokens", () => {
  const secret = "0123456789abcdef-secret";
  it("purpose, context and expiry", async () => {
    const t = await g.generateSignedToken(secret, { uid: 1 }, { purpose: "login", context: "sess" });
    expect(await g.verifySignedToken(t, secret, { purpose: "login", context: "sess" })).toEqual({ uid: 1 });
    expect(await g.verifySignedToken(t, secret, { purpose: "reset", context: "sess" })).toBeNull();
    expect(await g.verifySignedToken(t, secret, { purpose: "login" })).toBeNull();
    const meta = await g.verifySignedToken(t, secret, { purpose: "login", context: "sess", withMeta: true });
    expect(meta?.jti).toMatch(/^[A-Za-z0-9_-]{16}$/);
    await expect(g.verifySignedToken(t, "short")).rejects.toThrow(RangeError);
    for (const bad of [null, 1, "", "a.b.c", "é.é", "x".repeat(9000)]) expect(await g.verifySignedToken(bad, secret)).toBeNull();
  });
});

describe("SecretBox", () => {
  it("rotation and tamper detection", async () => {
    const k1 = g.generateEncryptionKey();
    const k2 = g.generateEncryptionKey();
    const old = await g.SecretBox.create(k1);
    const t = await old.encrypt("JBSWY3DPEHPK3PXP", "user-1");
    const box = await g.SecretBox.create(k2, [k1]);
    expect(box.needsRotation(t)).toBe(true);
    expect(await box.decrypt(t, "user-1")).toBe("JBSWY3DPEHPK3PXP");
    const fresh = await box.rotate(t, "user-1");
    expect(box.needsRotation(fresh)).toBe(false);
    await expect(box.decrypt(t, "user-2")).rejects.toBeInstanceOf(g.DecryptionError);
    await expect(box.decrypt(t.slice(0, -2) + (t.endsWith("AA") ? "BB" : "AA"), "user-1")).rejects.toBeInstanceOf(g.DecryptionError);
    expect(String(box)).not.toContain(k1);
  });
});

describe("APIKeyAuth + KeyStore", () => {
  it("issues, authenticates, scopes, revokes, rotates", async () => {
    const store = new g.KeyStore(new g.MemoryKeyStorage(), { pepper: "pepper-now" });
    const created = await store.create("ci-bot", { prefix: "sk", scopes: ["read:*"], meta: { team: "x" } });
    expect(created.record.hint).toMatch(/^sk-.{4}….{4}$/);
    const auth = new g.APIKeyAuth({ lookup: store.lookup, pepper: "pepper-now", prefix: "sk", requireChecksum: true });
    expect((await auth.authenticate(created.key)).id).toBe(created.id);
    expect((await auth.authenticate(created.key, null, ["read:users"])).name).toBe("ci-bot");
    await expect(auth.authenticate(created.key, null, ["write:users"])).rejects.toMatchObject({ status: 403 });
    const rotated = await store.rotate(created.id, { graceMinutes: 0, prefix: "sk" });
    expect(rotated.record.scopes).toEqual(["read:*"]);
    await expect(auth.authenticate(created.key)).rejects.toMatchObject({ status: 401, detail: "Invalid API key." });
    expect((await auth.authenticate(rotated.key)).id).toBe(rotated.id);
    expect(await store.revoke(rotated.id)).toBe(true);
    expect(await store.revoke(rotated.id)).toBe(false);
    await expect(auth.authenticate(rotated.key)).rejects.toMatchObject({ status: 401 });
    expect((await store.list({ activeOnly: true })).length).toBe(0);
    expect((await store.get(rotated.id))?.lastUsedAt).toBeTypeOf("number");
  });
  it("limiter returns 429 after repeated bad keys", async () => {
    const auth = new g.APIKeyAuth({ lookup: () => null, limiter: new g.AttemptLimiter({ maxAttempts: 2 }) });
    for (let i = 0; i < 2; i++) await expect(auth.authenticate("bad", "1.2.3.4")).rejects.toMatchObject({ status: 401 });
    await expect(auth.authenticate("bad", "1.2.3.4")).rejects.toMatchObject({ status: 429 });
    await expect(auth.authenticate("bad", "5.6.7.8")).rejects.toMatchObject({ status: 401 });
  });
  it("reads Fetch Headers, Maps and plain objects", () => {
    const auth = new g.APIKeyAuth({ lookup: () => null, queryParam: "key" });
    expect(auth.extract(new Headers({ authorization: "Bearer abc" }))).toBe("abc");
    expect(auth.extract(new Map([["x-api-key", "m"]]))).toBe("m");
    expect(auth.extract({ "X-API-KEY": "o" })).toBe("o");
    expect(auth.extract({}, new URLSearchParams("key=q"))).toBe("q");
    expect(auth.extract({ "x-api-key": ["a", "b"] })).toBeNull();
  });
});

describe("timingSafeEqual", () => {
  it("compares strings without throwing", () => {
    expect(g.timingSafeEqual("a", "a")).toBe(true);
    expect(g.timingSafeEqual("a", "b")).toBe(false);
    expect(g.timingSafeEqual("é", "é")).toBe(true);
    expect(g.timingSafeEqual(1, "1")).toBe(false);
  });
});

describe("release metadata", () => {
  it("VERSION matches package.json (and the PyPI version, checked on the Python side)", () => {
    expect(g.VERSION).toBe(pkg.version);
    expect((pkg as { dependencies?: object }).dependencies ?? {}).toEqual({});
  });
});

describe("review fixes", () => {
  it("generateApiKeys honours expiry", () => {
    const keys = g.generateApiKeys(2, { expiry: 5 });
    expect(keys.every((k) => k instanceof g.ApiKey && k.expiresAt !== null)).toBe(true);
  });
  it("recordIsActive reads millisecond timestamps as milliseconds", () => {
    expect(g.recordIsActive({ expires_at: Date.now() - 1000 })).toBe(false);
    expect(g.recordIsActive({ expires_at: Date.now() + 60_000 })).toBe(true);
    expect(g.recordIsActive({ expires_at: Date.now() / 1000 + 60 })).toBe(true);
  });
  it("RedisAttemptLimiter passes string arguments", async () => {
    let seen: unknown[] = [];
    const lim = new g.RedisAttemptLimiter({ eval: async (_s, _k, a) => ((seen = a), 1), get: async () => null, del: async () => 1 });
    await lim.hit("x");
    expect(seen.every((a) => typeof a === "string")).toBe(true);
  });
  it("warns once when a limiter can't see the client", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const auth = new g.APIKeyAuth({ lookup: () => null, limiter: new g.AttemptLimiter() });
    await expect(auth.authenticate("bad")).rejects.toMatchObject({ status: 401 });
    await expect(auth.authenticate("bad")).rejects.toMatchObject({ status: 401 });
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });
  it("KeyStore.lookup returns the updated lastUsedAt", async () => {
    const store = new g.KeyStore();
    const made = await store.create("x");
    expect((await store.find(made.key))?.lastUsedAt).toBeTypeOf("number");
  });
  it("recovery code arguments must be integers", () => {
    expect(() => g.generateRecoveryCodes(1.5)).toThrow(RangeError);
  });
});
