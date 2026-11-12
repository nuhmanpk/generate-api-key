// Micro-benchmarks, same operations as python/benchmarks/bench.py.
// Run: npm run build && node bench/bench.mjs
import * as g from "../dist/index.js";

const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

async function bench(label, fn, n = 20_000) {
  for (let i = 0; i < Math.min(n, 1000); i++) await fn(); // warm-up
  let best = Infinity;
  for (let r = 0; r < 3; r++) {
    const t0 = performance.now();
    for (let i = 0; i < n; i++) await fn();
    best = Math.min(best, (performance.now() - t0) / n);
  }
  const us = best * 1000;
  console.log(`${label.padEnd(44)} ${us.toFixed(2).padStart(9)} us/op   ${Math.round(1e6 / us).toLocaleString("en-US").padStart(12)} ops/s`);
  return best;
}

function naive() {
  // Common hand-rolled approach: one getRandomValues per char, modulo bias included.
  const buf = new Uint32Array(1);
  let s = "";
  for (let i = 0; i < 32; i++) s += ALNUM[crypto.getRandomValues(buf)[0] % 62];
  return s;
}

console.log(`${"operation".padEnd(44)} ${"time".padStart(12)}   ${"throughput".padStart(16)}`);
const base = await bench("baseline: getRandomValues per char x32", naive);
const fast = await bench("randomKey(32)  (rejection sampling)", () => g.randomKey(32, ALNUM));
console.log(`${"  -> speed-up vs baseline".padEnd(44)} ${(base / fast).toFixed(1).padStart(9)}x`);
await bench("generateApiKey()", () => g.generateApiKey());
await bench("generateApiKey({prefix, checksum})", () => g.generateApiKey({ prefix: "sk", checksum: true }));
await bench("deriveApiKey({secret, seed})  derived", () => g.deriveApiKey({ secret: "s".repeat(32), seed: "user-1" }));
const key = g.generateApiKey();
const stored = await g.hashApiKey(key, "pepper");
await bench("verifyApiKey (HMAC-SHA256)", () => g.verifyApiKey(key, stored, "pepper"));
const secret = g.generateTotpSecret();
const code = await g.totpNow(secret);
await bench("verifyTotp (window=1)", () => g.verifyTotp(secret, code));
await bench("hashOtp (PBKDF2 100k, deliberately slow)", () => g.hashOtp("123456"), 20);
