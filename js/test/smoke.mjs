// Runtime smoke test against the built package (dist/), with no test framework,
// so it runs unchanged on Node 20+, Bun and Deno:
//   node test/smoke.mjs      bun test/smoke.mjs      deno run --allow-read test/smoke.mjs
// Cloudflare Workers: node test/workers.mjs (runs the same checks inside workerd).
// It replays the deterministic parts of spec/vectors.json (generated from Python).
import { run } from "./smoke-core.mjs";

const { runtime, passed, failures, unsupported } = await run();
console.log(`[${runtime}] ${passed} passed, ${failures.length} failed${unsupported.length ? `; not supported by this runtime: ${unsupported.join(", ")}` : ""}`);
if (failures.length) {
  console.error(failures.slice(0, 20).join("\n"));
  (globalThis.Deno ? Deno.exit : process.exit)(1);
}
