// Run the smoke checks inside Cloudflare's real runtime (workerd, via Miniflare):
//   npm run build && node test/workers.mjs
import { build } from "esbuild";
import { Miniflare } from "miniflare";

const bundle = await build({
  stdin: {
    contents: `import { run } from "./test/smoke-core.mjs";
      export default { async fetch() { return Response.json(await run()); } };`,
    resolveDir: new URL("..", import.meta.url).pathname,
    loader: "js",
  },
  bundle: true,
  format: "esm",
  platform: "neutral",
  write: false,
});

const mf = new Miniflare({ modules: true, script: bundle.outputFiles[0].text, compatibilityDate: "2025-09-01" });
try {
  const res = await mf.dispatchFetch("http://localhost/");
  const { runtime, passed, failures, unsupported } = await res.json();
  console.log(`[${runtime}] ${passed} passed, ${failures.length} failed${unsupported.length ? `; not supported by this runtime: ${unsupported.join(", ")}` : ""}`);
  if (failures.length) {
    console.error(failures.slice(0, 20).join("\n"));
    process.exitCode = 1;
  }
} finally {
  await mf.dispose();
}
