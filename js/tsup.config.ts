import { defineConfig } from "tsup";

const adapters = ["web", "hono", "express", "fastify", "koa", "next"];

export default defineConfig([
  {
    entry: {
      index: "src/index.ts",
      qr: "src/qr.ts",
      ...Object.fromEntries(adapters.map((a) => [`integrations/${a}`, `src/integrations/${a}.ts`])),
    },
    format: ["esm", "cjs"],
    dts: true,
    target: "es2022",
    platform: "neutral",
    splitting: true,
    treeshake: true,
    clean: true,
    sourcemap: false,
    minify: false,
  },
  {
    entry: { cli: "src/cli.ts" },
    format: ["esm"],
    target: "node20",
    platform: "node",
    banner: { js: "#!/usr/bin/env node" },
    dts: false,
    clean: false,
  },
]);
