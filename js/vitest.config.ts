import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: [
      { test: { name: "node", include: ["test/**/*.test.ts"], environment: "node" } },
      {
        // Vercel Edge Runtime: no Node built-ins, Web Crypto only.
        test: { name: "edge", include: ["test/vectors.test.ts", "test/core.test.ts", "test/jwt.test.ts", "test/qr.test.ts"], environment: "edge-runtime" },
      },
    ],
  },
});
