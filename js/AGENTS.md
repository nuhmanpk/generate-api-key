# AGENTS.md (js/)

Guidance for AI coding agents working **on** the npm package. To *use* it, read
[llms.txt](https://github.com/nuhmanpk/generate-api-key/blob/main/js/llms.txt). Repo-wide rules
are in the root `AGENTS.md`; the wire formats are in `spec/SPEC.md`.

```
src/index.ts        public exports, VERSION (keep equal to package.json and the Python version)
src/keys.ts         generation, sampling, derivation, checksums, hashing, PBKDF2
src/mfa.ts          TOTP/HOTP/Steam, URIs, migration, recovery codes, OTP, limiters
src/tokens.ts       signed tokens, JWT; src/internal/pem.ts parses PEM/DER for RS/PS/ES/EdDSA
src/auth.ts         APIKeyAuth, issue/rotate, recordIsActive, pathExcluded
src/keystore.ts     KeyStore + Memory/Sql storage (same schema as Python)
src/integrations/   web hono express fastify koa next — types only, no framework imports
src/internal/       bytes (encodings, constant-time compare, CRC32), webcrypto (pooled RNG, key cache), pyjson
test/               vectors.test.ts (spec/vectors.json), core, jwt (fresh keys), adapters, qr
test/smoke.mjs      built package on Node 20 / Bun / Deno; workers.mjs runs it in workerd
test/interop.mjs    live JS <-> Python check (with python/scripts/interop.py)
```

```bash
npm ci
npm run typecheck   # core is checked WITHOUT Node types: no node:* / Buffer allowed in src/ (except cli.ts)
npm test            # vitest: node + edge-runtime projects
npm run build && npm run test:smoke && npm run test:workers
npm run lint:package
```

Rules:
- Zero runtime dependencies. Only `globalThis.crypto`, `TextEncoder`/`TextDecoder`, typed arrays.
- Randomness only via `randomBytes` in `internal/webcrypto.ts`; secret comparisons only via
  `safeEquals`/`bytesEqual`; verification loops never exit early.
- Wire formats must match Python exactly. Change a format only together with the spec, the Python
  code and regenerated vectors.
- Adapters stay thin: all logic is in `auth.ts`; every adapter passes the shared contract in
  `test/adapters.test.ts`.
- New public export → add to `src/index.ts`, JSDoc, tests, `README.md`, `llms.txt`, `docs/js.md`, `CHANGELOG.md`.
