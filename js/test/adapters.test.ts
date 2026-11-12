/** Every adapter against the real framework: same status codes, bodies and headers as the Python adapters. */

import type { AddressInfo } from "node:net";
import express from "express";
import Fastify from "fastify";
import { Hono } from "hono";
import Koa from "koa";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import * as g from "../src/index.js";
import { apiKey as expressKey } from "../src/integrations/express.js";
import { apiKey as fastifyKey, apiKeyPlugin } from "../src/integrations/fastify.js";
import { apiKey as honoKey } from "../src/integrations/hono.js";
import { apiKey as koaKey } from "../src/integrations/koa.js";
import { apiKeyMiddleware, withApiKey as nextRoute } from "../src/integrations/next.js";
import { withApiKey } from "../src/integrations/web.js";

const PEPPER = "adapter-pepper";
let good = "";
let admin = "";
let auth: g.APIKeyAuth<{ id: number; scopes: string[] }>;

beforeAll(async () => {
  const store = new g.KeyStore(new g.MemoryKeyStorage(), { pepper: PEPPER });
  good = (await store.create("reader", { prefix: "sk", scopes: ["read:*"] })).key;
  admin = (await store.create("admin", { prefix: "sk", scopes: ["*"] })).key;
  auth = new g.APIKeyAuth({ lookup: store.lookup, pepper: PEPPER, prefix: "sk", requireChecksum: true }) as never;
});

type Fetcher = (path: string, init?: RequestInit) => Promise<Response>;

/** The behaviour every adapter must share. */
async function contract(fetcher: Fetcher): Promise<void> {
  const missing = await fetcher("/api/items");
  expect(missing.status).toBe(401);
  expect(missing.headers.get("www-authenticate")).toBe('Bearer realm="api"');
  expect(await missing.json()).toEqual({ detail: "Missing API key." });

  const bad = await fetcher("/api/items", { headers: { "X-API-Key": "sk-nope" } });
  expect(bad.status).toBe(401);
  expect(await bad.json()).toEqual({ detail: "Invalid API key." });

  const ok = await fetcher("/api/items", { headers: { "X-API-Key": good } });
  expect(ok.status).toBe(200);
  expect(await ok.json()).toEqual({ id: 1 });

  const bearer = await fetcher("/api/items", { headers: { Authorization: `Bearer ${good}` } });
  expect(bearer.status).toBe(200);

  const scoped = await fetcher("/api/admin", { headers: { "X-API-Key": good } });
  expect(scoped.status).toBe(403);
  expect(await scoped.json()).toEqual({ detail: "Insufficient scope." });
  expect((await fetcher("/api/admin", { headers: { "X-API-Key": admin } })).status).toBe(200);

  expect((await fetcher("/api/health")).status).toBe(200);
}

describe("web (fetch handlers: Workers, Deno, Bun)", () => {
  it("contract", async () => {
    const items = withApiKey(auth, (_req, r) => Response.json({ id: r!.id }), { exclude: ["/api/health"] });
    const adminH = withApiKey(auth, (_req, r) => Response.json({ id: r!.id }), { scopes: ["admin"] });
    await contract(async (path, init) => {
      const req = new Request(`http://x${path}`, init);
      if (path === "/api/admin") return adminH(req);
      if (path === "/api/health") return await withApiKey(auth, () => Response.json({ ok: true }), { exclude: ["/api/health"] })(req);
      return items(req);
    });
  });
});

describe("Hono", () => {
  it("contract", async () => {
    const app = new Hono<{ Variables: { apiKey: { id: number } } }>();
    app.use("/api/*", honoKey(auth, { exclude: ["/api/health"] }));
    app.get("/api/items", (c) => c.json({ id: c.get("apiKey").id }));
    app.get("/api/admin", honoKey(auth, { scopes: ["admin"] }), (c) => c.json({ id: c.get("apiKey").id }));
    app.get("/api/health", (c) => c.json({ ok: true }));
    await contract(async (path, init) => app.request(path, init));
  });
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function listen(handler: (req: any, res: any) => void): Promise<{ fetcher: Fetcher; close: () => void }> {
  const http = await import("node:http");
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  return { fetcher: (p, i) => fetch(`http://127.0.0.1:${port}${p}`, i), close: () => server.close() };
}

describe("Express", () => {
  let srv: Awaited<ReturnType<typeof listen>>;
  beforeAll(async () => {
    const app = express();
    app.use("/api", expressKey(auth, { exclude: ["/health"] }));
    app.get("/api/items", (req, res) => void res.json({ id: (req as unknown as { apiKey: { id: number } }).apiKey.id }));
    app.get("/api/admin", expressKey(auth, { scopes: ["admin"] }), (req, res) => void res.json({ id: (req as unknown as { apiKey: { id: number } }).apiKey.id }));
    app.get("/api/health", (_req, res) => void res.json({ ok: true }));
    srv = await listen(app);
  });
  afterAll(() => srv.close());
  it("contract", async () => contract((p, i) => srv.fetcher(p, i)));
});

describe("Fastify", () => {
  it("plugin + per-route preHandler", async () => {
    const app = Fastify();
    await app.register(async (scope) => {
      await scope.register(apiKeyPlugin, { auth, exclude: ["/api/health"] });
      scope.get("/api/items", async (req) => ({ id: (req as unknown as { apiKey: { id: number } }).apiKey.id }));
      scope.get("/api/admin", { preHandler: fastifyKey(auth, { scopes: ["admin"] }) }, async (req) => ({ id: (req as unknown as { apiKey: { id: number } }).apiKey.id }));
      scope.get("/api/health", async () => ({ ok: true }));
    });
    await app.ready();
    await contract(async (path, init) => {
      const res = await app.inject({ method: "GET", url: path, headers: Object.fromEntries(new Headers(init?.headers)) });
      return new Response(res.body, { status: res.statusCode, headers: res.headers as Record<string, string> });
    });
    await app.close();
  });
});

describe("Koa", () => {
  let srv: Awaited<ReturnType<typeof listen>>;
  beforeAll(async () => {
    const app = new Koa();
    app.use(async (ctx, next) => {
      if (ctx.path === "/api/admin") return koaKey(auth, { scopes: ["admin"] })(ctx as never, next);
      return koaKey(auth, { exclude: ["/api/health"] })(ctx as never, next);
    });
    app.use((ctx) => {
      ctx.body = ctx.path === "/api/health" ? { ok: true } : { id: (ctx.state.apiKey as { id: number }).id };
    });
    srv = await listen(app.callback());
  });
  afterAll(() => srv.close());
  it("contract", async () => contract((p, i) => srv.fetcher(p, i)));
});

describe("Next.js", () => {
  it("middleware forwards the key id and strips forged headers", async () => {
    const mw = apiKeyMiddleware(auth, { exclude: ["/api/health"] });
    const ok = await mw(new Request("http://x/api/items", { headers: { "X-API-Key": good, "x-api-key-id": "999" } }));
    expect(ok.headers.get("x-middleware-next")).toBe("1");
    expect(ok.headers.get("x-middleware-request-x-api-key-id")).toBe("1");
    const forged = await mw(new Request("http://x/api/health", { headers: { "x-api-key-id": "999" } }));
    expect(forged.headers.get("x-middleware-request-x-api-key-id")).toBeNull();
    const bad = await mw(new Request("http://x/api/items"));
    expect(bad.status).toBe(401);
    expect(bad.headers.get("www-authenticate")).toBe('Bearer realm="api"');
  });
  it("route handler contract", async () => {
    const items = nextRoute(auth, (_req, r) => Response.json({ id: r.id }));
    const adminH = nextRoute(auth, (_req, r) => Response.json({ id: r.id }), { scopes: ["admin"] });
    await contract(async (path, init) => {
      const req = new Request(`http://x${path}`, init);
      if (path === "/api/health") return Response.json({ ok: true });
      return path === "/api/admin" ? adminH(req) : items(req);
    });
  });
});
