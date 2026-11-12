// Compile-only check: adapters must type-check against the real framework types, without casts.
import express from "express";
import Fastify from "fastify";
import { Hono } from "hono";
import Koa from "koa";
import { APIKeyAuth } from "../../src/index.js";
import { apiKey as expressKey } from "../../src/integrations/express.js";
import { apiKey as fastifyKey, apiKeyPlugin } from "../../src/integrations/fastify.js";
import { apiKey as honoKey } from "../../src/integrations/hono.js";
import { apiKey as koaKey } from "../../src/integrations/koa.js";

const auth = new APIKeyAuth({ lookup: () => null });

const e = express();
e.use(expressKey(auth));
e.get("/x", expressKey(auth, { scopes: ["a"] }), (_req, res) => void res.json({}));

const f = Fastify();
void f.register(apiKeyPlugin, { auth });
f.get("/x", { preHandler: fastifyKey(auth) }, async () => ({}));

const h = new Hono();
h.use("/api/*", honoKey(auth));

const k = new Koa();
k.use(koaKey(auth));
