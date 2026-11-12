/**
 * Hono middleware (types only; no runtime import of hono).
 *
 * @example
 * import { apiKey } from "@nuhmanpk/generateapikey/hono";
 * app.use("/api/*", apiKey(auth));
 * app.get("/api/items", (c) => c.json({ owner: c.get("apiKey").id }));
 */

import { type APIKeyAuth, AuthError, pathExcluded } from "../auth.js";

interface HonoContextLike {
  req: { raw: Request; path: string; header(name: string): string | undefined };
  set(key: string, value: unknown): void;
  json(body: unknown, status?: number, headers?: Record<string, string>): Response;
  env?: { incoming?: { socket?: { remoteAddress?: string } } } | unknown;
}

export interface HonoOptions {
  scopes?: readonly string[];
  exclude?: readonly string[];
  /** Context key for the record. Default ``"apiKey"``. */
  key?: string;
  /** Client id for the limiter. Default ``CF-Connecting-IP`` / ``X-Real-IP`` / the Node socket address. */
  client?: (c: HonoContextLike) => string | null | undefined;
}

/** ``@hono/node-server`` exposes the Node request as ``c.env.incoming``. */
function nodeSocketIp(c: HonoContextLike): string | null {
  const env = c.env as { incoming?: { socket?: { remoteAddress?: string } } } | undefined;
  return env?.incoming?.socket?.remoteAddress ?? null;
}

/** Hono middleware that sets ``c.get("apiKey")`` to the stored record, or responds 401/403/429. */
export function apiKey<R>(auth: APIKeyAuth<R>, options: HonoOptions = {}) {
  const ctxKey = options.key ?? "apiKey";
  return async (c: HonoContextLike, next: () => Promise<void>): Promise<Response | void> => {
    if (options.exclude && pathExcluded(c.req.path, options.exclude)) return next();
    const req = c.req.raw;
    const client = options.client ? options.client(c) : (c.req.header("cf-connecting-ip") ?? c.req.header("x-real-ip") ?? nodeSocketIp(c));
    try {
      const record = await auth.authenticate(auth.extract(req.headers, new URL(req.url).searchParams), client, options.scopes);
      c.set(ctxKey, record);
    } catch (e) {
      if (e instanceof AuthError) return c.json({ detail: e.detail }, e.status, auth.errorHeaders(e));
      throw e;
    }
    return next();
  };
}

export { AuthError };
