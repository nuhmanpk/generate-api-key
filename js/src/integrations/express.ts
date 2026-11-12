/**
 * Express (4/5) and Connect-style middleware (types only; no runtime import).
 *
 * @example
 * import { apiKey } from "@nuhmanpk/generateapikey/express";
 * app.use("/api", apiKey(auth));            // req.apiKey = stored record
 * app.get("/admin", apiKey(auth, { scopes: ["admin"] }), handler);
 */

import { type APIKeyAuth, AuthError, pathExcluded } from "../auth.js";

interface ReqLike {
  headers: Record<string, string | string[] | undefined>;
  query?: unknown;
  path?: string;
  url?: string;
  ip?: string | undefined;
  socket?: { remoteAddress?: string | undefined };
}
interface ResLike {
  status(code: number): unknown;
  setHeader(name: string, value: string): unknown;
  json(body: unknown): unknown;
}

export interface ExpressOptions {
  scopes?: readonly string[];
  exclude?: readonly string[];
  /** Property set on ``req``. Default ``"apiKey"``. */
  property?: string;
  /** Client id for the limiter. Default ``req.ip`` (configure Express ``trust proxy`` correctly). */
  client?: (req: ReqLike) => string | null | undefined;
}

/** Middleware: sets ``req.apiKey`` to the record, or responds ``{"detail": ...}`` with 401/403/429. */
export function apiKey<R>(auth: APIKeyAuth<R>, options: ExpressOptions = {}) {
  const prop = options.property ?? "apiKey";
  return (req: ReqLike, res: ResLike, next: (err?: unknown) => void): void => {
    const path = req.path ?? (req.url ?? "/").split("?")[0]!;
    if (options.exclude && pathExcluded(path, options.exclude)) return next();
    const query = req.query && typeof req.query === "object" ? (req.query as Record<string, unknown>) : null;
    const client = options.client ? options.client(req) : (req.ip ?? req.socket?.remoteAddress ?? null);
    auth.authenticate(auth.extract(req.headers, query), client, options.scopes).then(
      (record) => {
        (req as unknown as Record<string, unknown>)[prop] = record;
        next();
      },
      (e: unknown) => {
        if (!(e instanceof AuthError)) return next(e);
        for (const [k, v] of Object.entries(auth.errorHeaders(e))) res.setHeader(k, v);
        res.status(e.status);
        res.json({ detail: e.detail });
      },
    );
  };
}

export { AuthError };
