/**
 * Koa middleware (types only; no runtime import of koa).
 *
 * @example
 * import { apiKey } from "@nuhmanpk/generateapikey/koa";
 * app.use(apiKey(auth));   // ctx.state.apiKey = stored record
 */

import { type APIKeyAuth, AuthError, pathExcluded } from "../auth.js";

interface KoaContextLike {
  headers: Record<string, string | string[] | undefined>;
  query: Record<string, unknown>;
  path: string;
  ip?: string;
  state: Record<string, unknown>;
  status: number;
  body: unknown;
  set(name: string, value: string): void;
}

export interface KoaOptions {
  scopes?: readonly string[];
  exclude?: readonly string[];
  /** Key in ``ctx.state``. Default ``"apiKey"``. */
  key?: string;
  client?: (ctx: KoaContextLike) => string | null | undefined;
}

export function apiKey<R>(auth: APIKeyAuth<R>, options: KoaOptions = {}) {
  const stateKey = options.key ?? "apiKey";
  return async (ctx: KoaContextLike, next: () => Promise<unknown>): Promise<void> => {
    if (options.exclude && pathExcluded(ctx.path, options.exclude)) {
      await next();
      return;
    }
    try {
      ctx.state[stateKey] = await auth.authenticate(auth.extract(ctx.headers, ctx.query), options.client ? options.client(ctx) : (ctx.ip ?? null), options.scopes);
    } catch (e) {
      if (!(e instanceof AuthError)) throw e;
      for (const [k, v] of Object.entries(auth.errorHeaders(e))) ctx.set(k, v);
      ctx.status = e.status;
      ctx.body = { detail: e.detail };
      return;
    }
    await next();
  };
}

export { AuthError };
