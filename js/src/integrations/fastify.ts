/**
 * Fastify plugin + preHandler hook (types only; no runtime import of fastify
 * or fastify-plugin — the plugin opts out of encapsulation by itself).
 *
 * @example
 * import { apiKeyPlugin, apiKey } from "@nuhmanpk/generateapikey/fastify";
 * await app.register(apiKeyPlugin, { auth });               // every route
 * app.get("/admin", { preHandler: apiKey(auth, { scopes: ["admin"] }) }, handler);  // one route
 * // request.apiKey = stored record
 */

import { type APIKeyAuth, AuthError, pathExcluded } from "../auth.js";

interface FastifyRequestLike {
  headers: Record<string, string | string[] | undefined>;
  query?: unknown;
  url: string;
  ip?: string | undefined;
}
interface FastifyReplyLike {
  code(status: number): unknown;
  header(name: string, value: string): unknown;
  send(body: unknown): unknown;
}
interface FastifyInstanceLike {
  addHook(name: "preHandler", hook: (req: FastifyRequestLike, reply: FastifyReplyLike) => Promise<unknown>): unknown;
  decorateRequest?(name: string, value: unknown): unknown;
  hasRequestDecorator?(name: string): boolean;
}

export interface FastifyOptions {
  scopes?: readonly string[];
  exclude?: readonly string[];
  /** Property set on ``request``. Default ``"apiKey"``. */
  property?: string;
  /** Client id for the limiter. Default ``request.ip``. */
  client?: (req: FastifyRequestLike) => string | null | undefined;
}

/** ``preHandler`` hook for one route or a scope. */
export function apiKey<R>(auth: APIKeyAuth<R>, options: FastifyOptions = {}) {
  const prop = options.property ?? "apiKey";
  return async (req: FastifyRequestLike, reply: FastifyReplyLike): Promise<unknown> => {
    if (options.exclude && pathExcluded(req.url.split("?")[0]!, options.exclude)) return;
    const query = req.query && typeof req.query === "object" ? (req.query as Record<string, unknown>) : null;
    try {
      (req as unknown as Record<string, unknown>)[prop] = await auth.authenticate(auth.extract(req.headers, query), options.client ? options.client(req) : (req.ip ?? null), options.scopes);
    } catch (e) {
      if (!(e instanceof AuthError)) throw e;
      for (const [k, v] of Object.entries(auth.errorHeaders(e))) reply.header(k, v);
      reply.code(e.status);
      return reply.send({ detail: e.detail });
    }
    return;
  };
}

/** Plugin that protects every route registered on the instance. Options: ``{ auth, ...FastifyOptions }``. */
export const apiKeyPlugin = Object.assign(
  async function apiKeyPlugin(app: FastifyInstanceLike, // eslint-disable-next-line @typescript-eslint/no-explicit-any -- any record type
    opts: FastifyOptions & { auth: APIKeyAuth<any> }): Promise<void> {
    const prop = opts.property ?? "apiKey";
    if (app.decorateRequest && !app.hasRequestDecorator?.(prop)) app.decorateRequest(prop, null);
    app.addHook("preHandler", apiKey(opts.auth, opts));
  },
  { [Symbol.for("skip-override")]: true, [Symbol.for("fastify.display-name")]: "generateapikey" },
);

export { AuthError };
