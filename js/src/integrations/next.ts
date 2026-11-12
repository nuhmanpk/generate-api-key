/**
 * Next.js (App Router) helpers: ``middleware.ts`` on the Edge runtime and
 * route handlers. No runtime import of ``next``; uses standard ``Request``/``Response``.
 *
 * @example middleware.ts
 * import { apiKeyMiddleware } from "@nuhmanpk/generateapikey/next";
 * export const middleware = apiKeyMiddleware(auth, { exclude: ["/api/health"] });
 * export const config = { matcher: "/api/:path*" };
 *
 * @example app/api/items/route.ts
 * export const GET = withApiKey(auth, async (req, record) => Response.json({ owner: record.id }));
 */

import { type APIKeyAuth, AuthError, pathExcluded } from "../auth.js";
import { authenticateRequest, errorResponse, withApiKey as withWeb, type WebOptions } from "./web.js";

/** Default client id on Vercel: ``x-real-ip`` / first ``x-forwarded-for`` hop (set by the platform). */
export function vercelClient(req: Request): string | null {
  return req.headers.get("x-real-ip") ?? req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? null;
}

export interface NextOptions extends WebOptions {
  /**
   * Request header the middleware sets to the record's id (``record.id``) so
   * route handlers can read it. Default ``"x-api-key-id"``. Incoming values of
   * this header are always stripped, so clients can't forge it.
   */
  forwardHeader?: string | false;
}

/**
 * ``middleware.ts`` function: rejects bad keys with 401/403/429, otherwise
 * continues (``x-middleware-next``) and forwards the key's record id.
 */
export function apiKeyMiddleware<R>(auth: APIKeyAuth<R>, options: NextOptions = {}) {
  const header = options.forwardHeader === undefined ? "x-api-key-id" : options.forwardHeader;
  return async (req: Request): Promise<Response> => {
    const forwarded = new Headers(req.headers);
    if (header) forwarded.delete(header);
    const next = (): Response => {
      const h = new Headers({ "x-middleware-next": "1" });
      // Next.js reads overridden request headers from these two response headers.
      h.set("x-middleware-override-headers", [...forwarded.keys()].join(","));
      for (const [k, v] of forwarded) h.set(`x-middleware-request-${k}`, v);
      return new Response(null, { headers: h });
    };
    if (options.exclude && pathExcluded(new URL(req.url).pathname, options.exclude)) return next();
    try {
      const record = await authenticateRequest(auth, req, { client: vercelClient, ...options });
      const id = record && typeof record === "object" ? (record as { id?: unknown }).id : undefined;
      if (header && id !== undefined && id !== null) forwarded.set(header, String(id));
      return next();
    } catch (e) {
      if (e instanceof AuthError) return errorResponse(auth as APIKeyAuth<unknown>, e);
      throw e;
    }
  };
}

/** Route handler wrapper (App Router): ``export const GET = withApiKey(auth, (req, record) => ...)``. */
export function withApiKey<R, A extends unknown[]>(
  auth: APIKeyAuth<R>,
  handler: (req: Request, record: R, ...rest: A) => Response | Promise<Response>,
  options: Omit<WebOptions, "exclude"> = {},
): (req: Request, ...rest: A) => Promise<Response> {
  const { exclude: _ignored, ...opts } = options as WebOptions;
  return withWeb(auth, (req, record, ...rest: A) => handler(req, record as R, ...rest), { client: vercelClient, ...opts });
}

export { AuthError };
