/**
 * Fetch-API adapter: any ``(Request) => Response`` handler — Cloudflare
 * Workers, Deno.serve, Bun.serve, Vercel/Netlify edge functions, SvelteKit,
 * Remix, Astro, Elysia…
 *
 * @example
 * const auth = new APIKeyAuth({ lookup: (h) => db.find(h), pepper: env.PEPPER });
 * export default { fetch: withApiKey(auth, async (req, record) => Response.json({ ok: true })) };
 */

import { type APIKeyAuth, AuthError, pathExcluded } from "../auth.js";

export interface WebOptions {
  /** Scopes this handler requires (overrides ``auth.requiredScopes``). */
  scopes?: readonly string[];
  /** Paths that skip auth (segment-aware, e.g. ``["/health"]``). */
  exclude?: readonly string[];
  /** Client id for the limiter; default reads ``CF-Connecting-IP`` / ``X-Real-IP``. Return null to skip limiting. */
  client?: (req: Request) => string | null | undefined;
}

/** Default client id: platform IP headers only (``X-Forwarded-For`` is spoofable unless you trust a proxy). */
export function clientIp(req: Request): string | null {
  return req.headers.get("cf-connecting-ip") ?? req.headers.get("x-real-ip") ?? null;
}

/** JSON error ``Response`` (``{"detail": ...}``) with ``WWW-Authenticate`` on 401, like the Python adapters. */
export function errorResponse(auth: APIKeyAuth<unknown>, e: AuthError): Response {
  return Response.json({ detail: e.detail }, { status: e.status, headers: auth.errorHeaders(e) });
}

/** Authenticate a ``Request``: returns the record, or throws {@link AuthError}. */
export async function authenticateRequest<R>(auth: APIKeyAuth<R>, req: Request, options: WebOptions = {}): Promise<R> {
  const url = new URL(req.url);
  const key = auth.extract(req.headers, url.searchParams);
  return auth.authenticate(key, (options.client ?? clientIp)(req), options.scopes);
}

/** Wrap a fetch handler; it receives the authenticated record as the 2nd argument. */
export function withApiKey<R, A extends unknown[]>(
  auth: APIKeyAuth<R>,
  handler: (req: Request, record: R | null, ...rest: A) => Response | Promise<Response>,
  options: WebOptions = {},
): (req: Request, ...rest: A) => Promise<Response> {
  return async (req, ...rest) => {
    if (options.exclude && pathExcluded(new URL(req.url).pathname, options.exclude)) return handler(req, null, ...rest);
    let record: R;
    try {
      record = await authenticateRequest(auth, req, options);
    } catch (e) {
      if (e instanceof AuthError) return errorResponse(auth as APIKeyAuth<unknown>, e);
      throw e;
    }
    return handler(req, record, ...rest);
  };
}

export { AuthError };
