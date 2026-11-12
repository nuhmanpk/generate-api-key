/**
 * Framework-agnostic API key authentication (spec §12). Every adapter
 * (``@nuhmanpk/generateapikey/hono``, ``/express``, ``/fastify``, ``/koa``, ``/next``,
 * ``/web``) is a thin wrapper around {@link APIKeyAuth}, so behaviour is
 * identical everywhere and identical to the Python integrations.
 */

import { cpLength, cpSlice, isAscii } from "./internal/bytes.js";
import { ApiKey, CHECKSUM_LENGTH, type KeyOptions, checkPepper, generateApiKey, hashApiKey, verifyChecksum } from "./keys.js";
import { hasAllScopes } from "./scopes.js";

export const MAX_KEY_LENGTH = 512;

type MaybePromise<T> = T | Promise<T>;

/** Authentication failed. ``status`` is 401 (missing/invalid), 403 (scope) or 429 (rate limited). */
export class AuthError extends Error {
  override name = "AuthError";
  constructor(
    readonly status: 401 | 403 | 429,
    readonly detail: string,
  ) {
    super(detail);
  }
}

const MISSING = "Missing API key.";
const INVALID = "Invalid API key.";
const SCOPE = "Insufficient scope.";
const BLOCKED = "Too many invalid API keys. Try again later.";

// ---------------------------------------------------------------------------
// Issuing
// ---------------------------------------------------------------------------

/** Display hint: ``key[:7] + "…" + key[-4:]`` for keys of 16+ characters, else ``"…"``. */
export function keyHint(key: string): string {
  const n = cpLength(key);
  return n >= 16 ? `${cpSlice(key, 0, 7)}…${cpSlice(key, n - 4)}` : "…";
}

export interface IssuedKey {
  /** Give to the client once; never store it. */
  key: string;
  /** Store this (unique index); look records up by it. */
  hashed: string;
  /** Store and show in your UI to identify the key (``sk-AbCd…wXyZ``). */
  hint: string;
  /** Unix seconds, or null. */
  expiresAt: number | null;
}

export interface IssueOptions extends KeyOptions {
  pepper?: string | null;
  /** Lifetime in minutes. */
  expiry?: number;
}

/**
 * Generate a key plus everything you need to store for it. ``checksum``
 * defaults to true so bad keys are rejected before the database is touched.
 */
export async function issueApiKey(options: IssueOptions = {}): Promise<IssuedKey> {
  const { pepper, expiry, ...rest } = options;
  checkPepper(pepper);
  const opts = { checksum: true, ...rest };
  const made: string | ApiKey = expiry === undefined ? generateApiKey(opts) : generateApiKey({ ...opts, expiry });
  const key = String(made);
  return { key, hashed: await hashApiKey(key, pepper), hint: keyHint(key), expiresAt: made instanceof ApiKey ? made.expiresAt : null };
}

export interface Rotation {
  /** The new key: give it to the client. */
  key: string;
  /** Store for the new key. */
  hashed: string;
  hint: string;
  expiresAt: number | null;
  /** Set the old record's ``expires_at`` to this (unix seconds) so clients can switch without downtime. */
  oldExpiresAt: number;
}

/** Issue a replacement key and compute when the old one should stop working (default grace 24 h). */
export async function rotateApiKey(options: IssueOptions & { graceMinutes?: number } = {}): Promise<Rotation> {
  const { graceMinutes = 24 * 60, ...rest } = options;
  if (!(graceMinutes >= 0)) throw new RangeError("graceMinutes must be >= 0.");
  const issued = await issueApiKey(rest);
  return { ...issued, oldExpiresAt: Math.floor(Date.now() / 1000 + graceMinutes * 60) };
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/** @internal Read ``name`` (snake_case or camelCase) from an object or Map. */
export function field(record: unknown, name: string): unknown {
  const camel = name.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
  if (record instanceof Map) return record.has(name) ? record.get(name) : record.get(camel);
  if (record && typeof record === "object") {
    const r = record as Record<string, unknown>;
    return name in r ? r[name] : r[camel];
  }
  return undefined;
}

/**
 * Default validity check for a stored record (object or Map). Rejects
 * ``revoked`` truthy, ``is_active``/``isActive`` exactly false, or
 * ``expires_at``/``expiresAt`` in the past — a number is **unix seconds**
 * (same as Python; a value above 1e11 is taken as milliseconds), a ``Date`` is
 * compared directly; anything else fails closed.
 */
export function recordIsActive(record: unknown): boolean {
  if (record === null || record === undefined) return false;
  if (field(record, "revoked")) return false;
  if (field(record, "is_active") === false) return false;
  const expires = field(record, "expires_at");
  if (expires === undefined || expires === null) return true;
  if (expires instanceof Date) return Date.now() < expires.getTime();
  // Unix seconds, like Python. Values above 1e11 (year 5138 in seconds) can only be
  // JavaScript milliseconds (Date.now()), so they are read as milliseconds instead of never expiring.
  if (typeof expires === "number") return expires > 1e11 ? Date.now() < expires : Date.now() / 1000 < expires;
  return false;
}

/**
 * Segment-aware prefix match for exclude lists: ``/health`` matches
 * ``/health`` and ``/health/live`` but not ``/healthz``.
 */
export function pathExcluded(path: string, exclude: readonly string[]): boolean {
  for (const prefix of exclude) {
    const base = prefix.replace(/\/+$/, "");
    if (path === prefix || path === base || path.startsWith(base + "/")) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// APIKeyAuth
// ---------------------------------------------------------------------------

/** Headers as a Fetch ``Headers``, a ``Map`` or a plain (Node) object. */
export type HeadersLike = Headers | Map<string, string | string[] | undefined> | Record<string, string | string[] | undefined | null> | { get(name: string): string | null | undefined };
export type QueryLike = URLSearchParams | Map<string, unknown> | Record<string, unknown> | { get(name: string): unknown };

/** Any limiter with ``isBlocked``/``fail`` (``AttemptLimiter``, ``RedisAttemptLimiter`` or your own). */
export interface LimiterLike {
  isBlocked(client: string): MaybePromise<boolean>;
  fail(client: string): MaybePromise<unknown>;
}

export interface APIKeyAuthOptions<R = unknown> {
  /** ``lookup(hashed) → record | null``; query your table by the hash column. May be async. */
  lookup: (hashed: string) => MaybePromise<R | null | undefined>;
  /** Server-side pepper used when the keys were issued. */
  pepper?: string | null;
  /** Header to read the key from. Default ``X-API-Key``. */
  header?: string;
  /** Also accept ``Authorization: Bearer <key>``. Default true. */
  bearer?: boolean;
  /** Also accept ``?<queryParam>=<key>`` (discouraged: URLs end up in logs). */
  queryParam?: string | null;
  /** Reject keys not starting with this, before any lookup. */
  prefix?: string | null;
  /** Reject keys whose checksum fails, before any lookup. */
  requireChecksum?: boolean;
  /** ``validate(record) → boolean``; default {@link recordIsActive}. */
  validate?: (record: R) => MaybePromise<boolean>;
  /** Too many bad keys from one client → 429. */
  limiter?: LimiterLike | null;
  /** Called after a successful check (e.g. update ``last_used_at``). */
  onSuccess?: (record: R) => MaybePromise<unknown>;
  /** Old peppers still accepted during a pepper rotation. */
  previousPeppers?: readonly string[];
  /** Called with the record and its hash under the current pepper when it matched under an old one. */
  onRehash?: (record: R, newHashed: string) => MaybePromise<unknown>;
  /** Scopes every key must hold (``read:*`` and ``*`` wildcards work); failing keys get 403. */
  requiredScopes?: readonly string[];
}

function getHeader(headers: HeadersLike | null | undefined, name: string): string | null {
  if (!headers) return null;
  const pick = (v: unknown): string | null => (typeof v === "string" ? v : null);
  if (typeof (headers as Headers).get === "function" && !(headers instanceof Map)) {
    const h = headers as { get(n: string): unknown };
    return pick(h.get(name) ?? h.get(name.toLowerCase()));
  }
  const lname = name.toLowerCase();
  const entries: Iterable<[string, unknown]> = headers instanceof Map ? headers : Object.entries(headers as Record<string, unknown>);
  let direct: unknown;
  for (const [k, v] of entries) {
    if (k === name) return pick(v);
    if (direct === undefined && typeof k === "string" && k.toLowerCase() === lname) direct = v;
  }
  return pick(direct);
}

function getQuery(query: QueryLike | null | undefined, name: string): unknown {
  if (!query) return undefined;
  if (typeof (query as URLSearchParams).get === "function" && !(query instanceof Map)) return (query as { get(n: string): unknown }).get(name);
  if (query instanceof Map) return query.get(name);
  return (query as Record<string, unknown>)[name];
}

/** Extract, pre-check, hash and look up an API key. */
export class APIKeyAuth<R = unknown> {
  readonly lookup: APIKeyAuthOptions<R>["lookup"];
  readonly pepper: string | null;
  readonly header: string;
  readonly bearer: boolean;
  readonly queryParam: string | null;
  readonly prefix: string | null;
  readonly requireChecksum: boolean;
  readonly validate: (record: R) => MaybePromise<boolean>;
  readonly limiter: LimiterLike | null;
  readonly onSuccess: APIKeyAuthOptions<R>["onSuccess"];
  readonly previousPeppers: readonly string[];
  readonly onRehash: APIKeyAuthOptions<R>["onRehash"];
  readonly requiredScopes: readonly string[];
  private warnedNoClient = false;

  constructor(options: APIKeyAuthOptions<R>) {
    if (typeof options?.lookup !== "function") throw new TypeError("lookup must be a function: lookup(hashed) -> record | null");
    checkPepper(options.pepper);
    if (typeof options.previousPeppers === "string") throw new TypeError("previousPeppers must be an array of strings, not a string.");
    for (const p of options.previousPeppers ?? []) {
      if (p == null) throw new RangeError("previousPeppers entries must be non-empty strings.");
      checkPepper(p);
    }
    if (typeof options.requiredScopes === "string") throw new TypeError("requiredScopes must be an array of strings, not a string.");
    this.lookup = options.lookup;
    this.pepper = options.pepper ?? null;
    this.header = options.header ?? "X-API-Key";
    this.bearer = options.bearer ?? true;
    this.queryParam = options.queryParam ?? null;
    this.prefix = options.prefix ?? null;
    this.requireChecksum = options.requireChecksum ?? false;
    this.validate = options.validate ?? ((r: R) => recordIsActive(r));
    this.limiter = options.limiter ?? null;
    this.onSuccess = options.onSuccess;
    this.previousPeppers = Object.freeze([...(options.previousPeppers ?? [])]);
    this.onRehash = options.onRehash;
    this.requiredScopes = Object.freeze([...(options.requiredScopes ?? [])]);
  }

  /** Pull the raw key from request headers (case-insensitive), ``Authorization: Bearer`` or the query. */
  extract(headers: HeadersLike | null | undefined, query?: QueryLike | null): string | null {
    let value = getHeader(headers, this.header);
    if (!value && this.bearer) {
      const authz = getHeader(headers, "Authorization");
      if (authz) {
        const s = authz.trim();
        const i = s.indexOf(" ");
        const scheme = i < 0 ? s : s.slice(0, i);
        if (scheme.toLowerCase() === "bearer") value = i < 0 ? "" : s.slice(i + 1);
      }
    }
    if (!value && this.queryParam && query) {
      const q = getQuery(query, this.queryParam);
      value = typeof q === "string" ? q : null;
    }
    if (!value) return null;
    value = value.trim();
    return value || null;
  }

  /** @internal Cheap checks that never touch the database. */
  wellFormed(key: string): boolean {
    return !(
      key.length > MAX_KEY_LENGTH ||
      !isAscii(key) ||
      (this.prefix && !key.startsWith(this.prefix)) ||
      (this.requireChecksum && (key.length <= CHECKSUM_LENGTH || !verifyChecksum(key)))
    );
  }

  /**
   * The stored record for ``key``, or throws {@link AuthError}. ``client``
   * (e.g. the IP) keys the limiter; ``scopes`` overrides ``requiredScopes``.
   */
  async authenticate(key: string | null | undefined, client?: string | null, scopes?: readonly string[] | null): Promise<R> {
    if (this.limiter && !client && !this.warnedNoClient) {
      this.warnedNoClient = true;
      console.warn(
        "[generateapikey] APIKeyAuth has a limiter but no client id was passed, so this request is not rate limited. " +
          "Pass a `client` option to your adapter (e.g. the socket's remote address).",
      );
    }
    const limiter = client ? this.limiter : null;
    if (limiter && (await limiter.isBlocked(client!))) throw new AuthError(429, BLOCKED);
    if (!key) throw new AuthError(401, MISSING);
    let record: R | null | undefined = null;
    let matched = 0;
    let current = "";
    if (this.wellFormed(key)) {
      const peppers = [this.pepper, ...this.previousPeppers];
      for (let i = 0; i < peppers.length; i++) {
        const hashed = await hashApiKey(key, peppers[i]);
        if (i === 0) current = hashed;
        record = await this.lookup(hashed);
        if (record !== null && record !== undefined) {
          matched = i;
          break;
        }
      }
    }
    if (record === null || record === undefined || !(await this.validate(record))) {
      if (limiter) await limiter.fail(client!);
      throw new AuthError(401, INVALID);
    }
    const needed = scopes ?? this.requiredScopes;
    if (needed.length && !hasAllScopes(field(record, "scopes") as never, needed)) throw new AuthError(403, SCOPE);
    if (matched && this.onRehash) await this.onRehash(record, current);
    if (this.onSuccess) await this.onSuccess(record);
    return record;
  }

  /** Value for the ``WWW-Authenticate`` header on 401 responses. */
  challenge(): string {
    return this.bearer ? 'Bearer realm="api"' : `ApiKey header="${this.header}"`;
  }

  /** Response headers for an error (``WWW-Authenticate`` on 401). */
  errorHeaders(e: AuthError): Record<string, string> {
    return e.status === 401 ? { "WWW-Authenticate": this.challenge() } : {};
  }
}
