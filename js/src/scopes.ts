/**
 * Permission scopes for API keys: ``read:users``, wildcards ``read:*`` and ``*`` (spec §7).
 * Scopes are not secrets, so plain comparison is fine.
 */

export type Scopes = string | Iterable<unknown> | null | undefined;

const SPLIT = /[\s,]+/u;

/** Normalise ``"read write"``, ``"read,write"`` or ``["read", "write"]`` to a Set. */
export function parseScopes(scopes: Scopes): Set<string> {
  if (scopes == null) return new Set();
  if (typeof scopes === "string") return new Set(scopes.split(SPLIT).filter(Boolean));
  const out = new Set<string>();
  for (const s of scopes) if (typeof s === "string" && s) out.add(s);
  return out;
}

/**
 * True if ``required`` is covered by ``granted``. ``*`` grants everything;
 * ``read:*`` grants ``read:users``, ``read:users:list`` and ``read`` itself.
 */
export function hasScope(granted: Scopes, required: string): boolean {
  if (typeof required !== "string" || !required) return false;
  const have = granted instanceof Set ? (granted as Set<string>) : parseScopes(granted);
  if (have.has("*") || have.has(required)) return true;
  const parts = required.split(":");
  for (let i = 1; i < parts.length; i++) if (have.has(parts.slice(0, i).join(":") + ":*")) return true;
  return have.has(required + ":*");
}

const list = (required: string | Iterable<string>): Iterable<string> => (typeof required === "string" ? [required] : required);

/** True if every scope in ``required`` is covered (empty ``required`` → true). */
export function hasAllScopes(granted: Scopes, required: string | Iterable<string>): boolean {
  const have = parseScopes(granted);
  for (const r of list(required)) if (!hasScope(have, r)) return false;
  return true;
}

/** True if at least one scope in ``required`` is covered. */
export function hasAnyScope(granted: Scopes, required: string | Iterable<string>): boolean {
  const have = parseScopes(granted);
  for (const r of list(required)) if (hasScope(have, r)) return true;
  return false;
}
