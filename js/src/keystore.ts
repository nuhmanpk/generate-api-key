/**
 * A small key store: create, look up, revoke, rotate. Storage is pluggable:
 * {@link MemoryKeyStorage} (tests, single process) or {@link SqlKeyStorage}
 * for any SQL driver (Cloudflare D1, better-sqlite3, node:sqlite, libSQL…).
 * The SQL schema is the same as Python's ``KeyStore``, so both languages can
 * share one ``api_keys`` table.
 */

import { type IssueOptions, keyHint, rotateApiKey, issueApiKey } from "./auth.js";
import { hashApiKey } from "./keys.js";
import { parseScopes, type Scopes } from "./scopes.js";

/** A stored key (never the raw key). Works with ``recordIsActive`` and scope checks. */
export interface KeyRecord {
  id: number;
  name: string;
  hint: string;
  /** Sorted scope list. */
  scopes: string[];
  /** Unix seconds. */
  createdAt: number;
  /** Unix seconds, or null. */
  expiresAt: number | null;
  revoked: boolean;
  lastUsedAt: number | null;
  meta: Record<string, unknown>;
}

/** Row as stored (same columns as Python's SQLite ``api_keys`` table). */
export interface KeyRow {
  id: number;
  hashed: string;
  name: string;
  hint: string;
  scopes: string;
  created_at: number;
  expires_at: number | null;
  revoked_at: number | null;
  last_used_at: number | null;
  meta: string;
}

/** Storage backend. Implement these five methods for any database. */
export interface KeyStorage {
  insert(row: Omit<KeyRow, "id" | "revoked_at" | "last_used_at">): Promise<number>;
  findByHash(hashed: string): Promise<KeyRow | null>;
  get(id: number): Promise<KeyRow | null>;
  all(): Promise<KeyRow[]>;
  update(id: number, patch: Partial<Pick<KeyRow, "expires_at" | "revoked_at" | "last_used_at">>): Promise<void>;
}

/** In-memory storage (tests, prototypes, single process). */
export class MemoryKeyStorage implements KeyStorage {
  private rows = new Map<number, KeyRow>();
  private byHash = new Map<string, number>();
  private next = 1;

  async insert(row: Omit<KeyRow, "id" | "revoked_at" | "last_used_at">): Promise<number> {
    if (this.byHash.has(row.hashed)) throw new Error("UNIQUE constraint failed: api_keys.hashed");
    const id = this.next++;
    this.rows.set(id, { ...row, id, revoked_at: null, last_used_at: null });
    this.byHash.set(row.hashed, id);
    return id;
  }
  async findByHash(hashed: string): Promise<KeyRow | null> {
    const id = this.byHash.get(hashed);
    return id === undefined ? null : { ...this.rows.get(id)! };
  }
  async get(id: number): Promise<KeyRow | null> {
    const r = this.rows.get(id);
    return r ? { ...r } : null;
  }
  async all(): Promise<KeyRow[]> {
    return [...this.rows.values()].map((r) => ({ ...r }));
  }
  async update(id: number, patch: Partial<KeyRow>): Promise<void> {
    const r = this.rows.get(id);
    if (r) Object.assign(r, patch);
  }
}

/** ``CREATE TABLE`` statement, identical to Python's ``KeyStore``. */
export const KEYSTORE_SCHEMA = `
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hashed TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    hint TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER,
    last_used_at INTEGER,
    meta TEXT NOT NULL DEFAULT '{}'
)
`;

/** Minimal SQL driver: ``all`` returns rows, ``run`` returns the inserted row id. */
export interface SqlDriver {
  all(sql: string, params: unknown[]): Promise<Record<string, unknown>[]>;
  run(sql: string, params: unknown[]): Promise<{ lastInsertRowid?: number | bigint | null } | void>;
}

/**
 * SQL storage over any driver (SQLite dialect, ``?`` placeholders).
 *
 * @example Cloudflare D1
 * new SqlKeyStorage({
 *   all: async (sql, p) => (await env.DB.prepare(sql).bind(...p).all()).results,
 *   run: async (sql, p) => ({ lastInsertRowid: (await env.DB.prepare(sql).bind(...p).run()).meta.last_row_id }),
 * })
 */
export class SqlKeyStorage implements KeyStorage {
  constructor(
    private readonly db: SqlDriver,
    private readonly table = "api_keys",
  ) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) throw new RangeError("table must be a plain SQL identifier.");
  }

  /** Create the table if missing. */
  async migrate(): Promise<void> {
    await this.db.run(KEYSTORE_SCHEMA.replace("api_keys", this.table), []);
  }

  private row(r: Record<string, unknown> | undefined): KeyRow | null {
    if (!r) return null;
    const n = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));
    return {
      id: Number(r.id),
      hashed: String(r.hashed),
      name: String(r.name),
      hint: String(r.hint),
      scopes: String(r.scopes ?? "[]"),
      created_at: Number(r.created_at),
      expires_at: n(r.expires_at),
      revoked_at: n(r.revoked_at),
      last_used_at: n(r.last_used_at),
      meta: String(r.meta ?? "{}"),
    };
  }

  async insert(row: Omit<KeyRow, "id" | "revoked_at" | "last_used_at">): Promise<number> {
    const res = await this.db.run(
      `INSERT INTO ${this.table} (hashed, name, hint, scopes, created_at, expires_at, meta) VALUES (?,?,?,?,?,?,?)`,
      [row.hashed, row.name, row.hint, row.scopes, row.created_at, row.expires_at, row.meta],
    );
    const id = res && res.lastInsertRowid != null ? Number(res.lastInsertRowid) : null;
    if (id !== null) return id;
    const found = await this.findByHash(row.hashed);
    if (!found) throw new Error("insert failed");
    return found.id;
  }
  async findByHash(hashed: string): Promise<KeyRow | null> {
    return this.row((await this.db.all(`SELECT * FROM ${this.table} WHERE hashed = ?`, [hashed]))[0]);
  }
  async get(id: number): Promise<KeyRow | null> {
    return this.row((await this.db.all(`SELECT * FROM ${this.table} WHERE id = ?`, [id]))[0]);
  }
  async all(): Promise<KeyRow[]> {
    return (await this.db.all(`SELECT * FROM ${this.table} ORDER BY id`, [])).map((r) => this.row(r)!);
  }
  async update(id: number, patch: Partial<Pick<KeyRow, "expires_at" | "revoked_at" | "last_used_at">>): Promise<void> {
    const cols = Object.keys(patch).filter((k) => ["expires_at", "revoked_at", "last_used_at"].includes(k));
    if (!cols.length) return;
    await this.db.run(`UPDATE ${this.table} SET ${cols.map((c) => `${c} = ?`).join(", ")} WHERE id = ?`, [...cols.map((c) => patch[c as keyof typeof patch]), id]);
  }
}

const nowSec = (): number => Math.floor(Date.now() / 1000);

function toRecord(r: KeyRow): KeyRecord {
  return {
    id: r.id,
    name: r.name,
    hint: r.hint,
    scopes: JSON.parse(r.scopes) as string[],
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    revoked: r.revoked_at !== null,
    lastUsedAt: r.last_used_at,
    meta: JSON.parse(r.meta) as Record<string, unknown>,
  };
}

/** True if the record isn't revoked or expired. */
export function isKeyActive(r: KeyRecord): boolean {
  return !r.revoked && (r.expiresAt === null || Date.now() / 1000 < r.expiresAt);
}

export interface CreatedKey {
  id: number;
  /** Show to the user once. */
  key: string;
  record: KeyRecord;
}

export interface CreateOptions extends Omit<IssueOptions, "pepper"> {
  scopes?: Scopes;
  meta?: Record<string, unknown>;
}

/** Key store over a {@link KeyStorage}. Stores only hashes. */
export class KeyStore {
  readonly pepper: string | null;
  private readonly touch: boolean;

  constructor(
    readonly storage: KeyStorage = new MemoryKeyStorage(),
    options: { pepper?: string | null; touch?: boolean } = {},
  ) {
    this.pepper = options.pepper ?? null;
    this.touch = options.touch ?? true;
  }

  private async insert(key: string, hashed: string, expiresAt: number | null, name: string, scopes: Scopes, meta: Record<string, unknown> | undefined): Promise<KeyRecord> {
    const id = await this.storage.insert({
      hashed,
      name,
      hint: keyHint(key),
      scopes: JSON.stringify([...parseScopes(scopes)].sort()),
      created_at: nowSec(),
      expires_at: expiresAt,
      meta: JSON.stringify(meta ?? {}),
    });
    return toRecord((await this.storage.get(id))!);
  }

  /** Create and store a key (checksum on by default). ``expiry`` is minutes. */
  async create(name: string, options: CreateOptions = {}): Promise<CreatedKey> {
    if (typeof name !== "string" || !name) throw new RangeError("name must be a non-empty string.");
    const { scopes, meta, ...rest } = options;
    const issued = await issueApiKey({ ...rest, pepper: this.pepper });
    const record = await this.insert(issued.key, issued.hashed, issued.expiresAt, name, scopes, meta);
    return { id: record.id, key: issued.key, record };
  }

  /** ``lookup`` for {@link APIKeyAuth}: receives the hash, updates ``lastUsedAt``. */
  lookup = async (hashed: string): Promise<KeyRecord | null> => {
    const row = await this.storage.findByHash(hashed);
    if (!row) return null;
    if (this.touch) {
      row.last_used_at = nowSec();
      await this.storage.update(row.id, { last_used_at: row.last_used_at });
    }
    return toRecord(row);
  };

  /** Look up a raw key directly (hashes it with the store's pepper). */
  async find(key: string): Promise<KeyRecord | null> {
    return this.lookup(await hashApiKey(key, this.pepper));
  }

  async get(id: number): Promise<KeyRecord | null> {
    const r = await this.storage.get(id);
    return r ? toRecord(r) : null;
  }

  async list(options: { activeOnly?: boolean } = {}): Promise<KeyRecord[]> {
    const records = (await this.storage.all()).map(toRecord);
    return options.activeOnly ? records.filter(isKeyActive) : records;
  }

  /** Revoke a key immediately. True if a key was revoked. */
  async revoke(id: number): Promise<boolean> {
    const r = await this.storage.get(id);
    if (!r || r.revoked_at !== null) return false;
    await this.storage.update(id, { revoked_at: nowSec() });
    return true;
  }

  /** Issue a replacement with the same name, scopes and meta; the old key expires after the grace period (default 24 h). */
  async rotate(id: number, options: Omit<CreateOptions, "scopes" | "meta"> & { graceMinutes?: number } = {}): Promise<CreatedKey> {
    const old = await this.get(id);
    if (!old || !isKeyActive(old)) throw new Error(`no active key with id ${id}`);
    const rot = await rotateApiKey({ ...options, pepper: this.pepper });
    await this.storage.update(id, { expires_at: Math.min(old.expiresAt ?? rot.oldExpiresAt, rot.oldExpiresAt) });
    const record = await this.insert(rot.key, rot.hashed, rot.expiresAt, old.name, old.scopes, old.meta);
    return { id: record.id, key: rot.key, record };
  }
}
