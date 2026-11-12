"""A small SQLite key store (standard library only): create, look up, revoke, rotate.

Good for CLIs, internal tools and small services. For a real database use
:func:`~generateapikey.integrations.issue_api_key` with your own table.

    store = KeyStore("keys.db", pepper=PEPPER)
    issued = store.create("ci-bot", scopes=["read:*"], prefix="sk", expiry=60 * 24 * 90)
    issued.key                      # show once
    auth = APIKeyAuth(store.lookup, pepper=PEPPER)   # works with every framework adapter
    store.revoke(issued.id)
    new = store.rotate(issued.id, grace_minutes=24 * 60)   # old key keeps working for 24 h
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

from . import ApiKey, generate_api_key, hash_api_key
from .scopes import parse_scopes

__all__ = ["KeyRecord", "KeyStore", "Rotation", "rotate_api_key"]


@dataclass(frozen=True)
class KeyRecord:
    """A stored key (never the raw key). Works with ``record_is_active`` and scope checks."""

    id: int
    name: str
    hint: str
    scopes: frozenset[str]
    created_at: int
    expires_at: Optional[int]
    revoked: bool
    last_used_at: Optional[int]
    meta: dict[str, Any]

    @property
    def is_active(self) -> bool:
        return not self.revoked and (self.expires_at is None or time.time() < self.expires_at)


@dataclass(frozen=True)
class Rotation:
    """Result of :func:`rotate_api_key`: store ``hashed`` for the new key and give the old one ``old_expires_at``."""

    key: ApiKey
    hashed: str
    old_expires_at: int

    def __repr__(self) -> str:
        return f"Rotation(old_expires_at={self.old_expires_at}, hashed={self.hashed[:16]}…)"


def rotate_api_key(*, grace_minutes: float = 24 * 60, pepper: Optional[str] = None, **options: Any) -> Rotation:
    """Issue a replacement key and compute when the old one should stop working.

    Set the old record's ``expires_at`` to ``old_expires_at`` and store the new
    hash, so clients can switch without downtime. Takes every
    :func:`~generateapikey.generate_api_key` option for the new key.
    """
    if grace_minutes < 0:
        raise ValueError("grace_minutes must be >= 0.")
    options.setdefault("checksum", True)
    key = generate_api_key(**options)
    return Rotation(key=key, hashed=hash_api_key(key, pepper), old_expires_at=int(time.time() + grace_minutes * 60))


@dataclass(frozen=True)
class Created:
    """Returned by :meth:`KeyStore.create`: ``key`` is shown to the user once."""

    id: int
    key: ApiKey
    record: KeyRecord

    def __repr__(self) -> str:
        return f"Created(id={self.id}, hint={self.record.hint!r})"


_SCHEMA = """
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
"""


class KeyStore:
    """SQLite-backed API key store. Thread-safe; stores only hashes."""

    def __init__(
        self,
        path: str = ":memory:",
        *,
        pepper: Optional[str] = None,
        touch: bool = True,
        table_check: bool = True,
    ):
        self.pepper = pepper
        self._touch = touch
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        if table_check:
            self._db.execute(_SCHEMA)
            self._db.commit()

    # ---------------------------------------------------------------- helpers

    @staticmethod
    def _record(row: sqlite3.Row) -> KeyRecord:
        return KeyRecord(
            id=row["id"],
            name=row["name"],
            hint=row["hint"],
            scopes=frozenset(json.loads(row["scopes"])),
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            revoked=row["revoked_at"] is not None,
            last_used_at=row["last_used_at"],
            meta=json.loads(row["meta"]),
        )

    def _insert(self, key: ApiKey, name: str, scopes: Any, meta: Optional[dict[str, Any]]) -> KeyRecord:
        hint = f"{key[:7]}…{key[-4:]}" if len(key) >= 16 else "…"
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO api_keys (hashed, name, hint, scopes, created_at, expires_at, meta) VALUES (?,?,?,?,?,?,?)",
                (
                    hash_api_key(key, self.pepper),
                    name,
                    hint,
                    json.dumps(sorted(parse_scopes(scopes))),
                    int(time.time()),
                    key.expires_at,
                    json.dumps(meta or {}),
                ),
            )
            self._db.commit()
            row = self._db.execute("SELECT * FROM api_keys WHERE id = ?", (cur.lastrowid,)).fetchone()
        return self._record(row)

    # -------------------------------------------------------------------- API

    def create(
        self,
        name: str,
        *,
        scopes: Any = (),
        meta: Optional[dict[str, Any]] = None,
        expiry: Optional[float] = None,
        **options: Any,
    ) -> Created:
        """Create and store a key. ``expiry`` is minutes; other options go to ``generate_api_key``."""
        if not isinstance(name, str) or not name:
            raise ValueError("name must be a non-empty string.")
        options.setdefault("checksum", True)
        key = generate_api_key(expiry=expiry, **options)
        record = self._insert(key, name, scopes, meta)
        return Created(id=record.id, key=key, record=record)

    def lookup(self, hashed: str) -> Optional[KeyRecord]:
        """``lookup`` callback for :class:`~generateapikey.integrations.APIKeyAuth`. Updates ``last_used_at``."""
        with self._lock:
            row = self._db.execute("SELECT * FROM api_keys WHERE hashed = ?", (hashed,)).fetchone()
            if row is None:
                return None
            if self._touch:
                self._db.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (int(time.time()), row["id"]))
                self._db.commit()
        return self._record(row)

    def get(self, key_id: int) -> Optional[KeyRecord]:
        with self._lock:
            row = self._db.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
        return None if row is None else self._record(row)

    def list(self, *, active_only: bool = False) -> list[KeyRecord]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM api_keys ORDER BY id").fetchall()
        records = [self._record(r) for r in rows]
        return [r for r in records if r.is_active] if active_only else records

    def revoke(self, key_id: int) -> bool:
        """Revoke a key immediately. True if a key was revoked."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", (int(time.time()), key_id)
            )
            self._db.commit()
        return cur.rowcount > 0

    def rotate(self, key_id: int, *, grace_minutes: float = 24 * 60, **options: Any) -> Created:
        """Issue a replacement with the same name, scopes and meta; the old key expires after the grace period."""
        old = self.get(key_id)
        if old is None or not old.is_active:
            raise KeyError(f"no active key with id {key_id}")
        rotation = rotate_api_key(grace_minutes=grace_minutes, pepper=self.pepper, **options)
        with self._lock:
            self._db.execute(
                "UPDATE api_keys SET expires_at = MIN(COALESCE(expires_at, ?), ?) WHERE id = ?",
                (rotation.old_expires_at, rotation.old_expires_at, key_id),
            )
            self._db.commit()
        record = self._insert(rotation.key, old.name, old.scopes, old.meta)
        return Created(id=record.id, key=rotation.key, record=record)

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> KeyStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
