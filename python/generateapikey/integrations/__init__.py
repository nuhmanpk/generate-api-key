"""Framework-agnostic API key authentication.

Every framework adapter (FastAPI, Starlette, Django, DRF, Flask, Litestar) is
a thin wrapper around :class:`APIKeyAuth`, so behaviour is identical everywhere::

    from generateapikey.integrations import APIKeyAuth, issue_api_key

    # creating a key (e.g. in your "create key" endpoint)
    issued = issue_api_key(prefix="sk", pepper=PEPPER)
    db.save(hashed=issued.hashed, hint=issued.hint, owner=user)
    return issued.key                     # show once, never stored

    # checking requests
    auth = APIKeyAuth(lookup=lambda hashed: db.find_by_hash(hashed), pepper=PEPPER, prefix="sk")

Only the hash of the presented key reaches your ``lookup``. Index that column.
"""

from __future__ import annotations

import datetime as _dt
import inspect
import time
from collections.abc import Awaitable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol, Union

from .. import ApiKey, generate_api_key
from ..scopes import has_all_scopes
from ..utils import CHECKSUM_LENGTH, _check_pepper, hash_api_key, verify_checksum

__all__ = ["APIKeyAuth", "AuthError", "IssuedKey", "issue_api_key", "path_excluded", "record_is_active"]

MAX_KEY_LENGTH = 512

Lookup = Callable[[str], Union[Any, Awaitable[Any]]]


class HeaderSource(Protocol):
    """Anything header-like: a dict, werkzeug/Starlette/Django/aiohttp headers..."""

    def get(self, key: str, /) -> Any: ...

    def items(self) -> Iterable[Any]: ...


class QuerySource(Protocol):
    """Anything query-like with ``.get(name)``."""

    def get(self, key: str, /) -> Any: ...


class AuthError(Exception):
    """Authentication failed. ``status`` is 401 (missing/invalid) or 429 (rate limited)."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass(frozen=True)
class IssuedKey:
    """Result of :func:`issue_api_key`.

    ``key``: give to the client once. ``hashed``: store (unique index).
    ``hint``: store and show in your UI to identify the key (``sk-AbCd…wXyZ``).
    """

    key: ApiKey
    hashed: str
    hint: str

    def __repr__(self) -> str:  # never print the raw key
        return f"IssuedKey(hint={self.hint!r}, hashed={self.hashed[:16]}…)"


def _hint(key: str) -> str:
    return f"{key[:7]}…{key[-4:]}" if len(key) >= 16 else "…"


def issue_api_key(*, pepper: Optional[str] = None, checksum: bool = True, **options: Any) -> IssuedKey:
    """Generate a key plus everything you need to store for it.

    Accepts every :func:`~generateapikey.generate_api_key` option (``prefix``,
    ``length``, ``expiry``...). ``checksum`` defaults to True so bad keys can be
    rejected before the database is touched.
    """
    _check_pepper(pepper)
    key = generate_api_key(checksum=checksum, **options)
    return IssuedKey(key=key, hashed=hash_api_key(key, pepper), hint=_hint(key))


def _field(record: Any, name: str, default: Any = None) -> Any:
    if isinstance(record, Mapping):
        return record.get(name, default)
    return getattr(record, name, default)


def record_is_active(record: Any) -> bool:
    """Default validity check for a stored key record (object or dict).

    Rejects records with ``revoked`` truthy, ``is_active`` False, or
    ``expires_at`` (datetime or unix timestamp) in the past.
    """
    if record is None:
        return False
    if _field(record, "revoked", False):
        return False
    if _field(record, "is_active", True) is False:
        return False
    expires = _field(record, "expires_at")
    if expires is None:
        return True
    if isinstance(expires, _dt.datetime):
        now = _dt.datetime.now(expires.tzinfo) if expires.tzinfo else _dt.datetime.now()
        return now < expires
    if isinstance(expires, (int, float)):
        return time.time() < expires
    return False  # unknown type: fail closed


class APIKeyAuth:
    """Extract, pre-check, hash and look up an API key.

    Args:
        lookup: ``lookup(hashed) -> record | None``. May be ``async``. Receives
            ``hash_api_key(key, pepper)``; query your table by that column.
        pepper: Server-side pepper used when the keys were issued.
        header: Header to read the key from. Default ``X-API-Key``.
        bearer: Also accept ``Authorization: Bearer <key>``. Default True.
        query_param: Also accept ``?<query_param>=<key>`` (discouraged: URLs end
            up in logs). Default None.
        prefix: If set, reject keys not starting with it, before any lookup.
        require_checksum: Reject keys whose checksum fails (keys issued with
            ``checksum=True``) before any lookup.
        validate: ``validate(record) -> bool``; default :func:`record_is_active`.
        limiter: Optional limiter keyed by client (IP): too many bad keys -> 429.
            Protects your database. :class:`~generateapikey.mfa.AttemptLimiter`
            (one process) or :mod:`generateapikey.limiters` (Redis, shared).
        on_success: Optional ``on_success(record)`` hook (e.g. update last_used).
        previous_peppers: Old peppers still accepted during a pepper rotation.
            Keys are looked up under the current pepper first, then each old one.
        on_rehash: ``on_rehash(record, new_hashed)`` is called when a key matched
            under an old pepper, so you can store the new hash. Once every
            active key is re-hashed, drop the old pepper.
        required_scopes: Scopes every key must hold (checked against the record's
            ``scopes``; ``read:*`` and ``*`` wildcards work). Failing keys get 403.
            Override per route with ``authenticate(key, scopes=[...])``.
    """

    def __init__(
        self,
        lookup: Lookup,
        *,
        pepper: Optional[str] = None,
        header: str = "X-API-Key",
        bearer: bool = True,
        query_param: Optional[str] = None,
        prefix: Optional[str] = None,
        require_checksum: bool = False,
        validate: Callable[[Any], bool] = record_is_active,
        limiter: Optional[Any] = None,
        on_success: Optional[Callable[[Any], Any]] = None,
        previous_peppers: Sequence[str] = (),
        on_rehash: Optional[Callable[[Any, str], Any]] = None,
        required_scopes: Sequence[str] = (),
    ):
        if not callable(lookup):
            raise TypeError("lookup must be callable: lookup(hashed) -> record | None")
        _check_pepper(pepper)
        self.lookup = lookup
        self.pepper = pepper
        self.header = header
        self.bearer = bearer
        self.query_param = query_param
        self.prefix = prefix
        self.require_checksum = require_checksum
        self.validate = validate
        self.limiter = limiter
        self.on_success = on_success
        if isinstance(previous_peppers, str):
            raise TypeError("previous_peppers must be a sequence of strings, not a string.")
        for old in previous_peppers:
            if old is None:
                raise ValueError("previous_peppers entries must be non-empty strings.")
            _check_pepper(old)
        self.previous_peppers = tuple(previous_peppers)
        self.on_rehash = on_rehash
        if isinstance(required_scopes, str):
            raise TypeError("required_scopes must be a sequence of strings, not a string.")
        self.required_scopes = tuple(required_scopes)

    # ------------------------------------------------------------- extraction

    def extract(
        self,
        headers: HeaderSource,
        query: Optional[QuerySource] = None,
    ) -> Optional[str]:
        """Pull the raw key from request headers (case-insensitive) or query."""
        value = _get_header(headers, self.header)
        if not value and self.bearer:
            authz = _get_header(headers, "Authorization")
            if authz:
                scheme, _, token = authz.strip().partition(" ")
                if scheme.lower() == "bearer":
                    value = token
        if not value and self.query_param and query is not None:
            q = query.get(self.query_param)
            value = q if isinstance(q, str) else None
        if not value:
            return None
        value = value.strip()
        return value or None

    # --------------------------------------------------------------- checking

    def _hashes(self, key: str) -> tuple[str, ...]:
        """Current-pepper hash first, then one per previous pepper."""
        return (hash_api_key(key, self.pepper), *tuple(hash_api_key(key, p) for p in self.previous_peppers))

    def _well_formed(self, key: str) -> bool:
        """Cheap checks that never touch the database."""
        return not (
            len(key) > MAX_KEY_LENGTH
            or not key.isascii()
            or (self.prefix and not key.startswith(self.prefix))
            or (self.require_checksum and (len(key) <= CHECKSUM_LENGTH or not verify_checksum(key)))
        )

    def _ok(self, record: Any) -> bool:
        return record is not None and bool(self.validate(record))

    _BLOCKED = AuthError(429, "Too many invalid API keys. Try again later.")

    def _check_scopes(self, record: Any, scopes: Optional[Sequence[str]]) -> None:
        needed = self.required_scopes if scopes is None else tuple(scopes)
        if needed and not has_all_scopes(_field(record, "scopes"), needed):
            raise AuthError(403, "Insufficient scope.")

    def authenticate(
        self, key: Optional[str], client: Optional[str] = None, scopes: Optional[Sequence[str]] = None
    ) -> Any:
        """Return the stored record for ``key`` or raise :class:`AuthError`. Sync."""
        limiter = self.limiter if client else None
        if limiter is not None and _sync(limiter.is_blocked(client), "limiter"):
            raise AuthError(self._BLOCKED.status, self._BLOCKED.detail)
        if not key:
            raise AuthError(401, "Missing API key.")
        record: Any = None
        matched = 0
        hashes: tuple[str, ...] = ()
        if self._well_formed(key):
            hashes = self._hashes(key)
            for i, hashed in enumerate(hashes):
                record = _sync(self.lookup(hashed), "lookup")
                if record is not None:
                    matched = i
                    break
        if not self._ok(record):
            if limiter is not None:
                _sync(limiter.fail(client), "limiter")
            raise AuthError(401, "Invalid API key.")
        self._check_scopes(record, scopes)
        if matched and self.on_rehash is not None:
            self.on_rehash(record, hashes[0])
        if self.on_success is not None:
            self.on_success(record)
        return record

    async def aauthenticate(
        self, key: Optional[str], client: Optional[str] = None, scopes: Optional[Sequence[str]] = None
    ) -> Any:
        """Async version of :meth:`authenticate`.

        ``lookup``, ``on_success``, ``on_rehash`` and the limiter may each be sync or async.
        """
        limiter = self.limiter if client else None
        if limiter is not None and await _maybe_await(limiter.is_blocked(client)):
            raise AuthError(self._BLOCKED.status, self._BLOCKED.detail)
        if not key:
            raise AuthError(401, "Missing API key.")
        record: Any = None
        matched = 0
        hashes: tuple[str, ...] = ()
        if self._well_formed(key):
            hashes = self._hashes(key)
            for i, hashed in enumerate(hashes):
                record = await _maybe_await(self.lookup(hashed))
                if record is not None:
                    matched = i
                    break
        if not self._ok(record):
            if limiter is not None:
                await _maybe_await(limiter.fail(client))
            raise AuthError(401, "Invalid API key.")
        self._check_scopes(record, scopes)
        if matched and self.on_rehash is not None:
            await _maybe_await(self.on_rehash(record, hashes[0]))
        if self.on_success is not None:
            await _maybe_await(self.on_success(record))
        return record

    def challenge(self) -> str:
        """Value for the ``WWW-Authenticate`` header on 401 responses."""
        return 'Bearer realm="api"' if self.bearer else f'ApiKey header="{self.header}"'


def path_excluded(path: str, exclude: Sequence[str]) -> bool:
    """Segment-aware prefix match for ``exclude`` lists.

    ``/health`` matches ``/health`` and ``/health/live`` but *not* ``/healthz``
    or ``/health-admin``, so excluding one route can't open up a neighbour.
    """
    for prefix in exclude:
        base = prefix.rstrip("/")
        if path in (prefix, base) or path.startswith(base + "/"):
            return True
    return False


def _sync(value: Any, what: str) -> Any:
    if inspect.isawaitable(value):
        if hasattr(value, "close"):
            value.close()
        raise TypeError(f"{what} is async; use aauthenticate() / an async framework adapter.")
    return value


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _get_header(headers: HeaderSource, name: str) -> Optional[str]:
    value = headers.get(name)
    if value is None:
        value = headers.get(name.lower())
    if value is None and not hasattr(headers, "getlist"):
        lname = name.lower()
        for k, v in headers.items():
            if isinstance(k, str) and k.lower() == lname:
                value = v
                break
    # Frameworks differ (bytes, lists...); anything but a str is "no key".
    return value if isinstance(value, str) else None
