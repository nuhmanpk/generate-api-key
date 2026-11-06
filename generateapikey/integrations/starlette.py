"""Starlette (and any Starlette-based app, incl. FastAPI) authentication backend.

::

    from starlette.middleware import Middleware
    from starlette.middleware.authentication import AuthenticationMiddleware
    from generateapikey.integrations.starlette import APIKeyBackend, on_auth_error

    app = Starlette(middleware=[
        Middleware(AuthenticationMiddleware, backend=APIKeyBackend(auth), on_error=on_auth_error),
    ])

    @requires("authenticated")            # starlette.authentication.requires
    async def endpoint(request):
        record = request.user.record

Requests without a key pass through as unauthenticated (use ``@requires``);
requests with a *bad* key get 401/429.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Optional

try:
    from starlette.authentication import AuthCredentials, AuthenticationBackend, AuthenticationError, BaseUser
    from starlette.requests import HTTPConnection
    from starlette.responses import JSONResponse
except ImportError as e:  # pragma: no cover
    raise ImportError('Starlette support needs: pip install "generateapikey[starlette]"') from e

from . import APIKeyAuth, AuthError

__all__ = ["APIKeyBackend", "APIKeyUser", "on_auth_error"]


class APIKeyUser(BaseUser):
    """``request.user`` for a valid key; the stored record is ``.record``."""

    def __init__(self, record: Any):
        self.record = record

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        name = getattr(self.record, "name", None)
        if name is None and isinstance(self.record, dict):
            name = self.record.get("name")
        return str(name or "api-key")

    @property
    def identity(self) -> str:
        return self.display_name


class _KeyAuthError(AuthenticationError):
    def __init__(self, error: AuthError, challenge: str):
        super().__init__(error.detail)
        self.status = error.status
        self.challenge = challenge


class APIKeyBackend(AuthenticationBackend):
    """Starlette ``AuthenticationBackend`` backed by :class:`APIKeyAuth`.

    ``scopes(record)`` may return the granted scopes (default: ``["authenticated"]``
    plus the record's ``scopes`` field if it has one).
    """

    def __init__(self, auth: APIKeyAuth, scopes=None):
        self.auth = auth
        self.scopes = scopes or _default_scopes

    async def authenticate(self, conn: HTTPConnection) -> Optional[tuple[AuthCredentials, BaseUser]]:
        key = self.auth.extract(conn.headers, conn.query_params)
        if key is None:
            return None
        client = conn.client.host if conn.client else None
        try:
            record = await self.auth.aauthenticate(key, client)
        except AuthError as e:
            raise _KeyAuthError(e, self.auth.challenge()) from None
        return AuthCredentials(list(self.scopes(record))), APIKeyUser(record)


def _default_scopes(record: Any) -> Iterable[str]:
    extra = getattr(record, "scopes", None)
    if extra is None and isinstance(record, dict):
        extra = record.get("scopes")
    return ["authenticated", *(extra or [])]


def on_auth_error(conn: HTTPConnection, exc: Exception) -> JSONResponse:
    """``on_error`` handler for ``AuthenticationMiddleware``: proper 401/429 JSON."""
    status = getattr(exc, "status", 401)
    headers = {"WWW-Authenticate": exc.challenge} if status == 401 and hasattr(exc, "challenge") else None
    return JSONResponse({"detail": str(exc)}, status_code=status, headers=headers)
