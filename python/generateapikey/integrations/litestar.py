"""Litestar support: ``pip install "generateapikey[litestar]"``.

::

    from litestar import Litestar, get
    from generateapikey.integrations import APIKeyAuth
    from generateapikey.integrations.litestar import api_key_middleware

    auth = APIKeyAuth(lookup=find_key_by_hash, pepper=PEPPER, prefix="sk")

    @get("/items")
    async def items(request: Request) -> dict:
        request.auth            # your stored record

    app = Litestar([items], middleware=[api_key_middleware(auth, exclude=["/health"])])

Every route not excluded requires a valid key (401/429 otherwise).
"""

from __future__ import annotations

from typing import Any, Optional, Union

try:
    from litestar.connection import ASGIConnection
    from litestar.exceptions import NotAuthorizedException, TooManyRequestsException
    from litestar.middleware import AbstractAuthenticationMiddleware, AuthenticationResult, DefineMiddleware
except ImportError as e:  # pragma: no cover
    raise ImportError('Litestar support needs: pip install "generateapikey[litestar]"') from e

from . import APIKeyAuth, AuthError

__all__ = ["APIKeyMiddleware", "api_key_middleware"]


class APIKeyMiddleware(AbstractAuthenticationMiddleware):
    """Sets ``request.auth`` to the record and ``request.user`` to ``record.user`` (or the record)."""

    def __init__(self, app, auth: APIKeyAuth, **kwargs: Any):
        super().__init__(app, **kwargs)
        self.auth = auth

    async def authenticate_request(self, connection: ASGIConnection) -> AuthenticationResult:
        key = self.auth.extract(connection.headers, connection.query_params)
        client = connection.client.host if connection.client else None
        try:
            record = await self.auth.aauthenticate(key, client)
        except AuthError as e:
            if e.status == 429:
                raise TooManyRequestsException(detail=e.detail) from None
            raise NotAuthorizedException(detail=e.detail, headers={"WWW-Authenticate": self.auth.challenge()}) from None
        return AuthenticationResult(user=getattr(record, "user", None) or record, auth=record)


def api_key_middleware(
    auth: APIKeyAuth,
    *,
    exclude: Optional[Union[str, list[str]]] = None,
    exclude_from_auth_key: str = "exclude_from_auth",
) -> DefineMiddleware:
    """Return a ``DefineMiddleware`` for ``Litestar(middleware=[...])``.

    Mark individual routes public with ``opt={"exclude_from_auth": True}``.
    """
    return DefineMiddleware(APIKeyMiddleware, auth=auth, exclude=exclude, exclude_from_auth_key=exclude_from_auth_key)
