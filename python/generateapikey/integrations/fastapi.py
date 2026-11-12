"""FastAPI support: ``pip install "generateapikey[fastapi]"``.

::

    from fastapi import Depends, FastAPI
    from generateapikey.integrations import APIKeyAuth
    from generateapikey.integrations.fastapi import APIKeyDependency

    auth = APIKeyAuth(lookup=find_key_by_hash, pepper=PEPPER, prefix="sk")
    require_key = APIKeyDependency(auth)

    @app.get("/items")
    async def items(key=Depends(require_key)):     # key = your stored record
        ...

The dependency registers an OpenAPI security scheme, so ``/docs`` shows the
"Authorize" button.
"""

from __future__ import annotations

from typing import Any, Optional

try:
    from fastapi import HTTPException, Request
    from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
except ImportError as e:  # pragma: no cover
    raise ImportError('FastAPI support needs: pip install "generateapikey[fastapi]"') from e

from . import APIKeyAuth, AuthError

__all__ = ["APIKeyDependency"]


def _client(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


class APIKeyDependency:
    """FastAPI dependency returning the authenticated key record.

    Raises ``HTTPException`` 401 (with ``WWW-Authenticate``) or 429. The record
    is also stored on ``request.state.api_key``.
    """

    def __init__(self, auth: APIKeyAuth, *, scheme_name: str = "APIKey"):
        self.auth = auth
        # Only used to describe the scheme in OpenAPI; extraction is done by auth.
        self._header_scheme = APIKeyHeader(name=auth.header, auto_error=False, scheme_name=scheme_name)
        self._bearer_scheme = HTTPBearer(auto_error=False, scheme_name=f"{scheme_name}Bearer") if auth.bearer else None
        self.__signature__ = self._build_signature()

    def _build_signature(self):
        import inspect

        from fastapi import Security

        params = [
            inspect.Parameter("request", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Request),
            inspect.Parameter(
                "_header",
                inspect.Parameter.KEYWORD_ONLY,
                default=Security(self._header_scheme),
                annotation=Optional[str],
            ),
        ]
        if self._bearer_scheme is not None:
            params.append(
                inspect.Parameter(
                    "_bearer",
                    inspect.Parameter.KEYWORD_ONLY,
                    default=Security(self._bearer_scheme),
                    annotation=Optional[HTTPAuthorizationCredentials],
                )
            )
        return inspect.Signature(params)

    async def __call__(self, request: Request, _header: Any = None, _bearer: Any = None) -> Any:
        key = self.auth.extract(request.headers, request.query_params)
        try:
            record = await self.auth.aauthenticate(key, _client(request))
        except AuthError as e:
            headers = {"WWW-Authenticate": self.auth.challenge()} if e.status == 401 else None
            raise HTTPException(status_code=e.status, detail=e.detail, headers=headers) from None
        request.state.api_key = record
        return record
