"""Falcon support (WSGI and ASGI): ``pip install "generateapikey[falcon]"``.

::

    import falcon
    from generateapikey.integrations import APIKeyAuth
    from generateapikey.integrations.falcon import APIKeyMiddleware, require_api_key

    auth = APIKeyAuth(lookup=find_key_by_hash, pepper=PEPPER, prefix="sk")

    class Items:
        def on_get(self, req, resp):
            req.context.api_key      # your stored record

    app = falcon.App(middleware=[APIKeyMiddleware(auth, exclude=["/health"])])
    # ASGI: falcon.asgi.App(middleware=[AsyncAPIKeyMiddleware(auth)])

Or per resource/responder: ``@falcon.before(require_api_key(auth))`` (works
on WSGI and ASGI apps). Failures raise ``HTTPUnauthorized`` / ``HTTPTooManyRequests``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Optional

try:
    import falcon
    from falcon.asgi import Request as AsgiRequest
except ImportError as e:  # pragma: no cover
    raise ImportError('Falcon support needs: pip install "generateapikey[falcon]"') from e

from . import APIKeyAuth, AuthError, path_excluded

__all__ = ["APIKeyMiddleware", "AsyncAPIKeyMiddleware", "require_api_key"]


def _query(req) -> Mapping[str, Any]:
    # Repeated params come back as lists in Falcon; take the first value.
    return {k: (v[0] if isinstance(v, list) and v else v) for k, v in req.params.items()}


def _raise(auth: APIKeyAuth, e: AuthError):
    if e.status == 429:
        raise falcon.HTTPTooManyRequests(description=e.detail) from None
    raise falcon.HTTPUnauthorized(description=e.detail, challenges=[auth.challenge()]) from None


def _check(auth: APIKeyAuth, req) -> None:
    key = auth.extract(req.headers, _query(req))
    try:
        req.context.api_key = auth.authenticate(key, req.remote_addr)
    except AuthError as e:
        _raise(auth, e)


async def _acheck(auth: APIKeyAuth, req) -> None:
    key = auth.extract(req.headers, _query(req))
    try:
        req.context.api_key = await auth.aauthenticate(key, req.remote_addr)
    except AuthError as e:
        _raise(auth, e)


class _Base:
    def __init__(self, auth: APIKeyAuth, exclude: Optional[Iterable[str]] = None):
        self.auth = auth
        self.exclude = tuple(exclude or ())

    def _skip(self, req) -> bool:
        return bool(self.exclude) and path_excluded(req.path, self.exclude)


class APIKeyMiddleware(_Base):
    """WSGI middleware (``falcon.App``): every routed path not under an ``exclude`` prefix needs a key.

    Matching is per path segment: ``/health`` excludes ``/health/live`` but not ``/healthz``.
    """

    def process_resource(self, req, resp, resource, params) -> None:
        if resource is None or self._skip(req):
            return
        _check(self.auth, req)


class AsyncAPIKeyMiddleware(_Base):
    """ASGI middleware (``falcon.asgi.App``); ``lookup`` may be sync or async."""

    async def process_resource(self, req, resp, resource, params) -> None:
        if resource is None or self._skip(req):
            return
        await _acheck(self.auth, req)


def require_api_key(auth: APIKeyAuth):
    """Hook for ``@falcon.before(...)``. Sets ``req.context.api_key``.

    Works on ``falcon.App`` and ``falcon.asgi.App`` responders; on ASGI it
    returns a coroutine (which Falcon awaits), so ``lookup`` may be async.
    """

    def hook(req, resp, resource, params):
        if isinstance(req, AsgiRequest):
            return _acheck(auth, req)
        _check(auth, req)
        return None

    return hook
