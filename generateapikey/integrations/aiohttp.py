"""aiohttp support: ``pip install "generateapikey[aiohttp]"``.

::

    from aiohttp import web
    from generateapikey.integrations import APIKeyAuth
    from generateapikey.integrations.aiohttp import api_key_middleware, require_api_key

    auth = APIKeyAuth(lookup=find_key_by_hash, pepper=PEPPER, prefix="sk")

    async def items(request):
        request["api_key"]       # your stored record

    app = web.Application(middlewares=[api_key_middleware(auth, exclude=["/health"])])

Or per handler: ``@require_api_key(auth)``. ``lookup`` may be sync or async.
"""

from __future__ import annotations

import functools
from collections.abc import Iterable
from typing import Optional

try:
    from aiohttp import web
except ImportError as e:  # pragma: no cover
    raise ImportError('aiohttp support needs: pip install "generateapikey[aiohttp]"') from e

from . import APIKeyAuth, AuthError, path_excluded

__all__ = ["api_key_middleware", "require_api_key"]


def _error(auth: APIKeyAuth, e: AuthError) -> web.Response:
    headers = {"WWW-Authenticate": auth.challenge()} if e.status == 401 else None
    return web.json_response({"detail": e.detail}, status=e.status, headers=headers)


async def _check(auth: APIKeyAuth, request: web.Request) -> Optional[web.Response]:
    key = auth.extract(request.headers, request.query)
    try:
        request["api_key"] = await auth.aauthenticate(key, request.remote)
    except AuthError as e:
        return _error(auth, e)
    return None


def api_key_middleware(auth: APIKeyAuth, exclude: Optional[Iterable[str]] = None):
    """App middleware: every path not under an ``exclude`` prefix needs a key.

    Matching is per path segment: ``/health`` excludes ``/health/live`` but not ``/healthz``.
    """
    prefixes = tuple(exclude or ())

    @web.middleware
    async def middleware(request: web.Request, handler):
        if prefixes and path_excluded(request.path, prefixes):
            return await handler(request)
        error = await _check(auth, request)
        if error is not None:
            return error
        return await handler(request)

    return middleware


def require_api_key(auth: APIKeyAuth):
    """Handler decorator. Sets ``request["api_key"]``; returns 401/429 JSON otherwise."""

    def decorator(handler):
        @functools.wraps(handler)
        async def wrapper(request: web.Request, *args, **kwargs):
            error = await _check(auth, request)
            if error is not None:
                return error
            return await handler(request, *args, **kwargs)

        return wrapper

    return decorator
