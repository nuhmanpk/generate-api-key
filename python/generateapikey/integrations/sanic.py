"""Sanic support: ``pip install "generateapikey[sanic]"``.

::

    from generateapikey.integrations import APIKeyAuth
    from generateapikey.integrations.sanic import require_api_key

    auth = APIKeyAuth(lookup=find_key_by_hash, pepper=PEPPER, prefix="sk")

    @app.get("/items")
    @require_api_key(auth)
    async def items(request):
        request.ctx.api_key      # your stored record

``lookup`` may be sync or async.
"""

from __future__ import annotations

import functools

try:
    from sanic.response import json as json_response
except ImportError as e:  # pragma: no cover
    raise ImportError('Sanic support needs: pip install "generateapikey[sanic]"') from e

from . import APIKeyAuth, AuthError

__all__ = ["require_api_key"]


def _error(auth: APIKeyAuth, e: AuthError):
    headers = {"WWW-Authenticate": auth.challenge()} if e.status == 401 else None
    return json_response({"detail": e.detail}, status=e.status, headers=headers)


def require_api_key(auth: APIKeyAuth):
    """Handler decorator. Sets ``request.ctx.api_key``; returns 401/429 JSON otherwise."""

    def decorator(handler):
        @functools.wraps(handler)
        async def wrapper(request, *args, **kwargs):
            key = auth.extract(request.headers, request.args)
            try:
                request.ctx.api_key = await auth.aauthenticate(key, request.ip or None)
            except AuthError as e:
                return _error(auth, e)
            return await handler(request, *args, **kwargs)

        return wrapper

    return decorator
