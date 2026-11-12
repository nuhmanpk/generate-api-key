"""Quart support: ``pip install "generateapikey[quart]"``.

::

    from quart import g
    from generateapikey.integrations import APIKeyAuth
    from generateapikey.integrations.quart import require_api_key

    auth = APIKeyAuth(lookup=find_key_by_hash, pepper=PEPPER, prefix="sk")

    @app.get("/items")
    @require_api_key(auth)
    async def items():
        g.api_key          # your stored record

``lookup`` may be sync or async.
"""

from __future__ import annotations

import functools

try:
    from quart import g, jsonify, request
except ImportError as e:  # pragma: no cover
    raise ImportError('Quart support needs: pip install "generateapikey[quart]"') from e

from . import APIKeyAuth, AuthError

__all__ = ["require_api_key"]


async def _error(auth: APIKeyAuth, e: AuthError):
    resp = jsonify(detail=e.detail)
    resp.status_code = e.status
    if e.status == 401:
        resp.headers["WWW-Authenticate"] = auth.challenge()
    return resp


def require_api_key(auth: APIKeyAuth):
    """Async view decorator. Sets ``quart.g.api_key``; returns 401/429 JSON otherwise."""

    def decorator(view):
        @functools.wraps(view)
        async def wrapper(*args, **kwargs):
            key = auth.extract(request.headers, request.args)
            try:
                g.api_key = await auth.aauthenticate(key, request.remote_addr)
            except AuthError as e:
                return await _error(auth, e)
            return await view(*args, **kwargs)

        return wrapper

    return decorator
