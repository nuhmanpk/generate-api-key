"""Flask support: ``pip install "generateapikey[flask]"``.

::

    from generateapikey.integrations import APIKeyAuth
    from generateapikey.integrations.flask import require_api_key

    auth = APIKeyAuth(lookup=find_key_by_hash, pepper=PEPPER, prefix="sk")

    @app.get("/items")
    @require_api_key(auth)
    def items():
        g.api_key          # your stored record

Or app-wide: ``FlaskAPIKey(app, auth)`` then ``@api_key.required`` on views.
Async views (Flask[async]) work too.
"""

from __future__ import annotations

import functools
import inspect
from typing import Optional

try:
    from flask import Flask, g, jsonify, request
except ImportError as e:  # pragma: no cover
    raise ImportError('Flask support needs: pip install "generateapikey[flask]"') from e

from . import APIKeyAuth, AuthError

__all__ = ["FlaskAPIKey", "require_api_key"]


def _error(auth: APIKeyAuth, e: AuthError):
    resp = jsonify(detail=e.detail)
    resp.status_code = e.status
    if e.status == 401:
        resp.headers["WWW-Authenticate"] = auth.challenge()
    return resp


def require_api_key(auth: APIKeyAuth):
    """View decorator. Sets ``flask.g.api_key``; returns 401/429 JSON otherwise."""

    def decorator(view):
        if inspect.iscoroutinefunction(view):

            @functools.wraps(view)
            async def async_wrapper(*args, **kwargs):
                key = auth.extract(request.headers, request.args)
                try:
                    g.api_key = await auth.aauthenticate(key, request.remote_addr)
                except AuthError as e:
                    return _error(auth, e)
                return await view(*args, **kwargs)

            return async_wrapper

        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            key = auth.extract(request.headers, request.args)
            try:
                g.api_key = auth.authenticate(key, request.remote_addr)
            except AuthError as e:
                return _error(auth, e)
            return view(*args, **kwargs)

        return wrapper

    return decorator


class FlaskAPIKey:
    """Flask extension holding one :class:`APIKeyAuth` for the app."""

    def __init__(self, app: Optional[Flask] = None, auth: Optional[APIKeyAuth] = None):
        self.auth = auth
        if app is not None:
            self.init_app(app, auth)

    def init_app(self, app: Flask, auth: Optional[APIKeyAuth] = None) -> None:
        if auth is not None:
            self.auth = auth
        if self.auth is None:
            raise ValueError("FlaskAPIKey needs an APIKeyAuth instance.")
        app.extensions["generateapikey"] = self

    def required(self, view):
        """Decorator: ``@api_key.required``."""
        if self.auth is None:
            raise ValueError("call init_app() first.")
        return require_api_key(self.auth)(view)
