"""Django REST Framework support: ``pip install "generateapikey[drf]"``.

::

    # myproject/auth.py
    from generateapikey.integrations import APIKeyAuth
    from generateapikey.integrations.django import model_lookup
    auth = APIKeyAuth(lookup=model_lookup(APIKey, select_related=("user",)), pepper=..., prefix="sk")

    # settings.py
    GENERATEAPIKEY_AUTH = "myproject.auth.auth"
    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": ["generateapikey.integrations.drf.APIKeyAuthentication"],
    }

    # views
    class Items(APIView):
        permission_classes = [HasAPIKey]       # or IsAuthenticated
        def get(self, request):
            request.auth          # the APIKey row
            request.user          # record.user if it has one, else an APIKeyUser

Subclass ``APIKeyAuthentication`` and set ``auth = ...`` to skip the setting.
"""

from __future__ import annotations

from typing import Any, Optional

try:
    from rest_framework import exceptions
    from rest_framework.authentication import BaseAuthentication
    from rest_framework.permissions import BasePermission
except ImportError as e:  # pragma: no cover
    raise ImportError('DRF support needs: pip install "generateapikey[drf]"') from e

from . import APIKeyAuth, AuthError

__all__ = ["APIKeyAuthentication", "APIKeyUser", "HasAPIKey"]


class APIKeyUser:
    """``request.user`` when the key record has no ``user``: authenticated, not staff."""

    is_authenticated = True
    is_anonymous = False
    is_active = True
    is_staff = False
    is_superuser = False
    pk = id = None

    def __init__(self, record: Any):
        self.record = record

    def __str__(self) -> str:
        return str(getattr(self.record, "name", "") or "api-key")

    def has_perm(self, *a, **k) -> bool:
        return False


class Throttled429(exceptions.Throttled):
    pass


class APIKeyAuthentication(BaseAuthentication):
    auth: Optional[APIKeyAuth] = None

    def _auth(self) -> APIKeyAuth:
        auth = self.auth
        if auth is None:
            from .django import _auth_from_settings

            auth = type(self).auth = _auth_from_settings()
        return auth

    def authenticate(self, request):
        auth = self._auth()
        key = auth.extract(request.headers, request.query_params)
        if key is None:
            return None  # let other authenticators / permissions decide
        try:
            record = auth.authenticate(key, request.META.get("REMOTE_ADDR"))
        except AuthError as e:
            if e.status == 429:
                raise Throttled429(detail=e.detail) from None
            raise exceptions.AuthenticationFailed(e.detail) from None
        user = getattr(record, "user", None) or APIKeyUser(record)
        return user, record

    def authenticate_header(self, request) -> str:
        return self._auth().challenge()


class HasAPIKey(BasePermission):
    """Allow only requests authenticated by :class:`APIKeyAuthentication`."""

    message = "A valid API key is required."

    def has_permission(self, request, view) -> bool:
        return isinstance(getattr(request, "successful_authenticator", None), APIKeyAuthentication)
