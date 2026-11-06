"""Django support: ``pip install "generateapikey[django]"``.

1. A model (abstract base: add your own fields/FK)::

    # myapp/models.py
    from generateapikey.integrations.django import AbstractAPIKey

    class APIKey(AbstractAPIKey):
        user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    key_obj, raw_key = APIKey.objects.create_key(name="CI", user=request.user)
    # show raw_key once; only its hash is stored

2. Protect views (sync or async)::

    from generateapikey.integrations.django import APIKeyAuth, api_key_required, model_lookup

    auth = APIKeyAuth(lookup=model_lookup(APIKey), pepper=settings.API_KEY_PEPPER, prefix="sk")

    @api_key_required(auth)
    def my_view(request):
        request.api_key            # the APIKey row

   or globally with :class:`APIKeyMiddleware` (sets ``request.api_key`` when a
   valid key is present; rejects bad keys; views decide if a key is required).

Configure the middleware via ``settings.GENERATEAPIKEY_AUTH = "myproject.auth.auth"``
(dotted path to an :class:`APIKeyAuth` instance).
"""

from __future__ import annotations

import datetime
import functools
import inspect
from typing import Any, Callable, Optional

try:
    from asgiref.sync import iscoroutinefunction, markcoroutinefunction, sync_to_async
    from django.db import models
    from django.http import JsonResponse
    from django.utils import timezone
except ImportError as e:  # pragma: no cover
    raise ImportError('Django support needs: pip install "generateapikey[django]"') from e

from . import APIKeyAuth, AuthError, issue_api_key

__all__ = [
    "APIKeyAuth",
    "APIKeyManager",
    "APIKeyMiddleware",
    "AbstractAPIKey",
    "api_key_required",
    "model_lookup",
    "rehash_model",
    "touch_last_used",
]


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class APIKeyManager(models.Manager):
    def create_key(
        self, *, pepper: Optional[str] = None, key_options: Optional[dict] = None, **fields
    ) -> tuple[Any, str]:
        """Create a row and return ``(obj, raw_key)``. Only the hash is stored.

        ``key_options`` go to :func:`~generateapikey.generate_api_key` (e.g.
        ``{"prefix": "sk", "length": 40}``). Default prefix ``"sk"``.
        """
        options = {"prefix": "sk", **(key_options or {})}
        issued = issue_api_key(pepper=pepper, **options)
        if issued.key.expires_at is not None and "expires_at" not in fields:
            fields["expires_at"] = issued.key.expires_at_datetime
        obj = self.create(hashed_key=issued.hashed, hint=issued.hint, **fields)
        return obj, str(issued.key)


class AbstractAPIKey(models.Model):
    """Abstract API key model. Stores only the hash and a display hint."""

    name = models.CharField(max_length=100, blank=True, default="")
    hashed_key = models.CharField(max_length=128, unique=True, editable=False)
    hint = models.CharField(max_length=32, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True, editable=False)
    revoked = models.BooleanField(default=False)

    objects = APIKeyManager()

    class Meta:
        abstract = True

    def __str__(self) -> str:
        return f"{self.name or 'API key'} ({self.hint})"

    def revoke(self) -> None:
        self.revoked = True
        self.save(update_fields=["revoked"])

    def rotate(
        self,
        *,
        pepper: Optional[str] = None,
        grace: Optional[datetime.timedelta] = None,
        key_options: Optional[dict] = None,
        **fields,
    ) -> tuple[Any, str]:
        """Issue a replacement key and phase this one out.

        The old key keeps working for ``grace`` (default: stops immediately),
        so clients can switch without downtime. Other field values (``name``,
        FKs...) are copied unless overridden in ``fields``. Returns ``(new_obj, raw_key)``.
        """
        copy = {
            f.name: getattr(self, f.name)
            for f in self._meta.concrete_fields
            if f.name not in _NON_COPY_FIELDS and not f.primary_key
        }
        copy.update(fields)
        new_obj, raw = type(self)._default_manager.create_key(pepper=pepper, key_options=key_options, **copy)
        if grace:
            self.expires_at = (
                min(self.expires_at, timezone.now() + grace) if self.expires_at else timezone.now() + grace
            )
            self.save(update_fields=["expires_at"])
        else:
            self.revoke()
        return new_obj, raw


_NON_COPY_FIELDS = {"hashed_key", "hint", "created_at", "expires_at", "last_used_at", "revoked"}


def rehash_model(model: type[models.Model], *, field: str = "hashed_key") -> Callable[[Any, str], None]:
    """``on_rehash`` hook for pepper rotation: store the hash under the new pepper."""

    def on_rehash(record: Any, new_hashed: str) -> None:
        model._default_manager.filter(pk=record.pk).update(**{field: new_hashed})
        setattr(record, field, new_hashed)

    return on_rehash


def model_lookup(
    model: type[models.Model], *, field: str = "hashed_key", select_related: tuple[str, ...] = ()
) -> Callable[[str], Any]:
    """Build a sync ``lookup`` for :class:`APIKeyAuth` from a model."""

    def lookup(hashed: str):
        qs = model._default_manager.filter(**{field: hashed})
        if select_related:
            qs = qs.select_related(*select_related)
        return qs.first()

    return lookup


def touch_last_used(record: Any) -> None:
    """``on_success`` hook: update ``last_used_at`` without a full save."""
    if hasattr(record, "last_used_at") and record.pk is not None:
        now = timezone.now()
        type(record)._default_manager.filter(pk=record.pk).update(last_used_at=now)
        record.last_used_at = now


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------


def _client(request) -> Optional[str]:
    return request.META.get("REMOTE_ADDR")


def _error(auth: APIKeyAuth, e: AuthError) -> JsonResponse:
    resp = JsonResponse({"detail": e.detail}, status=e.status)
    if e.status == 401:
        resp["WWW-Authenticate"] = auth.challenge()
    return resp


def _authenticate_sync(auth: APIKeyAuth, request):
    return auth.authenticate(auth.extract(request.headers, request.GET), _client(request))


async def _authenticate_async(auth: APIKeyAuth, request):
    key = auth.extract(request.headers, request.GET)
    # Django ORM lookups are sync: run them off the event loop.
    if inspect.iscoroutinefunction(auth.lookup):
        return await auth.aauthenticate(key, _client(request))
    return await sync_to_async(auth.authenticate)(key, _client(request))


def api_key_required(auth: APIKeyAuth):
    """View decorator (sync or async views). Sets ``request.api_key``; 401/429 JSON otherwise."""

    def decorator(view):
        if iscoroutinefunction(view):

            @functools.wraps(view)
            async def async_wrapper(request, *args, **kwargs):
                try:
                    request.api_key = await _authenticate_async(auth, request)
                except AuthError as e:
                    return _error(auth, e)
                return await view(request, *args, **kwargs)

            return async_wrapper

        @functools.wraps(view)
        def wrapper(request, *args, **kwargs):
            try:
                request.api_key = _authenticate_sync(auth, request)
            except AuthError as e:
                return _error(auth, e)
            return view(request, *args, **kwargs)

        return wrapper

    return decorator


def _auth_from_settings() -> APIKeyAuth:
    from django.conf import settings
    from django.core.exceptions import ImproperlyConfigured
    from django.utils.module_loading import import_string

    path = getattr(settings, "GENERATEAPIKEY_AUTH", None)
    if not path:
        raise ImproperlyConfigured("Set GENERATEAPIKEY_AUTH to the dotted path of an APIKeyAuth instance.")
    auth = import_string(path)
    if not isinstance(auth, APIKeyAuth):
        raise ImproperlyConfigured("GENERATEAPIKEY_AUTH must point to an APIKeyAuth instance.")
    return auth


class APIKeyMiddleware:
    """Sets ``request.api_key`` (record or None). Requests with an invalid key get 401/429.

    Works in sync and async stacks. Configure with ``settings.GENERATEAPIKEY_AUTH``.
    """

    sync_capable = True
    async_capable = True

    def __init__(self, get_response, auth: Optional[APIKeyAuth] = None):
        self.get_response = get_response
        self.auth = auth or _auth_from_settings()
        self._async = iscoroutinefunction(get_response)
        if self._async:
            markcoroutinefunction(self)

    def __call__(self, request):
        if self._async:
            return self.__acall__(request)
        request.api_key = None
        if self.auth.extract(request.headers, request.GET) is not None:
            try:
                request.api_key = _authenticate_sync(self.auth, request)
            except AuthError as e:
                return _error(self.auth, e)
        return self.get_response(request)

    async def __acall__(self, request):
        request.api_key = None
        if self.auth.extract(request.headers, request.GET) is not None:
            try:
                request.api_key = await _authenticate_async(self.auth, request)
            except AuthError as e:
                return _error(self.auth, e)
        return await self.get_response(request)
