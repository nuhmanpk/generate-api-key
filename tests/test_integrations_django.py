"""Django + DRF adapters against a real in-memory Django project."""

import asyncio
import datetime as dt

import pytest

django = pytest.importorskip("django")  # settings are configured in conftest.py

from django.db import connection
from django.test import AsyncRequestFactory, RequestFactory

from generateapikey.integrations import APIKeyAuth, AuthError
from generateapikey.integrations.django import (
    AbstractAPIKey,
    APIKeyMiddleware,
    api_key_required,
    model_lookup,
    touch_last_used,
)

PEPPER = "django-test-pepper"


class APIKey(AbstractAPIKey):
    class Meta:
        app_label = "gak_tests"


with connection.schema_editor() as editor:
    editor.create_model(APIKey)

AUTH = APIKeyAuth(lookup=model_lookup(APIKey), pepper=PEPPER, prefix="sk", on_success=touch_last_used)

rf, arf = RequestFactory(), AsyncRequestFactory()


def make_key(**fields):
    fields.setdefault("name", "ci")
    return APIKey.objects.create_key(pepper=PEPPER, **fields)


@pytest.fixture(autouse=True)
def _clean():
    APIKey.objects.all().delete()


def test_create_key_stores_only_hash():
    obj, raw = make_key()
    assert raw.startswith("sk-") and raw not in obj.hashed_key and raw not in obj.hint
    assert obj.hashed_key.startswith("hmac-sha256$") and "…" in str(obj)


def test_create_key_with_expiry_option():
    obj, _ = APIKey.objects.create_key(pepper=PEPPER, key_options={"expiry": 60})
    assert obj.expires_at is not None and obj.expires_at > dt.datetime.now(dt.timezone.utc)


def test_decorator_sync_view():
    @api_key_required(AUTH)
    def view(request):
        from django.http import JsonResponse

        return JsonResponse({"name": request.api_key.name})

    obj, raw = make_key()
    assert view(rf.get("/", HTTP_X_API_KEY=raw)).status_code == 200
    assert view(rf.get("/", HTTP_AUTHORIZATION=f"Bearer {raw}")).status_code == 200
    resp = view(rf.get("/"))
    assert resp.status_code == 401 and resp["WWW-Authenticate"].startswith("Bearer")
    assert view(rf.get("/", HTTP_X_API_KEY="sk-wrong")).status_code == 401
    obj.refresh_from_db()
    assert obj.last_used_at is not None


def test_decorator_async_view():
    from django.http import JsonResponse

    @api_key_required(AUTH)
    async def view(request):
        return JsonResponse({"name": request.api_key.name})

    _, raw = make_key()
    assert asyncio.run(view(arf.get("/", headers={"X-API-Key": raw}))).status_code == 200
    assert asyncio.run(view(arf.get("/"))).status_code == 401


def test_revoked_and_expired_rejected():
    @api_key_required(AUTH)
    def view(request):
        from django.http import HttpResponse

        return HttpResponse("ok")

    obj, raw = make_key()
    obj.revoke()
    assert view(rf.get("/", HTTP_X_API_KEY=raw)).status_code == 401
    _, raw2 = make_key(expires_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1))
    assert view(rf.get("/", HTTP_X_API_KEY=raw2)).status_code == 401


def test_middleware_sync_and_async():
    from django.http import HttpResponse

    def get_response(request):
        return HttpResponse(str(request.api_key.name if request.api_key else None))

    async def aget_response(request):
        return HttpResponse(str(request.api_key.name if request.api_key else None))

    _, raw = make_key()
    mw = APIKeyMiddleware(get_response)  # auth from settings.GENERATEAPIKEY_AUTH
    assert mw(rf.get("/", HTTP_X_API_KEY=raw)).content == b"ci"
    assert mw(rf.get("/")).content == b"None"
    assert mw(rf.get("/", HTTP_X_API_KEY="sk-bad")).status_code == 401

    amw = APIKeyMiddleware(aget_response, auth=AUTH)
    assert asyncio.run(amw(arf.get("/", headers={"X-API-Key": raw}))).content == b"ci"
    assert asyncio.run(amw(arf.get("/", headers={"X-API-Key": "sk-bad"}))).status_code == 401


def test_middleware_misconfigured():
    from django.core.exceptions import ImproperlyConfigured
    from django.test import override_settings

    with override_settings(GENERATEAPIKEY_AUTH=None):
        with pytest.raises(ImproperlyConfigured):
            APIKeyMiddleware(lambda r: None)


# --------------------------------------------------------------------------- DRF


def test_drf_authentication_and_permission():
    pytest.importorskip("rest_framework")
    from rest_framework.response import Response
    from rest_framework.test import APIRequestFactory
    from rest_framework.views import APIView

    from generateapikey.integrations.drf import APIKeyAuthentication, APIKeyUser, HasAPIKey

    class Items(APIView):
        authentication_classes = [APIKeyAuthentication]
        permission_classes = [HasAPIKey]

        def get(self, request):
            assert isinstance(request.user, APIKeyUser) and request.user.is_authenticated
            return Response({"name": request.auth.name})

    view = Items.as_view()
    f = APIRequestFactory()
    _, raw = make_key()
    r = view(f.get("/", HTTP_X_API_KEY=raw))
    assert r.status_code == 200 and r.data == {"name": "ci"}
    missing = view(f.get("/"))
    assert missing.status_code == 401 and missing["WWW-Authenticate"].startswith("Bearer")
    assert view(f.get("/", HTTP_X_API_KEY="sk-bad")).status_code == 401


def test_rotate_with_grace_and_immediate():
    obj, raw = make_key(name="deploy")
    new_obj, new_raw = obj.rotate(pepper=PEPPER, grace=dt.timedelta(hours=1))
    assert new_raw != raw and new_obj.name == "deploy" and new_obj.pk != obj.pk
    obj.refresh_from_db()
    assert obj.expires_at is not None and not obj.revoked
    assert AUTH.authenticate(raw) and AUTH.authenticate(new_raw)  # both valid during grace

    new_obj.rotate(pepper=PEPPER)  # no grace -> revoked now
    new_obj.refresh_from_db()
    assert new_obj.revoked
    with pytest.raises(AuthError):
        AUTH.authenticate(new_raw)


def test_pepper_rotation_rehash_model():
    from generateapikey.integrations.django import rehash_model

    obj, raw = APIKey.objects.create_key(pepper="old-django-pepper", name="old")
    auth = APIKeyAuth(
        lookup=model_lookup(APIKey),
        pepper=PEPPER,
        previous_peppers=["old-django-pepper"],
        on_rehash=rehash_model(APIKey),
    )
    assert auth.authenticate(raw).name == "old"
    obj.refresh_from_db()
    assert AUTH.authenticate(raw).name == "old"  # now under the new pepper
