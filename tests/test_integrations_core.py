import asyncio
import datetime as dt
import time

import pytest
from conftest import PEPPER

from generateapikey import verify_checksum
from generateapikey.integrations import APIKeyAuth, AuthError, issue_api_key, record_is_active
from generateapikey.mfa import AttemptLimiter


def test_issue_api_key():
    issued = issue_api_key(prefix="sk", pepper=PEPPER)
    assert issued.key.startswith("sk-") and verify_checksum(issued.key)
    assert issued.hashed.startswith("hmac-sha256$")
    assert issued.hint.startswith("sk-") and "…" in issued.hint and issued.key not in issued.hint
    assert str(issued.key) not in repr(issued)


def test_extract_variants(auth):
    assert auth.extract({"X-API-Key": " sk-1 "}) == "sk-1"
    assert auth.extract({"x-api-key": "sk-1"}) == "sk-1"
    assert auth.extract({"Authorization": "Bearer sk-2"}) == "sk-2"
    assert auth.extract({"authorization": "bearer sk-2"}) == "sk-2"
    assert auth.extract({"Authorization": "Basic abc"}) is None
    assert auth.extract({}, {"api_key": "sk-3"}) is None
    q = APIKeyAuth(lambda h: None, query_param="api_key")
    assert q.extract({}, {"api_key": "sk-3"}) == "sk-3"
    nb = APIKeyAuth(lambda h: None, bearer=False)
    assert nb.extract({"Authorization": "Bearer x"}) is None


def test_authenticate_ok_and_failures(store, auth):
    key = store.add()
    assert auth.authenticate(key)["name"] == "test"
    for bad, status in [
        (None, 401),
        ("", 401),
        ("pk-" + key[3:], 401),
        (key[:-1] + "x", 401),
        ("sk-" + "a" * 600, 401),
        ("sk-é", 401),
    ]:
        with pytest.raises(AuthError) as e:
            auth.authenticate(bad)
        assert e.value.status == status


def test_checksum_rejects_before_lookup(store):
    calls = []
    auth = APIKeyAuth(lambda h: calls.append(h), pepper=PEPPER, require_checksum=True)
    with pytest.raises(AuthError):
        auth.authenticate("sk-nonsense-key-without-checksum")
    assert calls == []


@pytest.mark.parametrize(
    "fields",
    [
        {"revoked": True},
        {"is_active": False},
        {"expires_at": time.time() - 1},
        {"expires_at": dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)},
        {"expires_at": "garbage"},
    ],
)
def test_inactive_records_rejected(store, auth, fields):
    key = store.add(**fields)
    with pytest.raises(AuthError):
        auth.authenticate(key)


def test_record_is_active_future_and_objects():
    assert record_is_active({"expires_at": time.time() + 60})
    assert record_is_active({"expires_at": dt.datetime.now() + dt.timedelta(minutes=1)})

    class Row:
        revoked = False
        expires_at = None

    assert record_is_active(Row()) and not record_is_active(None)


def test_async_lookup(store):
    auth = APIKeyAuth(store.alookup, pepper=PEPPER)
    key = store.add()
    assert asyncio.run(auth.aauthenticate(key))["name"] == "test"
    with pytest.raises(TypeError):
        auth.authenticate(key)


def test_on_success_hook_sync_and_async(store):
    seen = []

    async def hook(rec):
        seen.append(rec)

    key = store.add()
    asyncio.run(APIKeyAuth(store.lookup, pepper=PEPPER, on_success=hook).aauthenticate(key))
    APIKeyAuth(store.lookup, pepper=PEPPER, on_success=seen.append).authenticate(key)
    assert len(seen) == 2


def test_limiter_blocks_client_after_bad_keys(store):
    auth = APIKeyAuth(store.lookup, pepper=PEPPER, limiter=AttemptLimiter(max_attempts=3, window=60))
    good = store.add()
    for _ in range(3):
        with pytest.raises(AuthError):
            auth.authenticate("sk-bad", client="1.2.3.4")
    with pytest.raises(AuthError) as e:
        auth.authenticate(good, client="1.2.3.4")
    assert e.value.status == 429
    assert auth.authenticate(good, client="5.6.7.8")


def test_wrong_pepper_never_matches(store):
    key = store.add()
    with pytest.raises(AuthError):
        APIKeyAuth(store.lookup, pepper="other-pepper").authenticate(key)


def test_bad_config():
    with pytest.raises(TypeError):
        APIKeyAuth("not callable")
    with pytest.raises(ValueError):
        APIKeyAuth(lambda h: None, pepper="")


def test_core_imports_no_framework():
    import subprocess
    import sys

    code = (
        "import sys, generateapikey, generateapikey.integrations, generateapikey.mfa, generateapikey.tokens;"
        "bad = [m for m in ('fastapi','starlette','django','rest_framework','flask','litestar','qrcode') if m in sys.modules];"
        "print(bad)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout.strip()
    assert out == "[]"


def test_path_excluded_is_segment_aware():
    from generateapikey.integrations import path_excluded

    ex = ["/health", "/public/"]
    assert path_excluded("/health", ex) and path_excluded("/health/live", ex)
    assert path_excluded("/public", ex) and path_excluded("/public/x", ex)
    assert not path_excluded("/healthz", ex) and not path_excluded("/health-admin", ex)
    assert not path_excluded("/publicity", ex) and not path_excluded("/api", ex)
