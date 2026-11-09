from __future__ import annotations

import time

import pytest

from generateapikey.integrations import APIKeyAuth, AuthError
from generateapikey.keystore import KeyStore, rotate_api_key

PEPPER = "test-pepper-value"


@pytest.fixture
def store():
    s = KeyStore(pepper=PEPPER)
    yield s
    s.close()


def test_create_lookup_and_auth(store):
    made = store.create("ci", scopes=["read:*"], prefix="sk", meta={"team": "x"})
    assert "…" in repr(made) and str(made.key) not in repr(made)
    auth = APIKeyAuth(store.lookup, pepper=PEPPER, prefix="sk", require_checksum=True, required_scopes=["read:users"])
    rec = auth.authenticate(str(made.key))
    assert rec.name == "ci" and rec.meta == {"team": "x"} and "read:*" in rec.scopes
    assert store.get(made.id).last_used_at is not None
    with pytest.raises(AuthError):
        auth.authenticate(str(made.key) + "x")


def test_only_hash_is_stored(store):
    made = store.create("ci")
    rows = store._db.execute("SELECT * FROM api_keys").fetchall()
    assert str(made.key) not in "".join(str(tuple(r)) for r in rows)


def test_revoke_and_expiry(store):
    made = store.create("a")
    auth = APIKeyAuth(store.lookup, pepper=PEPPER)
    assert auth.authenticate(str(made.key))
    assert store.revoke(made.id) is True and store.revoke(made.id) is False
    with pytest.raises(AuthError):
        auth.authenticate(str(made.key))
    short = store.create("b", expiry=0.01)  # 0.6 s
    time.sleep(0.7)
    with pytest.raises(AuthError):
        auth.authenticate(str(short.key))
    assert [r.name for r in store.list(active_only=True)] == []
    assert len(store.list()) == 2


def test_rotate_keeps_old_key_for_grace(store):
    old = store.create("svc", scopes=["a"], meta={"k": 1})
    new = store.rotate(old.id, grace_minutes=60)
    auth = APIKeyAuth(store.lookup, pepper=PEPPER)
    assert auth.authenticate(str(old.key)) and auth.authenticate(str(new.key))
    rec = store.get(new.id)
    assert rec.name == "svc" and rec.scopes == {"a"} and rec.meta == {"k": 1}
    assert store.get(old.id).expires_at <= int(time.time()) + 3600
    store.rotate(new.id, grace_minutes=0)
    time.sleep(1.1)
    with pytest.raises(AuthError):
        auth.authenticate(str(new.key))
    with pytest.raises(KeyError):
        store.rotate(9999)


def test_rotate_does_not_extend_shorter_expiry(store):
    old = store.create("svc", expiry=1)  # expires in 60 s
    store.rotate(old.id, grace_minutes=1000)
    assert store.get(old.id).expires_at <= int(time.time()) + 61


def test_validation_and_context_manager():
    with pytest.raises(ValueError):
        rotate_api_key(grace_minutes=-1)
    r = rotate_api_key(grace_minutes=5)
    assert r.old_expires_at > time.time() and "…" in repr(r)
    with KeyStore() as s:
        with pytest.raises(ValueError):
            s.create("")
