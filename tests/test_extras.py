"""crypto (SecretBox), Redis limiters, pepper rotation."""

import asyncio
import threading

import pytest
from conftest import PEPPER

from generateapikey.integrations import APIKeyAuth, AuthError, issue_api_key

# --------------------------------------------------------------------------- crypto


@pytest.fixture
def crypto():
    return pytest.importorskip("generateapikey.crypto", exc_type=ImportError)


def test_secretbox_roundtrip_and_aad(crypto):
    box = crypto.SecretBox(crypto.generate_encryption_key())
    ct = box.encrypt("JBSWY3DPEHPK3PXP", aad="user-1")
    assert ct.startswith("v1.") and "JBSWY3DP" not in ct
    assert box.decrypt(ct, aad="user-1") == "JBSWY3DPEHPK3PXP"
    assert box.encrypt("x") != box.encrypt("x")  # random nonce
    with pytest.raises(crypto.DecryptionError):
        box.decrypt(ct, aad="user-2")  # bound to user
    with pytest.raises(crypto.DecryptionError):
        box.decrypt(ct)


@pytest.mark.parametrize("bad", ["", "v1", "v2.a.b", "v1.zz.abc", "v1.x.é", None, 5])
def test_secretbox_rejects_garbage(crypto, bad):
    box = crypto.SecretBox(crypto.generate_encryption_key())
    with pytest.raises(crypto.DecryptionError):
        box.decrypt(bad)


def test_secretbox_tamper_detected(crypto):
    box = crypto.SecretBox(crypto.generate_encryption_key())
    v, kid, blob = box.encrypt("secret").split(".")
    flipped = blob[:-2] + ("A" if blob[-2] != "A" else "B") + blob[-1]
    with pytest.raises(crypto.DecryptionError):
        box.decrypt(f"{v}.{kid}.{flipped}")


def test_secretbox_rotation(crypto):
    old, new = crypto.generate_encryption_key(), crypto.generate_encryption_key()
    ct_old = crypto.SecretBox(old).encrypt("s", aad="u")
    box = crypto.SecretBox(new, old_keys=[old])
    assert box.decrypt(ct_old, aad="u") == "s" and box.needs_rotation(ct_old)
    ct_new = box.rotate(ct_old, aad="u")
    assert not box.needs_rotation(ct_new) and box.rotate(ct_new, aad="u") == ct_new
    with pytest.raises(crypto.DecryptionError):
        crypto.SecretBox(new).decrypt(ct_old, aad="u")  # old key dropped


def test_secretbox_bad_keys(crypto):
    for bad in ("", "short", "A" * 10):
        with pytest.raises(ValueError):
            crypto.SecretBox(bad)
    with pytest.raises(TypeError):
        crypto.SecretBox(crypto.generate_encryption_key(), old_keys="notalist")
    assert "key_id" in repr(crypto.SecretBox(crypto.generate_encryption_key()))


# --------------------------------------------------------------------------- redis limiters


@pytest.fixture
def fakeredis():
    return pytest.importorskip("fakeredis")


def test_redis_limiter(fakeredis):
    from generateapikey.limiters import RedisAttemptLimiter

    lim = RedisAttemptLimiter(fakeredis.FakeRedis(), max_attempts=3, window=60)
    assert lim.hit("u") and lim.hit("u") and lim.hit("u") and not lim.hit("u")
    assert lim.is_blocked("u") and lim.remaining("u") == 0
    lim.reset("u")
    assert not lim.is_blocked("u") and lim.remaining("u") == 3
    assert lim.fail("v") == 2
    keys = lim.client.keys("*")
    assert all(k[-1:] != b"v" for k in keys) and all(len(k) > 60 for k in keys)  # hashed keys
    assert 0 < lim.client.pttl(keys[0]) <= 60_000  # expires


def test_redis_limiter_atomic_under_threads(fakeredis):
    from generateapikey.limiters import RedisAttemptLimiter

    lim = RedisAttemptLimiter(fakeredis.FakeRedis(), max_attempts=5, window=60)
    allowed = []
    threads = [threading.Thread(target=lambda: lim.hit("victim") and allowed.append(1)) for _ in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(allowed) == 5


def test_async_redis_limiter_with_apikeyauth(fakeredis, store):
    from fakeredis import FakeAsyncRedis

    from generateapikey.limiters import AsyncRedisAttemptLimiter

    async def run():
        lim = AsyncRedisAttemptLimiter(FakeAsyncRedis(), max_attempts=2, window=60)
        auth = APIKeyAuth(store.lookup, pepper=PEPPER, limiter=lim)
        statuses = []
        for _ in range(3):
            try:
                await auth.aauthenticate("sk-bad", client="9.9.9.9")
            except AuthError as e:
                statuses.append(e.status)
        good = store.add()
        ok = await auth.aauthenticate(good, client="1.1.1.1")
        return statuses, ok

    statuses, ok = asyncio.run(run())
    assert statuses == [401, 401, 429] and ok["name"] == "test"


def test_async_limiter_rejected_in_sync_path(fakeredis, store):
    from fakeredis import FakeAsyncRedis

    from generateapikey.limiters import AsyncRedisAttemptLimiter

    auth = APIKeyAuth(store.lookup, pepper=PEPPER, limiter=AsyncRedisAttemptLimiter(FakeAsyncRedis()))
    with pytest.raises(TypeError):
        auth.authenticate(store.add(), client="1.1.1.1")


def test_redis_limiter_validation(fakeredis):
    from generateapikey.limiters import RedisAttemptLimiter

    with pytest.raises(ValueError):
        RedisAttemptLimiter(fakeredis.FakeRedis(), max_attempts=0)


# --------------------------------------------------------------------------- pepper rotation


def test_pepper_rotation_with_rehash():
    old_pepper, new_pepper = "old-pepper-value", "new-pepper-value"
    issued = issue_api_key(prefix="sk", pepper=old_pepper)
    rows = {issued.hashed: {"name": "legacy"}}
    rehashed = []

    def on_rehash(record, new_hash):
        rows[new_hash] = rows.pop(next(h for h, r in rows.items() if r is record))
        rehashed.append(new_hash)

    auth = APIKeyAuth(rows.get, pepper=new_pepper, previous_peppers=[old_pepper], on_rehash=on_rehash)
    assert auth.authenticate(issued.key)["name"] == "legacy" and len(rehashed) == 1
    # now stored under the new pepper; works without the old one
    assert APIKeyAuth(rows.get, pepper=new_pepper).authenticate(issued.key)["name"] == "legacy"
    assert asyncio.run(auth.aauthenticate(issued.key)) and len(rehashed) == 1  # no second rehash


def test_previous_peppers_validation():
    with pytest.raises(TypeError):
        APIKeyAuth(lambda h: None, previous_peppers="oops")
    with pytest.raises(ValueError):
        APIKeyAuth(lambda h: None, previous_peppers=[""])
