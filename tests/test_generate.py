import time
import asyncio

from generateApiKey import (
    generate_api_key,
    generate_api_key_async,
    generateApiKey,
    ApiKey,
    is_expired,
    CHARSETS,
)


def test_default_length_and_charset():
    key = generate_api_key()
    assert isinstance(key, ApiKey) and isinstance(key, str)
    assert len(key) == 32
    assert all(c in CHARSETS["alphanumeric"] for c in key)


def test_length():
    assert len(generate_api_key(length=48)) == 48


def test_charset_hex():
    key = generate_api_key(charset="hex", length=40)
    assert all(c in CHARSETS["hex"] for c in key)


def test_case_upper():
    key = generate_api_key(charset="alphabetic", case="upper", length=20)
    assert key.isupper()


def test_custom_charset():
    key = generate_api_key(charset="AB12", length=16)
    assert set(key) <= set("AB12")


def test_prefix():
    assert generate_api_key(prefix="sk", length=8).startswith("sk-")


def test_dashes():
    key = generate_api_key(dashes=True, dash_group=4, length=16)
    assert key.count("-") == 3


def test_expiry_metadata():
    key = generate_api_key(expiry=60)
    assert key.expires_at is not None
    assert not key.is_expired
    assert not is_expired(key)


def test_expired():
    past = ApiKey("x", int(time.time()) - 1)
    assert past.is_expired


def test_uniqueness():
    assert len({generate_api_key() for _ in range(1000)}) == 1000


def test_secret_seed_pair_required():
    for kwargs in ({"secret": "x"}, {"seed": "y"}):
        try:
            generate_api_key(**kwargs)
            assert False, "expected ValueError"
        except ValueError:
            pass


def test_bad_length():
    try:
        generate_api_key(length=0)
        assert False
    except ValueError:
        pass


def test_async_wrapper():
    key = asyncio.run(generate_api_key_async(length=8))
    assert len(key) == 8


def test_legacy_async():
    key = asyncio.run(generateApiKey("s", "seed", prefix="hf", add_dashes=True))
    assert key.startswith("hf-")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
    print("all passed")
