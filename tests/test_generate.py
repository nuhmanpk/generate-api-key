import asyncio
import datetime as dt
import json
import pickle
import time
import warnings
from collections import Counter

import pytest

import generateapikey
from generateapikey import (
    CHARSETS,
    CHECKSUM_LENGTH,
    ApiKey,
    WeakKeyWarning,
    entropy_bits,
    generate_api_key,
    generate_api_key_async,
    generate_api_keys,
    hash_api_key,
    is_expired,
    is_token_valid,
    verify_api_key,
    verify_checksum,
)
from generateapikey import (
    generateApiKey as legacy_generate,
)
from generateapikey.__main__ import main as cli
from generateapikey.utils import build_charset, derived_key, random_key

# --------------------------------------------------------------------------- basics


def test_default_length_and_charset():
    key = generate_api_key()
    assert isinstance(key, ApiKey) and isinstance(key, str)
    assert len(key) == 32
    assert set(key) <= set(CHARSETS["alphanumeric"])


@pytest.mark.parametrize("length", [1, 7, 32, 48, 255, 1000])
def test_length(length):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", WeakKeyWarning)
        assert len(generate_api_key(length=length)) == length


@pytest.mark.parametrize("name", list(CHARSETS))
def test_every_preset(name):
    key = generate_api_key(charset=name, length=64)
    assert set(key) <= set(CHARSETS[name])


def test_case_upper_lower():
    assert generate_api_key(charset="alphabetic", case="upper", length=40).isupper()
    assert generate_api_key(charset="alphabetic", case="lower", length=40).islower()


def test_custom_charset():
    with pytest.warns(WeakKeyWarning):
        key = generate_api_key(charset="AB12", length=16)
    assert set(key) <= set("AB12")


def test_unicode_and_large_charset():
    chars = "".join(chr(0x100 + i) for i in range(300))
    key = generate_api_key(charset=chars, length=30)
    assert len(key) == 30 and set(key) <= set(chars)


def test_prefix_and_separator():
    assert generate_api_key(prefix="sk").startswith("sk-")
    assert generate_api_key(prefix="pk", separator="_").startswith("pk_")
    assert generate_api_key(prefix="", length=32)[:3] != "-"


def test_dashes():
    key = generate_api_key(dashes=True, dash_group=4, length=32)
    assert key.count("-") == 7
    assert all(len(g) == 4 for g in key.split("-"))
    key = generate_api_key(dashes=True, dash_group=8, dash_char=" ", length=32)
    assert key.count(" ") == 3


def test_uniqueness():
    assert len({generate_api_key() for _ in range(2000)}) == 2000


# --------------------------------------------------------------------------- bias


def test_random_is_unbiased():
    # 62 chars: old code mapped bytes with % 62, making 8 chars ~25% more likely.
    c = Counter("".join(generate_api_key(length=200) for _ in range(500)))
    assert max(c.values()) / min(c.values()) < 1.3


def test_derived_is_unbiased():
    c = Counter("".join(generate_api_key("s", str(i), length=64) for i in range(2000)))
    assert max(c.values()) / min(c.values()) < 1.3


def test_duplicate_chars_in_charset_dont_skew():
    c = Counter(generate_api_key(charset="AAAB", length=20000))
    assert 0.9 < c["A"] / c["B"] < 1.1


def test_build_charset_rules():
    assert build_charset("aab") == "ab"
    assert "l" not in build_charset("base58", "lower")
    assert "O" not in build_charset("base58", "upper")
    with pytest.raises(ValueError):
        build_charset("a")
    with pytest.raises(ValueError):
        build_charset("")
    with pytest.raises(ValueError):
        build_charset("hex", "title")


# --------------------------------------------------------------------------- derived


def test_derived_is_deterministic():
    a = generate_api_key("secret", "user-1", length=40, include="prod")
    b = generate_api_key("secret", "user-1", length=40, include="prod")
    assert a == b


def test_derived_depends_on_every_input():
    base = generate_api_key("secret", "user-1")
    assert generate_api_key("secret2", "user-1") != base
    assert generate_api_key("secret", "user-2") != base
    assert generate_api_key("secret", "user-1", include="x") != base


def test_derived_fields_dont_collide():
    assert derived_key("k", "ab", "c", 32, "abcdef") != derived_key("k", "a", "bc", 32, "abcdef")


def test_derived_respects_charset():
    key = generate_api_key("s", "seed", charset="hex", length=50)
    assert set(key) <= set(CHARSETS["hex"])


def test_secret_seed_pair_required():
    for kwargs in ({"secret": "x"}, {"seed": "y"}):
        with pytest.raises(ValueError):
            generate_api_key(**kwargs)


def test_empty_secret_or_seed_rejected():
    with pytest.raises(ValueError):
        generate_api_key("", "")
    with pytest.raises(ValueError):
        generate_api_key("s", "")


def test_include_without_secret_rejected():
    with pytest.raises(ValueError):
        generate_api_key(include="x")


# --------------------------------------------------------------------------- validation


@pytest.mark.parametrize("length", [0, -1, 1.5, "32", True])
def test_bad_length(length):
    with pytest.raises(ValueError):
        generate_api_key(length=length)


def test_bad_dash_group():
    with pytest.raises(ValueError):
        generate_api_key(dashes=True, dash_group=0)


# --------------------------------------------------------------------------- entropy


def test_entropy_bits():
    assert entropy_bits(32, "hex") == 128
    assert round(entropy_bits(32), 1) == 190.5


def test_weak_key_warns():
    with pytest.warns(WeakKeyWarning):
        generate_api_key(charset="numeric", length=6)


def test_strong_key_does_not_warn():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        generate_api_key()
        generate_api_key(charset="hex", length=32)


def test_min_entropy():
    with pytest.raises(ValueError):
        generate_api_key(length=16, min_entropy=128)
    generate_api_key(length=32, min_entropy=128)


# --------------------------------------------------------------------------- checksum


def test_checksum_roundtrip():
    key = generate_api_key(prefix="sk", checksum=True, dashes=True)
    assert len(key) == len("sk-") + 32 + 7 + CHECKSUM_LENGTH
    assert verify_checksum(key)


def test_checksum_detects_typo_and_truncation():
    key = generate_api_key(checksum=True)
    swapped = key[:5] + ("A" if key[5] != "A" else "B") + key[6:]
    assert not verify_checksum(swapped)
    assert not verify_checksum(key[:-1])
    assert not verify_checksum("")
    assert not verify_checksum(None)


def test_checksum_on_derived_key():
    assert verify_checksum(generate_api_key("s", "seed", checksum=True))


# --------------------------------------------------------------------------- hashing


def test_hash_and_verify():
    key = generate_api_key()
    stored = hash_api_key(key)
    assert stored.startswith("sha256$") and key not in stored
    assert verify_api_key(key, stored)
    assert not verify_api_key(key + "x", stored)
    assert key.hash() == stored


def test_hash_with_pepper():
    key = generate_api_key()
    stored = hash_api_key(key, pepper="pep")
    assert stored.startswith("hmac-sha256$")
    assert verify_api_key(key, stored, pepper="pep")
    assert not verify_api_key(key, stored)
    assert not verify_api_key(key, stored, pepper="other")
    assert not verify_api_key(key, hash_api_key(key), pepper="pep")


def test_verify_bad_types():
    assert not verify_api_key(None, "sha256$00")
    assert not verify_api_key("k", None)


# --------------------------------------------------------------------------- expiry


def test_expiry_minutes():
    key = generate_api_key(expiry=60)
    assert abs(key.expires_at - (time.time() + 3600)) < 2
    assert not key.is_expired and not is_expired(key)
    assert 3590 < key.expires_in <= 3600
    assert key.expires_at_datetime.tzinfo is not None


def test_expiry_timedelta_and_float():
    assert abs(generate_api_key(expiry=dt.timedelta(hours=2)).expires_in - 7200) < 2
    assert abs(generate_api_key(expiry=0.5).expires_in - 30) < 2


@pytest.mark.parametrize("bad", [0, -5, dt.timedelta(0)])
def test_expiry_must_be_positive(bad):
    with pytest.raises(ValueError):
        generate_api_key(expiry=bad)


@pytest.mark.parametrize("bad", ["60", True])
def test_expiry_type(bad):
    with pytest.raises(TypeError):
        generate_api_key(expiry=bad)


def test_no_expiry():
    key = generate_api_key()
    assert key.expires_at is None and key.expires_in is None
    assert key.expires_at_datetime is None
    assert not key.is_expired


def test_expired():
    assert ApiKey("x", int(time.time()) - 1).is_expired
    assert not is_expired("plain string")


def test_apikey_pickle_and_repr():
    key = generate_api_key(expiry=5)
    clone = pickle.loads(pickle.dumps(key))
    assert clone == key and clone.expires_at == key.expires_at
    assert "expires_at" in repr(key)
    assert json.dumps({"k": key}) == json.dumps({"k": str(key)})


# --------------------------------------------------------------------------- batch / async / legacy


def test_generate_api_keys():
    keys = generate_api_keys(50, prefix="sk", length=40)
    assert len(keys) == len(set(keys)) == 50
    assert all(k.startswith("sk-") and len(k) == 43 for k in keys)
    assert generate_api_keys(0) == []


def test_generate_api_keys_rejects_bad_input():
    with pytest.raises(ValueError):
        generate_api_keys(-1)
    with pytest.raises(ValueError):
        generate_api_keys(3, secret="s", seed="x")


def test_generate_api_keys_warns_once():
    with pytest.warns(WeakKeyWarning) as rec:
        generate_api_keys(20, length=4)
    assert len([w for w in rec if issubclass(w.category, WeakKeyWarning)]) == 1


def test_async_wrapper():
    assert len(asyncio.run(generate_api_key_async(length=40))) == 40


def test_legacy_async():
    key = asyncio.run(legacy_generate("s", "seed", prefix="hf", add_dashes=True))
    assert key.startswith("hf-")


def test_legacy_is_unique_per_call():
    a = asyncio.run(legacy_generate("s", "seed"))
    b = asyncio.run(legacy_generate("s", "seed"))
    assert a != b and len(a) == 32


def test_legacy_expiry_and_errors():
    assert asyncio.run(legacy_generate("s", "seed", expiry=10)).expires_at is not None
    with pytest.raises(ValueError):
        asyncio.run(legacy_generate("", "seed"))


def test_is_token_valid_deprecated():
    with pytest.warns(DeprecationWarning):
        assert asyncio.run(is_token_valid(f"abc_{int(time.time()) + 60}"))
    with pytest.warns(DeprecationWarning):
        assert not asyncio.run(is_token_valid("abc"))


def test_random_key_helper():
    assert len(random_key(10, "xy")) == 10


def test_version():
    assert isinstance(generateapikey.__version__, str)


# --------------------------------------------------------------------------- cli


def test_cli_default(capsys):
    assert cli([]) == 0
    assert len(capsys.readouterr().out.strip()) == 32


def test_cli_many_with_options(capsys):
    assert cli(["-n", "3", "-p", "sk", "--checksum"]) == 0
    lines = capsys.readouterr().out.split()
    assert len(lines) == 3 and all(verify_checksum(k) and k.startswith("sk-") for k in lines)


def test_cli_json_hash(capsys):
    assert cli(["--json", "--hash", "--expiry", "5"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert verify_api_key(data["key"], data["hash"]) and "expires_at" in data


def test_cli_derived(capsys):
    cli(["--secret", "s", "--seed", "u"])
    first = capsys.readouterr().out
    cli(["--secret", "s", "--seed", "u"])
    assert capsys.readouterr().out == first


def test_cli_entropy(capsys):
    assert cli(["--entropy", "-c", "hex"]) == 0
    assert capsys.readouterr().out.strip() == "128.0"


def test_cli_error(capsys):
    assert cli(["--length", "0"]) == 2
    assert "error" in capsys.readouterr().err
