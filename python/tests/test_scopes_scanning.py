from __future__ import annotations

import re

import pytest

from generateapikey import (
    find_keys,
    generate_api_key,
    has_all_scopes,
    has_any_scope,
    has_scope,
    key_pattern,
    parse_scopes,
)
from generateapikey.integrations import APIKeyAuth, AuthError, issue_api_key
from generateapikey.scanning import gitleaks_rule

PEPPER = "test-pepper-value"


def test_parse_scopes_forms():
    assert parse_scopes("read write,admin") == {"read", "write", "admin"}
    assert parse_scopes(["a", "b", 3, ""]) == {"a", "b"}
    assert parse_scopes(None) == frozenset()


@pytest.mark.parametrize(
    ("granted", "required", "expected"),
    [
        (["read:users"], "read:users", True),
        (["read:users"], "read:orders", False),
        (["read:*"], "read:users", True),
        (["read:*"], "read:users:list", True),
        (["read:*"], "write:users", False),
        (["*"], "anything", True),
        (["read"], "read:users", False),  # a bare scope doesn't imply children
        (["read:users"], "read:*", False),  # nor does a child imply the wildcard
        ("read write", "write", True),
        (None, "read", False),
        (["*"], "", False),
        (["*"], None, False),
    ],
)
def test_has_scope(granted, required, expected):
    assert has_scope(granted, required) is expected


def test_all_any():
    assert has_all_scopes(["a", "b:*"], ["a", "b:x"])
    assert not has_all_scopes(["a"], ["a", "b"])
    assert has_all_scopes([], [])
    assert has_any_scope(["a"], ["x", "a"])
    assert not has_any_scope(["a"], ["x"])
    assert has_all_scopes(["a"], "a")


def _auth(**kw):
    issued = issue_api_key(prefix="sk", pepper=PEPPER)
    rows = {issued.hashed: {"scopes": ["read:*"]}}
    return APIKeyAuth(rows.get, pepper=PEPPER, **kw), str(issued.key)


def test_auth_scopes():
    auth, key = _auth(required_scopes=["read:users"])
    assert auth.authenticate(key)["scopes"] == ["read:*"]
    with pytest.raises(AuthError) as e:
        auth.authenticate(key, scopes=["write:users"])
    assert e.value.status == 403
    auth2, key2 = _auth(required_scopes=["admin"])
    with pytest.raises(AuthError) as e:
        auth2.authenticate(key2)
    assert e.value.status == 403
    assert auth2.authenticate(key2, scopes=[])  # per-route override


def test_auth_scopes_async_and_bad_key_stays_401():
    import asyncio

    auth, key = _auth(required_scopes=["write"])
    with pytest.raises(AuthError) as e:
        asyncio.run(auth.aauthenticate(key))
    assert e.value.status == 403
    with pytest.raises(AuthError) as e:
        auth.authenticate("sk-nope")
    assert e.value.status == 401  # unknown key never reveals scope info
    with pytest.raises(TypeError):
        APIKeyAuth(dict().get, required_scopes="read")


def test_key_pattern_matches_and_find_keys():
    key = generate_api_key(prefix="sk", checksum=True)
    assert re.fullmatch(key_pattern("sk"), key)
    text = f"token={key}\nother sk-{'a' * 32}ZZZZZZ and {key} again"
    assert find_keys(text, "sk") == [key]  # dedupes, drops the invalid-checksum look-alike
    assert find_keys(text, "sk", validate=False)[0] == key
    assert find_keys(f"x{key}", "sk") == []  # not inside a longer token
    assert find_keys(None, "sk") == []


@pytest.mark.parametrize(
    "opts",
    [
        {"length": 48},
        {"charset": "hex", "length": 32},
        {"charset": "base58"},
        {"charset": "alphabetic", "case": "lower"},
        {"prefix": "sk_live", "separator": "_"},
    ],
)
def test_key_pattern_options(opts):
    """The pattern built from the same options matches every key those options generate."""
    opts = dict(opts)
    prefix = opts.pop("prefix", "sk")
    for _ in range(20):
        key = generate_api_key(prefix=prefix, checksum=True, **opts)
        assert re.fullmatch(key_pattern(prefix, checksum=True, **opts), key)
        assert re.fullmatch(key_pattern(prefix, checksum=False, **opts), key[:-6])


def test_pattern_validation_and_gitleaks():
    with pytest.raises(ValueError):
        key_pattern("")
    with pytest.raises(ValueError):
        key_pattern("sk", length=0)
    rule = gitleaks_rule("sk", "acme-key")
    assert 'id = "acme-key"' in rule and "regex = '''" in rule and "(?<!" not in rule
    with pytest.raises(ValueError):
        gitleaks_rule("sk", 'bad"id')
