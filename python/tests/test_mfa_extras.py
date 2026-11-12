from __future__ import annotations

import base64
import hashlib
import hmac
import struct
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from generateapikey import google_migration_uri, steam_code, verify_steam_code

SECRET = "JBSWY3DPEHPK3PXP"
ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"


def _reference_steam(secret_b32: str, t: int) -> str:
    # independent re-implementation
    mac = hmac.new(base64.b32decode(secret_b32), struct.pack(">Q", t // 30), hashlib.sha1).digest()
    o = mac[19] & 15
    n = int.from_bytes(mac[o : o + 4], "big") & 0x7FFFFFFF
    out = ""
    for _ in range(5):
        out += ALPHABET[n % 26]
        n //= 26
    return out


@pytest.mark.parametrize("t", [0, 59, 1_700_000_000, 2_000_000_123])
def test_steam_matches_reference(t):
    assert steam_code(SECRET, t) == _reference_steam(SECRET, t)
    assert len(steam_code(SECRET, t)) == 5 and set(steam_code(SECRET, t)) <= set(ALPHABET)


def test_verify_steam():
    t = 1_700_000_000
    code = steam_code(SECRET, t)
    assert verify_steam_code(SECRET, code, at=t)
    assert verify_steam_code(SECRET, code.lower(), at=t + 30)
    assert not verify_steam_code(SECRET, code, at=t + 300)
    assert not verify_steam_code(SECRET, code, at=t + 30, window=0)
    for bad in ("", None, 12345, "ABCDEFG", "١٢٣٤٥"):
        assert verify_steam_code(SECRET, bad, at=t) is False


def _read_varint(b, i):
    n = shift = 0
    while True:
        x = b[i]
        i += 1
        n |= (x & 0x7F) << shift
        if not x & 0x80:
            return n, i
        shift += 7


def _parse(b):
    i, out = 0, []
    while i < len(b):
        tag, i = _read_varint(b, i)
        num, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = _read_varint(b, i)
        else:
            n, i = _read_varint(b, i)
            v, i = b[i : i + n], i + n
        out.append((num, v))
    return out


def test_google_migration_roundtrip():
    uri = google_migration_uri(
        [
            {"secret": SECRET, "name": "a@b.c", "issuer": "App"},
            {"secret": SECRET, "name": "x", "digits": 8, "algorithm": "sha256"},
        ]
    )
    u = urlparse(uri)
    assert u.scheme == "otpauth-migration"
    raw = base64.b64decode(unquote(parse_qs(u.query)["data"][0]))
    top = _parse(raw)
    accounts = [_parse(v) for n, v in top if n == 1]
    assert len(accounts) == 2
    first = dict(accounts[0])
    assert first[1] == base64.b32decode(SECRET) and first[2] == b"a@b.c" and first[3] == b"App"
    assert first[4] == 1 and first[5] == 1 and first[6] == 2  # sha1, 6 digits, TOTP
    second = dict(accounts[1])
    assert second[4] == 2 and second[5] == 2
    assert dict(top)[2] == 1  # version


def test_google_migration_validation():
    with pytest.raises(ValueError):
        google_migration_uri([])
    with pytest.raises(ValueError):
        google_migration_uri([{"secret": SECRET, "name": "a", "digits": 7}])
    with pytest.raises(ValueError):
        google_migration_uri([{"secret": SECRET, "name": "a", "algorithm": "md5"}])
