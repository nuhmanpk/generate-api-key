import base64
import json
import threading
import time
from urllib.parse import parse_qs, urlparse

import pytest

from generateapikey import mfa, tokens
from generateapikey.__main__ import main as cli
from generateapikey.mfa import (
    AttemptLimiter,
    find_totp_step,
    generate_otp,
    generate_recovery_codes,
    generate_totp_secret,
    hash_otp,
    hash_recovery_code,
    hotp,
    hotp_uri,
    normalize_recovery_code,
    totp,
    totp_now,
    totp_uri,
    verify_hotp,
    verify_otp,
    verify_recovery_code,
    verify_totp,
)
from generateapikey.tokens import generate_signed_token, verify_signed_token

RFC_SECRET = b"12345678901234567890"
RFC_SECRET_B32 = base64.b32encode(RFC_SECRET).decode()
K = "test-signing-secret-0123456789"  # >= 16 chars
K2 = "another-signing-secret-987654"


# --------------------------------------------------------------------------- HOTP (RFC 4226 Appendix D)

RFC4226 = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]


@pytest.mark.parametrize("counter,expected", list(enumerate(RFC4226)))
def test_hotp_rfc4226_vectors(counter, expected):
    assert hotp(RFC_SECRET, counter) == expected
    assert hotp(RFC_SECRET_B32, counter) == expected


def test_verify_hotp_returns_next_counter():
    assert verify_hotp(RFC_SECRET, "755224", 0) == 1
    assert verify_hotp(RFC_SECRET, "359152", 0) is None
    assert verify_hotp(RFC_SECRET, "359152", 0, look_ahead=3) == 3
    assert verify_hotp(RFC_SECRET, "abc", 0) is None


# --------------------------------------------------------------------------- TOTP (RFC 6238 Appendix B)

SEEDS = {
    "sha1": b"12345678901234567890",
    "sha256": b"12345678901234567890123456789012",
    "sha512": b"1234567890123456789012345678901234567890123456789012345678901234",
}
RFC6238 = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


@pytest.mark.parametrize("t,sha1,sha256,sha512", RFC6238)
def test_totp_rfc6238_vectors(t, sha1, sha256, sha512):
    for alg, expected in (("sha1", sha1), ("sha256", sha256), ("sha512", sha512)):
        assert totp(SEEDS[alg], at=t, digits=8, algorithm=alg) == expected


def test_totp_secret_format():
    s = generate_totp_secret()
    assert len(s) == 32 and "=" not in s
    assert len(base64.b32decode(s)) == 20
    assert generate_totp_secret() != s
    with pytest.raises(ValueError):
        generate_totp_secret(5)


def test_totp_accepts_messy_secret():
    s = generate_totp_secret()
    spaced = " ".join(s[i : i + 4] for i in range(0, len(s), 4)).lower()
    assert totp(spaced, at=1000) == totp(s, at=1000)
    with pytest.raises(ValueError):
        totp("not base32!!", at=0)


def test_verify_totp_now_and_drift():
    s = generate_totp_secret()
    now = 1_700_000_000
    assert verify_totp(s, totp(s, at=now), at=now)
    assert verify_totp(s, totp(s, at=now - 30), at=now)  # 1 step behind
    assert not verify_totp(s, totp(s, at=now - 90), at=now)  # 3 steps behind
    assert verify_totp(s, totp(s, at=now - 90), at=now, window=3)
    assert verify_totp(s, totp_now(s))
    code = totp(s, at=now)
    assert verify_totp(s, f"{code[:3]} {code[3:]}", at=now)  # spaces ok


def test_verify_totp_rejects_garbage():
    s = generate_totp_secret()
    for bad in ("", "12345", "1234567", "abcdef", None):
        assert not verify_totp(s, bad)


def test_totp_replay_protection():
    s = generate_totp_secret()
    now = 1_700_000_000
    code = totp(s, at=now)
    step = find_totp_step(s, code, at=now)
    assert step == now // 30
    assert find_totp_step(s, code, at=now, last_used_step=step) is None


def test_totp_validation():
    with pytest.raises(ValueError):
        totp(RFC_SECRET, digits=4)
    with pytest.raises(ValueError):
        totp(RFC_SECRET, digits=9)
    with pytest.raises(ValueError):
        totp("", at=0)
    with pytest.raises(ValueError):
        totp(b"short", at=0)
    with pytest.raises(ValueError):
        totp(RFC_SECRET, algorithm="md5")
    with pytest.raises(ValueError):
        totp(RFC_SECRET, period=0)
    with pytest.raises(ValueError):
        hotp(RFC_SECRET, -1)


def test_totp_uri():
    s = generate_totp_secret()
    uri = totp_uri(s, "alice@example.com", "My App")
    parsed = urlparse(uri)
    assert parsed.scheme == "otpauth" and parsed.netloc == "totp"
    assert parsed.path == "/My%20App:alice@example.com"
    q = parse_qs(parsed.query)
    assert q["secret"] == [s] and q["issuer"] == ["My App"]
    assert "digits" not in q and "period" not in q and "algorithm" not in q


def test_totp_uri_custom_params():
    q = parse_qs(urlparse(totp_uri("JBSWY3DPEHPK3PXP", "bob", digits=8, period=60, algorithm="sha256")).query)
    assert q["digits"] == ["8"] and q["period"] == ["60"] and q["algorithm"] == ["SHA256"]
    with pytest.raises(ValueError):
        totp_uri("JBSWY3DPEHPK3PXP", "")


def test_hotp_uri():
    uri = hotp_uri("JBSWY3DPEHPK3PXP", "bob", "X", counter=5)
    assert uri.startswith("otpauth://hotp/X:bob?") and "counter=5" in uri


# --------------------------------------------------------------------------- recovery codes


def test_recovery_codes_shape():
    codes = generate_recovery_codes()
    assert len(codes) == len(set(codes)) == 10
    for c in codes:
        assert len(c) == 11 and c[5] == "-"
        assert set(c.replace("-", "")) <= set(mfa._RECOVERY_CHARS)


def test_recovery_codes_options():
    codes = generate_recovery_codes(3, length=12, group=4)
    assert len(codes) == 3 and all(c.count("-") == 2 for c in codes)
    assert all("-" not in c for c in generate_recovery_codes(2, group=0))
    with pytest.raises(ValueError):
        generate_recovery_codes(0)
    with pytest.raises(ValueError):
        generate_recovery_codes(3, length=6)


def test_recovery_verify_single_use_flow():
    codes = generate_recovery_codes(5)
    stored = [hash_recovery_code(c) for c in codes]
    match = verify_recovery_code(codes[2], stored)
    assert match == stored[2]
    stored.remove(match)
    assert verify_recovery_code(codes[2], stored) is None
    assert verify_recovery_code(codes[0], stored) == stored[0]


def test_recovery_normalization():
    assert normalize_recovery_code(" abcd-oil1 ") == "ABCD0111"
    with pytest.raises(ValueError):
        normalize_recovery_code("é")
    code = generate_recovery_codes(1, group=0)[0]
    stored = [hash_recovery_code(code)]
    assert verify_recovery_code(code.lower(), stored)
    assert verify_recovery_code(f"{code[:5]} {code[5:]}", stored)
    assert verify_recovery_code(None, stored) is None


def test_recovery_with_pepper():
    code = generate_recovery_codes(1)[0]
    stored = [hash_recovery_code(code, pepper="p")]
    assert verify_recovery_code(code, stored, pepper="p")
    assert not verify_recovery_code(code, stored)


# --------------------------------------------------------------------------- OTP


def test_generate_otp():
    code = generate_otp()
    assert len(code) == 6 and code.isdigit()
    assert 590 < code.expires_in <= 600
    assert generate_otp(8, expiry=None).expires_at is None
    with pytest.raises(ValueError):
        generate_otp(3)
    with pytest.raises(ValueError):
        generate_otp(expiry=0)


def test_otp_distribution_is_uniform():
    from collections import Counter

    c = Counter("".join(generate_otp(12, None) for _ in range(2000)))
    assert max(c.values()) / min(c.values()) < 1.2


def test_verify_otp():
    code = generate_otp()
    stored = hash_otp(code)
    assert verify_otp(code, stored, code.expires_at)
    assert verify_otp(f"{code[:3]} {code[3:]}", stored, code.expires_at)
    assert not verify_otp("000000" if code != "000000" else "111111", stored, code.expires_at)
    assert not verify_otp(code, stored, time.time() - 1)
    assert verify_otp(code, stored)  # no expiry given


# --------------------------------------------------------------------------- attempt limiter


def test_attempt_limiter():
    lim = AttemptLimiter(max_attempts=3, window=60)
    assert not lim.is_blocked("u") and lim.remaining("u") == 3
    assert lim.fail("u") == 2
    lim.fail("u")
    assert not lim.is_blocked("u")
    assert lim.fail("u") == 0
    assert lim.is_blocked("u") and lim.remaining("u") == 0
    assert not lim.is_blocked("other")
    lim.reset("u")
    assert not lim.is_blocked("u")


def test_attempt_limiter_window_expires(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(mfa.time, "monotonic", lambda: clock[0])
    lim = AttemptLimiter(max_attempts=1, window=10)
    lim.fail("u")
    assert lim.is_blocked("u")
    clock[0] += 11
    assert not lim.is_blocked("u")


def test_attempt_limiter_thread_safe():
    lim = AttemptLimiter(max_attempts=10_000, window=60)
    threads = [threading.Thread(target=lambda: [lim.fail("u") for _ in range(500)]) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert lim.remaining("u") == 10_000 - 4000


def test_attempt_limiter_validation():
    with pytest.raises(ValueError):
        AttemptLimiter(0)


# --------------------------------------------------------------------------- signed tokens


def test_signed_token_roundtrip():
    tok = generate_signed_token(K, {"uid": 42}, purpose="login")
    assert "." in tok and "=" not in tok
    assert verify_signed_token(tok, K, purpose="login") == {"uid": 42}
    meta = verify_signed_token(tok, K, purpose="login", with_meta=True)
    assert meta["data"] == {"uid": 42} and meta["jti"] and meta["exp"]


def test_signed_token_unique():
    a = generate_signed_token(K, {"uid": 1})
    b = generate_signed_token(K, {"uid": 1})
    assert a != b


def test_signed_token_rejections():
    tok = generate_signed_token(K, {"uid": 1}, purpose="reset")
    assert verify_signed_token(tok, K2) is None
    assert verify_signed_token(tok, K, purpose="login") is None
    body, sig = tok.split(".")
    forged_body = tokens._b64e(json.dumps({"p": "reset", "d": {"uid": 2}}).encode())
    assert verify_signed_token(f"{forged_body}.{sig}", K, purpose="reset") is None
    for bad in ("", "abc", "a.b.c", None, f"{body}."):
        assert verify_signed_token(bad, K, purpose="reset") is None


def test_signed_token_expiry(monkeypatch):
    tok = generate_signed_token(K, expiry=1)
    assert verify_signed_token(tok, K) == {}
    real = time.time
    monkeypatch.setattr(tokens.time, "time", lambda: real() + 61)
    assert verify_signed_token(tok, K) is None


def test_signed_token_no_expiry_and_validation():
    tok = generate_signed_token(K, expiry=None)
    assert verify_signed_token(tok, K, with_meta=True)["exp"] is None
    with pytest.raises(ValueError):
        generate_signed_token("")
    with pytest.raises(ValueError):
        generate_signed_token("short")
    with pytest.raises(ValueError):
        verify_signed_token("a.b", "short")
    with pytest.raises(ValueError):
        generate_signed_token(K, expiry=0)


# --------------------------------------------------------------------------- top-level exports


def test_top_level_exports():
    import generateapikey as g

    for name in (
        "generate_totp_secret",
        "totp_uri",
        "verify_totp",
        "generate_recovery_codes",
        "verify_recovery_code",
        "generate_otp",
        "verify_otp",
        "AttemptLimiter",
        "generate_signed_token",
        "verify_signed_token",
    ):
        assert hasattr(g, name) and name in g.__all__


# --------------------------------------------------------------------------- QR (optional extra)


def test_qr_outputs():
    pytest.importorskip("qrcode")
    pytest.importorskip("png")
    from generateapikey.qr import qr_ascii, qr_png, qr_svg

    uri = totp_uri(generate_totp_secret(), "alice", "App")
    assert len(qr_ascii(uri).splitlines()) > 10
    assert qr_svg(uri).lstrip().startswith("<?xml") or "<svg" in qr_svg(uri)
    assert qr_png(uri).startswith(b"\x89PNG")


# --------------------------------------------------------------------------- CLI


def test_cli_totp(capsys):
    assert cli(["totp", "-a", "alice@x.com", "-i", "App", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["uri"].startswith("otpauth://totp/App:alice@x.com?")
    assert verify_totp(data["secret"], totp_now(data["secret"]))


def test_cli_code(capsys):
    s = generate_totp_secret()
    assert cli(["code", s, "--json"]) == 0
    assert verify_totp(s, json.loads(capsys.readouterr().out)["code"])


def test_cli_recovery(capsys):
    assert cli(["recovery", "-n", "4", "--hash", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 4
    assert all(verify_recovery_code(r["code"], [r["hash"]]) for r in rows)


def test_cli_otp(capsys):
    assert cli(["otp", "--digits", "8", "--hash", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["code"]) == 8 and verify_otp(data["code"], data["hash"], data["expires_at"])


def test_cli_token(capsys):
    assert cli(["token", "-s", K, "--purpose", "login", "--data", '{"uid": 7}']) == 0
    tok = capsys.readouterr().out.strip()
    assert verify_signed_token(tok, K, purpose="login") == {"uid": 7}


def test_cli_token_bad_data(capsys):
    assert cli(["token", "-s", K, "--data", "[1]"]) == 2


def test_cli_code_bad_secret(capsys):
    assert cli(["code", "!!!"]) == 2
    assert "error" in capsys.readouterr().err


def test_signed_token_context_binding():
    tok = generate_signed_token(K, {"uid": 1}, purpose="login", context="session-abc")
    assert verify_signed_token(tok, K, purpose="login", context="session-abc") == {"uid": 1}
    assert verify_signed_token(tok, K, purpose="login", context="session-xyz") is None
    assert verify_signed_token(tok, K, purpose="login") is None  # context required
    unbound = generate_signed_token(K, purpose="login")
    assert verify_signed_token(unbound, K, purpose="login", context="session-abc") is None
    assert "session-abc" not in tok  # never transmitted
    with pytest.raises(TypeError):
        generate_signed_token(K, context=123)
