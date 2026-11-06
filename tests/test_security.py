"""Regression tests for the 0.5.0 security review. One block per finding."""

import base64
import hashlib
import threading
import time

import pytest

from generateapikey import (
    ApiKey,
    generate_api_key,
    generate_otp,
    hash_api_key,
    hash_otp,
    hash_recovery_code,
    mfa,
    tokens,
    verify_api_key,
    verify_checksum,
    verify_otp,
    verify_recovery_code,
)
from generateapikey.__main__ import main as cli
from generateapikey.mfa import AttemptLimiter, generate_totp_secret, totp, totp_uri, verify_hotp, verify_totp
from generateapikey.tokens import generate_signed_token, verify_signed_token
from generateapikey.utils import hash_code, safe_equals, subkey, verify_code

K = "test-signing-secret-0123456789"
HOSTILE = ["١٢٣٤٥٦", "¹²³⁴⁵⁶", "é" * 6, "\ud800" * 6, "\x00" * 6, "0" * 10_000, None, 3.5, b"123456", [], {}]


# --------------------------------------------------------------------------- M1: never raise on attacker input


@pytest.mark.parametrize("bad", HOSTILE)
def test_verifiers_never_raise(bad):
    s = generate_totp_secret()
    assert verify_totp(s, bad) is False
    assert verify_hotp(s, bad, 0) is None
    assert verify_checksum(bad) is False
    assert verify_api_key(bad, hash_api_key("x")) is False
    assert verify_otp(bad, hash_otp("123456")) is False
    assert verify_recovery_code(bad, [hash_recovery_code("ABCDE12345")]) is None
    tok = generate_signed_token(K)
    assert verify_signed_token(bad, K) is None
    if isinstance(bad, str):
        assert verify_signed_token(tok.split(".")[0] + "." + bad, K) is None
        assert verify_checksum("sk-abcdefghij" + bad) is False


def test_safe_equals():
    assert safe_equals("abc", "abc") and not safe_equals("abc", "abd")
    assert not safe_equals("é", "e") and safe_equals("é", "é")
    assert not safe_equals(None, "a")


def test_non_ascii_purpose_round_trips():
    tok = generate_signed_token(K, purpose="réinitialiser")
    assert verify_signed_token(tok, K, purpose="réinitialiser") == {}
    assert verify_signed_token(tok, K, purpose="reset") is None


# --------------------------------------------------------------------------- M2: atomic limiter


def test_hit_is_atomic_under_concurrency():
    lim = AttemptLimiter(max_attempts=5, window=60)
    allowed = []

    def attempt():
        if lim.hit("victim"):
            time.sleep(0.01)  # simulated slow verification
            allowed.append(1)

    threads = [threading.Thread(target=attempt) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(allowed) == 5


def test_hit_reset_flow():
    lim = AttemptLimiter(max_attempts=2, window=60)
    assert lim.hit("u") and lim.hit("u") and not lim.hit("u")
    lim.reset("u")
    assert lim.hit("u")


# --------------------------------------------------------------------------- M3: bounded limiter


def test_limiter_memory_is_bounded_and_fast():
    lim = AttemptLimiter(max_attempts=5, window=900, max_keys=1000)
    for i in range(20_000):
        lim.fail(f"spray{i}")
    assert len(lim._entries) == 1000
    t = time.perf_counter()
    for i in range(2000):
        lim.fail(f"more{i}")
    assert time.perf_counter() - t < 0.5  # O(1) per call, not O(n)


def test_limiter_purges_expired_first(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(mfa.time, "monotonic", lambda: clock[0])
    lim = AttemptLimiter(max_attempts=1, window=10, max_keys=3)
    lim.fail("old")
    clock[0] = 20
    lim.fail("a")
    lim.fail("b")
    lim.fail("c")
    assert "old" not in lim._entries and lim.is_blocked("a")


# --------------------------------------------------------------------------- M4: short codes use salted slow hashing


def test_recovery_and_otp_hashes_are_salted_kdf():
    a, b = hash_recovery_code("ABCDE12345"), hash_recovery_code("ABCDE12345")
    assert a != b and a.startswith("pbkdf2-sha256$100000$")
    assert hash_otp("123456").startswith("pbkdf2-sha256$")
    fast = hashlib.sha256(b"123456").hexdigest()
    assert fast not in hash_otp("123456")


def test_verify_code_rejects_tampered_or_absurd_records():
    h = hash_code("123456")
    _, it, salt, digest = h.split("$")
    assert verify_code("123456", h)
    assert not verify_code("123456", f"pbkdf2-sha256$1${salt}${digest}")
    assert not verify_code("123456", f"pbkdf2-sha256$999999999${salt}${digest}")
    assert not verify_code("123456", f"pbkdf2-sha256$x${salt}${digest}")
    assert not verify_code("123456", "sha256$" + hashlib.sha256(b"123456").hexdigest())


def test_otp_with_pepper():
    h = hash_otp("123456", pepper="pep")
    assert verify_otp("123456", h, pepper="pep")
    assert not verify_otp("123456", h)
    assert not verify_otp("123456", h, pepper="other")


# --------------------------------------------------------------------------- L1: domain separation


def test_secret_reuse_cannot_cross_contexts():
    shared = "one-shared-server-secret-123"
    tok = generate_signed_token(shared)
    body, sig = tok.split(".")
    peppered = hash_api_key(body, pepper=shared).split("$", 1)[1]
    sig_hex = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)).hex()
    assert peppered != sig_hex
    assert subkey(shared, "token") != subkey(shared, "hash") != subkey(shared, "derive")


# --------------------------------------------------------------------------- L2: OTP charset validated


def test_otp_charset_validated_and_deduped():
    with pytest.raises(ValueError):
        generate_otp(charset="0")
    from collections import Counter

    c = Counter("".join(generate_otp(12, None, charset="00000000012") for _ in range(1000)))
    assert max(c.values()) / min(c.values()) < 1.2


# --------------------------------------------------------------------------- L3: integer codes keep leading zeros


def test_int_codes_are_zero_padded():
    s = generate_totp_secret()
    for t in range(0, 300_000, 30):
        code = totp(s, at=t)
        if code.startswith("0"):
            assert verify_totp(s, int(code), at=t)
            break
    else:  # pragma: no cover
        pytest.skip("no leading-zero code found")
    assert verify_totp(s, True) is False
    assert verify_totp(s, -1) is False


# --------------------------------------------------------------------------- L5: empty pepper / weak TOTP secret


@pytest.mark.parametrize(
    "fn",
    [
        lambda: hash_api_key("k", pepper=""),
        lambda: verify_api_key("k", "x", pepper=""),
        lambda: hash_otp("123456", pepper=""),
        lambda: hash_recovery_code("ABCDEFGH", pepper=""),
    ],
)
def test_empty_pepper_rejected(fn):
    with pytest.raises(ValueError):
        fn()


def test_short_totp_secret_rejected():
    for bad in ("", "AAAA", b"", b"123456789"):
        with pytest.raises(ValueError):
            totp(bad, at=0)


# --------------------------------------------------------------------------- L6: CLI secrets without argv


def test_cli_token_secret_from_env(monkeypatch, capsys):
    monkeypatch.setenv("GENERATEAPIKEY_SECRET", K)
    assert cli(["token", "--data", '{"u": 1}']) == 0
    assert verify_signed_token(capsys.readouterr().out.strip(), K) == {"u": 1}


def test_cli_code_secret_from_stdin(monkeypatch, capsys):
    import io

    s = generate_totp_secret()
    monkeypatch.setattr("sys.stdin", io.StringIO(s + "\n"))
    assert cli(["code", "-"]) == 0
    assert verify_totp(s, capsys.readouterr().out.split()[0])


def test_cli_code_without_secret_errors(monkeypatch, capsys):
    monkeypatch.delenv("GENERATEAPIKEY_TOTP_SECRET", raising=False)
    assert cli(["code"]) == 2


def test_cli_pepper_from_env(monkeypatch, capsys):
    monkeypatch.setenv("GENERATEAPIKEY_PEPPER", "env-pepper")
    assert cli(["--hash"]) == 0
    key, stored = capsys.readouterr().out.split()
    assert verify_api_key(key, stored, pepper="env-pepper")


# --------------------------------------------------------------------------- info items


def test_totp_digits_capped_at_8():
    with pytest.raises(ValueError):
        totp(generate_totp_secret(), digits=10)


def test_otpauth_label_rejects_colon_and_normalizes_secret():
    s = generate_totp_secret()
    with pytest.raises(ValueError):
        totp_uri(s, "alice", "Evil:Corp")
    with pytest.raises(ValueError):
        totp_uri(s, "a:lice", "Corp")
    dashed = "-".join(s[i : i + 4] for i in range(0, len(s), 4))
    assert f"secret={s}&" in totp_uri(dashed, "alice", "Corp")
    with pytest.raises(ValueError):
        totp_uri(s, "alice", period=0)


@pytest.mark.parametrize("bad", [float("inf"), float("nan"), -1])
def test_non_finite_expiry_rejected(bad):
    with pytest.raises(ValueError):
        generate_api_key(expiry=bad)
    with pytest.raises(ValueError):
        generate_signed_token(K, expiry=bad)
    with pytest.raises(ValueError):
        generate_otp(expiry=bad)


def test_cli_inf_expiry_is_clean_error(capsys):
    assert cli(["--expiry", "inf"]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_repr_is_redacted():
    key = generate_api_key(prefix="sk", expiry=5)
    r = repr(key)
    assert str(key) not in r and key[4:-4] not in r
    assert r.startswith("ApiKey('sk-") and "expires_at" in r
    assert repr(ApiKey("short")) == "ApiKey('…')"
    assert f"{key}" == str(key)  # full value still available on purpose


def test_token_rejects_non_numeric_exp():
    import json

    body = tokens._b64e(json.dumps({"p": "default", "exp": "never", "d": {}}).encode())
    assert verify_signed_token(f"{body}.{tokens._sign(K, body)}", K) is None


def test_oversized_token_rejected_cheaply():
    assert verify_signed_token("a" * 100_000 + ".b", K) is None
