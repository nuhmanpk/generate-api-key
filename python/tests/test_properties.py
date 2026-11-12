"""Property-based, statistical and fuzz tests (need `hypothesis`)."""

from __future__ import annotations

import math
import string
from collections import Counter

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from generateapikey import (
    decode_jwt,
    generate_api_key,
    hash_api_key,
    verify_api_key,
    verify_checksum,
    verify_signed_token,
    verify_totp,
)
from generateapikey.mfa import verify_otp, verify_recovery_code
from generateapikey.utils import random_key

FAST = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
SECRET = "k" * 32


@FAST
@given(length=st.integers(1, 200), prefix=st.one_of(st.none(), st.text(string.ascii_lowercase, min_size=1, max_size=8)))
def test_generated_keys_have_expected_shape(length, prefix):
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        key = generate_api_key(length=length, prefix=prefix, checksum=True)
    assert verify_checksum(key)
    assert len(key) == length + 6 + (len(prefix) + 1 if prefix else 0)
    if prefix:
        assert key.startswith(prefix + "-")


@FAST
@given(key=st.text(min_size=1, max_size=100), pepper=st.one_of(st.none(), st.text(min_size=1, max_size=20)))
def test_hash_verify_roundtrip(key, pepper):
    try:
        stored = hash_api_key(key, pepper)
    except (ValueError, UnicodeEncodeError):
        return
    assert verify_api_key(key, stored, pepper)
    assert not verify_api_key(key + "x", stored, pepper)


@FAST
@given(junk=st.one_of(st.text(), st.binary(), st.integers(), st.none(), st.lists(st.text())))
def test_verifiers_never_raise_on_garbage(junk):
    # Attacker-controlled input must give False/None, never an exception.
    assert verify_checksum(junk) in (True, False)
    assert verify_totp("JBSWY3DPEHPK3PXP", junk) in (True, False)
    assert verify_signed_token(junk, SECRET) is None or isinstance(verify_signed_token(junk, SECRET), dict)
    assert decode_jwt(junk, SECRET) is None
    assert verify_api_key(junk, "x") is False
    assert verify_recovery_code(junk, ["abc"]) is None
    assert verify_otp(junk, "pbkdf2-sha256$1$aa$bb", 0) in (True, False)


@FAST
@given(token=st.text(alphabet=string.ascii_letters + string.digits + "._-", max_size=300))
def test_fuzzed_token_shapes(token):
    assert decode_jwt(token, SECRET) is None
    assert verify_signed_token(token, SECRET) is None


def _chi_square(counts: Counter, alphabet: str, n: int) -> float:
    expected = n / len(alphabet)
    return sum((counts.get(c, 0) - expected) ** 2 / expected for c in alphabet)


@pytest.mark.parametrize(
    "alphabet", [string.ascii_letters + string.digits, "0123456789abcdef", "ABC123", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
)
def test_output_is_uniform_chi_square(alphabet):
    """Rejection sampling must be unbiased: chi-square over 200k characters.

    Threshold is ~ the 1e-6 upper tail, so a correct sampler fails about once in a million runs,
    while a ``byte % n`` bias (e.g. 62 chars: 4/256 skew) is detected at this sample size.
    """
    n = 200_000
    text = random_key(n, alphabet)
    df = len(alphabet) - 1
    stat = _chi_square(Counter(text), alphabet, n)
    threshold = df + 5.0 * math.sqrt(2 * df) + 10  # generous, far above df, far below a biased sampler
    assert stat < threshold, (alphabet, stat, threshold)


def test_chi_square_detects_modulo_bias():
    """Sanity check that the test above has teeth: a naive ``byte % 62`` sampler fails it."""
    import secrets

    alphabet = string.ascii_letters + string.digits
    n = 200_000
    biased = "".join(alphabet[b % 62] for b in secrets.token_bytes(n))
    df = 61
    assert _chi_square(Counter(biased), alphabet, n) > df + 5.0 * math.sqrt(2 * df) + 10
