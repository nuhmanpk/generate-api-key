"""Generate spec/vectors.json from the real Python implementation.

    cd python && python scripts/gen_vectors.py          # rewrite ../spec/vectors.json
    cd python && python scripts/gen_vectors.py --check  # exit 1 if the file is stale (CI)

The output is deterministic: randomness (salts, nonces, jti, batch ids) and the
clock are pinned with monkeypatches, so every vector is reproducible. Only
signatures that are randomized by design (RSA-PSS, ECDSA) can't be re-created
byte for byte; for those the previous token is kept while it still verifies.

Needs the ``crypto`` extra (``cryptography``) for SecretBox and RS/PS/ES/EdDSA JWTs.
Asymmetric JWT vectors are verify-only: tokens are signed with throw-away keys
generated in memory, and only the public keys are written. No private key is
ever stored in the repository.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import pathlib
import secrets
import sys
import time
import warnings
from collections.abc import Iterator
from typing import Any, Callable
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
PY_ROOT = HERE.parent
sys.path.insert(0, str(PY_ROOT))

import generateapikey as g  # noqa: E402
from generateapikey import integrations as integ  # noqa: E402
from generateapikey import mfa, scanning, scopes, tokens, utils  # noqa: E402

SPEC_DIR = PY_ROOT.parent / "spec"
OUT = SPEC_DIR / "vectors.json"
SPEC_VERSION = 1

#: The pinned clock for every time-dependent vector.
NOW = 1_700_000_000


# ---------------------------------------------------------------------------
# Determinism helpers
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def frozen(now: float = NOW, rand: bytes = b"", randbits: int = 0x1234567) -> Iterator[None]:
    """Pin time.time() and feed ``secrets`` from ``rand`` (repeated as needed)."""
    pool = bytearray()

    def token_bytes(n: int | None = None) -> bytes:
        n = 32 if n is None else n
        while len(pool) < n:
            pool.extend(rand or b"\x00")
        out = bytes(pool[:n])
        del pool[:n]
        return out

    with (
        mock.patch.object(time, "time", lambda: now),
        mock.patch.object(secrets, "token_bytes", token_bytes),
        mock.patch.object(secrets, "randbits", lambda k: randbits & ((1 << k) - 1)),
    ):
        yield


def hexb(b: bytes) -> str:
    return b.hex()


def outcome(fn: Callable[[], Any]) -> dict[str, Any]:
    """Run ``fn``; record its result or the exception type (ValueError/TypeError)."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return {"result": fn()}
    except (ValueError, TypeError) as e:
        return {"error": type(e).__name__}


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def charsets() -> dict[str, Any]:
    presets = {
        name: {case: utils.build_charset(name, case) for case in ("mixed", "lower", "upper")} for name in utils.CHARSETS
    }
    custom_inputs = ["abcabc", "aAbB", "0O1Il23", "αβγδ", "aé✓😀", "ab"]
    custom = [
        {"charset": c, "case": case, **outcome(lambda c=c, case=case: utils.build_charset(c, case))}
        for c in custom_inputs
        for case in ("mixed", "lower", "upper")
    ]
    errors = [
        {"charset": c, "case": case, **outcome(lambda c=c, case=case: utils.build_charset(c, case))}
        for c, case in [("a", "mixed"), ("aaaa", "mixed"), ("", "mixed"), ("alphanumeric", "title")]
    ]
    entropy = [
        {"length": n, "charset": c, "case": case, "bits": utils.entropy_bits(n, c, case)}
        for n, c, case in [
            (32, "alphanumeric", "mixed"),
            (22, "alphanumeric", "mixed"),
            (64, "hex", "mixed"),
            (26, "base32", "mixed"),
            (20, "base58", "lower"),
            (10, "numeric", "mixed"),
        ]
    ]
    return {"presets": presets, "custom": custom + errors, "entropy_bits": entropy}


DERIVED_CASES: list[dict[str, Any]] = [
    {"secret": "s3cret", "seed": "user-1"},
    {"secret": "s3cret", "seed": "user-2"},
    {"secret": "s3cret", "seed": "user-1", "include": "admin"},
    {"secret": "s3cret", "seed": "user-1", "include": ""},
    {"secret": "ab", "seed": "c"},
    {"secret": "a", "seed": "bc"},
    {"secret": "s3cret", "seed": "user-1", "length": 1},
    {"secret": "s3cret", "seed": "user-1", "length": 200},
    {"secret": "s3cret", "seed": "user-1", "charset": "hex", "length": 64},
    {"secret": "s3cret", "seed": "user-1", "charset": "base32", "case": "lower"},
    {"secret": "s3cret", "seed": "user-1", "charset": "base58"},
    {"secret": "s3cret", "seed": "user-1", "charset": "base58", "case": "lower"},
    {"secret": "s3cret", "seed": "user-1", "charset": "crockford", "case": "lower"},
    {"secret": "s3cret", "seed": "user-1", "charset": "numeric", "length": 50},
    {"secret": "s3cret", "seed": "user-1", "charset": "base64url"},
    {"secret": "s3cret", "seed": "user-1", "charset": "unambiguous"},
    {"secret": "s3cret", "seed": "user-1", "charset": "base16"},
    {"secret": "s3cret", "seed": "user-1", "charset": "alphabetic", "case": "upper"},
    {"secret": "s3cret", "seed": "user-1", "charset": "ACGT"},
    {"secret": "s3cret", "seed": "user-1", "charset": "αβγδεζηθ", "length": 40},
    {"secret": "s3cret", "seed": "user-1", "charset": "aé✓😀", "length": 40},
    {"secret": "s3cret", "seed": "user-1", "charset": "".join(chr(0x4E00 + i) for i in range(300)), "length": 40},
    {"secret": "s3cret", "seed": "user-1", "prefix": "sk"},
    {"secret": "s3cret", "seed": "user-1", "prefix": "sk", "separator": "_"},
    {"secret": "s3cret", "seed": "user-1", "prefix": "sk", "separator": ""},
    {"secret": "s3cret", "seed": "user-1", "prefix": "", "separator": "_"},
    {"secret": "s3cret", "seed": "user-1", "dashes": True},
    {"secret": "s3cret", "seed": "user-1", "dashes": True, "dash_group": 5, "dash_char": "."},
    {"secret": "s3cret", "seed": "user-1", "dashes": True, "length": 30, "dash_group": 7},
    {"secret": "s3cret", "seed": "user-1", "checksum": True},
    {"secret": "s3cret", "seed": "user-1", "prefix": "sk", "checksum": True},
    {"secret": "s3cret", "seed": "user-1", "prefix": "sk_live", "separator": "_", "dashes": True, "checksum": True},
    {"secret": "pässwörd", "seed": "ユーザー", "include": "✓"},
    # errors
    {"secret": "s3cret", "seed": None},
    {"secret": None, "seed": "x"},
    {"secret": "", "seed": "x"},
    {"secret": "s3cret", "seed": ""},
    {"secret": "s3cret", "seed": "user-1", "length": 0},
    {"secret": "s3cret", "seed": "user-1", "dashes": True, "dash_group": 0},
    {"secret": "s3cret", "seed": "user-1", "charset": "a"},
    {"secret": "s3cret", "seed": "user-1", "case": "title"},
]


def derived_keys() -> list[dict[str, Any]]:
    out = []
    for case in DERIVED_CASES:
        opts = {k: v for k, v in case.items() if k not in ("secret", "seed")}
        res = outcome(lambda c=case, o=opts: str(g.generate_api_key(c["secret"], c["seed"], **o)))
        out.append({"options": case, **res})
    # Raw derivation stream: derived_key() with an explicit salt (used by the legacy API).
    chars = utils.build_charset("alphanumeric")
    out.append(
        {
            "options": {"secret": "s3cret", "seed": "user-1", "salt_hex": "00112233445566778899aabbccddeeff"},
            "result": utils.derived_key(
                "s3cret", "user-1", None, 32, chars, salt=bytes.fromhex("00112233445566778899aabbccddeeff")
            ),
        }
    )
    return out


def random_key_formats() -> list[dict[str, Any]]:
    """Option sets whose *shape* must match; JS validates against the pattern."""
    cases = [
        {},
        {"length": 40, "charset": "hex"},
        {"prefix": "sk", "checksum": True},
        {"prefix": "pk_test", "separator": "_", "length": 24, "charset": "base62"},
        {"dashes": True, "length": 32},
        {"length": 26, "charset": "crockford", "case": "lower"},
    ]
    out = []
    for c in cases:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            sample = str(g.generate_api_key(**c))
        out.append({"options": c, "length_total": len(sample), "sample": sample})
    weak = [
        {"options": {"length": 16}, "weak": True},
        {"options": {"length": 22}, "weak": False},
        {"options": {"length": 21}, "weak": True},
        {"options": {"length": 32, "charset": "numeric"}, "weak": True},
        {"options": {"length": 39, "charset": "numeric"}, "weak": False},
    ]
    for w in weak:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            g.generate_api_key(**w["options"])
        assert bool(caught) == w["weak"], w
    min_entropy = [
        {
            "options": {"length": 16, "min_entropy": 128},
            **outcome(lambda: str(g.generate_api_key(length=16, min_entropy=128))),
        },
    ]
    min_entropy[0].pop("result", None)
    return [*out, {"weak_key_warning": weak}, {"min_entropy": min_entropy}]


def checksums() -> dict[str, Any]:
    inputs = ["", "a", "abc", "sk-abcdef", "The quick brown fox", "é✓😀", "0" * 100, "sk_live_" + "Z" * 32]
    compute = [{"input": s, "checksum": utils.compute_checksum(s)} for s in inputs]
    valid = "sk-" + "a" * 32
    valid += utils.compute_checksum(valid)
    verify = [
        {"key": valid, "valid": True},
        {"key": valid[:-1] + ("A" if valid[-1] != "A" else "B"), "valid": False},
        {"key": valid[1:], "valid": False},
        {"key": "abcdef", "valid": False},
        {"key": "abcdefg", "valid": utils.verify_checksum("abcdefg")},
        {"key": "", "valid": False},
        {"key": "a" + utils.compute_checksum("a"), "valid": True},
        {"key": "é" + utils.compute_checksum("é"), "valid": True},
    ]
    for v in verify:
        assert utils.verify_checksum(v["key"]) == v["valid"], v
    return {"compute": compute, "verify": verify}


def key_hashes() -> dict[str, Any]:
    keys = ["", "sk-abc", "sk-" + "A" * 32, "é✓😀", "key with spaces"]
    peppers = [None, "pepper", "another-pepper-✓"]
    hashed = [{"key": k, "pepper": p, "hashed": utils.hash_api_key(k, p)} for k in keys for p in peppers]
    h0 = utils.hash_api_key("sk-abc")
    h1 = utils.hash_api_key("sk-abc", "pepper")
    verify = [
        {"key": "sk-abc", "hashed": h0, "pepper": None},
        {"key": "sk-abd", "hashed": h0, "pepper": None},
        {"key": "sk-abc", "hashed": h1, "pepper": "pepper"},
        {"key": "sk-abc", "hashed": h1, "pepper": "other"},
        {"key": "sk-abc", "hashed": h1, "pepper": None},
        {"key": "sk-abc", "hashed": h0, "pepper": "pepper"},
        {"key": "sk-abc", "hashed": h0.upper(), "pepper": None},
        {"key": "sk-abc", "hashed": h0[7:], "pepper": None},
        {"key": "sk-abc", "hashed": "", "pepper": None},
        {"key": "sk-abc", "hashed": "md5$abc", "pepper": None},
        {"key": "sk-abc", "hashed": h0, "pepper": ""},
    ]
    for v in verify:
        v.update(outcome(lambda v=v: utils.verify_api_key(v["key"], v["hashed"], v["pepper"])))
    pepper_errors = [{"pepper": "", **outcome(lambda: utils.hash_api_key("k", ""))}]
    subkeys = [
        {"secret": s, "label": label, "hex": hexb(utils.subkey(s, label))}
        for s in ("secret", "pässwörd")
        for label in ("derive", "hash", "code", "token")
    ]
    return {"hash": hashed, "verify": verify, "pepper_errors": pepper_errors, "subkeys": subkeys}


SALT = bytes(range(16))


def code_hashes() -> dict[str, Any]:
    cases = [
        ("123456", None, 100_000),
        ("123456", "pepper", 100_000),
        ("123456", None, 1_000),
        ("ABCDE12345", None, 100_000),
        ("é✓", None, 1_000),
    ]
    hashed = []
    for code, pepper, it in cases:
        with frozen(rand=SALT):
            h = utils.hash_code(code, pepper, it)
        hashed.append({"code": code, "pepper": pepper, "iterations": it, "salt_hex": hexb(SALT), "hashed": h})
    base = hashed[2]["hashed"]  # 1k iterations: cheap to verify
    parts = base.split("$")
    verify = [
        {"code": "123456", "hashed": base, "pepper": None},
        {"code": "123457", "hashed": base, "pepper": None},
        {"code": "123456", "hashed": hashed[1]["hashed"], "pepper": "pepper"},
        {"code": "123456", "hashed": hashed[1]["hashed"], "pepper": None},
        {"code": "123456", "hashed": hashed[1]["hashed"], "pepper": "wrong"},
        {"code": "123456", "hashed": base.replace("pbkdf2-sha256", "pbkdf2-sha1"), "pepper": None},
        {"code": "123456", "hashed": "$".join([parts[0], "999", parts[2], parts[3]]), "pepper": None},
        {"code": "123456", "hashed": "$".join([parts[0], "10000001", parts[2], parts[3]]), "pepper": None},
        {"code": "123456", "hashed": "$".join([parts[0], "abc", parts[2], parts[3]]), "pepper": None},
        {"code": "123456", "hashed": "$".join([parts[0], parts[1], parts[2] + "A", parts[3]]), "pepper": None},
        {"code": "123456", "hashed": "$".join([parts[0], parts[1], parts[2]]), "pepper": None},
        {"code": "123456", "hashed": base + "$x", "pepper": None},
        {"code": "123456", "hashed": "", "pepper": None},
        {"code": "123456", "hashed": "$".join([parts[0], parts[1], parts[2], parts[3][:-2]]), "pepper": None},
        # Padded and standard-alphabet salts (Python's decoder is lenient here).
        {"code": "123456", "hashed": "$".join([parts[0], parts[1], parts[2] + "==", parts[3]]), "pepper": None},
    ]
    for v in verify:
        v.update(outcome(lambda v=v: utils.verify_code(v["code"], v["hashed"], v["pepper"])))
    return {"hash": hashed, "verify": verify}


def recovery_codes() -> dict[str, Any]:
    normalize = [
        {"input": s, **outcome(lambda s=s: mfa.normalize_recovery_code(s))}
        for s in ["7kq2m-9xpab", "7KQ2M9XPAB", " 7KQ2M 9XPAB ", "oil-OIL", "ABCDE-FGHIJ", "ééé", "a" * 65, "a" * 64, ""]
    ]
    with frozen(rand=SALT):
        h1 = mfa.hash_recovery_code("7KQ2M-9XPAB")
    with frozen(rand=bytes(range(16, 32))):
        h2 = mfa.hash_recovery_code("0111A-BCDEF")
    with frozen(rand=SALT):
        hp = mfa.hash_recovery_code("7KQ2M-9XPAB", "pepper")
    hashes = [h1, h2]
    verify = []
    for code, pepper, hs in [
        ("7kq2m9xpab", None, hashes),
        ("OIL1A-BCDEF", None, hashes),
        ("7KQ2M-9XPAC", None, hashes),
        ("7KQ2M-9XPAB", "pepper", [hp]),
        ("7KQ2M-9XPAB", None, [hp]),
        ("7KQ2M-9XPAB", None, []),
        ("7KQ2M-9XPAB", None, [h1, h1]),
    ]:
        match = mfa.verify_recovery_code(code, hs, pepper)
        verify.append(
            {"code": code, "pepper": pepper, "hashes": hs, "match_index": None if match is None else hs.index(match)}
        )
    fmt = []
    for count, length, group in [(10, 10, 5), (3, 8, 4), (2, 12, 0)]:
        codes = mfa.generate_recovery_codes(count, length, group)
        fmt.append({"count": count, "length": length, "group": group, "sample": codes[0]})
    errors = [
        {"count": c, "length": n, **outcome(lambda c=c, n=n: mfa.generate_recovery_codes(c, n))}
        for c, n in [(0, 10), (1, 7)]
    ]
    hashed = [
        {"code": "7KQ2M-9XPAB", "pepper": None, "salt_hex": hexb(SALT), "hashed": h1},
        {"code": "0111A-BCDEF", "pepper": None, "salt_hex": hexb(bytes(range(16, 32))), "hashed": h2},
        {"code": "7KQ2M-9XPAB", "pepper": "pepper", "salt_hex": hexb(SALT), "hashed": hp},
    ]
    return {
        "normalize": normalize,
        "hash": hashed,
        "verify": verify,
        "format": fmt,
        "errors": errors,
        "alphabet": mfa._RECOVERY_CHARS,
    }


def otps() -> dict[str, Any]:
    with frozen(rand=SALT):
        h = mfa.hash_otp("123456")
    with frozen(rand=SALT):
        hp = mfa.hash_otp("12-34 56", "pepper")
    verify = []
    for code, hashed, exp, pepper in [
        ("123456", h, None, None),
        ("123 456", h, None, None),
        ("12-34-56", h, None, None),
        (123456, h, None, None),
        ("654321", h, None, None),
        ("123456", h, NOW + 60, None),
        ("123456", h, NOW, None),
        ("123456", h, NOW - 1, None),
        ("123456", hp, None, "pepper"),
        ("123456", hp, None, None),
        ("１２３４５６", h, None, None),
        (True, h, None, None),
    ]:
        with frozen():
            ok = mfa.verify_otp(code, hashed, exp, pepper=pepper)
        verify.append({"code": code, "hashed": hashed, "expires_at": exp, "pepper": pepper, "valid": ok})
    errors = [
        {"digits": d, "expiry": e, **outcome(lambda d=d, e=e: str(mfa.generate_otp(d, e)))}
        for d, e in [(3, 10), (13, 10), (6, 0), (6, -1), (6, float("inf"))]
    ]
    for e in errors:
        e.pop("result", None)
        if e["expiry"] == float("inf"):
            e["expiry"] = "Infinity"
    with frozen():
        code = mfa.generate_otp(6, 10)
    return {
        "hash": [
            {"code": "123456", "pepper": None, "salt_hex": hexb(SALT), "hashed": h},
            {"code": "12-34 56", "pepper": "pepper", "salt_hex": hexb(SALT), "hashed": hp},
        ],
        "verify": verify,
        "errors": errors,
        "generate": {"digits": 6, "expiry_minutes": 10, "now": NOW, "expires_at": code.expires_at},
    }


RFC_SECRET = b"12345678901234567890"
RFC_SECRETS = {
    "sha1": RFC_SECRET,
    "sha256": b"12345678901234567890123456789012",
    "sha512": b"1234567890123456789012345678901234567890123456789012345678901234",
}


def b32(b: bytes) -> str:
    return base64.b32encode(b).decode().rstrip("=")


def otp_codes() -> dict[str, Any]:
    hotp = [
        {
            "secret": b32(RFC_SECRET),
            "counter": c,
            "counter_str": str(c),
            "digits": 6,
            "algorithm": "sha1",
            "code": mfa.hotp(RFC_SECRET, c),
        }
        for c in range(10)
    ]
    hotp += [
        {
            "secret": b32(RFC_SECRETS[a]),
            "counter": c,
            "counter_str": str(c),
            "digits": d,
            "algorithm": a,
            "code": mfa.hotp(RFC_SECRETS[a], c, digits=d, algorithm=a),
        }
        for a in ("sha256", "sha512")
        for c in (0, 1, 2**32, 2**63 - 1)
        for d in (6, 7, 8)
    ]
    totp = [
        {
            "secret": b32(RFC_SECRETS[a]),
            "at": t,
            "period": 30,
            "digits": 8,
            "algorithm": a,
            "code": mfa.totp(RFC_SECRETS[a], t, digits=8, algorithm=a),
        }
        for t in (59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000)
        for a in ("sha1", "sha256", "sha512")
    ]
    totp += [
        {
            "secret": b32(RFC_SECRET),
            "at": t,
            "period": p,
            "digits": 6,
            "algorithm": "sha1",
            "code": mfa.totp(RFC_SECRET, t, period=p),
        }
        for t in (0, 29.999, 30, NOW, NOW + 0.5)
        for p in (30, 60, 1)
    ]
    # Secret normalisation and validation.
    base = b32(RFC_SECRET)
    variants = [
        base,
        base.lower(),
        " ".join(base[i : i + 4] for i in range(0, len(base), 4)),
        "-".join(base[i : i + 4] for i in range(0, len(base), 4)),
        base + "====",
        "JBSWY3DPEHPK3PXP",
        "JBSWY3DPEHPK3PX",
        "JBSWY3DPEHPK3P",
        "JBSWY3DPEHPK3",
        "JBSWY3DPEHPK",
        "JBSWY3DPEHP",
        "JBSWY3DPEB",
        "JBSWY3DPE8",
        "",
        "!!!!!!!!!!!!!!!!",
        "AAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAB",
        "AAAAAAAAAAAAAAAAB",
        "AAAAAAAAAAAAAAAAA",
        base + "=",
        "A=AAAAAAAAAAAAAAA",
        "ééé",
    ]
    secrets_ = []
    for s in variants:
        r = outcome(lambda s=s: hexb(mfa._decode_secret(s)))
        secrets_.append({"secret": s, **({"bytes_hex": r["result"]} if "result" in r else {"error": r["error"]})})
    find = []
    secret = b32(RFC_SECRET)
    at = NOW
    cur = int(at // 30)
    for code, kw in [
        (mfa.hotp(RFC_SECRET, cur), {}),
        (mfa.hotp(RFC_SECRET, cur - 1), {}),
        (mfa.hotp(RFC_SECRET, cur + 1), {}),
        (mfa.hotp(RFC_SECRET, cur - 2), {}),
        (mfa.hotp(RFC_SECRET, cur - 2), {"window": 2}),
        (mfa.hotp(RFC_SECRET, cur - 1), {"window": 0}),
        (mfa.hotp(RFC_SECRET, cur), {"last_used_step": cur}),
        (mfa.hotp(RFC_SECRET, cur + 1), {"last_used_step": cur}),
        (mfa.hotp(RFC_SECRET, cur), {"last_used_step": cur - 1}),
        (mfa.hotp(RFC_SECRET, cur)[:3] + " " + mfa.hotp(RFC_SECRET, cur)[3:], {}),
        (mfa.hotp(RFC_SECRET, cur)[:3] + "-" + mfa.hotp(RFC_SECRET, cur)[3:], {}),
        (int(mfa.hotp(RFC_SECRET, cur)), {}),
        ("12345", {}),
        ("1234567", {}),
        ("abcdef", {}),
        ("", {}),
        (None, {}),
        (True, {}),
        (-1, {}),
        (mfa.hotp(RFC_SECRET, cur, digits=8), {"digits": 8}),
        (mfa.hotp(RFC_SECRET, cur, algorithm="sha256"), {"algorithm": "sha256"}),
        (mfa.hotp(RFC_SECRET, int(at // 60), digits=6), {"period": 60}),
    ]:
        step = mfa.find_totp_step(secret, code, at=at, **kw)
        find.append({"secret": secret, "code": code, "at": at, "options": kw, "step": step})
    # Leading zero int code: find a step whose code starts with 0.
    s = cur
    while not mfa.hotp(RFC_SECRET, s).startswith("0"):
        s += 1
    find.append(
        {
            "secret": secret,
            "code": int(mfa.hotp(RFC_SECRET, s)),
            "at": s * 30,
            "options": {},
            "step": mfa.find_totp_step(secret, int(mfa.hotp(RFC_SECRET, s)), at=s * 30),
        }
    )
    verify_hotp = []
    for code, counter, la in [
        ("755224", 0, 0),
        ("287082", 0, 0),
        ("287082", 0, 1),
        ("359152", 0, 3),
        ("399871", 5, 3),
        ("520489", 5, 3),
        (755224, 0, 0),
        ("abc", 0, 0),
    ]:
        verify_hotp.append(
            {
                "secret": secret,
                "code": code,
                "counter": counter,
                "look_ahead": la,
                "next_counter": mfa.verify_hotp(secret, code, counter, look_ahead=la),
            }
        )
    steam = [{"secret": secret, "at": t, "code": mfa.steam_code(secret, t)} for t in (0, 59, NOW, 1234567890)]
    sc = mfa.steam_code(secret, NOW)
    verify_steam = [
        {
            "secret": secret,
            "code": c,
            "at": NOW,
            "window": w,
            "valid": mfa.verify_steam_code(secret, c, window=w, at=NOW),
        }
        for c, w in [
            (sc, 1),
            (sc.lower(), 1),
            (mfa.steam_code(secret, NOW - 30), 1),
            (mfa.steam_code(secret, NOW - 30), 0),
            ("BBBBB", 1),
            ("BBBB", 1),
        ]
    ]
    errors = [
        {
            "fn": "hotp",
            "args": {"secret": secret, "counter": 0, "digits": 5},
            **outcome(lambda: mfa.hotp(secret, 0, digits=5)),
        },
        {
            "fn": "hotp",
            "args": {"secret": secret, "counter": 0, "digits": 9},
            **outcome(lambda: mfa.hotp(secret, 0, digits=9)),
        },
        {
            "fn": "hotp",
            "args": {"secret": secret, "counter": 0, "algorithm": "md5"},
            **outcome(lambda: mfa.hotp(secret, 0, algorithm="md5")),
        },
        {"fn": "hotp", "args": {"secret": secret, "counter": -1}, **outcome(lambda: mfa.hotp(secret, -1))},
        {"fn": "hotp", "args": {"secret": "AAAAAAAA", "counter": 0}, **outcome(lambda: mfa.hotp("AAAAAAAA", 0))},
        {
            "fn": "totp",
            "args": {"secret": secret, "at": 0, "period": 0},
            **outcome(lambda: mfa.totp(secret, 0, period=0)),
        },
        {
            "fn": "hotp",
            "args": {"secret": secret, "counter": 0, "algorithm": "SHA256"},
            **outcome(lambda: mfa.hotp(secret, 0, algorithm="SHA256")),
        },
    ]
    return {
        "hotp": hotp,
        "totp": totp,
        "secrets": secrets_,
        "find_totp_step": find,
        "verify_hotp": verify_hotp,
        "steam": steam,
        "verify_steam": verify_steam,
        "errors": errors,
    }


def otpauth_uris() -> dict[str, Any]:
    s = "JBSWY3DPEHPK3PXP"
    cases = [
        ("totp", s, "alice@example.com", "MyApp", {}),
        ("totp", s, "alice@example.com", None, {}),
        ("totp", "jbsw y3dp ehpk 3pxp", "alice@example.com", "My App", {}),
        ("totp", s, "a b/c?d&e=f+g~h_i.j-k!l'm(n)o*p", "Ac-me & Co/✓", {}),
        ("totp", s, "ünïcødé@exämple.com", "Ünï", {}),
        ("totp", s, "alice", "MyApp", {"period": 60, "digits": 8, "algorithm": "sha256"}),
        ("totp", s, "alice", "MyApp", {"algorithm": "SHA512"}),
        ("totp", s, "alice", "MyApp", {"image": "https://example.com/logo.png?x=1&y=2"}),
        ("hotp", s, "alice", "MyApp", {}),
        ("hotp", s, "alice", "MyApp", {"counter": 42, "digits": 7, "algorithm": "sha512"}),
        ("totp", s, "", "MyApp", {}),
        ("totp", s, "a:b", "MyApp", {}),
        ("totp", s, "alice", "My:App", {}),
        ("totp", "AAAA", "alice", "MyApp", {}),
        ("totp", s, "alice", "MyApp", {"digits": 9}),
        ("totp", s, "alice", "MyApp", {"period": 0}),
        ("totp", s, "alice", "", {}),
    ]
    out = []
    for kind, secret, account, issuer, opts in cases:
        fn = mfa.totp_uri if kind == "totp" else mfa.hotp_uri
        out.append(
            {
                "kind": kind,
                "secret": secret,
                "account": account,
                "issuer": issuer,
                "options": opts,
                **outcome(
                    lambda fn=fn, secret=secret, account=account, issuer=issuer, opts=opts: fn(
                        secret, account, issuer, **opts
                    )
                ),
            }
        )
    migration = []
    for accounts in [
        [{"secret": s, "name": "alice@example.com", "issuer": "MyApp"}],
        [
            {"secret": s, "name": "alice", "issuer": "A", "digits": 8, "algorithm": "sha256"},
            {"secret": b32(RFC_SECRET), "name": "bob ✓"},
        ],
        [],
        [{"secret": s, "name": "x", "digits": 7}],
    ]:
        with frozen(randbits=0x1234567):
            migration.append(
                {"accounts": accounts, "batch_id": 0x1234567, **outcome(lambda a=accounts: mfa.google_migration_uri(a))}
            )
    return {"uris": out, "google_migration": migration}


def scope_checks() -> dict[str, Any]:
    parse = [
        {"input": i, "result": sorted(scopes.parse_scopes(i))}
        for i in [
            None,
            "",
            "read write",
            "read,write",
            " read , write  admin ",
            "read\twrite\nadmin",
            ["read", "write", "", 1, None, "read"],
            [],
            "a,,b",
        ]
    ]
    granted_sets = [
        "*",
        "read:*",
        "read:users",
        "read:users:*",
        "read write",
        "read:users:list",
        "",
        None,
        ["admin", "read:*"],
    ]
    required = [
        "read",
        "read:users",
        "read:users:list",
        "read:orders",
        "write",
        "write:users",
        "admin",
        "",
        "*",
        "read:*",
        "readx:users",
        "read:",
    ]
    has = [{"granted": gs, "required": r, "result": scopes.has_scope(gs, r)} for gs in granted_sets for r in required]
    all_any = []
    for gs, req in [
        ("read:* write:users", ["read:x", "write:users"]),
        ("read:* write:users", ["read:x", "write:orders"]),
        ("read", []),
        ("", []),
        ("read", "read"),
        ("read", "write"),
    ]:
        all_any.append(
            {
                "granted": gs,
                "required": req,
                "all": scopes.has_all_scopes(gs, req),
                "any": scopes.has_any_scope(gs, req),
            }
        )
    return {"parse": parse, "has_scope": has, "all_any": all_any}


def scanning_vectors() -> dict[str, Any]:
    def key(prefix: str, sep: str = "-", body: str = "A" * 32, checksum: bool = True) -> str:
        k = f"{prefix}{sep}{body}"
        return k + utils.compute_checksum(k) if checksum else k

    good = key("sk")
    patterns = [
        {"prefix": p, "options": o, **outcome(lambda p=p, o=o: scanning.key_pattern(p, **o))}
        for p, o in [
            ("sk", {}),
            ("sk_live", {"separator": "_", "length": 24}),
            ("a.b+c", {"charset": "hex", "checksum": False}),
            ("sk", {"charset": "base64url"}),
            ("sk", {"charset": "a-z]^\\["}),
            ("", {}),
            ("sk", {"length": 0}),
        ]
    ]
    texts = [
        (f"token={good} other", "sk", {}),
        (f"{good} {good}", "sk", {}),
        (f"x{good}", "sk", {}),
        (f"{good}x", "sk", {}),
        (f"_{good}", "sk", {}),
        (f"({good})", "sk", {}),
        (good[:-1] + ("B" if good[-1] != "B" else "C"), "sk", {}),
        (good[:-1] + ("B" if good[-1] != "B" else "C"), "sk", {"validate": False}),
        (key("sk", body="A" * 31), "sk", {}),
        ("sk-" + "A" * 32, "sk", {"checksum": False}),
        (f"{key('pk', '_')} {good}", "pk", {"separator": "_"}),
        (key("sk", body="é" * 32, checksum=False), "sk", {"checksum": False}),
    ]
    find = [{"text": t, "prefix": p, "options": o, "found": scanning.find_keys(t, p, **o)} for t, p, o in texts]
    gitleaks = [
        {
            "prefix": "sk",
            "rule_id": "acme-api-key",
            "options": {},
            **outcome(lambda: scanning.gitleaks_rule("sk", "acme-api-key")),
        },
        {
            "prefix": "pk",
            "rule_id": "x",
            "options": {"description": "Acme key", "separator": "_"},
            **outcome(lambda: scanning.gitleaks_rule("pk", "x", description="Acme key", separator="_")),
        },
        {"prefix": "sk", "rule_id": "bad id", "options": {}, **outcome(lambda: scanning.gitleaks_rule("sk", "bad id"))},
    ]
    return {"key_pattern": patterns, "find_keys": find, "gitleaks_rule": gitleaks}


TOKEN_SECRET = "0123456789abcdef-token-secret"
JTI_BYTES = bytes(range(100, 112))


def signed_tokens() -> dict[str, Any]:
    gen = []
    for data, purpose, expiry, context in [
        ({"uid": 42}, "default", 15, None),
        ({"uid": 42}, "login", 15, None),
        ({}, "default", None, None),
        (None, "reset", 60, None),
        ({"email": "a@b.c", "n": [1, 2, {"z": True, "a": None}]}, "verify", 15, None),
        ({"uid": 42}, "login", 15, "session-abc"),
        ({"name": "José ✓ 😀", "b": "x"}, "default", 15, None),
        ({"uid": 42}, "default", 0.5, None),
    ]:
        with frozen(rand=JTI_BYTES):
            tok = tokens.generate_signed_token(TOKEN_SECRET, data, purpose=purpose, expiry=expiry, context=context)
        gen.append(
            {
                "secret": TOKEN_SECRET,
                "data": data,
                "purpose": purpose,
                "expiry": expiry,
                "context": context,
                "now": NOW,
                "jti_hex": hexb(JTI_BYTES),
                "token": tok,
            }
        )
    t = gen[0]["token"]
    body, sig = t.split(".")
    tl = gen[1]["token"]
    tc = gen[5]["token"]
    forged_body = tokens._b64e(
        json.dumps(
            {"p": "default", "jti": "x", "d": {"uid": 1}, "exp": NOW + 999}, separators=(",", ":"), sort_keys=True
        ).encode()
    )
    verify_cases: list[tuple[str, dict[str, Any], float]] = [
        (t, {}, NOW),
        (t, {"with_meta": True}, NOW),
        (t, {"purpose": "login"}, NOW),
        (tl, {"purpose": "login"}, NOW),
        (t, {}, NOW + 15 * 60 - 1),
        (t, {}, NOW + 15 * 60),
        (gen[2]["token"], {}, NOW + 10**9),
        (tc, {"purpose": "login", "context": "session-abc"}, NOW),
        (tc, {"purpose": "login", "context": "session-xyz"}, NOW),
        (tc, {"purpose": "login"}, NOW),
        (t, {"context": "session-abc"}, NOW),
        (t + "x", {}, NOW),
        (body + "." + sig[:-1] + ("A" if sig[-1] != "A" else "B"), {}, NOW),
        (body + "x." + sig, {}, NOW),
        (forged_body + "." + sig, {}, NOW),
        (t + ".x", {}, NOW),
        (body, {}, NOW),
        ("", {}, NOW),
        ("é" + t, {}, NOW),
        ("a" * 8193, {}, NOW),
        (gen[6]["token"], {}, NOW),
        (gen[4]["token"], {"purpose": "verify", "with_meta": True}, NOW),
    ]
    verify = []
    for tok, opts, now in verify_cases:
        with frozen(now=now):
            r = tokens.verify_signed_token(tok, TOKEN_SECRET, **opts)
        verify.append({"token": tok, "secret": TOKEN_SECRET, "options": opts, "now": now, "result": r})
    with frozen(now=NOW):
        other = tokens.verify_signed_token(t, TOKEN_SECRET + "x")
    verify.append({"token": t, "secret": TOKEN_SECRET + "x", "options": {}, "now": NOW, "result": other})
    # Tokens signed over non-canonical JSON bodies (what another implementation might emit) still verify.
    for payload in [
        f'{{"p":"default","jti":"abc","d":{{"uid":42}},"exp":{NOW + 60}}}',
        f'{{"exp":{NOW + 60}.0,"d":{{"é":"✓"}},"p":"default"}}',
        '{"p":"default","d":[1,2]}',
        '{"p":1}',
        "[1,2]",
        '{"p":"default","exp":"soon"}',
        '{"p":"default","exp":true}',
        f'{{"p":"default","exp":{NOW}.5}}',
    ]:
        b = tokens._b64e(payload.encode())
        tok = f"{b}.{tokens._sign(TOKEN_SECRET, b)}"
        with frozen(now=NOW):
            r = tokens.verify_signed_token(tok, TOKEN_SECRET, with_meta=True)
        verify.append(
            {
                "token": tok,
                "secret": TOKEN_SECRET,
                "options": {"with_meta": True},
                "now": NOW,
                "result": r,
                "note": payload,
            }
        )
    errors = [
        {"secret": "short", **outcome(lambda: tokens.generate_signed_token("short"))},
        {"secret": "x" * 15, **outcome(lambda: tokens.generate_signed_token("x" * 15))},
        {"secret": "é" * 16, **outcome(lambda: tokens.generate_signed_token("é" * 16))},
        {"secret": TOKEN_SECRET, "expiry": 0, **outcome(lambda: tokens.generate_signed_token(TOKEN_SECRET, expiry=0))},
        {
            "secret": TOKEN_SECRET,
            "expiry": -5,
            **outcome(lambda: tokens.generate_signed_token(TOKEN_SECRET, expiry=-5)),
        },
    ]
    for e in errors:
        e.pop("result", None)
    return {"generate": gen, "verify": verify, "errors": errors}


JWT_SECRET = "jwt-secret-0123456789-abcdef"


def jwt_hs() -> dict[str, Any]:
    gen = []
    for claims, kw in [
        ({"sub": "42"}, {}),
        ({"sub": "42"}, {"algorithm": "HS384"}),
        ({"sub": "42"}, {"algorithm": "HS512"}),
        ({"sub": "42", "iat": 1}, {"expiry": None}),
        ({"sub": "42"}, {"issuer": "me", "audience": "you"}),
        ({"sub": "42", "iss": "preset"}, {"issuer": "ignored"}),
        ({"sub": "42"}, {"headers": {"kid": "k1", "alg": "none", "typ": "x"}}),
        ({"name": "José ✓", "roles": ["a", "b"], "n": 1.5}, {"expiry": 0.5}),
    ]:
        with frozen():
            tok = tokens.encode_jwt(claims, JWT_SECRET, **kw)
        gen.append({"claims": claims, "secret": JWT_SECRET, "options": kw, "now": NOW, "token": tok})
    t = gen[0]["token"]
    h, b, s = t.split(".")
    none_tok = tokens._b64e(b'{"alg":"none","typ":"JWT"}') + "." + b + "."

    def hs(header: dict[str, Any], claims: dict[str, Any], alg: str = "HS256") -> str:
        hh = tokens._b64e(json.dumps(header, separators=(",", ":")).encode())
        bb = tokens._b64e(json.dumps(claims, separators=(",", ":")).encode())
        return f"{hh}.{bb}.{tokens._b64e(tokens._jwt_sig(JWT_SECRET, f'{hh}.{bb}'.encode(), alg))}"

    cases: list[tuple[str, dict[str, Any], float]] = [
        (t, {}, NOW),
        (t, {}, NOW + 900),
        (t, {"leeway": 5}, NOW + 904),
        (t, {"algorithms": ["HS384"]}, NOW),
        (gen[1]["token"], {"algorithms": ["HS256", "HS384"]}, NOW),
        (gen[3]["token"], {}, NOW),
        (gen[3]["token"], {"require_exp": False}, NOW),
        (gen[4]["token"], {"issuer": "me", "audience": "you"}, NOW),
        (gen[4]["token"], {"issuer": "other"}, NOW),
        (gen[4]["token"], {"audience": "other"}, NOW),
        (gen[5]["token"], {"issuer": "preset"}, NOW),
        (gen[6]["token"], {}, NOW),
        (none_tok, {}, NOW),
        (f"{h}.{b}.{s[:-2]}AA", {}, NOW),
        (f"{h}.{b}x.{s}", {}, NOW),
        (f"{h}.{b}", {}, NOW),
        ("", {}, NOW),
        (hs({"alg": "HS256"}, {"exp": NOW + 60, "nbf": NOW + 10}), {}, NOW),
        (hs({"alg": "HS256"}, {"exp": NOW + 60, "nbf": NOW + 10}), {"leeway": 10}, NOW),
        (hs({"alg": "HS256"}, {"exp": NOW + 60, "aud": ["a", "b"]}), {"audience": "b"}, NOW),
        (hs({"alg": "HS256"}, {"exp": NOW + 60, "aud": ["a", "b"]}), {"audience": "c"}, NOW),
        (hs({"alg": "HS256"}, {"exp": True}), {}, NOW),
        (hs({"alg": "HS256"}, {"exp": "later"}), {}, NOW),
        (hs({"alg": "HS256"}, {"exp": NOW + 60, "nbf": "x"}), {}, NOW),
        (hs({"alg": "HS256"}, {"exp": NOW + 60.5}), {}, NOW + 60.25),
        (hs({"typ": "JWT"}, {"exp": NOW + 60}), {}, NOW),
        (hs({"alg": "HS384"}, {"exp": NOW + 60}), {}, NOW),
        (hs({"alg": "HS384"}, {"exp": NOW + 60}, "HS384"), {"algorithms": ["HS384"]}, NOW),
        (hs({"alg": "HS256"}, {"exp": NOW + 60, "iss": 1}), {"issuer": "1"}, NOW),
        (tokens._b64e(b"[1]") + "." + b + "." + s, {}, NOW),
    ]
    decode = []
    for tok, opts, now in cases:
        kw = dict(opts)
        if "algorithms" in kw:
            kw["algorithms"] = tuple(kw["algorithms"])
        with frozen(now=now):
            r = tokens.decode_jwt(tok, JWT_SECRET, **kw)
        decode.append({"token": tok, "secret": JWT_SECRET, "options": opts, "now": now, "result": r})
    with frozen():
        wrong = tokens.decode_jwt(t, JWT_SECRET + "x")
    decode.append({"token": t, "secret": JWT_SECRET + "x", "options": {}, "now": NOW, "result": wrong})
    # Python-only leniency (non-normative): its base64 decoder skips junk and accepts +/.
    lenient = [
        {
            "token": f"{h}.{b}.{s[:5]}!!{s[5:]}",
            "python_result_is_valid": tokens.decode_jwt(f"{h}.{b}.{s[:5]}!!{s[5:]}", JWT_SECRET) is not None,
        },
    ]
    errors = [
        {
            "fn": "encode_jwt",
            "options": {"algorithm": "none"},
            **outcome(lambda: tokens.encode_jwt({}, JWT_SECRET, algorithm="none")),
        },
        {"fn": "encode_jwt", "options": {"secret": "short"}, **outcome(lambda: tokens.encode_jwt({}, "short"))},
        {
            "fn": "decode_jwt",
            "options": {"algorithms": ["none"]},
            **outcome(lambda: tokens.decode_jwt(t, JWT_SECRET, algorithms=("none",))),
        },
        {
            "fn": "decode_jwt",
            "options": {"algorithms": []},
            **outcome(lambda: tokens.decode_jwt(t, JWT_SECRET, algorithms=())),
        },
        {
            "fn": "decode_jwt",
            "options": {"algorithms": ["HS256", "RS256"]},
            **outcome(lambda: tokens.decode_jwt(t, JWT_SECRET, algorithms=("HS256", "RS256"))),
        },
    ]
    for e in errors:
        e.pop("result", None)
    return {"encode": gen, "decode": decode, "python_lenient_non_normative": lenient, "errors": errors}


# ---------------------------------------------------------------------------
# Asymmetric JWTs
# ---------------------------------------------------------------------------

KEY_NAMES = ("rsa", "p256", "p384", "p521", "ed25519")


def _ephemeral_keys() -> dict[str, Any]:
    """Fresh private keys, in memory only. They are never written anywhere."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    return {
        "rsa": rsa.generate_private_key(65537, 2048),
        "p256": ec.generate_private_key(ec.SECP256R1()),
        "p384": ec.generate_private_key(ec.SECP384R1()),
        "p521": ec.generate_private_key(ec.SECP521R1()),
        "ed25519": ed25519.Ed25519PrivateKey.generate(),
    }


def _public_forms(private_key: Any) -> dict[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    pub = private_key.public_key()
    forms = {
        "public_spki": pub.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    }
    if isinstance(private_key, rsa.RSAPrivateKey):
        forms["public_pkcs1"] = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1).decode()
    return forms


def _private_pem(private_key: Any) -> str:
    from cryptography.hazmat.primitives import serialization

    return private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


def _jwk(public_pem: str, kid: str) -> dict[str, Any]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    from generateapikey._jwt_asym import _b64u

    pub = serialization.load_pem_public_key(public_pem.encode())
    if isinstance(pub, rsa.RSAPublicKey):
        n = pub.public_numbers()
        return {"kty": "RSA", "kid": kid, "n": _b64u(n.n), "e": _b64u(n.e)}
    if isinstance(pub, ec.EllipticCurvePublicKey):
        n = pub.public_numbers()
        crv, size = {"secp256r1": ("P-256", 32), "secp384r1": ("P-384", 48), "secp521r1": ("P-521", 66)}[pub.curve.name]

        def b(v: int, size: int = size) -> str:
            return base64.urlsafe_b64encode(v.to_bytes(size, "big")).decode().rstrip("=")

        return {"kty": "EC", "kid": kid, "crv": crv, "x": b(n.x), "y": b(n.y)}
    assert isinstance(pub, ed25519.Ed25519PublicKey)
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "kid": kid, "crv": "Ed25519", "x": base64.urlsafe_b64encode(raw).decode().rstrip("=")}


ALG_KEYS = {
    "RS256": "rsa",
    "RS384": "rsa",
    "RS512": "rsa",
    "PS256": "rsa",
    "PS384": "rsa",
    "PS512": "rsa",
    "ES256": "p256",
    "ES384": "p384",
    "ES512": "p521",
    "EdDSA": "ed25519",
}
ASYM_CLAIMS = {"sub": "42", "scope": "read"}


def _signed_set() -> dict[str, Any]:
    """Sign one token per algorithm with throw-away keys; keep only public material."""
    priv = _ephemeral_keys()
    keys = {name: _public_forms(k) for name, k in priv.items()}
    sign = []
    with frozen():
        for alg, kname in ALG_KEYS.items():
            token = tokens.encode_jwt(ASYM_CLAIMS, _private_pem(priv[kname]), algorithm=alg, headers={"kid": kname})
            sign.append({"alg": alg, "key": kname, "claims": ASYM_CLAIMS, "now": NOW, "token": token})
        extra = {
            "no_kid": tokens.encode_jwt({"sub": "1"}, _private_pem(priv["ed25519"]), algorithm="EdDSA"),
            "wrong_kid": tokens.encode_jwt(
                {"sub": "1"}, _private_pem(priv["ed25519"]), algorithm="EdDSA", headers={"kid": "rsa"}
            ),
            "unknown_kid": tokens.encode_jwt(
                {"sub": "1"}, _private_pem(priv["ed25519"]), algorithm="EdDSA", headers={"kid": "nope"}
            ),
        }
    del priv  # private keys are dropped here and never serialised
    return {"keys": keys, "sign": sign, "extra": extra}


def _set_still_valid(prev: dict[str, Any]) -> bool:
    try:
        with frozen():
            return (
                all(
                    tokens.decode_jwt(s["token"], prev["keys"][s["key"]]["public_spki"], algorithms=(s["alg"],))
                    == {**ASYM_CLAIMS, "iat": NOW, "exp": NOW + 900}
                    for s in prev["sign"]
                )
                and set(prev["keys"]) == set(KEY_NAMES)
                and len(prev["sign"]) == len(ALG_KEYS)
                and "extra" in prev
            )
    except (KeyError, TypeError, ValueError):
        return False


def jwt_asym(previous: dict[str, Any]) -> dict[str, Any]:
    """Verify-only vectors: public keys + tokens signed by keys that no longer exist.

    No private key is stored in the repository. The signed set is reused while it
    still verifies, so regenerating doesn't churn the file. Signing (and private
    key formats) is covered by each test suite with fresh keys at run time and by
    the cross-language interop CI job.
    """
    prev = previous.get("jwt_asym", {})
    base = {k: prev[k] for k in ("keys", "sign", "extra")} if _set_still_valid(prev) else _signed_set()
    keys, sign, extra = base["keys"], base["sign"], base["extra"]
    verify = []
    for s in sign:
        alg, kname, tok = s["alg"], s["key"], s["token"]
        h, b, sig = tok.split(".")
        raw = tokens._b64d(sig)
        flipped = tokens._b64e(bytes([raw[0] ^ 1]) + raw[1:])
        other = "p256" if kname in ("rsa", "ed25519", "p384") else "p384"
        candidates: list[tuple[str, str, str]] = [
            (kname, "public_spki", tok),
            (kname, "public_spki", f"{h}.{b}.{flipped}"),
            (kname, "public_spki", f"{h}.{b}x.{sig}"),
            (other, "public_spki", tok),
        ]
        if "public_pkcs1" in keys[kname]:
            candidates.append((kname, "public_pkcs1", tok))
        for key, form, t in candidates:
            with frozen():
                r = outcome(
                    lambda key=key, form=form, t=t, alg=alg: tokens.decode_jwt(t, keys[key][form], algorithms=(alg,))
                )
            verify.append({"alg": alg, "key": key, "key_form": form, "token": t, "algorithms": [alg], "now": NOW, **r})
        with frozen(now=NOW + 900):
            r = outcome(
                lambda tok=tok, kname=kname, alg=alg: tokens.decode_jwt(
                    tok, keys[kname]["public_spki"], algorithms=(alg,)
                )
            )
        verify.append(
            {
                "alg": alg,
                "key": kname,
                "key_form": "public_spki",
                "token": tok,
                "algorithms": [alg],
                "now": NOW + 900,
                **r,
            }
        )
    rs = next(s["token"] for s in sign if s["alg"] == "RS256")
    with frozen():
        verify.append(
            {
                "alg": "RS256",
                "key": "rsa",
                "key_form": "public_spki",
                "token": rs,
                "algorithms": ["PS256"],
                "now": NOW,
                **outcome(lambda: tokens.decode_jwt(rs, keys["rsa"]["public_spki"], algorithms=("PS256",))),
            }
        )
    jwks = {"keys": [_jwk(keys[k]["public_spki"], k) for k in KEY_NAMES]}
    jwks_cases = []
    for t, algs in [
        *((s["token"], [s["alg"]]) for s in sign),
        (extra["no_kid"], ["EdDSA"]),
        (extra["wrong_kid"], ["EdDSA"]),
        (extra["unknown_kid"], ["EdDSA"]),
    ]:
        with frozen():
            r = outcome(lambda t=t, algs=algs: tokens.decode_jwt_jwks(t, jwks, algorithms=tuple(algs)))
        jwks_cases.append({"token": t, "algorithms": algs, "now": NOW, **r})
    return {"keys": keys, "sign": sign, "extra": extra, "verify": verify, "jwks": jwks, "jwks_decode": jwks_cases}


def secretbox() -> dict[str, Any]:
    from generateapikey.crypto import DecryptionError, SecretBox

    k1 = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    k2 = base64.urlsafe_b64encode(bytes(range(32, 64))).decode().rstrip("=")
    box = SecretBox(k1)
    nonce = bytes(range(200, 212))
    enc = []
    for pt, aad in [
        ("JBSWY3DPEHPK3PXP", None),
        ("JBSWY3DPEHPK3PXP", "user-42"),
        ("", None),
        ("héllo ✓ 😀", "ä"),
        ("x" * 100, ""),
    ]:
        with frozen(rand=nonce):
            enc.append(
                {"key": k1, "plaintext": pt, "aad": aad, "nonce_hex": hexb(nonce), "token": box.encrypt(pt, aad)}
            )
    with frozen(rand=nonce):
        old_tok = SecretBox(k2).encrypt("rotated", None)
    t = enc[1]["token"]
    v, kid, blob = t.split(".")
    raw = base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4))
    tampered = f"{v}.{kid}.{base64.urlsafe_b64encode(raw[:-1] + bytes([raw[-1] ^ 1])).decode().rstrip('=')}"

    def dec(key: str, old: list[str], tok: str, aad: Any) -> dict[str, Any]:
        try:
            return {"result": SecretBox(key, old_keys=old).decrypt(tok, aad)}
        except DecryptionError:
            return {"error": "DecryptionError"}

    decrypt = [
        {"key": k1, "old_keys": [], "token": t, "aad": "user-42", **dec(k1, [], t, "user-42")},
        {"key": k1, "old_keys": [], "token": t, "aad": None, **dec(k1, [], t, None)},
        {"key": k1, "old_keys": [], "token": t, "aad": "user-43", **dec(k1, [], t, "user-43")},
        {"key": k1, "old_keys": [], "token": enc[0]["token"], "aad": "", **dec(k1, [], enc[0]["token"], "")},
        {"key": k1, "old_keys": [], "token": tampered, "aad": "user-42", **dec(k1, [], tampered, "user-42")},
        {"key": k1, "old_keys": [], "token": old_tok, "aad": None, **dec(k1, [], old_tok, None)},
        {"key": k1, "old_keys": [k2], "token": old_tok, "aad": None, **dec(k1, [k2], old_tok, None)},
        {
            "key": k1,
            "old_keys": [],
            "token": "v2." + kid + "." + blob,
            "aad": "user-42",
            **dec(k1, [], "v2." + kid + "." + blob, "user-42"),
        },
        {"key": k1, "old_keys": [], "token": f"v1.{kid}.AAAA", "aad": None, **dec(k1, [], f"v1.{kid}.AAAA", None)},
        {"key": k1, "old_keys": [], "token": "garbage", "aad": None, **dec(k1, [], "garbage", None)},
        {"key": k1, "old_keys": [], "token": "é" + t, "aad": None, **dec(k1, [], "é" + t, None)},
    ]
    rotation = [
        {"key": k1, "old_keys": [k2], "token": old_tok, "needs_rotation": SecretBox(k1, [k2]).needs_rotation(old_tok)},
        {"key": k1, "old_keys": [k2], "token": t, "needs_rotation": SecretBox(k1, [k2]).needs_rotation(t)},
        {"key": k1, "old_keys": [k2], "token": "nope", "needs_rotation": SecretBox(k1, [k2]).needs_rotation("nope")},
    ]
    key_errors = [
        {"key": k, **outcome(lambda k=k: repr(SecretBox(k)))}
        for k in ["", "short", k1 + "AA", base64.urlsafe_b64encode(bytes(31)).decode()]
    ]
    for e in key_errors:
        e.pop("result", None)
    key_ids = [{"key": k, "key_id": SecretBox(k)._current_id} for k in (k1, k2)]
    return {"encrypt": enc, "decrypt": decrypt, "rotation": rotation, "key_errors": key_errors, "key_ids": key_ids}


def auth_core() -> dict[str, Any]:
    from generateapikey.limiters import _Base

    good = "sk-" + "A" * 32
    good += utils.compute_checksum(good)
    extract = []
    for headers, query, opts in [
        ({"X-API-Key": "abc"}, None, {}),
        ({"x-api-key": "abc"}, None, {}),
        ({"X-Api-Key": "  abc  "}, None, {}),
        ({"Authorization": "Bearer abc"}, None, {}),
        ({"authorization": "bearer   abc"}, None, {}),
        ({"Authorization": "Basic abc"}, None, {}),
        ({"Authorization": "Bearer"}, None, {}),
        ({"Authorization": "Bearer abc"}, None, {"bearer": False}),
        ({"X-API-Key": "abc", "Authorization": "Bearer xyz"}, None, {}),
        ({"X-API-Key": "", "Authorization": "Bearer xyz"}, None, {}),
        ({"X-API-Key": "   "}, None, {}),
        ({}, {"api_key": "q"}, {"query_param": "api_key"}),
        ({}, {"api_key": "q"}, {}),
        ({"X-Token": "t"}, None, {"header": "X-Token"}),
        ({}, None, {}),
    ]:
        auth = integ.APIKeyAuth(lambda h: None, **opts)
        extract.append({"headers": headers, "query": query, "options": opts, "key": auth.extract(headers, query)})
    wf_cases = []
    for key, opts in [
        (good, {}),
        (good, {"prefix": "sk"}),
        (good, {"prefix": "pk"}),
        (good, {"require_checksum": True}),
        (good[:-1] + ("B" if good[-1] != "B" else "C"), {"require_checksum": True}),
        ("abc", {"require_checksum": True}),
        ("a" * 512, {}),
        ("a" * 513, {}),
        ("é" * 10, {}),
    ]:
        auth = integ.APIKeyAuth(lambda h: None, **opts)
        wf_cases.append({"key": key, "options": opts, "well_formed": bool(auth._well_formed(key))})
    active = []
    for rec in [
        None,
        {},
        {"revoked": True},
        {"revoked": False},
        {"is_active": False},
        {"is_active": 0},
        {"expires_at": NOW + 1},
        {"expires_at": NOW},
        {"expires_at": NOW - 1},
        {"expires_at": "tomorrow"},
        {"expires_at": None},
        {"revoked": 1},
        {"revoked": ""},
    ]:
        with frozen():
            active.append({"record": rec, "now": NOW, "active": integ.record_is_active(rec)})
    excluded = []
    for path, exclude in [
        ("/health", ["/health"]),
        ("/health/live", ["/health"]),
        ("/healthz", ["/health"]),
        ("/health-admin", ["/health"]),
        ("/health", ["/health/"]),
        ("/docs/x", ["/docs/"]),
        ("/", ["/"]),
        ("/a", ["/"]),
        ("/a", []),
        ("/docs", ["/docs/"]),
    ]:
        excluded.append({"path": path, "exclude": exclude, "excluded": integ.path_excluded(path, exclude)})
    hints = [
        {"key": k, "hint": integ._hint(k)} for k in ["", "short", "a" * 15, "a" * 16, good, "sk-ÄÖÜabcdefghijklmn"]
    ]

    # End-to-end authenticate flows against a small in-memory table.
    pepper, old = "pepper-now", "pepper-old"
    k_cur, k_old, k_rev, k_exp, k_scoped = ("sk-" + c * 32 for c in "BCDEF")
    k_cur, k_old, k_rev, k_exp, k_scoped = (
        k + utils.compute_checksum(k) for k in (k_cur, k_old, k_rev, k_exp, k_scoped)
    )
    table = {
        utils.hash_api_key(k_cur, pepper): {"id": 1, "scopes": ["read:*"]},
        utils.hash_api_key(k_old, old): {"id": 2, "scopes": "read write"},
        utils.hash_api_key(k_rev, pepper): {"id": 3, "revoked": True},
        utils.hash_api_key(k_exp, pepper): {"id": 4, "expires_at": NOW - 1},
        utils.hash_api_key(k_scoped, pepper): {"id": 5, "scopes": ["write:users"]},
    }
    flows = []
    for key, kw in [
        (k_cur, {}),
        (k_old, {}),
        (k_rev, {}),
        (k_exp, {}),
        (None, {}),
        ("", {}),
        ("sk-unknown", {}),
        (k_cur, {"scopes": ["read:users"]}),
        (k_scoped, {"scopes": ["read:users"]}),
        (k_scoped, {"scopes": ["write:users"]}),
        (k_cur, {"required_scopes": ["admin"]}),
        (k_cur, {"required_scopes": ["admin"], "scopes": []}),
        (k_cur, {"prefix": "pk"}),
    ]:
        rehashed: list[Any] = []
        init = {
            "pepper": pepper,
            "previous_peppers": [old],
            "on_rehash": lambda r, h, rh=rehashed: rh.append([r["id"], h]),
            "require_checksum": True,
        }
        call: dict[str, Any] = {}
        if "required_scopes" in kw:
            init["required_scopes"] = kw["required_scopes"]
        if "prefix" in kw:
            init["prefix"] = kw["prefix"]
        if "scopes" in kw:
            call["scopes"] = kw["scopes"]
        auth = integ.APIKeyAuth(table.get, **init)
        with frozen():
            try:
                rec = auth.authenticate(key, **call)
                res: dict[str, Any] = {"record_id": rec["id"]}
            except integ.AuthError as e:
                res = {"status": e.status, "detail": e.detail}
        flows.append({"key": key, "options": kw, **res, "rehashed": rehashed})
    challenge = [
        {"options": {}, "challenge": integ.APIKeyAuth(lambda h: None).challenge()},
        {"options": {"bearer": False}, "challenge": integ.APIKeyAuth(lambda h: None, bearer=False).challenge()},
        {
            "options": {"bearer": False, "header": "X-Token"},
            "challenge": integ.APIKeyAuth(lambda h: None, bearer=False, header="X-Token").challenge(),
        },
    ]

    class _FakeRedis:
        def register_script(self, s: str) -> Any:
            return None

    lim = _Base(_FakeRedis())
    limiter_keys = [{"key": k, "redis_key": lim._key(k)} for k in ["1.2.3.4", "alice@example.com", "é"]]
    issued = []
    with frozen(rand=bytes(range(256))):
        ik = integ.issue_api_key(prefix="sk", pepper=pepper)
    issued.append(
        {
            "options": {"prefix": "sk", "pepper": pepper},
            "rand_hex": hexb(bytes(range(256))),
            "key_shape": len(ik.key),
            "hashed": ik.hashed,
            "hint": ik.hint,
            "key": str(ik.key),
        }
    )
    return {
        "max_key_length": integ.MAX_KEY_LENGTH,
        "messages": {
            "missing": "Missing API key.",
            "invalid": "Invalid API key.",
            "scope": "Insufficient scope.",
            "blocked": "Too many invalid API keys. Try again later.",
        },
        "extract": extract,
        "well_formed": wf_cases,
        "record_is_active": active,
        "path_excluded": excluded,
        "hints": hints,
        "authenticate": {
            "pepper": pepper,
            "previous_peppers": [old],
            "require_checksum": True,
            "table": table,
            "flows": flows,
        },
        "challenge": challenge,
        "redis_limiter_keys": {
            "script": __import__("generateapikey.limiters", fromlist=["_SCRIPT"])._SCRIPT,
            "prefix": "gak:attempts:",
            "keys": limiter_keys,
        },
        "issue_api_key": issued,
    }


def random_sampling() -> list[dict[str, Any]]:
    """random_key() fed a fixed byte stream: pins the rejection-sampling rule."""
    out = []
    stream = hashlib.sha256(b"generateapikey.vectors.stream").digest() * 64
    for chars in [
        utils.build_charset("alphanumeric"),
        utils.build_charset("hex"),
        utils.build_charset("numeric"),
        utils.build_charset("base58"),
        "αβγδεζηθικ",
        "".join(chr(0x4E00 + i) for i in range(300)),
    ]:
        with frozen(rand=stream):
            key = utils.random_key(40, chars)
        out.append({"chars": chars, "length": 40, "stream_hex": hexb(stream), "result": key})
    return out


def build(previous: dict[str, Any]) -> dict[str, Any]:
    return {
        "spec_version": SPEC_VERSION,
        "generated_by": f"generateapikey {g.__version__} (python/scripts/gen_vectors.py)",
        "now": NOW,
        "charsets": charsets(),
        "random_sampling": random_sampling(),
        "derived_keys": derived_keys(),
        "random_key_formats": random_key_formats(),
        "checksums": checksums(),
        "key_hashes": key_hashes(),
        "code_hashes": code_hashes(),
        "recovery_codes": recovery_codes(),
        "otp": otps(),
        "hotp_totp": otp_codes(),
        "otpauth": otpauth_uris(),
        "scopes": scope_checks(),
        "scanning": scanning_vectors(),
        "signed_tokens": signed_tokens(),
        "jwt_hs": jwt_hs(),
        "jwt_asym": jwt_asym(previous),
        "secretbox": secretbox(),
        "auth": auth_core(),
    }


def _strip_samples(v: Any) -> Any:
    """Random samples differ per run; drop them when comparing for --check."""
    if isinstance(v, dict):
        return {k: _strip_samples(x) for k, x in v.items() if k not in ("sample",)}
    if isinstance(v, list):
        return [_strip_samples(x) for x in v]
    return v


def dumps(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=1, ensure_ascii=False, sort_keys=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="fail if spec/vectors.json is out of date")
    args = ap.parse_args()
    previous = json.loads(OUT.read_text(encoding="utf-8")) if OUT.exists() else {}
    data = build(previous)
    if args.check:
        if _strip_samples(previous) != _strip_samples(json.loads(dumps(data))):
            print(
                "spec/vectors.json is stale: run `python scripts/gen_vectors.py` and commit the result.",
                file=sys.stderr,
            )
            return 1
        print("spec/vectors.json is up to date.")
        return 0
    # Keep previous random samples so regenerating doesn't churn the file.
    OUT.write_text(dumps(_keep_samples(previous, data)), encoding="utf-8")
    print(f"wrote {OUT.relative_to(PY_ROOT.parent)}")
    return 0


def _keep_samples(prev: Any, new: Any) -> Any:
    if isinstance(new, dict) and isinstance(prev, dict):
        return {k: (prev[k] if k == "sample" and k in prev else _keep_samples(prev.get(k), v)) for k, v in new.items()}
    if isinstance(new, list) and isinstance(prev, list) and len(prev) == len(new):
        return [_keep_samples(p, n) for p, n in zip(prev, new)]
    return new


if __name__ == "__main__":
    sys.exit(main())
