"""Run the shared cross-language vectors (spec/vectors.json) against this package.

The same file is run by the JavaScript test suite, so these tests are what
keeps the two implementations wire-compatible. Skipped outside the monorepo
checkout (e.g. when testing an sdist), where spec/ isn't available.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import time
import warnings
from typing import Any
from unittest import mock

import pytest

import generateapikey as g
from generateapikey import integrations as integ
from generateapikey import mfa, scanning, scopes, tokens, utils

SPEC = pathlib.Path(__file__).resolve().parents[2] / "spec" / "vectors.json"
if not SPEC.is_file():  # pragma: no cover
    pytest.skip("spec/vectors.json not available (not in the monorepo checkout)", allow_module_level=True)

V: dict[str, Any] = json.loads(SPEC.read_text(encoding="utf-8"))


def at(now: float) -> Any:
    return mock.patch.object(time, "time", lambda: now)


def outcome(fn: Any) -> dict[str, Any]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return {"result": fn()}
    except (ValueError, TypeError) as e:
        return {"error": type(e).__name__}


def test_spec_version() -> None:
    assert V["spec_version"] == 1


def test_charsets() -> None:
    for name, cases in V["charsets"]["presets"].items():
        for case, chars in cases.items():
            assert utils.build_charset(name, case) == chars
    for c in V["charsets"]["custom"]:
        expected = {k: c[k] for k in ("result", "error") if k in c}
        assert outcome(lambda c=c: utils.build_charset(c["charset"], c["case"])) == expected
    for e in V["charsets"]["entropy_bits"]:
        assert utils.entropy_bits(e["length"], e["charset"], e["case"]) == pytest.approx(e["bits"])


def test_derived_keys() -> None:
    for v in V["derived_keys"]:
        o = dict(v["options"])
        if "salt_hex" in o:
            salt = bytes.fromhex(o.pop("salt_hex"))
            got = utils.derived_key(o["secret"], o["seed"], None, 32, utils.build_charset("alphanumeric"), salt=salt)
            assert got == v["result"]
            continue
        secret, seed = o.pop("secret"), o.pop("seed")
        expected = {k: v[k] for k in ("result", "error") if k in v}
        assert outcome(lambda: str(g.generate_api_key(secret, seed, **o))) == expected, v["options"]


def test_random_sampling() -> None:
    for v in V["random_sampling"]:
        stream = bytes.fromhex(v["stream_hex"])
        pool = bytearray()

        def source(n: int, pool: bytearray = pool, stream: bytes = stream) -> bytes:
            while len(pool) < n:
                pool.extend(stream)
            out = bytes(pool[:n])
            del pool[:n]
            return out

        assert utils._sample(source, v["length"], v["chars"]) == v["result"]


def test_checksums() -> None:
    for c in V["checksums"]["compute"]:
        assert utils.compute_checksum(c["input"]) == c["checksum"]
    for c in V["checksums"]["verify"]:
        assert utils.verify_checksum(c["key"]) is c["valid"]


def test_key_hashes() -> None:
    kh = V["key_hashes"]
    for h in kh["hash"]:
        assert utils.hash_api_key(h["key"], h["pepper"]) == h["hashed"]
    for v in kh["verify"]:
        expected = {k: v[k] for k in ("result", "error") if k in v}
        assert outcome(lambda v=v: utils.verify_api_key(v["key"], v["hashed"], v["pepper"])) == expected
    for s in kh["subkeys"]:
        assert utils.subkey(s["secret"], s["label"]).hex() == s["hex"]


def test_code_hashes() -> None:
    for h in V["code_hashes"]["hash"]:
        with mock.patch("secrets.token_bytes", lambda n, h=h: bytes.fromhex(h["salt_hex"])[:n]):
            assert utils.hash_code(h["code"], h["pepper"], h["iterations"]) == h["hashed"]
    for v in V["code_hashes"]["verify"]:
        expected = {k: v[k] for k in ("result", "error") if k in v}
        assert outcome(lambda v=v: utils.verify_code(v["code"], v["hashed"], v["pepper"])) == expected


def test_recovery_codes() -> None:
    r = V["recovery_codes"]
    for n in r["normalize"]:
        expected = {k: n[k] for k in ("result", "error") if k in n}
        assert outcome(lambda n=n: mfa.normalize_recovery_code(n["input"])) == expected
    for v in r["verify"]:
        match = mfa.verify_recovery_code(v["code"], v["hashes"], v["pepper"])
        assert (None if match is None else v["hashes"].index(match)) == v["match_index"]


def test_otp() -> None:
    for v in V["otp"]["verify"]:
        with at(V["now"]):
            assert mfa.verify_otp(v["code"], v["hashed"], v["expires_at"], pepper=v["pepper"]) is v["valid"]


def test_hotp_totp() -> None:
    o = V["hotp_totp"]
    for h in o["hotp"]:
        assert mfa.hotp(h["secret"], h["counter"], digits=h["digits"], algorithm=h["algorithm"]) == h["code"]
    for t in o["totp"]:
        assert (
            mfa.totp(t["secret"], t["at"], period=t["period"], digits=t["digits"], algorithm=t["algorithm"])
            == t["code"]
        )
    for s in o["secrets"]:
        got = outcome(lambda s=s: mfa._decode_secret(s["secret"]).hex())
        assert got == ({"result": s["bytes_hex"]} if "bytes_hex" in s else {"error": s["error"]})
    for f in o["find_totp_step"]:
        assert mfa.find_totp_step(f["secret"], f["code"], at=f["at"], **f["options"]) == f["step"]
    for h in o["verify_hotp"]:
        assert mfa.verify_hotp(h["secret"], h["code"], h["counter"], look_ahead=h["look_ahead"]) == h["next_counter"]
    for s in o["steam"]:
        assert mfa.steam_code(s["secret"], s["at"]) == s["code"]
    for s in o["verify_steam"]:
        assert mfa.verify_steam_code(s["secret"], s["code"], window=s["window"], at=s["at"]) is s["valid"]


def test_otpauth_uris() -> None:
    for u in V["otpauth"]["uris"]:
        fn = mfa.totp_uri if u["kind"] == "totp" else mfa.hotp_uri
        expected = {k: u[k] for k in ("result", "error") if k in u}
        assert outcome(lambda u=u, fn=fn: fn(u["secret"], u["account"], u["issuer"], **u["options"])) == expected
    for m in V["otpauth"]["google_migration"]:
        expected = {k: m[k] for k in ("result", "error") if k in m}
        with mock.patch("secrets.randbits", lambda k, m=m: m["batch_id"]):
            assert outcome(lambda m=m: mfa.google_migration_uri(m["accounts"])) == expected


def test_scopes() -> None:
    s = V["scopes"]
    for p in s["parse"]:
        assert sorted(scopes.parse_scopes(p["input"])) == p["result"]
    for h in s["has_scope"]:
        assert scopes.has_scope(h["granted"], h["required"]) is h["result"]
    for a in s["all_any"]:
        assert scopes.has_all_scopes(a["granted"], a["required"]) is a["all"]
        assert scopes.has_any_scope(a["granted"], a["required"]) is a["any"]


def test_scanning() -> None:
    sc = V["scanning"]
    for p in sc["key_pattern"]:
        expected = {k: p[k] for k in ("result", "error") if k in p}
        assert outcome(lambda p=p: scanning.key_pattern(p["prefix"], **p["options"])) == expected
    for f in sc["find_keys"]:
        assert scanning.find_keys(f["text"], f["prefix"], **f["options"]) == f["found"]
    for r in sc["gitleaks_rule"]:
        expected = {k: r[k] for k in ("result", "error") if k in r}
        assert outcome(lambda r=r: scanning.gitleaks_rule(r["prefix"], r["rule_id"], **r["options"])) == expected


def test_signed_tokens() -> None:
    st = V["signed_tokens"]
    for gen in st["generate"]:
        with at(gen["now"]), mock.patch("secrets.token_bytes", lambda n, gen=gen: bytes.fromhex(gen["jti_hex"])[:n]):
            tok = tokens.generate_signed_token(
                gen["secret"], gen["data"], purpose=gen["purpose"], expiry=gen["expiry"], context=gen["context"]
            )
        assert tok == gen["token"]
    for v in st["verify"]:
        with at(v["now"]):
            assert tokens.verify_signed_token(v["token"], v["secret"], **v["options"]) == v["result"]


def test_jwt_hs() -> None:
    j = V["jwt_hs"]
    for e in j["encode"]:
        with at(e["now"]):
            assert tokens.encode_jwt(e["claims"], e["secret"], **e["options"]) == e["token"]
    for d in j["decode"]:
        opts = dict(d["options"])
        if "algorithms" in opts:
            opts["algorithms"] = tuple(opts["algorithms"])
        with at(d["now"]):
            assert tokens.decode_jwt(d["token"], d["secret"], **opts) == d["result"]


def test_jwt_asym() -> None:
    """Verify-only: the tokens were signed by throw-away keys; only public keys are stored."""
    pytest.importorskip("cryptography")
    j = V["jwt_asym"]
    keys = j["keys"]
    for k in keys.values():
        assert all("PRIVATE" not in pem for pem in k.values())
    for s in j["sign"]:
        with at(s["now"]):
            assert tokens.decode_jwt(s["token"], keys[s["key"]]["public_spki"], algorithms=(s["alg"],)) is not None
    for v in j["verify"]:
        expected = {k: v[k] for k in ("result", "error") if k in v}
        with at(v["now"]):
            got = outcome(
                lambda v=v: tokens.decode_jwt(
                    v["token"], keys[v["key"]][v["key_form"]], algorithms=tuple(v["algorithms"])
                )
            )
        assert got == expected
    for d in j["jwks_decode"]:
        expected = {k: d[k] for k in ("result", "error") if k in d}
        with at(d["now"]):
            assert (
                outcome(lambda d=d: tokens.decode_jwt_jwks(d["token"], j["jwks"], algorithms=tuple(d["algorithms"])))
                == expected
            )


def test_secretbox() -> None:
    pytest.importorskip("cryptography")
    from generateapikey.crypto import DecryptionError, SecretBox

    sb = V["secretbox"]
    for e in sb["encrypt"]:
        with mock.patch("secrets.token_bytes", lambda n, e=e: bytes.fromhex(e["nonce_hex"])[:n]):
            assert SecretBox(e["key"]).encrypt(e["plaintext"], e["aad"]) == e["token"]
    for d in sb["decrypt"]:
        try:
            got: dict[str, Any] = {"result": SecretBox(d["key"], old_keys=d["old_keys"]).decrypt(d["token"], d["aad"])}
        except DecryptionError:
            got = {"error": "DecryptionError"}
        assert got == {k: d[k] for k in ("result", "error") if k in d}
    for k in sb["key_ids"]:
        assert SecretBox(k["key"])._current_id == k["key_id"]


def test_auth_core() -> None:
    a = V["auth"]
    for e in a["extract"]:
        assert integ.APIKeyAuth(lambda h: None, **e["options"]).extract(e["headers"], e["query"]) == e["key"]
    for w in a["well_formed"]:
        assert bool(integ.APIKeyAuth(lambda h: None, **w["options"])._well_formed(w["key"])) is w["well_formed"]
    for r in a["record_is_active"]:
        with at(r["now"]):
            assert integ.record_is_active(r["record"]) is r["active"]
    for p in a["path_excluded"]:
        assert integ.path_excluded(p["path"], p["exclude"]) is p["excluded"]
    for h in a["hints"]:
        assert integ._hint(h["key"]) == h["hint"]
    flow = a["authenticate"]
    for f in flow["flows"]:
        rehashed: list[Any] = []
        init: dict[str, Any] = {
            "pepper": flow["pepper"],
            "previous_peppers": flow["previous_peppers"],
            "require_checksum": flow["require_checksum"],
            "on_rehash": lambda r, h, rh=rehashed: rh.append([r["id"], h]),
        }
        for k in ("required_scopes", "prefix"):
            if k in f["options"]:
                init[k] = f["options"][k]
        call = {"scopes": f["options"]["scopes"]} if "scopes" in f["options"] else {}
        auth = integ.APIKeyAuth(flow["table"].get, **init)
        with at(V["now"]):
            try:
                got: dict[str, Any] = {"record_id": auth.authenticate(f["key"], **call)["id"]}
            except integ.AuthError as e:
                got = {"status": e.status, "detail": e.detail}
        assert got == {k: f[k] for k in ("record_id", "status", "detail") if k in f}
        assert rehashed == f["rehashed"]


def test_vectors_file_is_current() -> None:
    """Regenerating the vectors must not change the committed file."""
    pytest.importorskip("cryptography")
    path = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "gen_vectors.py"
    spec = importlib.util.spec_from_file_location("gen_vectors", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fresh = json.loads(mod.dumps(mod.build(V)))
    assert mod._strip_samples(fresh) == mod._strip_samples(V), "run `python scripts/gen_vectors.py`"
