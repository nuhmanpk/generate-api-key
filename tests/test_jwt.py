from __future__ import annotations

import base64
import json
import time

import pytest

from generateapikey import decode_jwt, encode_jwt

SECRET = "k" * 32


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


def test_roundtrip_and_interop_with_pyjwt():
    tok = encode_jwt({"uid": 7}, SECRET, issuer="me", audience="api")
    claims = decode_jwt(tok, SECRET, issuer="me", audience="api")
    assert claims and claims["uid"] == 7 and "exp" in claims and "iat" in claims
    pyjwt = pytest.importorskip("jwt")
    assert pyjwt.decode(tok, SECRET, algorithms=["HS256"], audience="api", issuer="me")["uid"] == 7
    foreign = pyjwt.encode({"x": 1, "exp": int(time.time()) + 60}, SECRET, algorithm="HS256")
    assert decode_jwt(foreign, SECRET)["x"] == 1


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_algorithms(alg):
    assert decode_jwt(encode_jwt({"a": 1}, SECRET, algorithm=alg), SECRET, algorithms=(alg,))["a"] == 1


def test_rejects_tampering_wrong_secret_and_alg_confusion():
    tok = encode_jwt({"a": 1}, SECRET)
    h, b, s = tok.split(".")
    assert decode_jwt(tok, "z" * 32) is None
    assert decode_jwt(f"{h}.{_b64({'a': 2, 'exp': 9999999999})}.{s}", SECRET) is None
    assert decode_jwt(encode_jwt({"a": 1}, SECRET, algorithm="HS512"), SECRET) is None  # not in allowed algs
    none_tok = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'a': 1, 'exp': 9999999999})}."
    assert decode_jwt(none_tok, SECRET) is None
    assert decode_jwt(none_tok, SECRET, require_exp=False) is None


def test_time_claims_and_audience():
    assert decode_jwt(encode_jwt({"a": 1, "exp": int(time.time()) - 5}, SECRET), SECRET) is None
    assert decode_jwt(encode_jwt({"a": 1, "exp": int(time.time()) - 5}, SECRET), SECRET, leeway=10) is not None
    assert decode_jwt(encode_jwt({"nbf": int(time.time()) + 100}, SECRET), SECRET) is None
    assert decode_jwt(encode_jwt({}, SECRET, expiry=None), SECRET) is None
    assert decode_jwt(encode_jwt({}, SECRET, expiry=None), SECRET, require_exp=False) is not None
    assert decode_jwt(encode_jwt({}, SECRET, audience="a"), SECRET, audience="b") is None
    assert decode_jwt(encode_jwt({"aud": ["a", "b"]}, SECRET), SECRET, audience="b") is not None
    assert decode_jwt(encode_jwt({}, SECRET, issuer="x"), SECRET, issuer="y") is None


@pytest.mark.parametrize("bad", ["", "a.b", "a.b.c", "x" * 9000, "é.é.é", None, 5, "..", "e30.e30.e30"])
def test_garbage_never_raises(bad):
    assert decode_jwt(bad, SECRET) is None


def test_bad_arguments():
    with pytest.raises(ValueError):
        encode_jwt({}, "short")
    with pytest.raises(ValueError):
        encode_jwt({}, SECRET, algorithm="none")
    with pytest.raises(ValueError):
        decode_jwt("a.b.c", SECRET, algorithms=("none",))
    with pytest.raises(ValueError):
        encode_jwt({}, SECRET, expiry=float("nan"))


# ---- RS256 / ES256 (optional `crypto` extra) ----
def _pems(kind: str):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    priv = (
        rsa.generate_private_key(65537, 2048)
        if kind == "rsa"
        else ec.generate_private_key({"ES256": ec.SECP256R1(), "ES384": ec.SECP384R1(), "ES512": ec.SECP521R1()}[kind])
    )
    private = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    public = (
        priv.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return private, public


@pytest.mark.parametrize(
    ("kind", "alg"),
    [("rsa", "RS256"), ("rsa", "RS384"), ("rsa", "RS512"), ("ES256", "ES256"), ("ES384", "ES384"), ("ES512", "ES512")],
)
def test_asymmetric_roundtrip_and_pyjwt_interop(kind, alg):
    private, public = _pems(kind)
    tok = encode_jwt({"uid": 1}, private, algorithm=alg)
    assert decode_jwt(tok, public, algorithms=(alg,))["uid"] == 1
    assert decode_jwt(tok, public, algorithms=("RS256" if alg != "RS256" else "ES256",)) is None
    pyjwt = pytest.importorskip("jwt")
    assert pyjwt.decode(tok, public, algorithms=[alg])["uid"] == 1  # we sign what PyJWT accepts
    theirs = pyjwt.encode({"uid": 2, "exp": int(time.time()) + 60}, private, algorithm=alg)
    assert decode_jwt(theirs, public, algorithms=(alg,))["uid"] == 2  # and accept what PyJWT signs


def test_asymmetric_rejects_forgery_and_confusion():
    private, public = _pems("rsa")
    other_private, other_public = _pems("rsa")
    tok = encode_jwt({"uid": 1}, private, algorithm="RS256")
    assert decode_jwt(tok, other_public, algorithms=("RS256",)) is None
    h, b, s = tok.split(".")
    assert decode_jwt(f"{h}.{_b64({'uid': 9, 'exp': 9999999999})}.{s}", public, algorithms=("RS256",)) is None
    # algorithm confusion: HMAC token keyed with the PEM public key must not verify
    import hashlib
    import hmac

    forged_head, forged_body = _b64({"alg": "HS256", "typ": "JWT"}), _b64({"uid": 1, "exp": 9999999999})
    mac = hmac.new(public.encode(), f"{forged_head}.{forged_body}".encode(), hashlib.sha256).digest()
    forged = f"{forged_head}.{forged_body}.{base64.urlsafe_b64encode(mac).decode().rstrip('=')}"
    assert decode_jwt(forged, public, algorithms=("RS256",)) is None
    with pytest.raises(ValueError):
        decode_jwt(forged, public, algorithms=("HS256", "RS256"))
    with pytest.raises(ValueError):
        encode_jwt({}, public, algorithm="ES256")  # wrong key type / not a private key
    assert decode_jwt(tok, public, algorithms=("RS256",), issuer="x") is None


def test_asymmetric_wrong_curve_rejected():
    private, _ = _pems("ES384")
    with pytest.raises(ValueError):
        encode_jwt({}, private, algorithm="ES256")


# ---- EdDSA, PS256, JWKS ----
def _ed():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    return (
        priv.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
        priv.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
    )


def test_eddsa_roundtrip_and_pyjwt_interop():
    private, public = _ed()
    tok = encode_jwt({"uid": 1}, private, algorithm="EdDSA")
    assert decode_jwt(tok, public, algorithms=("EdDSA",))["uid"] == 1
    other_private, other_public = _ed()
    assert decode_jwt(tok, other_public, algorithms=("EdDSA",)) is None
    pyjwt = pytest.importorskip("jwt")
    assert pyjwt.decode(tok, public, algorithms=["EdDSA"])["uid"] == 1
    theirs = pyjwt.encode({"uid": 2, "exp": int(time.time()) + 60}, private, algorithm="EdDSA")
    assert decode_jwt(theirs, public, algorithms=("EdDSA",))["uid"] == 2


@pytest.mark.parametrize("alg", ["PS256", "PS384", "PS512"])
def test_pss_roundtrip_and_pyjwt_interop(alg):
    private, public = _pems("rsa")
    tok = encode_jwt({"uid": 1}, private, algorithm=alg)
    assert decode_jwt(tok, public, algorithms=(alg,))["uid"] == 1
    assert decode_jwt(tok, public, algorithms=("RS256",)) is None
    pyjwt = pytest.importorskip("jwt")
    assert pyjwt.decode(tok, public, algorithms=[alg])["uid"] == 1
    theirs = pyjwt.encode({"uid": 2, "exp": int(time.time()) + 60}, private, algorithm=alg)
    assert decode_jwt(theirs, public, algorithms=(alg,))["uid"] == 2


@pytest.mark.parametrize(("kind", "alg"), [("rsa", "RS256"), ("ES256", "ES256"), ("ES384", "ES384")])
def test_jwks_selects_key_by_kid(kind, alg):
    pytest.importorskip("cryptography")
    jwt_mod = pytest.importorskip("jwt")
    from cryptography.hazmat.primitives import serialization

    from generateapikey import decode_jwt_jwks

    private, public = _pems(kind)
    other_private, other_public = _pems(kind)

    def jwk(pem: str, kid: str) -> dict:
        d = json.loads(
            jwt_mod.algorithms.get_default_algorithms()[alg].to_jwk(serialization.load_pem_public_key(pem.encode()))
        )
        d["kid"] = kid
        return d

    jwks = {"keys": [jwk(other_public, "old"), jwk(public, "new")]}
    tok = encode_jwt({"uid": 1}, private, algorithm=alg, headers={"kid": "new"})
    assert decode_jwt_jwks(tok, jwks, algorithms=(alg,))["uid"] == 1
    assert (
        decode_jwt_jwks(encode_jwt({}, private, algorithm=alg, headers={"kid": "nope"}), jwks, algorithms=(alg,))
        is None
    )
    assert decode_jwt_jwks(tok, {"keys": [jwk(other_public, "new")]}, algorithms=(alg,)) is None
    assert decode_jwt_jwks("garbage", jwks, algorithms=(alg,)) is None
    with pytest.raises(ValueError):
        decode_jwt_jwks(tok, jwks, algorithms=("HS256",))
