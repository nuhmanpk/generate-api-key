"""RS/PS/ES 256-384-512 and EdDSA signing for ``encode_jwt`` / ``decode_jwt``.

Needs ``pip install "generateapikey[crypto]"``; imported lazily so the core stays dependency-free.
"""

from __future__ import annotations

from typing import Any, Union

__all__ = ["ASYM_ALGS", "sign", "verify"]

ASYM_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA")
_CURVES = {"ES256": ("secp256r1", 32), "ES384": ("secp384r1", 48), "ES512": ("secp521r1", 66)}


def _crypto() -> Any:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    except ImportError as exc:  # pragma: no cover
        raise ImportError('RS/ES JWT algorithms need: pip install "generateapikey[crypto]"') from exc
    return hashes, serialization, ec, padding, rsa, utils


def _hash(alg: str) -> Any:
    hashes = _crypto()[0]
    return {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}[alg[2:]]()


def _rsa_padding(alg: str) -> Any:
    padding = _crypto()[3]
    if alg.startswith("RS"):
        return padding.PKCS1v15()
    h = _hash(alg)
    return padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size)


def _pem(key: Union[str, bytes]) -> bytes:
    return key.encode() if isinstance(key, str) else key


def _check_curve(alg: str, key: Any) -> None:
    if alg in _CURVES and key.curve.name != _CURVES[alg][0]:
        raise ValueError(f"{alg} requires a {_CURVES[alg][0]} key.")


def sign(alg: str, private_key: Union[str, bytes], data: bytes) -> bytes:
    _, serialization, ec, _padding, rsa, utils = _crypto()
    key = serialization.load_pem_private_key(_pem(private_key), password=None)
    if alg == "EdDSA":
        from cryptography.hazmat.primitives.asymmetric import ed25519

        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise ValueError("EdDSA requires an Ed25519 private key.")
        return bytes(key.sign(data))
    if alg[:2] in ("RS", "PS"):
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError(f"{alg} requires an RSA private key.")
        if key.key_size < 2048:
            raise ValueError("RSA keys must be at least 2048 bits.")
        return bytes(key.sign(data, _rsa_padding(alg), _hash(alg)))
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError(f"{alg} requires an EC private key.")
    _check_curve(alg, key)
    r, s = utils.decode_dss_signature(key.sign(data, ec.ECDSA(_hash(alg))))
    size = _CURVES[alg][1]
    return int(r).to_bytes(size, "big") + int(s).to_bytes(size, "big")


def verify(alg: str, public_key: Union[str, bytes], data: bytes, signature: bytes) -> bool:
    """True if valid. Raises ValueError for an unusable key; never for a bad signature."""
    from cryptography.exceptions import InvalidSignature

    _, serialization, ec, _padding, rsa, utils = _crypto()
    pem = _pem(public_key)
    try:
        key = serialization.load_pem_public_key(pem)
    except ValueError:
        key = serialization.load_pem_private_key(pem, password=None).public_key()
    try:
        if alg == "EdDSA":
            from cryptography.hazmat.primitives.asymmetric import ed25519

            if not isinstance(key, ed25519.Ed25519PublicKey):
                raise ValueError("EdDSA requires an Ed25519 key.")
            key.verify(signature, data)
            return True
        if alg[:2] in ("RS", "PS"):
            if not isinstance(key, rsa.RSAPublicKey):
                raise ValueError(f"{alg} requires an RSA key.")
            key.verify(signature, data, _rsa_padding(alg), _hash(alg))
            return True
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise ValueError(f"{alg} requires an EC key.")
        _check_curve(alg, key)
        size = _CURVES[alg][1]
        if len(signature) != 2 * size:
            return False
        r, s = int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big")
        key.verify(utils.encode_dss_signature(r, s), data, ec.ECDSA(_hash(alg)))
        return True
    except InvalidSignature:
        return False


def _b64u(n: int) -> str:
    import base64

    raw = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _int(s: str) -> int:
    import base64

    return int.from_bytes(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)), "big")


def jwk_to_pem(jwk: dict[str, Any]) -> bytes:
    """Convert a public JWK (RSA, EC or OKP/Ed25519) to a PEM public key."""
    import base64

    _, serialization, ec, _padding, rsa, _utils = _crypto()
    kty = jwk.get("kty")
    if kty == "RSA":
        key: Any = rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
    elif kty == "EC":
        curve = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}[jwk["crv"]]()
        key = ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), curve).public_key()
    elif kty == "OKP" and jwk.get("crv") == "Ed25519":
        from cryptography.hazmat.primitives.asymmetric import ed25519

        raw = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
        key = ed25519.Ed25519PublicKey.from_public_bytes(raw)
    else:
        raise ValueError(f"unsupported JWK: kty={kty!r}")
    return bytes(key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
