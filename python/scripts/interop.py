"""Live cross-language interop (CI): Python makes values with fresh randomness and
fresh keys, JavaScript verifies them, and the other way round.

    python scripts/interop.py make   > /tmp/py.json
    python scripts/interop.py verify /tmp/js.json

Private keys exist only in memory; the JSON carries public keys and tokens.
Needs the ``crypto`` extra.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

import generateapikey as g
from generateapikey import mfa, tokens, utils
from generateapikey.crypto import SecretBox, generate_encryption_key

PEPPER = "interop-pepper"
SECRET = "interop-signing-secret-0123456789"
ALGS = {"RS256": "rsa", "PS384": "rsa", "ES256": "p256", "ES384": "p384", "ES512": "p521", "EdDSA": "ed25519"}


def _new(kind: str) -> Any:
    return {
        "rsa": lambda: rsa.generate_private_key(65537, 2048),
        "p256": lambda: ec.generate_private_key(ec.SECP256R1()),
        "p384": lambda: ec.generate_private_key(ec.SECP384R1()),
        "p521": lambda: ec.generate_private_key(ec.SECP521R1()),
        "ed25519": ed25519.Ed25519PrivateKey.generate,
    }[kind]()


def make() -> dict[str, Any]:
    key = str(g.generate_api_key(prefix="sk", checksum=True))
    totp_secret = mfa.generate_totp_secret()
    at = int(time.time())
    recovery = mfa.generate_recovery_codes(1)[0]
    otp = mfa.generate_otp()
    enc_key = generate_encryption_key()
    jwt: dict[str, Any] = {}
    keys: dict[str, Any] = {}
    for alg, kind in ALGS.items():
        k = keys.setdefault(kind, _new(kind))
        priv = k.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        pub = (
            k.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )
        jwt[alg] = {"token": tokens.encode_jwt({"sub": "py", "n": 1}, priv, algorithm=alg), "public": pub}
    return {
        "from": "py",
        "key": key,
        "hash": utils.hash_api_key(key),
        "hmac": utils.hash_api_key(key, PEPPER),
        "derived": {
            "secret": "derive-secret",
            "seed": "user-42",
            "include": "ctx",
            "key": str(g.generate_api_key("derive-secret", "user-42", include="ctx", prefix="dk", checksum=True)),
        },
        "code": {"code": "123456", "hashed": utils.hash_code("123456", PEPPER)},
        "recovery": {"code": recovery, "hashed": mfa.hash_recovery_code(recovery)},
        "otp": {"code": str(otp), "hashed": mfa.hash_otp(otp, PEPPER)},
        "totp": {
            "secret": totp_secret,
            "at": at,
            "code": mfa.totp(totp_secret, at),
            "sha512": mfa.totp(totp_secret, at, algorithm="sha512", digits=8),
        },
        "signed": tokens.generate_signed_token(
            SECRET, {"uid": 42, "name": "José ✓"}, purpose="login", context="session-1"
        ),
        "hs256": tokens.encode_jwt(
            {"sub": "py", "roles": ["a"]}, SECRET, algorithm="HS512", issuer="py", audience="js"
        ),
        "jwt": jwt,
        "secretbox": {"key": enc_key, "token": SecretBox(enc_key).encrypt("JBSWY3DPEHPK3PXP ✓", aad="user-42")},
    }


def verify(d: dict[str, Any]) -> int:
    other = "py" if d["from"] == "js" else "js"
    signed = tokens.verify_signed_token(d["signed"], SECRET, purpose="login", context="session-1") or {}
    hs = tokens.decode_jwt(d["hs256"], SECRET, algorithms=("HS512",), issuer=d["from"], audience=other) or {}
    results = {
        "hash": utils.verify_api_key(d["key"], d["hash"]),
        "hmac": utils.verify_api_key(d["key"], d["hmac"], PEPPER),
        "checksum": utils.verify_checksum(d["key"]),
        "derived": str(
            g.generate_api_key(
                d["derived"]["secret"],
                d["derived"]["seed"],
                include=d["derived"]["include"],
                prefix="dk",
                checksum=True,
            )
        )
        == d["derived"]["key"],
        "pbkdf2": utils.verify_code(d["code"]["code"], d["code"]["hashed"], PEPPER),
        "recovery": mfa.verify_recovery_code(d["recovery"]["code"].lower(), [d["recovery"]["hashed"]])
        == d["recovery"]["hashed"],
        "otp": mfa.verify_otp(d["otp"]["code"], d["otp"]["hashed"], pepper=PEPPER),
        "totp": mfa.totp(d["totp"]["secret"], d["totp"]["at"]) == d["totp"]["code"]
        and mfa.totp(d["totp"]["secret"], d["totp"]["at"], algorithm="sha512", digits=8) == d["totp"]["sha512"],
        "signed token": signed.get("uid") == 42 and signed.get("name") == "José ✓",
        "jwt HS512": hs.get("sub") == d["from"],
        "secretbox": SecretBox(d["secretbox"]["key"]).decrypt(d["secretbox"]["token"], aad="user-42")
        == "JBSWY3DPEHPK3PXP ✓",
    }
    for alg, j in d["jwt"].items():
        results[f"jwt {alg}"] = (tokens.decode_jwt(j["token"], j["public"], algorithms=(alg,)) or {}).get("sub") == d[
            "from"
        ]
    failed = [k for k, ok in results.items() if not ok]
    print(f"Python verified {len(results) - len(failed)}/{len(results)} values made by {d['from']}")
    if failed:
        print("FAILED:", ", ".join(failed), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["make"]:
        print(json.dumps(make(), indent=1))
        sys.exit(0)
    if sys.argv[1:2] == ["verify"] and len(sys.argv) == 3:
        sys.exit(verify(json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))))
    print(__doc__, file=sys.stderr)
    sys.exit(2)
