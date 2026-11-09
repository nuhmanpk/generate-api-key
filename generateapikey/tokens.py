"""Signed, self-expiring tokens for magic links, email verification and password resets.

Format: ``<base64url(json payload)>.<base64url(HMAC-SHA256)>``. The payload is
readable (not encrypted), so don't put secrets in it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
import time
from typing import Any, Optional, Union

from .utils import safe_equals, subkey

__all__ = ["decode_jwt", "decode_jwt_jwks", "encode_jwt", "generate_signed_token", "verify_signed_token"]


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


MIN_SECRET_LENGTH = 16
_MAX_TOKEN_LENGTH = 8192


def _check_secret(secret: str) -> None:
    if not isinstance(secret, str) or len(secret) < MIN_SECRET_LENGTH:
        raise ValueError(
            f"secret must be a string of at least {MIN_SECRET_LENGTH} characters; "
            "a short secret can be brute-forced from any token."
        )


def _sign(secret: str, body: str, context: Optional[str] = None) -> str:
    # Per-purpose subkey: reusing one secret as a hash pepper can't forge tokens.
    msg = body.encode()
    if context is not None:
        # Bound tokens sign an extra, never-transmitted value (session id, device id...).
        msg += b"\x1f" + hashlib.sha256(context.encode("utf-8", "surrogatepass")).digest()
    return _b64e(hmac.new(subkey(secret, "token"), msg, hashlib.sha256).digest())


def generate_signed_token(
    secret: str,
    data: Optional[dict[str, Any]] = None,
    *,
    purpose: str = "default",
    expiry: Optional[float] = 15,
    context: Optional[str] = None,
) -> str:
    """Return a URL-safe signed token.

    Args:
        secret: Server secret, at least 16 characters (keep it out of the database).
        data: JSON-serialisable dict, e.g. ``{"uid": 42}``.
        purpose: Binds the token to one use (``"login"``, ``"reset"``...), so
            a token made for one flow is rejected by another.
        expiry: Lifetime in minutes (default 15). ``None`` = never expires.
        context: Optional value the token is *bound* to, such as the session
            id or a device cookie. It is signed but not stored in the token, so
            a leaked link only works where the same ``context`` is presented at
            verification. Don't bind to IP addresses; mobile IPs change.

    Each token carries a random ``jti`` id; store used ids if a token must
    work only once.
    """
    _check_secret(secret)
    if not isinstance(purpose, str):
        raise TypeError("purpose must be a string.")
    if expiry is not None and (not math.isfinite(expiry) or expiry <= 0):
        raise ValueError("expiry must be a positive, finite number of minutes.")
    payload: dict[str, Any] = {"p": purpose, "jti": secrets.token_urlsafe(12), "d": data or {}}
    if expiry is not None:
        payload["exp"] = int(time.time() + expiry * 60)
    body = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    if context is not None and not isinstance(context, str):
        raise TypeError("context must be a string.")
    return f"{body}.{_sign(secret, body, context)}"


def verify_signed_token(
    token: str,
    secret: str,
    *,
    purpose: str = "default",
    with_meta: bool = False,
    context: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Return the token's ``data`` if the signature, purpose and expiry check out, else None.

    With ``with_meta=True`` returns ``{"data", "jti", "exp"}`` instead.
    ``context`` must equal the value the token was generated with (if any).
    """
    _check_secret(secret)
    if not isinstance(token, str) or len(token) > _MAX_TOKEN_LENGTH or not token.isascii() or token.count(".") != 1:
        return None
    body, sig = token.split(".")
    if context is not None and not isinstance(context, str):
        return None
    if not safe_equals(_sign(secret, body, context), sig):
        return None
    try:
        payload = json.loads(_b64d(body))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict) or not safe_equals(str(payload.get("p", "")), purpose):
        return None
    exp = payload.get("exp")
    if exp is not None and (not isinstance(exp, (int, float)) or time.time() >= exp):
        return None
    if with_meta:
        return {"data": payload.get("d", {}), "jti": payload.get("jti"), "exp": exp}
    data: dict[str, Any] = payload.get("d", {})
    return data


_ASYM = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA")
_JWT_ALGS: dict[str, Any] = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def _jwt_sig(secret: str, signing_input: bytes, algorithm: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), signing_input, _JWT_ALGS[algorithm]).digest()


def encode_jwt(
    claims: dict[str, Any],
    secret: Union[str, bytes],
    *,
    algorithm: str = "HS256",
    expiry: Optional[float] = 15,
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
    headers: Optional[dict[str, Any]] = None,
) -> str:
    """Return a standard HMAC-signed JWT (RFC 7519), readable by any JWT library.

    ``expiry`` is minutes (``None`` = no ``exp``). ``iat``, ``exp``, ``iss`` and
    ``aud`` are added to ``claims`` unless already set.

    ``algorithm`` is HS256/384/512 (``secret`` is a shared secret of 16+ chars)
    or RS/PS/ES 256/384/512 or EdDSA (``secret`` is a PEM private key; needs
    ``pip install "generateapikey[crypto]"``). ``alg: none`` can neither be
    created nor accepted.
    """
    asym = algorithm in _ASYM
    if not asym:
        _check_secret(secret)  # type: ignore[arg-type]
    if algorithm not in _JWT_ALGS and not asym:
        raise ValueError(f"algorithm must be one of {sorted([*_JWT_ALGS, *_ASYM])}.")
    if expiry is not None and (not math.isfinite(expiry) or expiry <= 0):
        raise ValueError("expiry must be a positive, finite number of minutes.")
    now = int(time.time())
    payload = dict(claims)
    payload.setdefault("iat", now)
    if expiry is not None:
        payload.setdefault("exp", int(now + expiry * 60))
    if issuer is not None:
        payload.setdefault("iss", issuer)
    if audience is not None:
        payload.setdefault("aud", audience)
    header = {**(headers or {}), "alg": algorithm, "typ": "JWT"}

    def enc(obj: dict[str, Any]) -> str:
        return _b64e(json.dumps(obj, separators=(",", ":")).encode())

    signing_input = f"{enc(header)}.{enc(payload)}"
    if asym:
        from . import _jwt_asym

        sig = _jwt_asym.sign(algorithm, secret, signing_input.encode())
    else:
        sig = _jwt_sig(secret, signing_input.encode(), algorithm)  # type: ignore[arg-type]
    return f"{signing_input}.{_b64e(sig)}"


def decode_jwt(
    token: str,
    secret: Union[str, bytes],
    *,
    algorithms: tuple[str, ...] = ("HS256",),
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
    leeway: float = 0,
    require_exp: bool = True,
) -> Optional[dict[str, Any]]:
    """Return the claims if the JWT is valid, else None (never raises on bad tokens).

    The accepted ``algorithms`` are pinned by you, never taken from the token
    header, which blocks algorithm-confusion attacks. Checks signature, ``exp``,
    ``nbf``, and ``iss``/``aud`` when you pass them. ``require_exp`` rejects
    tokens without an ``exp``.

    For RS/ES algorithms pass the PEM public key as ``secret``. HS and RS/ES
    algorithms can't be mixed in one call: that is the classic algorithm-confusion
    attack (an HMAC token "signed" with your public key).
    """
    known = [*_JWT_ALGS, *_ASYM]
    if isinstance(algorithms, str) or not algorithms or not all(a in known for a in algorithms):
        raise ValueError(f"algorithms must be a tuple drawn from {sorted(known)}.")
    asym = algorithms[0] in _ASYM
    if any((a in _ASYM) != asym for a in algorithms):
        raise ValueError("Don't mix HS* and RS*/ES* algorithms in one decode_jwt call.")
    if not asym:
        _check_secret(secret)  # type: ignore[arg-type]
    if not isinstance(token, str) or len(token) > _MAX_TOKEN_LENGTH or not token.isascii() or token.count(".") != 2:
        return None
    head, body, sig = token.split(".")
    try:
        header = json.loads(_b64d(head))
        claims = json.loads(_b64d(body))
        given = _b64d(sig)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return None
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in algorithms:
        return None
    signing_input = f"{head}.{body}".encode()
    if asym:
        from . import _jwt_asym

        if not _jwt_asym.verify(alg, secret, signing_input, given):
            return None
    elif not hmac.compare_digest(_jwt_sig(secret, signing_input, alg), given):  # type: ignore[arg-type]
        return None
    now = time.time()
    exp, nbf = claims.get("exp"), claims.get("nbf")
    if exp is None:
        if require_exp:
            return None
    elif isinstance(exp, bool) or not isinstance(exp, (int, float)) or now >= exp + leeway:
        return None
    if nbf is not None and (isinstance(nbf, bool) or not isinstance(nbf, (int, float)) or now < nbf - leeway):
        return None
    if issuer is not None and claims.get("iss") != issuer:
        return None
    if audience is not None:
        aud = claims.get("aud")
        if audience != aud and not (isinstance(aud, list) and audience in aud):
            return None
    return claims


def decode_jwt_jwks(
    token: str,
    jwks: dict[str, Any],
    *,
    algorithms: tuple[str, ...] = ("RS256",),
    **options: Any,
) -> Optional[dict[str, Any]]:
    """Verify an asymmetric JWT against a JWKS document (``{"keys": [...]}``).

    The token's ``kid`` only *selects* one of the keys you already trust; the
    algorithm is still pinned by ``algorithms``. A token whose ``kid`` matches
    no key is rejected. Fetch and cache the JWKS yourself (it's just JSON from
    your identity provider's ``/.well-known/jwks.json``). Other ``options`` are
    passed to :func:`decode_jwt` (``issuer``, ``audience``, ``leeway``...).
    """
    from . import _jwt_asym

    if algorithms[0] not in _ASYM:
        raise ValueError("decode_jwt_jwks only supports RS/PS/ES/EdDSA algorithms.")
    if not isinstance(token, str) or token.count(".") != 2 or not token.isascii():
        return None
    try:
        header = json.loads(_b64d(token.split(".", maxsplit=1)[0]))
    except (ValueError, UnicodeDecodeError):
        return None
    kid = header.get("kid") if isinstance(header, dict) else None
    keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
    for jwk in keys:
        if isinstance(jwk, dict) and (kid is None or jwk.get("kid") == kid):
            try:
                pem = _jwt_asym.jwk_to_pem(jwk)
            except (ValueError, KeyError):
                continue
            claims = decode_jwt(token, pem, algorithms=algorithms, **options)
            if claims is not None:
                return claims
    return None
