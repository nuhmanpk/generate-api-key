"""Complete FastAPI example: API keys + TOTP 2FA + recovery codes + magic links.

    pip install "generateapikey[fastapi,crypto]" uvicorn
    API_KEY_PEPPER=... ENCRYPTION_KEY=... TOKEN_SECRET=... uvicorn examples.fastapi_app:app --reload

Storage is an in-memory dict to keep the example short; use your database.
Generate the secrets with:  python -c "import secrets; print(secrets.token_urlsafe(32))"
and ENCRYPTION_KEY with:    python -c "from generateapikey.crypto import generate_encryption_key as g; print(g())"
"""

from __future__ import annotations

import os
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from generateapikey import (
    AttemptLimiter,
    generate_recovery_codes,
    generate_signed_token,
    generate_totp_secret,
    hash_recovery_code,
    totp_uri,
    verify_recovery_code,
    verify_signed_token,
)
from generateapikey.crypto import SecretBox
from generateapikey.integrations import APIKeyAuth, issue_api_key
from generateapikey.integrations.fastapi import APIKeyDependency
from generateapikey.mfa import find_totp_step

PEPPER = os.environ["API_KEY_PEPPER"]
TOKEN_SECRET = os.environ["TOKEN_SECRET"]
box = SecretBox(os.environ["ENCRYPTION_KEY"])

# --- "database" -------------------------------------------------------------
KEYS: dict[str, dict[str, Any]] = {}  # hashed key -> record
USERS: dict[str, dict[str, Any]] = {"alice": {"totp": None, "last_step": None, "recovery": []}}

auth = APIKeyAuth(lookup=KEYS.get, pepper=PEPPER, prefix="sk", require_checksum=True)
require_key = APIKeyDependency(auth)
mfa_limiter = AttemptLimiter(max_attempts=5, window=15 * 60)

app = FastAPI(title="generateapikey example")


# --- API keys ---------------------------------------------------------------
@app.post("/keys")
def create_key(owner: str = "alice") -> dict[str, str]:
    issued = issue_api_key(prefix="sk", pepper=PEPPER)
    KEYS[issued.hashed] = {"owner": owner, "hint": issued.hint, "revoked": False}
    return {"api_key": issued.key, "hint": issued.hint}  # shown once


@app.get("/me")
def me(key: dict[str, Any] = Depends(require_key)) -> dict[str, Any]:
    return {"owner": key["owner"], "key": key["hint"]}


# --- TOTP 2FA ---------------------------------------------------------------
@app.post("/2fa/setup")
def setup_2fa(key: dict[str, Any] = Depends(require_key)) -> dict[str, Any]:
    user = USERS[key["owner"]]
    secret = generate_totp_secret()
    user["totp"] = box.encrypt(secret, aad=key["owner"])  # encrypted at rest, bound to user
    codes = generate_recovery_codes()
    user["recovery"] = [hash_recovery_code(c, PEPPER) for c in codes]
    return {"otpauth_uri": totp_uri(secret, key["owner"], "ExampleApp"), "recovery_codes": codes}


class Code(BaseModel):
    code: str


@app.post("/2fa/verify")
def verify_2fa(body: Code, key: dict[str, Any] = Depends(require_key)) -> dict[str, bool]:
    owner = key["owner"]
    user = USERS[owner]
    if not mfa_limiter.hit(owner):
        raise HTTPException(429, "Too many attempts")
    secret = box.decrypt(user["totp"], aad=owner)
    step = find_totp_step(secret, body.code, last_used_step=user["last_step"])
    if step is not None:
        user["last_step"] = step
        mfa_limiter.reset(owner)
        return {"ok": True}
    used = verify_recovery_code(body.code, user["recovery"], PEPPER)
    if used:
        user["recovery"].remove(used)
        mfa_limiter.reset(owner)
        return {"ok": True}
    raise HTTPException(401, "Invalid code")


# --- Magic links --------------------------------------------------------------
@app.post("/magic-link")
def magic_link(email: str, session_id: str) -> dict[str, str]:
    token = generate_signed_token(TOKEN_SECRET, {"email": email}, purpose="login", expiry=15, context=session_id)
    return {"link": f"https://example.com/login?token={token}"}  # email this


@app.get("/login")
def login(token: str, session_id: str) -> dict[str, Optional[str]]:
    data = verify_signed_token(token, TOKEN_SECRET, purpose="login", context=session_id)
    if data is None:
        raise HTTPException(401, "Invalid or expired link")
    return {"logged_in_as": data["email"]}
