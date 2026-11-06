"""Keep examples/ working: run the FastAPI example end to end."""

import importlib
import pathlib
import sys
import urllib.parse as up

import pytest

ROOT = pathlib.Path(__file__).parents[1]


def test_fastapi_example_end_to_end(monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    crypto = pytest.importorskip("generateapikey.crypto", exc_type=ImportError)
    from fastapi.testclient import TestClient

    from generateapikey.mfa import totp

    monkeypatch.setenv("API_KEY_PEPPER", "example-pepper")
    monkeypatch.setenv("TOKEN_SECRET", "example-token-secret-123456")
    monkeypatch.setenv("ENCRYPTION_KEY", crypto.generate_encryption_key())
    monkeypatch.syspath_prepend(str(ROOT))
    sys.modules.pop("examples.fastapi_app", None)
    app = importlib.import_module("examples.fastapi_app").app

    c = TestClient(app)
    key = c.post("/keys").json()["api_key"]
    h = {"X-API-Key": key}
    assert c.get("/me", headers=h).json()["owner"] == "alice"
    assert c.get("/me").status_code == 401

    setup = c.post("/2fa/setup", headers=h).json()
    secret = up.parse_qs(up.urlparse(setup["otpauth_uri"]).query)["secret"][0]
    code = totp(secret)
    assert c.post("/2fa/verify", headers=h, json={"code": code}).json() == {"ok": True}
    assert c.post("/2fa/verify", headers=h, json={"code": code}).status_code == 401  # replay
    rc = setup["recovery_codes"][0]
    assert c.post("/2fa/verify", headers=h, json={"code": rc}).status_code == 200
    assert c.post("/2fa/verify", headers=h, json={"code": rc}).status_code == 401  # single use

    link = c.post("/magic-link", params={"email": "a@x.com", "session_id": "s1"}).json()["link"]
    tok = up.parse_qs(up.urlparse(link).query)["token"][0]
    assert c.get("/login", params={"token": tok, "session_id": "s1"}).status_code == 200
    assert c.get("/login", params={"token": tok, "session_id": "s2"}).status_code == 401


def test_benchmark_script_imports():
    spec = importlib.util.spec_from_file_location("bench", ROOT / "benchmarks" / "bench.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert callable(mod.main)
