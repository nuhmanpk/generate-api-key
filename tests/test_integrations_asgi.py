"""FastAPI, Starlette and Litestar adapters against the real frameworks."""

import pytest
from conftest import PEPPER

from generateapikey.integrations import APIKeyAuth
from generateapikey.mfa import AttemptLimiter

# --------------------------------------------------------------------------- FastAPI


@pytest.fixture
def fastapi_app(store, auth):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi import Depends, FastAPI, Request

    from generateapikey.integrations.fastapi import APIKeyDependency

    app = FastAPI()
    require_key = APIKeyDependency(auth)

    @app.get("/me")
    async def me(request: Request, key=Depends(require_key)):
        assert request.state.api_key is key
        return {"name": key["name"]}

    @app.get("/public")
    def public():
        return {"ok": True}

    async_store_auth = APIKeyAuth(store.alookup, pepper=PEPPER)

    @app.get("/async-lookup")
    async def async_lookup(key=Depends(APIKeyDependency(async_store_auth, scheme_name="Async"))):
        return {"name": key["name"]}

    return app


def test_fastapi_flow(fastapi_app, store):
    from fastapi.testclient import TestClient

    c = TestClient(fastapi_app)
    key = store.add(name="alice")
    assert c.get("/me", headers={"X-API-Key": key}).json() == {"name": "alice"}
    assert c.get("/me", headers={"Authorization": f"Bearer {key}"}).status_code == 200
    assert c.get("/async-lookup", headers={"X-API-Key": key}).json() == {"name": "alice"}
    r = c.get("/me")
    assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Bearer")
    assert c.get("/me", headers={"X-API-Key": "sk-wrong"}).status_code == 401
    assert c.get("/me", headers={"X-API-Key": "sk-é".encode("latin-1")}).status_code == 401
    assert c.get("/public").status_code == 200


def test_fastapi_openapi_has_security_schemes(fastapi_app):
    from fastapi.testclient import TestClient

    spec = TestClient(fastapi_app).get("/openapi.json").json()
    schemes = spec["components"]["securitySchemes"]
    assert schemes["APIKey"] == {"type": "apiKey", "in": "header", "name": "X-API-Key"}
    assert schemes["APIKeyBearer"]["scheme"] == "bearer"
    assert "security" in spec["paths"]["/me"]["get"]
    assert "security" not in spec["paths"]["/public"]["get"]
    params = [p["name"] for p in spec["paths"]["/me"]["get"].get("parameters", [])]
    assert "_header" not in params and "_bearer" not in params


def test_fastapi_rate_limit(store):
    pytest.importorskip("fastapi")
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from generateapikey.integrations.fastapi import APIKeyDependency

    auth = APIKeyAuth(store.lookup, pepper=PEPPER, limiter=AttemptLimiter(max_attempts=2, window=60))
    app = FastAPI()

    @app.get("/x")
    def x(key=Depends(APIKeyDependency(auth))):
        return {}

    c = TestClient(app)
    codes = [c.get("/x", headers={"X-API-Key": "sk-bad"}).status_code for _ in range(3)]
    assert codes == [401, 401, 429]


# --------------------------------------------------------------------------- Starlette


def test_starlette_backend(store, auth):
    pytest.importorskip("starlette")
    from starlette.applications import Starlette
    from starlette.authentication import requires
    from starlette.middleware import Middleware
    from starlette.middleware.authentication import AuthenticationMiddleware
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from generateapikey.integrations.starlette import APIKeyBackend, on_auth_error

    @requires("authenticated")
    async def me(request):
        return JSONResponse({"name": request.user.display_name, "scopes": request.auth.scopes})

    @requires("write")
    async def write(request):
        return JSONResponse({})

    async def public(request):
        return JSONResponse({"auth": request.user.is_authenticated})

    app = Starlette(
        routes=[Route("/me", me), Route("/write", write), Route("/public", public)],
        middleware=[Middleware(AuthenticationMiddleware, backend=APIKeyBackend(auth), on_error=on_auth_error)],
    )
    c = TestClient(app)
    key = store.add(name="bob", scopes=["read"])
    r = c.get("/me", headers={"X-API-Key": key})
    assert r.json() == {"name": "bob", "scopes": ["authenticated", "read"]}
    assert c.get("/write", headers={"X-API-Key": key}).status_code == 403
    assert c.get("/me").status_code == 403  # no key -> unauthenticated
    bad = c.get("/public", headers={"X-API-Key": "sk-bad"})
    assert bad.status_code == 401 and "www-authenticate" in bad.headers
    assert c.get("/public").json() == {"auth": False}


# --------------------------------------------------------------------------- Litestar


def test_litestar_middleware(store, auth):
    pytest.importorskip("litestar")
    from litestar import Litestar, Request, get
    from litestar.testing import TestClient

    from generateapikey.integrations.litestar import api_key_middleware

    @get("/me", sync_to_thread=False)
    def me(request: Request) -> dict:
        return {"name": request.auth["name"]}

    @get("/health", sync_to_thread=False)
    def health() -> dict:
        return {"ok": True}

    @get("/open", opt={"exclude_from_auth": True}, sync_to_thread=False)
    def open_route() -> dict:
        return {"ok": True}

    app = Litestar([me, health, open_route], middleware=[api_key_middleware(auth, exclude=["/health"])])
    key = store.add(name="carol")
    with TestClient(app) as c:
        assert c.get("/me", headers={"X-API-Key": key}).json() == {"name": "carol"}
        r = c.get("/me")
        assert r.status_code == 401 and "www-authenticate" in r.headers
        assert c.get("/me", headers={"X-API-Key": "sk-nope"}).status_code == 401
        assert c.get("/health").status_code == 200
        assert c.get("/open").status_code == 200
