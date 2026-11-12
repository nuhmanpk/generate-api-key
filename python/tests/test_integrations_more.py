"""Sanic, aiohttp, Quart and Falcon adapters against the real frameworks."""

import asyncio
import itertools

import pytest
from conftest import PEPPER

from generateapikey.integrations import APIKeyAuth
from generateapikey.mfa import AttemptLimiter

_names = itertools.count()


def _limited(store):
    return APIKeyAuth(store.lookup, pepper=PEPPER, limiter=AttemptLimiter(max_attempts=2, window=60))


# --------------------------------------------------------------------------- Sanic


def _sanic_app(store, auth):
    pytest.importorskip("sanic")
    pytest.importorskip("sanic_testing")
    from sanic import Sanic
    from sanic.response import json

    from generateapikey.integrations.sanic import require_api_key

    app = Sanic(f"gak_test_{next(_names)}")

    @app.get("/me")
    @require_api_key(auth)
    async def me(request):
        return json({"name": request.ctx.api_key["name"]})

    @app.get("/async-lookup")
    @require_api_key(APIKeyAuth(store.alookup, pepper=PEPPER))
    async def async_lookup(request):
        return json({"name": request.ctx.api_key["name"]})

    @app.get("/limited")
    @require_api_key(_limited(store))
    async def limited(request):
        return json({"ok": True})

    @app.get("/public")
    async def public(request):
        return json({"ok": True})

    return app


def test_sanic_flow(store, auth):
    app = _sanic_app(store, auth)
    key = store.add(name="sam")

    async def run():
        c = app.asgi_client
        _, r = await c.get("/me", headers={"X-API-Key": key})
        assert r.status == 200 and r.json == {"name": "sam"}
        _, r = await c.get("/me", headers={"Authorization": f"Bearer {key}"})
        assert r.status == 200
        _, r = await c.get("/async-lookup", headers={"X-API-Key": key})
        assert r.json == {"name": "sam"}
        _, r = await c.get("/me")
        assert r.status == 401 and r.headers["www-authenticate"].startswith("Bearer")
        assert r.json == {"detail": "Missing API key."}
        _, r = await c.get("/me", headers={"X-API-Key": "sk-wrong"})
        assert r.status == 401
        _, r = await c.get("/public")
        assert r.status == 200
        statuses = []
        for _ in range(3):
            _, r = await c.get("/limited", headers={"X-API-Key": "nope"})
            statuses.append(r.status)
        assert statuses == [401, 401, 429]
        assert "www-authenticate" not in r.headers

    asyncio.run(run())


# --------------------------------------------------------------------------- aiohttp


def test_aiohttp_middleware_and_decorator(store, auth):
    pytest.importorskip("aiohttp")
    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer

    from generateapikey.integrations.aiohttp import api_key_middleware, require_api_key

    async def me(request):
        return web.json_response({"name": request["api_key"]["name"]})

    async def health(request):
        return web.json_response({"ok": True})

    app = web.Application(middlewares=[api_key_middleware(auth, exclude=["/health"])])
    app.router.add_get("/me", me)
    app.router.add_get("/health", health)

    @require_api_key(APIKeyAuth(store.alookup, pepper=PEPPER))
    async def decorated(request):
        return web.json_response({"name": request["api_key"]["name"]})

    @require_api_key(_limited(store))
    async def limited(request):
        return web.json_response({"ok": True})

    app2 = web.Application()
    app2.router.add_get("/decorated", decorated)
    app2.router.add_get("/limited", limited)
    app2.router.add_get("/public", health)

    key = store.add(name="aio")

    async def run():
        async with TestClient(TestServer(app)) as c:
            r = await c.get("/me", headers={"X-API-Key": key})
            assert r.status == 200 and await r.json() == {"name": "aio"}
            r = await c.get("/me", headers={"Authorization": f"Bearer {key}"})
            assert r.status == 200
            r = await c.get("/me")
            assert r.status == 401 and r.headers["WWW-Authenticate"].startswith("Bearer")
            assert await r.json() == {"detail": "Missing API key."}
            r = await c.get("/me", headers={"X-API-Key": "sk-wrong"})
            assert r.status == 401
            assert (await c.get("/health")).status == 200

        async with TestClient(TestServer(app2)) as c:
            r = await c.get("/decorated", headers={"X-API-Key": key})
            assert r.status == 200 and await r.json() == {"name": "aio"}
            r = await c.get("/decorated", headers={"Authorization": f"Bearer {key}"})
            assert r.status == 200
            r = await c.get("/decorated")
            assert r.status == 401 and "WWW-Authenticate" in r.headers
            assert (await c.get("/public")).status == 200
            statuses = [(await c.get("/limited", headers={"X-API-Key": "nope"})).status for _ in range(3)]
            assert statuses == [401, 401, 429]

    asyncio.run(run())


# --------------------------------------------------------------------------- Quart


def test_quart_flow(store, auth):
    pytest.importorskip("quart")
    from quart import Quart, g

    from generateapikey.integrations.quart import require_api_key

    app = Quart(__name__)

    @app.get("/me")
    @require_api_key(auth)
    async def me():
        return {"name": g.api_key["name"]}

    @app.get("/async-lookup")
    @require_api_key(APIKeyAuth(store.alookup, pepper=PEPPER))
    async def async_lookup():
        return {"name": g.api_key["name"]}

    @app.get("/limited")
    @require_api_key(_limited(store))
    async def limited():
        return {"ok": True}

    @app.get("/public")
    async def public():
        return {"ok": True}

    key = store.add(name="quinn")

    async def run():
        c = app.test_client()
        r = await c.get("/me", headers={"X-API-Key": key})
        assert r.status_code == 200 and await r.get_json() == {"name": "quinn"}
        r = await c.get("/me", headers={"Authorization": f"Bearer {key}"})
        assert r.status_code == 200
        r = await c.get("/async-lookup", headers={"X-API-Key": key})
        assert await r.get_json() == {"name": "quinn"}
        r = await c.get("/me")
        assert r.status_code == 401 and r.headers["WWW-Authenticate"].startswith("Bearer")
        assert await r.get_json() == {"detail": "Missing API key."}
        r = await c.get("/me", headers={"X-API-Key": "sk-wrong"})
        assert r.status_code == 401
        assert (await c.get("/public")).status_code == 200
        statuses = [(await c.get("/limited", headers={"X-API-Key": "nope"})).status_code for _ in range(3)]
        assert statuses == [401, 401, 429]

    asyncio.run(run())


# --------------------------------------------------------------------------- Falcon


def _falcon_resources(asgi):
    class Me:
        if asgi:

            async def on_get(self, req, resp):
                resp.media = {"name": req.context.api_key["name"]}
        else:

            def on_get(self, req, resp):
                resp.media = {"name": req.context.api_key["name"]}

    class Public:
        if asgi:

            async def on_get(self, req, resp):
                resp.media = {"ok": True}
        else:

            def on_get(self, req, resp):
                resp.media = {"ok": True}

    return Me, Public


def _check_falcon(c, key, protected="/me", public="/health"):
    r = c.simulate_get(protected, headers={"X-API-Key": key})
    assert r.status_code == 200 and r.json == {"name": "fal"}
    assert c.simulate_get(protected, headers={"Authorization": f"Bearer {key}"}).status_code == 200
    r = c.simulate_get(protected)
    assert r.status_code == 401 and r.headers["WWW-Authenticate"].startswith("Bearer")
    assert r.json["description"] == "Missing API key."
    assert c.simulate_get(protected, headers={"X-API-Key": "sk-wrong"}).status_code == 401
    assert c.simulate_get(public).status_code == 200


@pytest.mark.parametrize("asgi", [False, True], ids=["wsgi", "asgi"])
def test_falcon_middleware(store, auth, asgi):
    falcon = pytest.importorskip("falcon")
    import falcon.asgi
    import falcon.testing

    from generateapikey.integrations.falcon import APIKeyMiddleware, AsyncAPIKeyMiddleware

    Me, Public = _falcon_resources(asgi)
    if asgi:
        mw = AsyncAPIKeyMiddleware(APIKeyAuth(store.alookup, pepper=PEPPER), exclude=["/health"])
        app = falcon.asgi.App(middleware=[mw])
    else:
        app = falcon.App(middleware=[APIKeyMiddleware(auth, exclude=["/health"])])
    app.add_route("/me", Me())
    app.add_route("/health", Public())
    c = falcon.testing.TestClient(app)
    _check_falcon(c, store.add(name="fal"))
    assert c.simulate_get("/nowhere").status_code == 404  # unrouted: no auth, plain 404


@pytest.mark.parametrize("asgi", [False, True], ids=["wsgi", "asgi"])
def test_falcon_hook(store, auth, asgi):
    falcon = pytest.importorskip("falcon")
    import falcon.asgi
    import falcon.testing

    from generateapikey.integrations.falcon import require_api_key

    Me, Public = _falcon_resources(asgi)
    hook_auth = APIKeyAuth(store.alookup, pepper=PEPPER) if asgi else auth
    Protected = falcon.before(require_api_key(hook_auth))(Me)
    # falcon.before() decorates a class in place, so wrap a fresh copy.
    Limited = falcon.before(require_api_key(_limited(store)))(_falcon_resources(asgi)[1])

    app = falcon.asgi.App() if asgi else falcon.App()
    app.add_route("/me", Protected())
    app.add_route("/public", Public())
    app.add_route("/limited", Limited())
    c = falcon.testing.TestClient(app)
    _check_falcon(c, store.add(name="fal"), public="/public")
    statuses = [c.simulate_get("/limited", headers={"X-API-Key": "nope"}).status_code for _ in range(3)]
    assert statuses == [401, 401, 429]


def test_falcon_query_param(store):
    falcon = pytest.importorskip("falcon")
    import falcon.testing

    from generateapikey.integrations.falcon import APIKeyMiddleware

    Me, _ = _falcon_resources(False)
    auth = APIKeyAuth(store.lookup, pepper=PEPPER, query_param="api_key")
    app = falcon.App(middleware=[APIKeyMiddleware(auth)])
    app.add_route("/me", Me())
    c = falcon.testing.TestClient(app)
    key = store.add(name="fal")
    assert c.simulate_get("/me", params={"api_key": key}).json == {"name": "fal"}
    assert c.simulate_get("/me", query_string=f"api_key={key}&api_key=x").status_code == 200
