import pytest

flask = pytest.importorskip("flask")

from flask import Flask, g

from generateapikey.integrations.flask import FlaskAPIKey, require_api_key


@pytest.fixture
def client(store, auth):
    app = Flask(__name__)
    ext = FlaskAPIKey(app, auth)

    @app.get("/me")
    @require_api_key(auth)
    def me():
        return {"name": g.api_key["name"]}

    @app.get("/ext")
    @ext.required
    def via_ext():
        return {"ok": True}

    @app.get("/async")
    @require_api_key(auth)
    async def async_view():
        return {"name": g.api_key["name"]}

    return app.test_client()


def test_flask_flow(client, store):
    key = store.add(name="dave")
    assert client.get("/me", headers={"X-API-Key": key}).json == {"name": "dave"}
    assert client.get("/me", headers={"Authorization": f"Bearer {key}"}).status_code == 200
    assert client.get("/ext", headers={"X-API-Key": key}).status_code == 200
    r = client.get("/me")
    assert r.status_code == 401 and r.headers["WWW-Authenticate"].startswith("Bearer")
    assert client.get("/ext", headers={"X-API-Key": "sk-bad"}).status_code == 401


def test_flask_async_view(client, store):
    pytest.importorskip("asgiref")
    key = store.add(name="erin")
    assert client.get("/async", headers={"X-API-Key": key}).json == {"name": "erin"}


def test_flask_ext_requires_auth():
    with pytest.raises(ValueError):
        FlaskAPIKey(Flask(__name__))
