import asyncio
import os
import sys
import tempfile

import pytest

from generateapikey.integrations import APIKeyAuth, issue_api_key

PEPPER = "test-pepper-value"


class Store:
    """In-memory key table: hashed -> record dict."""

    def __init__(self):
        self.rows = {}

    def add(self, **fields):
        issued = issue_api_key(prefix="sk", pepper=PEPPER)
        self.rows[issued.hashed] = {"name": "test", "hint": issued.hint, **fields}
        return str(issued.key)

    def lookup(self, hashed):
        return self.rows.get(hashed)

    async def alookup(self, hashed):
        return self.rows.get(hashed)


@pytest.fixture(autouse=True)
def _ensure_event_loop():
    """Python < 3.12: asyncio.run() leaves no current loop, but some framework test
    clients (Falcon ASGI, fakeredis async) call get_event_loop() at setup."""
    if sys.version_info < (3, 12):
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())
    yield


@pytest.fixture
def store():
    return Store()


@pytest.fixture
def auth(store):
    return APIKeyAuth(lookup=store.lookup, pepper=PEPPER, prefix="sk", require_checksum=True)


def _configure_django():
    """One shared Django config for every test module (docs test imports the adapter too)."""
    try:
        import django
        from django.conf import settings
    except ImportError:
        return
    if settings.configured:
        return
    settings.configure(
        DEBUG=False,
        SECRET_KEY="test-only",
        # File DB, not :memory: - async views run ORM calls in a worker thread,
        # and each thread would get its own empty in-memory database.
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": os.path.join(tempfile.mkdtemp(), "test.sqlite3"),
            }
        },
        INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth"],
        USE_TZ=True,
        ALLOWED_HOSTS=["*"],
        GENERATEAPIKEY_AUTH="test_integrations_django.AUTH",
        REST_FRAMEWORK={"UNAUTHENTICATED_USER": None},
    )
    django.setup()


_configure_django()
