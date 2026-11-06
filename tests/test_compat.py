"""The old ``generateApiKey`` import name must keep working after the rename."""

import asyncio
import importlib
import sys
import warnings


def _fresh_import(name):
    for mod in [m for m in sys.modules if m == "generateApiKey" or m.startswith("generateApiKey.")]:
        del sys.modules[mod]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        module = importlib.import_module(name)
    return module, caught


def test_old_name_aliases_new_package():
    import generateapikey

    old, caught = _fresh_import("generateApiKey")
    assert old is generateapikey
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)


def test_old_from_imports_work():
    _fresh_import("generateApiKey")
    from generateApiKey import generate_api_key, generateApiKey
    from generateApiKey.mfa import verify_totp  # noqa: F401
    from generateApiKey.utils import CHARSETS

    assert len(generate_api_key()) == 32
    assert "hex" in CHARSETS
    assert asyncio.run(generateApiKey("s", "seed")).__class__.__name__ == "ApiKey"


def test_submodules_are_the_same_objects():
    import generateapikey.utils

    _fresh_import("generateApiKey")
    import generateApiKey.utils

    assert generateApiKey.utils is generateapikey.utils


def test_version_matches_pyproject():
    import pathlib
    import re

    import generateapikey

    text = (pathlib.Path(__file__).parents[1] / "pyproject.toml").read_text()
    assert re.search(r'^version = "([^"]+)"', text, re.M).group(1) == generateapikey.__version__
