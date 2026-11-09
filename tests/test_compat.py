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
    # importlib avoids import-sorting differences between case-sensitive and
    # case-insensitive filesystems (generateApiKey vs generateapikey).
    old = importlib.import_module("generateApiKey")
    old_mfa = importlib.import_module("generateApiKey.mfa")
    old_utils = importlib.import_module("generateApiKey.utils")

    assert callable(old_mfa.verify_totp)
    assert len(old.generate_api_key()) == 32
    assert "hex" in old_utils.CHARSETS
    assert asyncio.run(old.generateApiKey("s", "seed")).__class__.__name__ == "ApiKey"


def test_submodules_are_the_same_objects():
    import generateapikey.utils

    _fresh_import("generateApiKey")
    import generateApiKey.utils

    assert generateApiKey.utils is generateapikey.utils


def test_version_matches_pyproject():
    import pathlib
    import re

    import generateapikey

    text = (pathlib.Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^version = "([^"]+)"', text, re.M).group(1) == generateapikey.__version__
