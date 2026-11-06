"""Keep the docs that AI agents read in sync with the real API."""

import importlib
import pathlib
import re

import generateapikey
from generateapikey.__main__ import main as cli

ROOT = pathlib.Path(__file__).parents[1]
GUIDE = ROOT / "generateapikey" / "llms-full.txt"
DOCS = [GUIDE, ROOT / "README.md", ROOT / "skills" / "generateapikey" / "SKILL.md"]

_IMPORT = re.compile(r"from (generateapikey(?:\.\w+)*) import \(?([\w\s,]+?)\)?\s*(?:#|$)", re.M)


def _imports(text):
    for module, names in _IMPORT.findall(text):
        for name in re.split(r"[\s,]+", names.strip()):
            if name:
                yield module, name


def test_every_documented_import_exists():
    missing = []
    for doc in DOCS:
        for module, name in _imports(doc.read_text()):
            try:
                mod = importlib.import_module(module)
            except ImportError:
                continue  # optional extra (qr, framework) not installed here
            if not hasattr(mod, name):
                missing.append(f"{doc.name}: {module}.{name}")
    assert not missing, missing


def test_every_public_name_is_in_llm_guide():
    text = GUIDE.read_text()
    skip = {"__version__", "CHECKSUM_LENGTH", "generateApiKey", "is_token_valid"}
    absent = [n for n in generateapikey.__all__ if n not in skip and n not in text]
    assert not absent, absent


def test_cli_prints_guide(capsys):
    assert cli(["--llms"]) == 0
    assert capsys.readouterr().out.startswith("# generateapikey")


def test_skill_frontmatter():
    text = (ROOT / "skills" / "generateapikey" / "SKILL.md").read_text()
    assert text.startswith("---\nname: generateapikey\ndescription: ")
