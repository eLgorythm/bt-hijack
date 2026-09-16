import re

import pytest

import main as menu
from bthj import TOOL_NAME, __author__, __version__, cli


def test_version_flag_output(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert f"{TOOL_NAME} {__version__}" in out
    assert __author__ in out


def test_report_source_format():
    assert cli.REPORT_SOURCE == f"{TOOL_NAME}/{__version__} ({__author__})"
    assert "0xfndLabs" in cli.REPORT_SOURCE


def test_constants():
    assert TOOL_NAME == "bt-hijack"
    assert __version__ == "0.2.0"
    assert __author__ == "0xfndLabs"


def test_pyproject_version_sync():
    with open("pyproject.toml") as fh:
        text = fh.read()
    assert re.search(r"version\s*=\s*\"0\.2\.0\"", text)


def test_menu_banner_branded(capsys, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt="": "0")
    menu.loop()
    out = capsys.readouterr().out
    assert f"{TOOL_NAME} {__version__}" in out
    assert __author__ in out