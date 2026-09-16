import pathlib

import pytest

from bthj.hid_ble import count_keystrokes, parse_payload
from bthj.payloads import apply_vars, load_payload, missing_tokens, parse_vars


def test_apply_vars_replaces():
    out = apply_vars(
        "connect to http://{{ATTACKER_IP}}:{{PORT}}",
        {"ATTACKER_IP": "10.0.0.5", "PORT": "8000"},
    )
    assert out == "connect to http://10.0.0.5:8000"


def test_apply_vars_unknown_left():
    out = apply_vars("{{KNOWN}} {{UNKNOWN}}", {"KNOWN": "x"})
    assert out == "x {{UNKNOWN}}"
    assert missing_tokens(out) == ["UNKNOWN"]


def test_parse_vars():
    assert parse_vars(["A=1", "B=two"]) == {"A": "1", "B": "two"}
    with pytest.raises(ValueError):
        parse_vars(["no-equals"])


def test_load_payload_conflict():
    with pytest.raises(ValueError):
        load_payload(text="x", path="y.txt")


def test_load_payload_from_file(tmp_path):
    p = tmp_path / "p.txt"
    p.write_text("STRING {{NAME}}")
    assert load_payload(path=str(p), variables={"NAME": "alfred"}) == "STRING alfred"


def test_payload_pack_files_parse(tmp_path):
    payloads_dir = pathlib.Path(__file__).resolve().parent.parent / "payloads"
    for pf in sorted(payloads_dir.glob("*.txt")):
        text = pf.read_text()
        actions = parse_payload(text)
        assert count_keystrokes(actions) > 0, pf.name