import json

from bthj.bluez_cli import parse_devices, parse_scan_lines
from bthj.hid_ble import (
    MOD_ALT,
    MOD_CTRL,
    MOD_GUI,
    MOD_SHIFT,
    _usage,
    count_keystrokes,
    estimate_duration,
    parse_payload,
    script_reports,
)
from bthj.models import Device


def test_parse_scan_nonew_lines():
    text = (
        "[NEW] Device AA:BB:CC:DD:EE:FF Logitech MX Keys\n"
        "[CHG] Device AA:BB:CC:DD:EE:FF RSSI: -42\n"
        "[NEW] Device 11:22:33:44:55:66\n"
        "[CHG] Device 11:22:33:44:55:66 RSSI: -70\n"
    )
    devices = parse_scan_lines(text)
    assert len(devices) == 2
    d = devices[0]
    assert d.address == "AA:BB:CC:DD:EE:FF"
    assert d.name == "Logitech MX Keys"
    assert d.rssi == -42
    assert devices[1].name is None
    assert devices[1].rssi == -70


def test_parse_info_blocks():
    text = (
        "Device AA:BB:CC:DD:EE:FF [public]\n"
        "\tName: Galaxy S23\n"
        "\tAlias: Galaxy S23\n"
        "\tClass: 0x000205\n"
        "\tPaired: yes\n"
        "\tUUID: Serial Port (00001101-0000-1000-8000-00805f9b34fb)\n"
        "\n"
        "Device FF:EE:DD:CC:BB:AA [random]\n"
        "\tName: JBL Flip 6\n"
    )
    devices = parse_devices(text)
    assert len(devices) == 2
    assert devices[0].address == "AA:BB:CC:DD:EE:FF"
    assert devices[0].paired is True
    assert "00001101-0000-1000-8000-00805f9b34fb" in devices[0].services
    assert devices[1].name == "JBL Flip 6"


def test_parse_scan_ansi():
    text = (
        "\x1b[0;93m[NEW]\x1b[0m Device AA:BB:CC:DD:EE:FF Logitech MX Keys\n"
        "\x1b[0;93m[CHG]\x1b[0m Device AA:BB:CC:DD:EE:FF RSSI: -42\n"
    )
    devices = parse_scan_lines(text)
    assert len(devices) == 1
    assert devices[0].name == "Logitech MX Keys"
    assert devices[0].rssi == -42


def test_usage_shift():
    base, mod = _usage("A")
    assert base == 0x04
    assert mod == MOD_SHIFT
    assert _usage("\n")[0] == 0x28


def test_script_report_count():
    reports = script_reports("Hi")
    assert len(reports) == 4
    assert len(script_reports("Hi\nx")) == 6


def test_payload_parse():
    text = (
        "REM a comment line\n"
        "STRING Hi\n"
        "DELAY 500\n"
        "ENTER\n"
        "WIN r\n"
        "CTRL ALT DELETE\n"
    )
    actions = parse_payload(text)
    assert count_keystrokes(actions) == 5
    reports = [r for r, _ in actions if r is not None]
    assert reports[0] == bytes([MOD_SHIFT, 0, 0x0B, 0, 0, 0, 0, 0])
    assert reports[-2] == bytes([MOD_CTRL | MOD_ALT, 0, 0x4C, 0, 0, 0, 0, 0])
    assert any(r is None for r, _ in actions)
    assert estimate_duration(actions) >= 0.5


def test_payload_plain_line_is_string():
    actions = parse_payload("ls -la\n")
    assert count_keystrokes(actions) == len("ls -la")
    first = next(r for r, _ in actions if r is not None)
    assert first == bytes([0, 0, 0x0F, 0, 0, 0, 0, 0])


def test_payload_win_combo():
    actions = parse_payload("GUI r")
    report = next(r for r, _ in actions if r is not None)
    assert report[0] == MOD_GUI
    assert report[2] == 0x15


def test_report_schema():
    from bthj.models import Report

    r = Report(source="t", cmd="scan")
    r.devices = [Device(address="AA:BB:CC:DD:EE:FF").to_dict()]
    as_json = json.loads(json.dumps(r.to_dict()))
    assert as_json["cmd"] == "scan"
    assert as_json["devices"][0]["address"] == "AA:BB:CC:DD:EE:FF"