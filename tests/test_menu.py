import pytest

import main as menu


class FakeInput:
    def __init__(self, values):
        self.values = list(values)

    def __call__(self, prompt=""):
        if not self.values:
            raise EOFError
        return self.values.pop(0)


@pytest.fixture
def fake_input(monkeypatch):
    def _install(values):
        monkeypatch.setattr("builtins.input", FakeInput(values))
        return FakeInput

    return _install


def test_scan_menu_builds_argv(fake_input):
    fake_input(["10", "n"])
    argv = menu._dispatch(1)
    assert argv == ["--backend", "bluez", "scan", "--timeout", "10"]


def test_probe_blank_addr_returns_empty(fake_input):
    fake_input([""])
    assert menu._dispatch(2) == []


def test_probe_menu_builds_argv(fake_input):
    fake_input(["AA:BB:CC:DD:EE:FF"])
    assert menu._dispatch(2) == [
        "--backend", "bluez", "probe", "AA:BB:CC:DD:EE:FF", "--timeout", "6",
    ]


def test_rfcomm_menu_builds_argv(fake_input):
    fake_input(["AA:BB:CC:DD:EE:FF", "n", "y"])
    argv = menu._dispatch(3)
    assert argv[:4] == ["--backend", "bluez", "rfcomm", "AA:BB:CC:DD:EE:FF"]
    assert "--skip-sdp" not in argv
    assert "--skip-hid-psms" in argv


def test_ble_hid_menu_with_vars(fake_input):
    fake_input(["payloads/shell.txt", "n", "1", "y", "ATTACKER_IP=10.0.0.5", "n"])
    argv = menu._dispatch(4)
    assert "--script-file" in argv
    assert "--var" in argv
    assert argv[argv.index("--var") + 1] == "ATTACKER_IP=10.0.0.5"


def test_clone_menu_with_loop(fake_input):
    fake_input(["AA:BB:CC:DD:EE:FF", "", "payloads/persist.txt", "y", "n"])
    argv = menu._dispatch(5)
    assert argv[3] == "AA:BB:CC:DD:EE:FF"
    assert "--loop" in argv


def test_spoof_noop(fake_input):
    fake_input(["", ""])
    assert menu._dispatch(6) == ["--backend", "bluez", "spoof"]


def test_fixed_subcommands():
    assert menu._dispatch(7) == ["--backend", "bluez", "self-test"]
    assert menu._dispatch(8) == ["--backend", "bluez", "doctor"]


def test_pass_through(fake_input):
    fake_input(["scan --timeout 5"])
    argv = menu._dispatch(9)
    assert argv == ["--backend", "bluez", "scan", "--timeout", "5"]


def test_pass_through_blank(fake_input):
    fake_input([""])
    assert menu._dispatch(9) is None


def test_audio_probe_menu(fake_input):
    fake_input(["00:31:A7:19:51:1E", "probe"])
    assert menu._dispatch(10) == [
        "--backend", "bluez", "audio", "00:31:A7:19:51:1E", "--probe",
    ]


def test_audio_blast_menu(fake_input):
    fake_input(["00:31:A7:19:51:1E", "blast", "5", "100"])
    assert menu._dispatch(10) == [
        "--backend", "bluez", "audio", "00:31:A7:19:51:1E",
        "--blast", "--seconds", "5", "--volume", "100",
    ]


def test_audio_blast_loop_menu(fake_input):
    fake_input(["00:31:A7:19:51:1E", "blast", "5", "100", "y", "30"])
    assert menu._dispatch(10) == [
        "--backend", "bluez", "audio", "00:31:A7:19:51:1E",
        "--blast", "--seconds", "5", "--volume", "100",
        "--loop", "--every", "30",
    ]


def test_audio_blank_addr(fake_input):
    fake_input([""])
    assert menu._dispatch(10) == []


def test_loop_invokes_engine(fake_input, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(menu, "cli_main", lambda argv: calls.append(argv) or 0)
    fake_input(["9", "scan --timeout 3", "", "0"])
    menu.loop()
    assert len(calls) == 1
    assert calls[0] == ["--backend", "bluez", "scan", "--timeout", "3"]