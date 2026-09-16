import bthj.impersonate as im
from bthj.hal import SimBackend
from bthj.hid_ble import count_keystrokes
from bthj.impersonate import probe_identity, run_attack, scan_for_identity


def test_probe_identity_from_scan():
    backend = SimBackend()
    dev = probe_identity(backend, "AA:BB:CC:DD:EE:FF")
    assert dev.address == "AA:BB:CC:DD:EE:FF"
    assert dev.name == "sim-keyboard"


def test_scan_for_identity_falls_back_to_named():
    backend = SimBackend()
    dev = scan_for_identity(backend)
    assert dev is not None
    assert dev.name == "sim-keyboard"


def test_run_attack_orchestrates(monkeypatch):
    calls: list[tuple] = []

    class FakeGadget:
        def __init__(self, name):
            self.name = name

        def run(self, actions, timeout=120.0, countdown=0.0, max_fires=1, on_state=None):
            calls.append(("run", self.name, count_keystrokes(actions)))
            return 4

    monkeypatch.setattr(im, "BluezHidGadget", FakeGadget)
    backend = SimBackend()
    states: list[str] = []
    sent = run_attack(
        backend,
        identity_name="CloneKB",
        identity_class=0x002540,
        script_text="WIN r\nENTER",
        countdown=1,
        on_state=states.append,
    )
    assert sent == 4
    assert calls[0][1] == "CloneKB"
    assert any("cloned identity as 'CloneKB'" in s for s in states)
    assert any("restored to 'bthj-sim'" in s for s in states)


def test_run_attack_empty_payload_aborts(monkeypatch):
    called = {"run": False}

    class FakeGadget:
        def __init__(self, name):
            pass

        def run(self, *a, **k):
            called["run"] = True
            return 0

    monkeypatch.setattr(im, "BluezHidGadget", FakeGadget)
    backend = SimBackend()
    states: list[str] = []
    sent = run_attack(backend, identity_name="X", script_text="", on_state=states.append)
    assert sent == 0
    assert called["run"] is False