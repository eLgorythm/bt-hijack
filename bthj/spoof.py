from __future__ import annotations

from bthj.bluez_cli import BluezCLIBackend

KEYBOARD_CLASS = 0x002540
MOUSE_CLASS = 0x002580
PHONE_CLASS = 0x000204
COMPUTER_CLASS = 0x000100


def spoof_name(backend: BluezCLIBackend, name: str) -> None:
    backend.set_name(name)


def spoof_class(backend: BluezCLIBackend, device_class: int) -> None:
    backend.set_class(device_class)


def restore(backend: BluezCLIBackend, name: str | None) -> None:
    if name:
        backend.set_name(name)
    backend.reset_adapter()