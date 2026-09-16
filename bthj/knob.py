from __future__ import annotations

from bthj.bluez_cli import BluezCLIBackend


def knob_posture(backend: BluezCLIBackend, target: str) -> dict:
    raise NotImplementedError(
        "KNOB compliance check needs the negotiated encryption key size from "
        "an active link (HCI Read Encryption Key Size). Stubbed."
    )