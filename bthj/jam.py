from __future__ import annotations

import subprocess


def ubertooth_check() -> dict[str, bool | str]:
    out: dict[str, bool | str] = {"present": False}
    try:
        subprocess.run(["ubertooth-btle"], capture_output=True, timeout=5, check=False)
        out["present"] = True
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        out["present"] = True
    return out


def jam(backend, target: str) -> None:
    raise NotImplementedError(
        "BLE jamming + connection-race preemption requires raw-phy access "
        "(Ubertooth or nRF52 with custom firmware). Not available over host BlueZ."
    )