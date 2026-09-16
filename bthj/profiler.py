from __future__ import annotations

from bthj.bluez_cli import _cod_major
from bthj.models import AttackSuggestion, Device, Profile

_ATTACK_DB: list[tuple[AttackSuggestion, callable]] = [
    (
        AttackSuggestion(
            module="ble-hid",
            transport="ble",
            name="BLE HID injection (keyboard/mouse emulation)",
            confidence=0.8,
            notes=["Target advertises HID or is a general BLE peripheral.",
                   "Pair/victim must trust the injected peripheral."],
        ),
        lambda p, d: p.transport == "ble" or "hid" in p.hints,
    ),
    (
        AttackSuggestion(
            module="hid-classic",
            transport="classic",
            name="Classic HID impersonation (SDP/L2CAP PSM 17/19)",
            confidence=0.5,
            notes=["Depends on target's pairing UX; SSP numeric consent likely.",
                   "Best against low-interaction hosts / kiosk mode."],
        ),
        lambda p, d: p.cod_major == "computer" or "hid" in p.hints,
    ),
    (
        AttackSuggestion(
            module="spoof",
            transport="both",
            name="Identity spoof to impersonate a known paired device",
            confidence=0.6,
            notes=["Clone name/class/BD_ADDR of the target's trusted device.",
                   "This is scan + spoof + reconnect; needs timing work in the field."],
        ),
        lambda p, d: d is not None and d.paired,
    ),
    (
        AttackSuggestion(
            module="rfcomm-scan",
            transport="classic",
            name="RFCOMM channel discovery + service fingerprint",
            confidence=0.7,
            notes=["Maps open channels for later connect/sniff."],
        ),
        lambda p, d: p.cod_major in ("phone", "computer", "lan", "wearable"),
    ),
    (
        AttackSuggestion(
            module="knob-check",
            transport="classic",
            name="KNOB encryption-downgrade susceptibility check",
            confidence=0.3,
            notes=["Full exploit needs controller/FW with 1-byte encryption.",
                   "This module only reports the compliance posture."],
        ),
        lambda p, d: p.cod_major in ("phone", "computer", "health", "wearable"),
    ),
    (
        AttackSuggestion(
            module="jam-race",
            transport="ble",
            name="BLE link preemption (jam + connection race)",
            confidence=0.2,
            notes=["REQUIRES RF hardware (Ubertooth / nRF + custom FW).",
                   "Stubbed: raw-phy access not possible via host BlueZ alone."],
        ),
        lambda p, d: True,
    ),
]


def profile_device(dev: Device) -> Profile:
    cod_major = _cod_major(dev.device_class) if dev.device_class else None
    cod_minor = (
        "peripheral" if cod_major == "peripheral" and dev.device_class else None
    )
    hints: list[str] = []
    for svc in dev.services:
        hint = _hint(svc)
        if hint:
            hints.append(hint)
    le_services = [s for s in dev.services if "1800" <= s.replace("-", "")[:4] <= "18ff"]
    return Profile(
        transport="ble" if dev.addr_type and dev.addr_type != "public" else "classic",
        cod_major=cod_major,
        cod_minor=cod_minor,
        services=dev.services,
        le_services=le_services,
        hints=sorted(set(hints)),
    )


def suggest_attacks(profile: Profile, device: Device | None = None) -> list[AttackSuggestion]:
    out = []
    for suggestion, predicate in _ATTACK_DB:
        if predicate(profile, device):
            out.append(suggestion)
    out.sort(key=lambda s: s.confidence, reverse=True)
    return out


def _hint(uuid: str) -> str | None:
    from bthj.bluez_cli import _uuid_hint

    return _uuid_hint(uuid)