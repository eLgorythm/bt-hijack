from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from bthj.hal import Backend, BackendError
from bthj.models import Device

COD_MAJOR = {
    0x00: "misc",
    0x01: "computer",
    0x02: "phone",
    0x03: "lan",
    0x04: "audio/video",
    0x05: "peripheral",
    0x06: "imaging",
    0x07: "wearable",
    0x08: "toy",
    0x09: "health",
    0x1F: "uncategorized",
}

CHIP_VENDORS = {
    0x0001: "Ericsson",
    0x0002: "Intel",
    0x0003: "CSR",
    0x000d: "Texas Instruments",
    0x000e: "Nokia",
    0x002d: "Realtek",
    0x0004: "Broadcom",
    0x000f: "3Com",
    0x0010: "Microdia",
    0x0011: "Marvell",
    0x0012: "Mitsubishi",
    0x0013: "Lucent",
    0x0014: "RTX",
    0x001d: "Zeevo",
    0x0023: "Atmel",
    0x0061: "Ralink",
    0x0006: "Motorola",
    0x0055: "NXP",
}

UUID_HINTS = {
    "00001124-0000-1000-8000-00805f9b34fb": "HID",
    "0000110a-0000-1000-8000-00805f9b34fb": "audio/sink",
    "0000110b-0000-1000-8000-00805f9b34fb": "audio/source",
    "0000110e-0000-1000-8000-00805f9b34fb": "avrcp",
    "00001101-0000-1000-8000-00805f9b34fb": "serial",
    "00001103-0000-1000-8000-00805f9b34fb": "dialup",
    "0000110f-0000-1000-8000-00805f9b34fb": "objxfer",
    "00001112-0000-1000-8000-00805f9b34fb": "headset",
    "00001130-0000-1000-8000-00805f9b34fb": "hotspot",
    "00001200-0000-1000-8000-00805f9b34fb": "pnp",
    "00001800-0000-1000-8000-00805f9b34fb": "gatt",
    "00001801-0000-1000-8000-00805f9b34fb": "gatt_server",
    "0000180a-0000-1000-8000-00805f9b34fb": "device_info",
    "0000180f-0000-1000-8000-00805f9b34fb": "battery",
    "00001812-0000-1000-8000-00805f9b34fb": "hid",
    "0000180d-0000-1000-8000-00805f9b34fb": "heart_rate",
    "00001808-0000-1000-8000-00805f9b34fb": "hrm",
    "0000180e-0000-1000-8000-00805f9b34fb": "wsp",
    "00001813-0000-1000-8000-00805f9b34fb": "scp",
    "00001816-0000-1000-8000-00805f9b34fb": "cycling_speed",
    "00001818-0000-1000-8000-00805f9b34fb": "cp",
    "00001819-0000-1000-8000-00805f9b34fb": "location",
}


def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            input="",
        )
    except FileNotFoundError as exc:
        raise BackendError(f"binary not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise BackendError(f"{cmd[0]} timed out") from exc
    if proc.returncode != 0:
        raise BackendError(
            f"{' '.join(cmd)} exited {proc.returncode}: {proc.stderr.strip()}"
        )
    return proc.stdout


_SCAN_LINE = re.compile(
    r"^\[(?:NEW|CHG)\]\s+Device\s+"
    r"(?P<addr>[0-9A-F]{2}(?::[0-9A-F]{2}){5})"
    r"(?:\s+(?P<rest>.*))?$"
)

_ENDPOINT = re.compile(
    r"^Device\s+(?P<addr>[0-9A-F]{2}(?::[0-9A-F]{2}){5})\s*\[(?P<transport>\w+)\]"
)


def _parse_scan_block(block: str) -> Device | None:
    m = _SCAN_LINE.match(block)
    if not m:
        return None
    addr = m.group("addr")
    dev = Device(address=addr, addr_type="unknown")
    rest = m.group("rest")
    if rest:
        dev.name = rest
    return dev


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _clean_line(ln: str) -> str:
    return _ANSI.sub("", ln).strip()


def _parse_rssi(raw: str) -> int | None:
    raw = raw.strip()
    m = re.search(r"\((-?\d+)\)", raw)
    if m:
        return int(m.group(1))
    m = re.match(r"^0x[0-9a-fA-F]+$", raw)
    if m:
        val = int(raw, 16)
        return val - 256 if val > 127 else val
    try:
        return int(raw)
    except ValueError:
        return None


def parse_scan_lines(text: str) -> list[Device]:
    index: dict[str, Device] = {}
    order: list[str] = []
    for ln in text.splitlines():
        m = _SCAN_LINE.match(_clean_line(ln))
        if not m:
            continue
        addr = m.group("addr")
        if addr not in index:
            index[addr] = Device(address=addr, addr_type="unknown")
            order.append(addr)
        dev = index[addr]
        rest = m.group("rest")
        if rest is None or not rest:
            continue
        if rest == "":
            continue
        if rest.isdigit():
            continue
        if rest.startswith("RSSI:"):
            rssi = _parse_rssi(rest.split(":", 1)[1])
            if rssi is not None:
                dev.rssi = rssi
        elif rest.startswith("Name:"):
            dev.name = rest.split(":", 1)[1].strip()
        elif rest.startswith("Class:"):
            try:
                dev.device_class = int(rest.split(":", 1)[1].strip(), 16)
            except (ValueError, IndexError):
                pass
        else:
            dev.name = rest
    for addr in order:
        index[addr].addr_type = "public" if ":" in index[addr].address else "random"
    return [index[a] for a in order]


def parse_devices(text: str) -> list[Device]:
    out = parse_scan_lines(text)
    if out:
        return out
    result: list[Device] = []
    for raw in text.split("\n\n"):
        raw = _clean_line(raw)
        if not raw or "Device" not in raw:
            continue
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        if not lines or "Device" not in lines[0]:
            continue
        joined = "\n".join(lines)
        if _ENDPOINT.match(lines[0]):
            result.append(_parse_device_block(joined))
    return result


def _parse_device_block(block: str) -> Device:
    lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
    m = _ENDPOINT.match(_clean_line(lines[0])) if lines else None
    addr = m.group("addr") if m else lines[0].strip()
    dev = Device(address=addr, addr_type=m.group("transport") if m else None)
    for ln in lines:
        key, _, val = ln.partition(":")
        key, val = key.strip(), val.strip()
        if key == "Name":
            dev.name = val
        elif key == "RSSI":
            rssi = _parse_rssi(val)
            if rssi is not None:
                dev.rssi = rssi
        elif key == "Class":
            try:
                dev.device_class = int(val, 16)
            except ValueError:
                pass
        elif key == "Paired":
            dev.paired = val == "yes"
        elif key == "Trusted":
            dev.trusted = val == "yes"
        elif key == "Connected":
            dev.connected = val == "yes"
        elif key == "UUID":
            m_uuid = re.search(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                val,
            )
            dev.services.append(m_uuid.group(0) if m_uuid else val)
        elif key == "Icon":
            dev.flags.append(val)
    return dev


def _cod_major(dev_class: int) -> str | None:
    return COD_MAJOR.get((dev_class >> 8) & 0x1F)


def _uuid_hint(uuid: str) -> str | None:
    return UUID_HINTS.get(uuid.lower())


class BluezCLIBackend(Backend):
    name = "bluez"
    capabilities = (
        "discovery",
        "fingerprint",
        "spoof_name",
        "spoof_class",
        "classic",
        "ble",
        "pairing",
        "gatt_server",
        "hid_sink",
    )

    def __init__(self) -> None:
        for tool in ("bluetoothctl",):
            if not shutil.which(tool):
                raise BackendError(f"required binary '{tool}' not installed (BlueZ)")
        self._ctl = "bluetoothctl"
        self._adapter = self._first_adapter()

    def _first_adapter(self) -> str:
        for line in _run([self._ctl, "list"]).splitlines():
            m = re.match(r"Controller ([0-9A-F:]{17})", line)
            if m:
                return m.group(1)
        raise BackendError("no BlueZ controller found")

    def controller_info(self) -> dict:
        if not Path("/sys/class/bluetooth").exists():
            raise BackendError("no /sys/class/bluetooth; is the adapter present?")
        infos: list[str] = []
        for dev in sorted(Path("/sys/class/bluetooth").iterdir()):
            if dev.name.startswith("hci"):
                infos.append(dev.name)
        info: dict = {
            "adapter": self._adapter,
            "hci_devices": infos,
        }
        ctl = Path("/sys/class/bluetooth") / infos[0] if infos else None
        if ctl and (ctl / "device").exists():
            info["controller"] = ctl.name
        for line in _run([self._ctl, "show", self._adapter]).splitlines():
            ln = line.strip()
            if ln.startswith("Controller"):
                m_addr = re.match(r"^Controller\s+([0-9A-F:]+)", ln)
                if m_addr:
                    info["address"] = m_addr.group(1)
            elif ln.startswith("Name:"):
                info["name"] = ln.split(":", 1)[1].strip()
            elif ln.startswith("Alias:"):
                info["alias"] = ln.split(":", 1)[1].strip()
            elif ln.startswith("Class:"):
                info["class"] = ln.split(":", 1)[1].strip()
            elif ln.startswith("Powered:"):
                info["powered"] = ln.split(":", 1)[1].strip() == "yes"
            elif ln.startswith("Discoverable:"):
                info["discoverable"] = ln.split(":", 1)[1].strip() == "yes"
            elif ln.startswith("Pairable:"):
                info["pairable"] = ln.split(":", 1)[1].strip() == "yes"
            elif ln.startswith("UUID:"):
                raw = ln.split(":", 1)[1].strip().lower()
                m_uuid = re.search(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                    raw,
                )
                info.setdefault("uuids", []).append(m_uuid.group(0) if m_uuid else raw)
        info["uuid_hints"] = [
            h for u in info.get("uuids", []) if (h := _uuid_hint(u)) is not None
        ]
        return info

    def discover(self, timeout: int, passive: bool = False) -> list[Device]:
        _run([self._ctl, "power", "on"])
        flags = ["--timeout", str(int(timeout))]
        out = _run(
            [self._ctl, *flags, "scan", "off" if passive else "on"],
            timeout=int(timeout) + 15,
        )
        return parse_devices(out)

    def set_name(self, name: str) -> None:
        _run([self._ctl, "system-alias", name])

    def set_class(self, device_class: int) -> None:
        if not shutil.which("btmgmt"):
            raise BackendError("btmgmt not installed; cannot set Device Class on this host")
        major = (device_class >> 8) & 0x1F
        minor = (device_class >> 2) & 0x3F
        proc = subprocess.run(
            ["btmgmt", "class", hex(major), hex(minor)],
            capture_output=True, text=True, timeout=10, check=False, input="",
        )
        combined = (proc.stdout + " " + proc.stderr).lower()
        if proc.returncode != 0 or "status 0x14" in combined or "permission denied" in combined:
            raise BackendError(
                "btmgmt class needs CAP_NET_ADMIN; run bthj as root (or sudo) for --class"
            )

    def reset_adapter(self) -> None:
        _run([self._ctl, "power", "off"])
        _run([self._ctl, "power", "on"])