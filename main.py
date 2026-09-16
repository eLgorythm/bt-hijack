#!/usr/bin/env python3
"""bt-hijack interactive menu frontend."""

from __future__ import annotations

import sys
from pathlib import Path

from bthj import TOOL_NAME, __author__, __version__
from bthj.cli import main as cli_main
from bthj.hal import BackendError

_TTY = bool(getattr(sys.stdout, "isatty", lambda: False)())

_C = {
    "r": "\x1b[0m",
    "b": "\x1b[1m",
    "d": "\x1b[2m",
    "c": "\x1b[36m",
    "y": "\x1b[33m",
    "g": "\x1b[32m",
    "e": "\x1b[31m",
    "m": "\x1b[35m",
}


def _p(tag: str, s: str, bold: bool = False) -> str:
    if not _TTY:
        return s
    return f"{_C['b'] if bold else ''}{_C[tag]}{s}{_C['r']}"


MENU = [
    "Scan devices",
    "Probe target",
    "Classic recon (rfcomm)",
    "BLE HID injection",
    "Impersonate / clone",
    "Spoof identity (name / class)",
    "Info / Self-test",
    "Doctor (readiness)",
    "Run free CLI command",
]

GROUPS = [
    ("RECON", [
        ("1", "Scan", "discover BLE / Classic devices (RSSI, class)"),
        ("2", "Probe", "profile a target + attack suggestions"),
        ("3", "Classic recon", "RFCOMM channels, SDP services, HID PSMs"),
    ]),
    ("ATTACK", [
        ("4", "BLE HID", "keystroke injection via GATT keyboard gadget"),
        ("5", "Impersonate", "clone target identity + fire HID payload"),
        ("6", "Spoof", "change adapter name / Device Class"),
    ]),
    ("UTILITY", [
        ("7", "Self-test", "check tooling + controller posture"),
        ("8", "Doctor", "host readiness + engagement runbook"),
        ("9", "Free CLI", "run any bthj command directly"),
    ]),
]

_ADAPTER_STATUS = None


def _controller_status() -> dict | None:
    global _ADAPTER_STATUS
    if _ADAPTER_STATUS is not None:
        return _ADAPTER_STATUS
    try:
        from bthj.hal import UnsupportedBackend, get_backend

        _ADAPTER_STATUS = get_backend("bluez").controller_info()
    except (BackendError, UnsupportedBackend, OSError, RuntimeError):
        _ADAPTER_STATUS = {}
    return _ADAPTER_STATUS


def _adapter_line() -> str:
    info = _controller_status() or {}
    if not info.get("address"):
        return ""
    powered = _p("g", "powered", bold=True) if info.get("powered") else _p("e", "OFF", bold=True)
    return (
        f"  adapter {info.get('address')} '{info.get('name') or '?'}'"
        f"  class={info.get('class') or '?'}  {powered}"
    )


def _print_menu() -> None:
    print()
    print(_p("c", "═" * 56, bold=True))
    print(f"  {_p('y', TOOL_NAME + ' ' + __version__, bold=True)} — {_p('c', __author__, bold=True)}  [interactive menu]")
    if _TTY:
        line = _adapter_line()
        if line:
            print(line)
    print(_p("d", "  type a number + Enter · Ctrl+C aborts the running command"))
    print(_p("c", "═" * 56, bold=True))
    for gname, items in GROUPS:
        print()
        print(f"  {_p('c', gname, bold=True)}")
        for num, name, desc in items:
            n = _p("y", f"{num:>2}", bold=True)
            print(f"    {n}.  {name:<16} {_p('d', desc)}")
    print(f"    {_p('g', ' 0', bold=True)}.  Exit")
    print()


def _prompt_choice() -> int:
    _print_menu()
    while True:
        try:
            raw = input(_p("y", "  Choice [0-9]: ", bold=True)).strip()
            if not raw:
                continue
            n = int(raw)
            if 0 <= n <= len(MENU):
                return n
        except (ValueError, EOFError):
            pass
        print(_p("e", "  ⚠ invalid choice, try again."))


def _ask(question: str, default: str | None = None) -> str:
    if default is not None:
        prompt = f"  {_p('y', question, bold=True)} [{default}]: "
    else:
        prompt = f"  {_p('y', question, bold=True)}: "
    while True:
        try:
            val = input(prompt).strip()
        except EOFError:
            return default or ""
        if val:
            return val
        if default is not None:
            return default
        print(_p("e", "    required value — try again"))


def _ask_bool(question: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        val = _ask(f"{question} ({hint})", "").lower()
        if val in ("y", "yes", "1", "true"):
            return True
        if val in ("n", "no", "0", "false", ""):
            return default
        print(_p("e", "    enter y or n"))


def _pick_script(prompt: str) -> str:
    files = sorted(Path("payloads").glob("*.txt")) if Path("payloads").is_dir() else []
    if files:
        print(_p("d", "  available payloads:"))
        for i, f in enumerate(files, 1):
            print(f"    {_p('y', f'{i:>2}', bold=True)}  {f.name}")
        print(_p("d", "  (type a number, or a full path)"))
        while True:
            val = _ask(prompt)
            if not val:
                return ""
            if val.isdigit():
                n = int(val)
                if 1 <= n <= len(files):
                    return str(files[n - 1])
                print(_p("e", "    out of range — try again"))
                continue
            return val
    return _ask(prompt)


def _prompt_scan() -> list[str]:
    timeout = _ask("Scan duration (seconds)", "8")
    passive = _ask_bool("Passive (LE-only) scan?", False)
    argv = ["--backend", "bluez", "scan", "--timeout", timeout]
    if passive:
        argv.append("--passive")
    return argv


def _prompt_probe() -> list[str]:
    addr = _ask("Target BD_ADDR (from scan output)")
    if not addr:
        return []
    return ["--backend", "bluez", "probe", addr, "--timeout", "6"]


def _prompt_rfcomm() -> list[str]:
    addr = _ask("Target BD_ADDR (from scan output)")
    if not addr:
        return []
    argv = ["--backend", "bluez", "rfcomm", addr, "--channels", "1-30",
            "--connect-timeout", "4", "--channel-timeout", "0.4"]
    if _ask_bool("Skip SDP browse?", False):
        argv.append("--skip-sdp")
    if _ask_bool("Skip HID PSM probe?", False):
        argv.append("--skip-hid-psms")
    return argv


def _prompt_ble_hid() -> list[str]:
    script = _pick_script("Script file path")
    if not script:
        return []
    argv = ["--backend", "bluez", "ble-hid",
            "--script-file", script, "--timeout", "120"]
    if _ask_bool("Loop: re-fire on every re-association?", False):
        argv.append("--loop")
    else:
        mf = _ask("Max fires (1 = single shot)", "1")
        if mf != "1":
            argv.append("--max-fires")
            argv.append(mf)
    return _prompt_vars(argv)


def _prompt_clone() -> list[str]:
    addr = _ask("Target BD_ADDR to clone (blank = use --identity-name)")
    argv = ["--backend", "bluez", "impersonate"]
    if addr:
        argv.append(addr)
    id_name = _ask("Identity name override (blank = probe from target)", "")
    if id_name:
        argv += ["--identity-name", id_name]
    script = _pick_script("Script file path")
    if not script:
        return []
    argv += ["--script-file", script, "--timeout", "120"]
    if _ask_bool("Loop: re-fire on re-association?", False):
        argv.append("--loop")
    else:
        mf = _ask("Max fires (1 = single shot)", "1")
        if mf != "1":
            argv += ["--max-fires", mf]
    return _prompt_vars(argv)


def _prompt_spoof() -> list[str]:
    argv = ["--backend", "bluez", "spoof"]
    name = _ask("New adapter name (blank = skip)", "")
    if name:
        argv += ["--name", name]
    mode = _ask("Class mode: keyboard / mouse / hex-class (blank = skip)", "").lower()
    if mode in ("keyboard", "kb"):
        argv.append("--keyboard")
    elif mode in ("mouse",):
        argv.append("--mouse")
    elif mode:
        argv += ["--class", mode]
    if len(argv) <= 3:
        print(_p("e", "    no name or class set — nothing to do"))
    return argv


def _prompt_vars(argv: list[str]) -> list[str]:
    while _ask_bool("Add a variable substitution ({{TOKEN}})?", False):
        pair = _ask("Variable as NAME=VALUE")
        if "=" not in pair:
            print(_p("e", "    skipping — need NAME=VALUE format"))
            continue
        argv += ["--var", pair]
    return argv


def _dispatch(choice: int) -> list[str] | None:
    if choice == 1:
        return _prompt_scan()
    if choice == 2:
        return _prompt_probe()
    if choice == 3:
        return _prompt_rfcomm()
    if choice == 4:
        return _prompt_ble_hid()
    if choice == 5:
        return _prompt_clone()
    if choice == 6:
        return _prompt_spoof()
    if choice in (7, 8):
        sub = "self-test" if choice == 7 else "doctor"
        return ["--backend", "bluez", sub]
    if choice == 9:
        raw = _ask("Enter bthj command + args (e.g. scan --timeout 10)")
        return ["--backend", "bluez"] + raw.split() if raw else None
    return None


def _run(argv: list[str]) -> int:
    print()
    print(_p("m", "─" * 56, bold=True))
    rc = cli_main(argv)
    print(_p("m", "─" * 56, bold=True))
    cmd = next((a for a in argv if not a.startswith("-")), "")
    status = _p("g", "done", bold=True) if rc == 0 else _p("e", f"failed (rc={rc})", bold=True)
    print(f"  {status}  ·  command: {cmd or argv[-1]}")
    return rc


def loop() -> None:
    while True:
        try:
            choice = _prompt_choice()
        except KeyboardInterrupt:
            print("\n  use 0 to exit")
            continue
        if choice == 0:
            print(_p("g", "  bye — 0xfndLabs", bold=True))
            break
        try:
            argv = _dispatch(choice)
            if argv is None or not argv:
                continue
            try:
                _run(argv)
            except KeyboardInterrupt:
                print(_p("e", "  [interrupted]"))
        except KeyboardInterrupt:
            print(_p("e", "  [cancelled]"))
        try:
            input("  Press Enter to continue...")
        except EOFError:
            break


if __name__ == "__main__":
    loop()