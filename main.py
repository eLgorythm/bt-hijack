#!/usr/bin/env python3
"""bt-hijack interactive menu frontend."""

from __future__ import annotations

from bthj.cli import main as cli_main

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


def _print_menu() -> None:
    print()
    print("=" * 50)
    print(" bt-hijack — interactive menu")
    print("=" * 50)
    for i, label in enumerate(MENU, start=1):
        print(f"  {i:>2}. {label}")
    print("   0. Exit")
    print()


def _prompt_choice() -> int:
    _print_menu()
    while True:
        try:
            raw = input("  Choice: ").strip()
            if not raw:
                continue
            n = int(raw)
            if 0 <= n <= len(MENU):
                return n
        except (ValueError, EOFError):
            pass
        print("  Invalid choice, try again.")


def _ask(question: str, default: str | None = None) -> str:
    if default is not None:
        prompt = f"  {question} [{default}]: "
    else:
        prompt = f"  {question}: "
    while True:
        try:
            val = input(prompt).strip()
        except EOFError:
            return default or ""
        if val:
            return val
        if default is not None:
            return default
        print("    value required")


def _ask_bool(question: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        val = _ask(f"{question} ({hint})", "").lower()
        if val in ("y", "yes", "1", "true"):
            return True
        if val in ("n", "no", "0", "false", ""):
            return default
        print("    enter y or n")


def _prompt_scan() -> list[str]:
    timeout = _ask("Scan duration (seconds)", "8")
    passive = _ask_bool("Passive (LE-only) scan?", False)
    argv = ["--backend", "bluez", "scan", "--timeout", timeout]
    if passive:
        argv.append("--passive")
    return argv


def _prompt_probe() -> list[str]:
    addr = _ask("Target BD_ADDR (AA:BB:CC:DD:EE:FF)")
    if not addr:
        return []
    return ["--backend", "bluez", "probe", addr, "--timeout", "6"]


def _prompt_rfcomm() -> list[str]:
    addr = _ask("Target BD_ADDR")
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
    script = _ask("Script file path (e.g. payloads/shell.txt)")
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
    addr = _ask("Target BD_ADDR to clone (blank to use --identity-name)")
    argv = ["--backend", "bluez", "impersonate"]
    if addr:
        argv.append(addr)
    id_name = _ask("Identity name override (blank = probe from target)", "")
    if id_name:
        argv += ["--identity-name", id_name]
    script = _ask("Script file path")
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
        print("    no name or class set — nothing to do")
    return argv


def _prompt_vars(argv: list[str]) -> list[str]:
    while _ask_bool("Add a variable substitution ({{TOKEN}})?", False):
        pair = _ask("Variable as NAME=VALUE")
        if "=" not in pair:
            print("    skipping — need NAME=VALUE format")
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
    rc = cli_main(argv)
    print()
    if rc != 0:
        print(f"  [exit code {rc}]")
    return rc


def loop() -> None:
    while True:
        try:
            choice = _prompt_choice()
        except KeyboardInterrupt:
            print("\n  use 0 to exit")
            continue
        if choice == 0:
            print("  bye")
            break
        argv = _dispatch(choice)
        if argv is None or not argv:
            continue
        try:
            _run(argv)
        except KeyboardInterrupt:
            print("\n  [interrupted]")
        try:
            input("  Press Enter to continue...")
        except EOFError:
            break


if __name__ == "__main__":
    loop()