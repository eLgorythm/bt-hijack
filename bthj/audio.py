"""Bluetooth speaker hijack: A2DP audio blast + AVRCP control via host BlueZ/PipeWire.

Host path: connect -> BlueZ exports A2DP Source transport -> PipeWire exposes a
``bluez_output.<addr>.1`` sink -> `pactl set-default-sink` + `pw-play` streams
audio into the speaker. AVRCP remote control (play/pause/next) needs BlueZ to
export a MediaPlayer1 object; most BlueZ 5.x builds do not (Controller role
unsupported), so users fall back to blast/volume.
"""

from __future__ import annotations

import asyncio
import math
import shutil
import struct
import subprocess
import time
import wave
from pathlib import Path

from dbus_next import BusType, Message, MessageType
from dbus_next.aio import MessageBus
from dbus_next.signature import Variant

from bthj.hal import BackendError

A2DP_SOURCE_UUID = "0000110a-0000-1000-8000-00805f9b34fb"
A2DP_SINK_UUID = "0000110b-0000-1000-8000-00805f9b34fb"

CONTROL_METHODS = {
    "play": "Play",
    "pause": "Pause",
    "stop": "Stop",
    "next": "Next",
    "previous": "Previous",
}


class AudioError(BackendError):
    pass


def _norm(addr: str) -> str:
    return addr.lower().replace(":", "_")


def _v(prop) -> str:
    if isinstance(prop, Variant):
        return str(prop.value)
    return "" if prop is None else str(prop)


def local_run(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, input="", check=False
        )
    except FileNotFoundError as exc:
        raise AudioError(f"binary not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise AudioError(f"{cmd[0]} timed out") from exc


def connect(addr: str, timeout: int = 20, shell=local_run) -> None:
    p = shell(["bluetoothctl", "--timeout", str(timeout), "connect", addr], timeout=timeout + 10)
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode != 0 or "Connection successful" not in out:
        raise AudioError(f"could not connect {addr}: {out.strip()[-160:]}")


def sink_name(addr: str, shell=local_run) -> str | None:
    prefix = "bluez_output." + _norm(addr) + ".1"
    p = shell(["pactl", "list", "sinks", "short"])
    for line in (p.stdout or "").splitlines():
        if prefix in line.lower():
            parts = line.split("\t")
            return parts[1] if len(parts) > 1 else line.split()[1]
    return None


def _force_a2dp(addr: str, shell=local_run) -> dict:
    card = "bluez_card." + _norm(addr) + ".1"
    for profile in ("a2dp-sink", "a2dp_sink"):
        try:
            p = shell(["pactl", "set-card-profile", card, profile])
        except OSError:
            continue
        if p.returncode == 0:
            return {"card": card, "profile": profile, "ok": True}
    return {"card": card, "profile": None, "ok": False}


def _active_profile_note(addr: str, shell=local_run) -> str | None:
    p = shell(["pactl", "list", "cards"])
    target = "bluez_card." + _norm(addr) + ".1"
    in_card = False
    for line in (p.stdout or "").splitlines():
        if line.strip().startswith("Name:") and target in line:
            in_card = True
        elif line.strip().startswith("Card #"):
            in_card = False
        elif in_card and line.strip().startswith("Active Profile:"):
            return line.split(":", 1)[1].strip()
    return None


def wait_sink(addr: str, timeout: float = 30.0, shell=local_run) -> str:
    _force_a2dp(addr, shell)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        name = sink_name(addr, shell)
        if name is not None:
            return name
        time.sleep(1.0)
    profile = _active_profile_note(addr, shell) or "?"
    raise AudioError(
        f"no A2DP sink for {addr} after {timeout:.0f}s "
        f"(card profile: {profile}) — is the speaker powered and paired, "
        f"and is PipeWire/WirePlumber running?"
    )


def set_default(addr: str, shell=local_run) -> str:
    name = sink_name(addr, shell)
    if name is None:
        raise AudioError(f"no A2DP sink for {addr} — is it connected and visible to PipeWire?")
    p = shell(["pactl", "set-default-sink", name])
    if p.returncode != 0:
        raise AudioError(f"set-default-sink failed: {(p.stderr or '').strip()}")
    return name


def set_volume(addr: str, pct: int = 100, shell=local_run) -> str:
    name = sink_name(addr, shell)
    if name is None:
        raise AudioError(f"no A2DP sink for {addr} — is it connected and visible to PipeWire?")
    p = shell(["pactl", "set-sink-volume", name, f"{max(0, min(150, pct))}%"])
    if p.returncode != 0:
        raise AudioError(f"set-sink-volume failed: {(p.stderr or '').strip()}")
    return name


def synth_tone(path: str, seconds: float = 5.0, freq: float = 880.0,
               rate: int = 48000) -> str:
    with wave.open(path, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(rate)
        frames = bytearray()
        n = max(1, int(rate * seconds))
        for i in range(n):
            v = int(0.3 * 32767 * math.sin(2 * math.pi * freq * i / rate))
            frames += struct.pack("<hh", v, v)
        w.writeframes(bytes(frames))
    return path


def blast(addr: str, wav_path: str | None = None, seconds: float = 5.0,
          volume: int = 100, repeat: int = 1, shell=local_run, wait: float = 30.0) -> dict:
    name = wait_sink(addr, timeout=wait, shell=shell)
    q = shell(["pactl", "set-default-sink", name])
    if q.returncode != 0:
        raise AudioError(f"set-default-sink failed: {(q.stderr or '').strip()}")
    set_volume(addr, volume, shell)
    source = wav_path
    cleanup: Path | None = None
    if source is None or source == "-":
        cleanup = Path(f"/tmp/bthj_blast_{_norm(addr)}.wav")
        synth_tone(str(cleanup), seconds)
        source = str(cleanup)
    for _ in range(repeat):
        p = shell(["pw-play", source])
        if p.returncode != 0:
            raise AudioError(f"pw-play failed: {(p.stderr or '').strip()}")
    if cleanup is not None:
        cleanup.unlink(missing_ok=True)
    return {"target": addr, "file": source, "repeat": repeat, "volume": volume}


async def _scan_bluez() -> dict:
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    try:
        reply = await bus.call(Message(
            destination="org.bluez",
            path="/",
            interface="org.freedesktop.DBus.ObjectManager",
            member="GetManagedObjects",
        ))
        if reply.message_type != MessageType.METHOD_RETURN:
            return {}
        return reply.body[0]
    finally:
        bus.disconnect()


async def _media_players(addr: str) -> list[tuple[str, dict]]:
    objects = await _scan_bluez()
    dev_token = f"/dev_{_norm(addr)}"
    players = []
    for path, ifaces in objects.items():
        player = ifaces.get("org.bluez.MediaPlayer1")
        if player and dev_token in path.lower():
            players.append((path, {
                "status": _v(player.get("PlaybackStatus", "?")),
                "volume": _v(player.get("Volume", "?")),
                "name": _v(player.get("Name", "?")),
            }))
    return players


def control(addr: str, action: str, shell=local_run) -> dict:
    method = CONTROL_METHODS.get(action)
    if method is None:
        raise AudioError(f"unknown AVRCP action: {action}")
    players = asyncio.run(_media_players(addr))
    if not players:
        raise AudioError(
            "no AVRCP player object on this BlueZ build — Controller role unsupported; "
            "use --blast / --volume instead"
        )

    async def _fire():
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        try:
            reply = await bus.call(Message(
                destination="org.bluez",
                path=players[0][0],
                interface="org.bluez.MediaPlayer1",
                member=method,
            ))
            return reply.message_type == MessageType.METHOD_RETURN
        finally:
            bus.disconnect()

    fire_ok = asyncio.run(_fire())
    return {"target": addr, "action": action, "player": players[0][0], "ok": fire_ok}


def probe(addr: str, shell=local_run) -> dict:
    norm = _norm(addr)
    info: dict = {
        "address": addr,
        "connected": False,
        "name": None,
        "class": None,
        "transports": [],
        "players": [],
        "sink": None,
        "tools": {name: shutil.which(name) is not None for name in ("pw-play", "pactl", "wpctl")},
    }
    objects = asyncio.run(_scan_bluez())
    dev_token = f"/dev_{norm}"
    for path, ifaces in objects.items():
        dev = ifaces.get("org.bluez.Device1")
        if dev and _v(dev.get("Address", "")).upper() == addr.upper():
            info["connected"] = _v(dev.get("Connected", "false")) == "True"
            info["name"] = _v(dev.get("Alias", "")) or None
            info["class"] = _v(dev.get("Class", "")) or None
            break
    for path, ifaces in objects.items():
        if dev_token not in path.lower():
            continue
        if "org.bluez.MediaTransport1" in ifaces:
            t = ifaces["org.bluez.MediaTransport1"]
            info["transports"].append({
                "path": path,
                "uuid": _v(t.get("UUID", "")),
                "codec": _v(t.get("Codec", "")),
                "state": _v(t.get("State", "")),
            })
        player = ifaces.get("org.bluez.MediaPlayer1")
        if player:
            info["players"].append({
                "status": _v(player.get("PlaybackStatus", "?")),
                "volume": _v(player.get("Volume", "?")),
                "name": _v(player.get("Name", "?")),
            })
    info["sink"] = sink_name(addr, shell)
    return info