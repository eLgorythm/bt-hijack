import struct
import wave
from types import SimpleNamespace

import pytest

from bthj import audio
from bthj.audio import (
    AudioError,
    blast,
    connect,
    probe,
    set_default,
    set_volume,
    sink_name,
)


def fake_shell(stdout="", stderr="", rc=0):
    def inner(cmd, timeout=30):
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=rc)
    return inner


async def _empty_dict() -> dict:
    return {}


async def _no_players(addr: str) -> list:
    return []


def test_synth_tone_valid_wav(tmp_path):
    p = tmp_path / "tone.wav"
    audio.synth_tone(str(p), seconds=0.25, freq=880.0)
    with wave.open(str(p)) as w:
        assert w.getnchannels() == 2
        assert w.getsampwidth() == 2
        assert w.getnframes() == 48000 * 25 // 100
        frames = w.readframes(1)
        assert len(struct.unpack("<hh", frames)) == 2


def test_sink_name_parse():
    out = "02\tbluez_output.00_31_a7_19_51_1e.1\tPipeWire\ts16le 2ch 48000Hz\tSUSPENDED\n05\talsacard\tPipeWire\t...\n"
    assert sink_name("00:31:A7:19:51:1E", fake_shell(stdout=out)) == "bluez_output.00_31_a7_19_51_1e.1"


def test_sink_name_missing_returns_none():
    assert sink_name("00:31:A7:19:51:1E", fake_shell(stdout="05\talsacard\n")) is None


def test_set_default_invokes_pactl():
    calls = []
    out = "02\tbluez_output.00_31_a7_19_51_1e.1\tPipeWire\ts16le\tRUNNING\n"
    shell = lambda cmd, timeout=30: calls.append(cmd) or SimpleNamespace(stdout=out, stderr="", returncode=0)
    name = set_default("00:31:A7:19:51:1E", shell)
    assert name == "bluez_output.00_31_a7_19_51_1e.1"
    assert calls == [["pactl", "list", "sinks", "short"], ["pactl", "set-default-sink", name]]


def test_set_default_no_sink_raises():
    with pytest.raises(AudioError):
        set_default("00:31:A7:19:51:1E", fake_shell(stdout="05\talsacard\n"))


def test_set_volume_clamps_and_calls():
    calls = []
    out = "02\tbluez_output.00_31_a7_19_51_1e.1\tPipeWire\n"
    shell = lambda cmd, timeout=30: calls.append(cmd) or SimpleNamespace(stdout=out, stderr="", returncode=0)
    set_volume("00:31:A7:19:51:1E", 180, shell)
    assert calls[-1] == ["pactl", "set-sink-volume", "bluez_output.00_31_a7_19_51_1e.1", "150%"]


def test_connect_success():
    shell = lambda cmd, timeout=30: SimpleNamespace(
        stdout="[CHG] Device ... Connected: yes\nConnection successful\n", stderr="", returncode=0
    )
    assert connect("00:31:A7:19:51:1E", shell=shell) is None


def test_connect_failure_raises():
    shell = lambda cmd, timeout=30: SimpleNamespace(stdout="Failed to connect\n", stderr="", returncode=1)
    with pytest.raises(AudioError):
        connect("00:31:A7:19:51:1E", shell=shell)


def test_blast_builds_tone_and_plays(tmp_path, monkeypatch):
    calls = []
    out = "02\tbluez_output.00_31_a7_19_51_1e.1\tPipeWire\n"
    def shell(cmd, timeout=30):
        calls.append(cmd)
        return SimpleNamespace(stdout=out, stderr="", returncode=0)
    monkeypatch.setattr(audio, "synth_tone", lambda p, seconds, freq=880.0: p)
    result = blast("00:31:A7:19:51:1E", wav_path="-", seconds=0.2, volume=60, repeat=2, shell=shell)
    assert result["repeat"] == 2
    assert result["volume"] == 60
    plate = [c for c in calls if c[0] == "pw-play"]
    assert len(plate) == 2
    set_defaults = [c for c in calls if c[:3] == ["pactl", "set-default-sink", "bluez_output.00_31_a7_19_51_1e.1"]]
    set_vol = [c for c in calls if c[:4] == ["pactl", "set-sink-volume", "bluez_output.00_31_a7_19_51_1e.1", "60%"]]
    assert len(set_defaults) == 1
    assert len(set_vol) == 1


def test_blast_failed_play_raises(monkeypatch):
    out = "02\tbluez_output.00_31_a7_19_51_1e.1\tPipeWire\n"
    def shell(cmd, timeout=30):
        return SimpleNamespace(stdout=out, stderr="boom", returncode=1) if cmd[0] == "pw-play" \
            else SimpleNamespace(stdout=out, stderr="", returncode=0)
    monkeypatch.setattr(audio, "synth_tone", lambda p, seconds, freq=880.0: p)
    with pytest.raises(AudioError):
        blast("00:31:A7:19:51:1E", wav_path="-", shell=shell)


def test_control_unsupported_raises(monkeypatch):
    monkeypatch.setattr(audio, "_media_players", _no_players)
    with pytest.raises(AudioError) as ei:
        audio.control("00:31:A7:19:51:1E", "play")
    assert "AVRCP player object" in str(ei.value)


def test_control_unknown_action():
    with pytest.raises(AudioError):
        audio.control("00:31:A7:19:51:1E", "rewind")


def test_probe_shape_without_bluez(monkeypatch):
    monkeypatch.setattr(audio, "_scan_bluez", _empty_dict)
    info = probe("00:31:A7:19:51:1E", fake_shell(stdout=""))
    assert info["address"] == "00:31:A7:19:51:1E"
    assert info["transports"] == []
    assert info["tools"] is not None