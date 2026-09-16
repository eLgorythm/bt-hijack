from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field

RFCOMM_PSM = 0x0003
SDP_PSM = 0x0001

SABM = 0x2F
UA = 0x73
DM = 0x0F
DISC = 0x43
UIH = 0xEF

STATUS_OPEN = "open"
STATUS_CLOSED = "closed"
STATUS_TIMEOUT = "timeout"


@dataclass
class ChannelResult:
    channel: int
    status: str
    rtt_ms: float | None = None


@dataclass
class SweepResult:
    target: str
    reachable: bool
    psm_error: str | None = None
    channels: list[ChannelResult] = field(default_factory=list)

    @property
    def open_channels(self) -> list[int]:
        return [c.channel for c in self.channels if c.status == STATUS_OPEN]


def addr_byte(dlci: int, cr: bool) -> int:
    return (dlci << 2) | 0x01 | (0x02 if cr else 0x00)


def _sabm_frame(dlci: int) -> bytes:
    return bytes([addr_byte(dlci, True), 0x3F, 0x00])


def _match_response(buf: bytes, dlci: int) -> str | None:
    want_addr = addr_byte(dlci, False)
    for i in range(len(buf) - 1):
        if buf[i] != want_addr:
            continue
        ctrl = buf[i + 1]
        if ctrl == UA:
            return STATUS_OPEN
        if ctrl == DM:
            return STATUS_CLOSED
    return None


def open_l2cap(addr: str, psm: int = RFCOMM_PSM, timeout: float = 4.0,
               factory=socket.socket):
    s = factory(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    s.settimeout(timeout)
    s.connect((addr, psm))
    return s


def probe_channel(sock, dlci: int, timeout: float, clock=time.monotonic) -> ChannelResult:
    start = clock()
    sock.sendall(_sabm_frame(dlci))
    end = clock() + timeout
    buf = b""
    prev_timeout = sock.gettimeout()
    try:
        sock.settimeout(timeout)
        while clock() < end:
            try:
                chunk = sock.recv(1024)
            except TimeoutError:
                break
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            status = _match_response(buf, dlci)
            if status is not None:
                return ChannelResult(
                    channel=dlci, status=status, rtt_ms=round((clock() - start) * 1000)
                )
    finally:
        sock.settimeout(prev_timeout)
    return ChannelResult(channel=dlci, status=STATUS_TIMEOUT)


def sweep(
    target: str,
    channels: range | list[int] = range(1, 31),
    connect_timeout: float = 4.0,
    channel_timeout: float = 0.5,
    psm: int = RFCOMM_PSM,
    factory=socket.socket,
) -> SweepResult:
    result = SweepResult(target=target, reachable=False)
    try:
        sock = open_l2cap(target, psm=psm, timeout=connect_timeout, factory=factory)
    except OSError as exc:
        result.psm_error = f"{type(exc).__name__}: {exc}"
        return result

    result.reachable = True
    try:
        for dlci in channels:
            result.channels.append(probe_channel(sock, dlci, channel_timeout))
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return result


def summarize(result: SweepResult) -> list[str]:
    lines = [f"target {result.target}: reachable={result.reachable}"]
    if result.psm_error:
        lines.append(f"  connect failed: {result.psm_error}")
        return lines
    open_ch = result.open_channels
    lines.append(f"  {len(open_ch)} open channel(s): {open_ch or 'none'}")
    for entry in result.channels:
        rtt = f" {entry.rtt_ms:>5.0f}ms" if entry.rtt_ms is not None else "      -"
        lines.append(f"  ch {entry.channel:>2}  {entry.status:<7}{rtt}")
    return lines