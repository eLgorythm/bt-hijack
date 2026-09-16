

from bthj.rfcomm import (
    STATUS_CLOSED,
    STATUS_OPEN,
    STATUS_TIMEOUT,
    _match_response,
    _sabm_frame,
    addr_byte,
    probe_channel,
    summarize,
    sweep,
)


class FakeSocket:
    def __init__(self, resp_map, connect_error=None):
        self.resp_map = resp_map
        self.connect_error = connect_error
        self.timeout = 1.0
        self.sent = None
        self.family = self.kind = self.proto = None

    def settimeout(self, t):
        self.timeout = t

    def gettimeout(self):
        return self.timeout

    def connect(self, sa):
        if self.connect_error is not None:
            raise self.connect_error

    def sendall(self, data):
        self.sent = data

    def recv(self, n):
        dlci = self.sent[0] >> 2
        resp = self.resp_map.get(dlci)
        if resp is None:
            raise TimeoutError("timed out")
        return resp

    def close(self):
        pass

    def __call__(self, *args):
        return self


def make_factory(resp_map, connect_error=None):
    sock = FakeSocket(resp_map, connect_error=connect_error)
    return sock, lambda *a, **k: sock


def test_addr_byte_command_and_response():
    assert addr_byte(0, True) == 0x03
    assert addr_byte(0, False) == 0x01
    assert addr_byte(1, True) == 0x07
    assert addr_byte(1, False) == 0x05


def test_sabm_frame():
    assert _sabm_frame(0) == bytes([0x03, 0x3F, 0x00])
    assert _sabm_frame(1) == bytes([0x07, 0x3F, 0x00])


def test_match_response_open_closed():
    open_frame = bytes([addr_byte(1, False), 0x73, 0x00])
    closed_frame = bytes([addr_byte(1, False), 0x0F, 0x00])
    assert _match_response(open_frame, 1) == STATUS_OPEN
    assert _match_response(closed_frame, 1) == STATUS_CLOSED
    assert _match_response(b"\x05\x54\x00", 1) is None


def test_probe_all_statuses():
    sock, _ = make_factory({1: bytes([addr_byte(1, False), 0x73, 0x00])})
    r = probe_channel(sock, 1, timeout=0.2)
    assert r.status == STATUS_OPEN and r.rtt_ms is not None

    sock, _ = make_factory({1: bytes([addr_byte(1, False), 0x0F, 0x00])})
    r = probe_channel(sock, 1, timeout=0.2)
    assert r.status == STATUS_CLOSED

    sock, _ = make_factory({})
    r = probe_channel(sock, 1, timeout=0.05)
    assert r.status == STATUS_TIMEOUT


def test_sweep_open_channels():
    resp = {1: bytes([addr_byte(1, False), 0x73, 0x00]),
            3: bytes([addr_byte(3, False), 0x73, 0x00])}
    _, factory = make_factory(resp)
    result = sweep("AA:BB:CC:DD:EE:FF", channels=[1, 2, 3],
                   channel_timeout=0.05, factory=factory)
    assert result.reachable is True
    assert result.open_channels == [1, 3]
    assert [c.status for c in result.channels] == [
        STATUS_OPEN, STATUS_TIMEOUT, STATUS_OPEN]
    assert "1" in summarize(result)[1]


def test_sweep_connect_error():
    _, factory = make_factory({}, connect_error=OSError("no route to host"))
    result = sweep("AA:BB:CC:DD:EE:FF", channels=[1], factory=factory)
    assert result.reachable is False
    assert "no route to host" in result.psm_error
    assert result.channels == []


def test_summarize_unreachable():
    _, factory = make_factory({}, connect_error=OSError("EHOSTUNREACH"))
    result = sweep("AA:BB:CC:DD:EE:FF", channels=[1], factory=factory)
    lines = summarize(result)
    assert "reachable=False" in lines[0]
    assert "EHOSTUNREACH" in " ".join(lines)