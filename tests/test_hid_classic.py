import struct

from bthj.hid_classic import (
    _decode_element,
    _encode_sequence,
    _encode_string,
    _encode_uint,
    _encode_uuid16,
    _extract_uuid16,
    detect,
    probe_hid_psms,
    sdp_browse,
    sdp_search,
)


class FakeSock:
    def __init__(self, handler):
        self._handler = handler
        self._timeout = 1.0
        self.sent = None
        self.family = self.kind = self.proto = None

    def settimeout(self, t):
        self._timeout = t

    def gettimeout(self):
        return self._timeout

    def connect(self, sa):
        pass

    def sendall(self, data):
        self.sent = data

    def recv(self, n):
        return self._handler(self.sent)

    def close(self):
        pass

    def __call__(self, *a, **k):
        return self


def _make_handler(pid_search, tid_search, handles, pid_attr, tid_attr, attr_bytes):
    def handler(data):
        if data[0] == 0x02:
            return (
                bytes([pid_search])
                + struct.pack(">H", tid_search)
                + struct.pack(">H", 1)
                + struct.pack(">H", 1)
                + b"".join(struct.pack(">I", h) for h in handles)
                + bytes([0x00])
            )
        if data[0] == 0x06:
            return (
                bytes([pid_attr])
                + struct.pack(">H", tid_attr)
                + struct.pack(">H", 1)
                + struct.pack(">H", 1)
                + struct.pack(">H", len(attr_bytes))
                + attr_bytes
                + bytes([0x00])
            )
        raise ValueError("unexpected PDU")

    return handler


def test_encode_roundtrip_uint():
    for val, oct in [(0, 1), (255, 1), (0x1234, 2), (0x00010000, 4)]:
        b = _encode_uint(val, oct)
        typ, v, off = _decode_element(b, 0)
        assert typ == "uint"
        assert v == val
        assert off == len(b)


def test_encode_roundtrip_uuid16():
    b = _encode_uuid16(0x0111)
    assert b[0] == 0x19
    typ, val, _ = _decode_element(b)
    assert typ == "uuid16"
    assert val == 0x0111


def test_extract_uuid16():
    items = [("uuid16", 0x0111), ("uint", 99), ("uuid16", 0x0003)]
    assert _extract_uuid16(items) == [0x0111, 0x0003]


def test_sdp_lifecycle():
    record = b""
    record += _encode_sequence(_encode_uint(0x0000, 4) + _encode_uint(0x00000001, 4))
    record += _encode_sequence(_encode_uint(0x0001, 4) + _encode_sequence(_encode_uuid16(0x0111)))
    record += _encode_sequence(
        _encode_uint(0x0004, 4)
        + _encode_sequence(
            _encode_sequence(_encode_uuid16(0x0100))
            + _encode_sequence(_encode_uuid16(0x0003) + _encode_uint(5, 1))
        )
    )
    record += _encode_sequence(
        _encode_uint(0x0100, 4) + _encode_string("Test HID")
    )
    h = _make_handler(0x03, 0x1234, [1], 0x07, 0x5678, _encode_sequence(record))
    factory = FakeSock(h)
    handles = sdp_search("AA:BB:CC:DD:EE:FF", timeout=0.2, factory=factory)
    assert handles == [1]
    records = sdp_browse("AA:BB:CC:DD:EE:FF", timeout=0.2, factory=factory)
    assert len(records) == 1
    assert records[0]["name"] == "Test HID"
    assert records[0]["rfcomm_channel"] == 5
    assert 0x111 in [int(u, 16) for u in records[0]["service_uuids"]]


def test_probe_hid_psms_results():
    def faky(*a, **k):
        s = FakeSock(lambda d: b"")
        s._fail_psm = True

        def connect(sa):
            if isinstance(sa, tuple) and sa[1] == 0x0013:
                raise OSError("refused")

        s.connect = connect
        return s

    out = probe_hid_psms("AA:BB:CC:DD:EE:FF", timeout=0.05, factory=faky)
    assert out["ctrl"] is True
    assert out["intr"] is False


def test_detect_summary():
    def silent_factory(*a, **k):
        s = FakeSock(lambda d: b"")
        s.close = lambda: None
        return s

    r = detect("AA:BB:CC:DD:EE:FF",
               timeout=0.05, connect_timeout=0.05, channel_timeout=0.01,
               include_sdps=False, include_psms=False, factory=silent_factory)
    assert r["reachable"] is True
    assert r["hid_supported"] is False
    assert r["sdp_records"] == []