from __future__ import annotations

import socket
import struct

from bthj.rfcomm import (
    SDP_PSM,
    open_l2cap,
    sweep,
)

SDP_ERROR = 0x01
SDP_SEARCH_REQ = 0x02
SDP_SEARCH_RESP = 0x03
SDP_SEARCH_ATTR_REQ = 0x06
SDP_SEARCH_ATTR_RESP = 0x07

HIDP_CTRL_PSM = 0x0011
HIDP_INTR_PSM = 0x0013

BROWSE_GROUP_UUID16 = 0x1002
HID_SVC_UUID16 = 0x0111
HID_MOUSE_SVC_UUID16 = 0x0112
HID_KBD_SVC_UUID16 = 0x0124
L2CAP_UUID16 = 0x0100
RFCOMM_UUID16 = 0x0003

ATTR_RECORD_HANDLE = 0x0000
ATTR_SERVICE_CLASS = 0x0001
ATTR_PROTOCOL_DESC = 0x0004
ATTR_BROWSE_GROUP = 0x0005
ATTR_LANGUAGE_BASE = 0x0006
ATTR_ADDITION_PROTO_OFFSETS = 0x000D
ATTR_SERVICE_NAME = 0x0100
ATTR_SERVICE_DESC = 0x0101
ATTR_PROVIDER_NAME = 0x0102


def _encode_element(value, type_id: int, size_index: int) -> bytes:
    header = ((type_id & 0x1F) << 3) | (size_index & 0x07)
    return bytes([header]) + value


def _encode_uint(value: int, octets: int) -> bytes:
    if octets == 1:
        return _encode_element(struct.pack(">B", value), 1, 0)
    if octets == 2:
        return _encode_element(struct.pack(">H", value), 1, 1)
    if octets == 4:
        return _encode_element(struct.pack(">I", value), 1, 2)
    if octets == 8:
        return _encode_element(struct.pack(">Q", value), 1, 3)
    return _encode_element(struct.pack(">Q", value)[:octets], 1, 0)


def _encode_uuid16(value: int) -> bytes:
    return _encode_element(struct.pack(">H", value), 3, 1)


def _encode_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) <= 0xFF:
        return _encode_element(bytes([len(raw)]) + raw, 4, 5)
    return _encode_element(struct.pack(">H", len(raw)) + raw, 4, 6)


def _encode_sequence(items: bytes) -> bytes:
    if len(items) <= 0xFF:
        return _encode_element(bytes([len(items)]) + items, 6, 5)
    return _encode_element(struct.pack(">H", len(items)) + items, 6, 6)


def _encode_attr_id_range(start: int, end: int) -> bytes:
    return _encode_sequence(_encode_uint(start, 2) + _encode_uint(end, 2))


def _decode_element(buf: bytes, off: int = 0):
    if off >= len(buf):
        raise ValueError("truncated element")
    hdr = buf[off]
    off += 1
    type_id = (hdr >> 3) & 0x1F
    size_idx = hdr & 0x07

    def _ints(octets: int, fmt: str):
        return struct.unpack_from(">" + fmt, buf, off)[0]

    def _uuid():
        if size_idx == 1:
            return ("uuid16", _ints(2, "H"), off + 2)
        if size_idx == 2:
            return ("uuid32", _ints(4, "I"), off + 4)
        if size_idx == 4:
            val = buf[off : off + 16]
            return ("uuid128", val.hex(), off + 16)
        raise ValueError(f"bad uuid size index {size_idx}")

    def _string():
        if size_idx == 5:
            if off >= len(buf):
                raise ValueError("truncated string len")
            n = buf[off]; off2 = off + 1
        elif size_idx == 6:
            n = struct.unpack_from(">H", buf, off)[0]; off2 = off + 2
        else:
            octets = {0: None, 1: 1, 2: 2, 3: 4, 4: 8}.get(size_idx)
            if octets is None:
                raise ValueError(f"bad string size index {size_idx}")
            n = octets; off2 = off
        return buf[off2 : off2 + n].decode("utf-8", errors="replace"), off2 + n

    if type_id == 1 or type_id == 2:
        if size_idx > 4:
            raise ValueError(f"bad int size index {size_idx}")
        octets = 1 << size_idx
        fmt = {1: "b" if type_id == 2 else "B", 2: "h" if type_id == 2 else "H",
               4: "i" if type_id == 2 else "I", 8: "q" if type_id == 2 else "Q"}[octets]
        return ("uint" if type_id == 1 else "sint", _ints(octets, fmt), off + octets)

    if type_id == 3:
        return _uuid()

    if type_id in (4, 8):
        val, off2 = _string()
        return ("string" if type_id == 4 else "url", val, off2)

    if type_id == 5:
        return ("bool", buf[off] != 0, off + 1)

    if type_id in (6, 7):
        if size_idx == 5:
            n = buf[off]; off2 = off + 1
        elif size_idx == 6:
            n = struct.unpack_from(">H", buf, off)[0]; off2 = off + 2
        else:
            raise ValueError(f"bad sequence size index {size_idx}")
        items: list = []
        end = off2 + n
        while off2 < end:
            typ, val, off2 = _decode_element(buf, off2)
            items.append((typ, val))
        return ("sequence" if type_id == 6 else "alternative", items, end)

    if type_id == 0:
        return ("nil", None, off)

    raise ValueError(f"unknown element type {type_id}")


def _decode_sequence(buf: bytes, off: int = 0) -> tuple[list[tuple[str, object]], int]:
    typ, val, off2 = _decode_element(buf, off)
    if typ not in ("sequence", "alternative"):
        return [(typ, val)], off2
    return val, off2


def _extract_uuid16(items: list[tuple[str, object]]) -> list[int]:
    return [v for (t, v) in items if t in ("uuid16", "uuid32") and isinstance(v, int) and v <= 0xFFFF]


def _find_attr(attrs: dict[int, tuple[str, object]], attr_id: int, kind: str | None = None):
    entry = attrs.get(attr_id)
    if entry is None:
        return None
    t, v = entry
    if kind and t != kind:
        return None
    return v


def _decode_record(buf: bytes) -> dict[int, tuple[str, object]]:
    attrs: dict[int, tuple[str, object]] = {}
    off = 0
    while off < len(buf):
        typ, val, off2 = _decode_element(buf, off)
        if typ != "sequence":
            break
        for inner in val:
            if inner[0] != "sequence" or len(inner[1]) < 2:
                continue
            id_entry, data_entry = inner[1][0], inner[1][1]
            if id_entry[0] not in ("uint",):
                continue
            attrs[id_entry[1]] = data_entry
        off = off2
    return attrs


def _parse_sdp_search(buf: bytes, tid: int):
    resp_id = buf[0]
    resp_tid = struct.unpack_from(">H", buf, 1)[0]
    if resp_id == SDP_ERROR:
        code = struct.unpack_from(">H", buf, 3)[0]
        raise OSError(f"SDP error response 0x{code:04x}")
    if resp_id != SDP_SEARCH_RESP or resp_tid != tid:
        raise OSError(f"unexpected SDP response PDU 0x{resp_id:02x}")
    total = struct.unpack_from(">H", buf, 3)[0]
    current = struct.unpack_from(">H", buf, 5)[0]
    off = 7
    handles: list[int] = []
    for _ in range(current):
        handles.append(struct.unpack_from(">I", buf, off)[0]); off += 4
    cont = buf[off] if off < len(buf) else 0
    if cont != 0:
        raise OSError("SDP response continuation not supported")
    return handles, total


def _parse_sdp_attr(buf: bytes, tid: int):
    resp_id = buf[0]
    resp_tid = struct.unpack_from(">H", buf, 1)[0]
    if resp_id == SDP_ERROR:
        code = struct.unpack_from(">H", buf, 3)[0]
        raise OSError(f"SDP error response 0x{code:04x}")
    if resp_id != SDP_SEARCH_ATTR_RESP or resp_tid != tid:
        raise OSError(f"unexpected SDP response PDU 0x{resp_id:02x}")
    current = struct.unpack_from(">H", buf, 5)[0]
    avail = struct.unpack_from(">H", buf, 7)[0]
    off = 9
    record_list: list[dict[int, tuple[str, object]]] = []
    end = off + avail
    for _ in range(current):
        items, off2 = _decode_sequence(buf, off)
        attrs: dict[int, tuple[str, object]] = {}
        for inner in items:
            if inner[0] != "sequence" or len(inner[1]) < 2:
                continue
            id_entry = inner[1][0]
            if id_entry[0] != "uint":
                continue
            attrs[id_entry[1]] = inner[1][1]
        record_list.append(attrs)
        off = off2
    if off != end:
        off = end
    return record_list


def sdp_search(
    addr: str,
    timeout: float = 5.0,
    search_uuid: int = BROWSE_GROUP_UUID16,
    connect_timeout: float | None = None,
    factory=socket.socket,
):
    tid = 0x1234
    search = _encode_sequence(_encode_uuid16(search_uuid))
    pdu = (b"\x02" + struct.pack(">H", tid) + search + struct.pack(">H", 0) + b"\x00")
    sock = open_l2cap(addr, psm=SDP_PSM, timeout=connect_timeout or timeout, factory=factory)
    try:
        sock.settimeout(timeout)
        sock.sendall(pdu)
        data = sock.recv(65535)
    finally:
        sock.close()
    handles, _ = _parse_sdp_search(data, tid)
    return handles


def sdp_browse(
    addr: str,
    timeout: float = 5.0,
    connect_timeout: float | None = None,
    factory=socket.socket,
) -> list[dict]:
    handles = sdp_search(
        addr,
        timeout=timeout,
        search_uuid=BROWSE_GROUP_UUID16,
        connect_timeout=connect_timeout,
        factory=factory,
    )
    if not handles:
        return []
    tid = 0x5678
    search = _encode_sequence(_encode_uint(handles[0], 4))
    attrs = _encode_attr_id_range(0x0000, 0xFFFF)
    pdu = b"\x06" + struct.pack(">H", tid) + search + attrs + struct.pack(">H", 0xFFFF) + b"\x00"
    sock = open_l2cap(addr, psm=SDP_PSM, timeout=connect_timeout or timeout, factory=factory)
    try:
        sock.settimeout(timeout)
        sock.sendall(pdu)
        data = sock.recv(65535)
    finally:
        sock.close()
    records = _parse_sdp_attr(data, tid)
    out: list[dict] = []
    for attrs in records:
        svc_ids = _extract_uuid16(attrs.get(0x0001, (None, []))[1]) if attrs.get(0x0001) else []
        proto_seqs: list[tuple[str, object]] = (attrs.get(0x0004) or (None, []))[1] if attrs.get(0x0004) else []
        rfcomm_channel = None
        for proto in proto_seqs:
            if proto[0] != "sequence":
                continue
            puuid = _extract_uuid16(proto[1])
            if RFCOMM_UUID16 in puuid:
                for inner in proto[1]:
                    if inner[0] == "uint":
                        rfcomm_channel = inner[1]
                        break
        name = _find_attr(attrs, ATTR_SERVICE_NAME, "string")
        desc = _find_attr(attrs, ATTR_SERVICE_DESC, "string")
        out.append({
            "record_handle": _find_attr(attrs, ATTR_RECORD_HANDLE),
            "service_uuids": [hex(u) for u in svc_ids],
            "rfcomm_channel": rfcomm_channel,
            "name": name or desc,
        })
    return out


def probe_hid_psms(
    addr: str,
    timeout: float = 1.0,
    factory=socket.socket,
) -> dict[str, bool]:
    results: dict[str, bool] = {}
    for psm, label in [(HIDP_CTRL_PSM, "ctrl"), (HIDP_INTR_PSM, "intr")]:
        try:
            s = factory(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
            s.settimeout(timeout)
            try:
                s.connect((addr, psm))
                results[label] = True
            except (TimeoutError, OSError):
                results[label] = False
            finally:
                try:
                    s.close()
                except OSError:
                    pass
        except OSError:
            results[label] = False
    return results


def detect(
    target: str,
    timeout: float = 5.0,
    connect_timeout: float = 4.0,
    channel_timeout: float = 0.4,
    include_sdps: bool = True,
    include_psms: bool = True,
    factory=socket.socket,
) -> dict:
    sweep_result = sweep(
        target,
        channels=range(1, 31),
        connect_timeout=connect_timeout,
        channel_timeout=channel_timeout,
        psm=0x0003,
        factory=factory,
    )
    sdp_records: list[dict] = []
    hid_psms: dict[str, bool] = {}
    if sweep_result.reachable:
        if include_sdps:
            try:
                sdp_records = sdp_browse(target, timeout=timeout, factory=factory)
            except OSError:
                pass
        if include_psms:
            hid_psms = probe_hid_psms(target, timeout=timeout, factory=factory)
    return {
        "target": target,
        "reachable": sweep_result.reachable,
        "psm_error": sweep_result.psm_error,
        "channels": sweep_result.channels,
        "sdp_records": sdp_records,
        "hid_psms": hid_psms,
        "hid_supported": all(hid_psms.values()) if hid_psms else False,
        "hid_uuid_present": any(
            any(u in (hex(HID_SVC_UUID16), hex(HID_KBD_SVC_UUID16), hex(HID_MOUSE_SVC_UUID16))
                for u in r.get("service_uuids", []))
            for r in sdp_records
        ),
    }