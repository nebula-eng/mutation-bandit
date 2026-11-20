"""Three instrumented parsers used as fuzzing targets.

Design rule that makes the benchmark meaningful: a *defect* is a check
the parser FAILS to perform, not a malformed input the parser correctly
rejects.  Truncated headers, bad checksums and illegal characters all
return cleanly.  Only the seeded defects raise ``InjectedBug``, and each
of them requires a structurally valid prefix to reach.  Consequently
time-to-first-bug measures the scheduler, not the mutation operator's
ability to append random bytes.

Instrumentation uses monotonically increasing node ids.  Because the
coverage map hashes ``node ^ prev``, the same node reached from two
different predecessors yields two distinct edges, which is what makes
"new coverage" a meaningful signal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from . import coverage as _cov
from .errors import Budget, bug


# --------------------------------------------------------------------------
# TLV: magic | count | (type, len, payload, crc8) * count
#      len == 0xFF selects a 2-byte big-endian extended length
#      type & 0x80 marks a nested TLV container
# --------------------------------------------------------------------------

def _crc8(payload: bytes) -> int:
    crc = 0x5A
    for byte in payload:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1D) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def _tlv_extract(data: bytes) -> list[tuple[int, bytes]]:
    """Best-effort structural parse used by the repair mutator."""
    if len(data) < 4 or data[:3] != b"TLV":
        return []
    count = data[3]
    off = 4
    records: list[tuple[int, bytes]] = []
    for _ in range(count):
        if off + 2 > len(data):
            break
        rtype = data[off]
        rlen = data[off + 1]
        off += 2
        if rlen == 0xFF:
            if off + 2 > len(data):
                break
            rlen = int.from_bytes(data[off : off + 2], "big")
            off += 2
        if off + rlen > len(data):
            break
        payload = data[off : off + rlen]
        off += rlen
        if off < len(data):
            off += 1  # existing crc byte, rewritten below
        records.append((rtype, payload))
    return records


def _tlv_fixup(data: bytes) -> bytes:
    """Recompute record count, extended lengths and every CRC.

    This is the structure-aware repair that stock AFL cannot perform
    without a grammar: it keeps checksum-valid inputs alive so the deep
    checksum-guarded paths stay reachable.
    """
    records = _tlv_extract(data)
    if not records:
        return data
    out = bytearray(b"TLV")
    out.append(len(records) & 0xFF)
    for rtype, payload in records:
        out.append(rtype & 0xFF)
        if len(payload) >= 0xFF:
            out.append(0xFF)
            out.extend(len(payload).to_bytes(2, "big"))
        else:
            out.append(len(payload) & 0xFF)
        out.extend(payload)
        out.append(_crc8(payload))
    return bytes(out)


def _run_tlv(data: bytes, budget: Budget, depth: int = 0) -> None:
    if len(data) < 4:
        return
    _cov.COV.hit(10)
    if data[:3] != b"TLV":
        return
    _cov.COV.hit(11)
    count = data[3]
    if count == 0:
        return
    _cov.COV.hit(12)
    off = 4
    total = 0
    for _ in range(count):
        budget.tick()
        _cov.COV.hit(13)
        if off + 2 > len(data):
            return
        rtype = data[off]
        rlen = data[off + 1]
        off += 2
        if rlen == 0xFF:
            _cov.COV.hit(22)
            if off + 2 > len(data):
                return
            rlen = int.from_bytes(data[off : off + 2], "big")
            off += 2
        if off + rlen + 1 > len(data):
            _cov.COV.hit(23)
            return
        _cov.COV.hit(14)
        payload = data[off : off + rlen]
        off += rlen
        crc = data[off]
        off += 1
        if rtype == 0 and rlen == 0:
            # Zero-length fast path frees the node twice.
            bug("tlv.zero_len_double_free")
        if crc == 0xFF:
            _cov.COV.hit(15)
            if rlen > 64:
                # The 0xFF sentinel is treated as "checksum disabled".
                bug("tlv.crc_sentinel_bypass")
        elif _crc8(payload) != crc:
            _cov.COV.hit(16)
            return
        else:
            _cov.COV.hit(17)
        total += rlen
        if total > 255 and count >= 4:
            # 8-bit accumulator in the reference implementation wraps.
            bug("tlv.total_len_wrap")
        if rtype & 0x80:
            _cov.COV.hit(18)
            if depth >= 3:
                # Recursion guard missing in the reference implementation.
                bug("tlv.nested_depth_unbounded")
            _run_tlv(payload, budget, depth + 1)
        if rtype == 0x40:
            _cov.COV.hit(19)
    _cov.COV.hit(20)
    if off < len(data) - 8:
        _cov.COV.hit(21)


def run_tlv(data: bytes, budget: Budget) -> None:
    _run_tlv(data, budget, 0)


# --------------------------------------------------------------------------
# JSON-lite
# --------------------------------------------------------------------------

WS = b" \t\r\n"
HEX = b"0123456789abcdefABCDEF"


def _skip_ws(data: bytes, i: int) -> int:
    while i < len(data) and data[i] in WS:
        i += 1
    return i


def _parse_string(data: bytes, i: int, budget: Budget) -> int:
    i += 1
    while i < len(data):
        budget.tick()
        ch = data[i]
        if ch == 0x22:
            return i + 1
        if ch == 0x5C:
            _cov.COV.hit(31)
            if i + 1 >= len(data):
                _cov.COV.hit(42)
                return i + 1
            esc = data[i + 1]
            if esc == 0x75:
                _cov.COV.hit(30)
                raw = data[i + 2 : i + 6]
                if len(raw) != 4:
                    _cov.COV.hit(43)
                    return i + 1
                for byte in raw:
                    if byte not in HEX:
                        _cov.COV.hit(44)
                        return i + 1
                i += 6
                continue
            i += 2
            continue
        if ch < 0x20:
            _cov.COV.hit(45)
            return i + 1
        i += 1
    return i


def _parse_value(data: bytes, i: int, depth: int, budget: Budget, seen: set[bytes]) -> int:
    budget.tick()
    i = _skip_ws(data, i)
    if i >= len(data):
        return i
    if depth > 48:
        # No depth counter in the reference implementation.
        bug("json.depth_overflow")
    ch = data[i]
    if ch == 0x7B:
        _cov.COV.hit(32)
        i = _skip_ws(data, i + 1)
        if i < len(data) and data[i] == 0x7D:
            _cov.COV.hit(46)
            return i + 1
        while i < len(data):
            i = _skip_ws(data, i)
            if i >= len(data) or data[i] != 0x22:
                return i
            key_start = i
            i = _parse_string(data, i, budget)
            key = data[key_start:i]
            if depth == 0:
                _cov.COV.hit(33)
                if key in seen:
                    # Duplicate key frees the previous value while it is
                    # still referenced by the member table.
                    bug("json.duplicate_key")
                seen.add(key)
            i = _skip_ws(data, i)
            if i >= len(data) or data[i] != 0x3A:
                return i
            _cov.COV.hit(47)
            i = _parse_value(data, i + 1, depth + 1, budget, seen)
            i = _skip_ws(data, i)
            if i < len(data) and data[i] == 0x2C:
                i += 1
                continue
            if i < len(data) and data[i] == 0x7D:
                return i + 1
            return i
        return i
    if ch == 0x5B:
        _cov.COV.hit(34)
        i = _skip_ws(data, i + 1)
        if i < len(data) and data[i] == 0x5D:
            _cov.COV.hit(48)
            return i + 1
        while i < len(data):
            i = _parse_value(data, i, depth + 1, budget, seen)
            i = _skip_ws(data, i)
            if i < len(data) and data[i] == 0x2C:
                i += 1
                continue
            if i < len(data) and data[i] == 0x5D:
                return i + 1
            return i
        return i
    if ch == 0x22:
        _cov.COV.hit(35)
        return _parse_string(data, i, budget)
    if ch in b"-0123456789":
        _cov.COV.hit(36)
        start = i
        if data[i] == 0x2D:
            i += 1
        while i < len(data) and data[i] in b"0123456789.eE+-":
            i += 1
        if i - start > 64:
            # Fixed 64-byte decimal buffer in the reference implementation.
            bug("json.number_buffer_overflow")
        return i
    if data[i : i + 4] == b"true":
        _cov.COV.hit(37)
        return i + 4
    if data[i : i + 5] == b"false":
        _cov.COV.hit(38)
        return i + 5
    if data[i : i + 4] == b"null":
        _cov.COV.hit(39)
        return i + 4
    _cov.COV.hit(49)
    return i


def run_json(data: bytes, budget: Budget) -> None:
    if not data:
        return
    _cov.COV.hit(40)
    _parse_value(data, 0, 0, budget, set())


def _json_fixup(data: bytes) -> bytes:
    """Close dangling brackets and quote an unterminated string."""
    stack: list[int] = []
    in_string = False
    escape = False
    for byte in data:
        if in_string:
            if escape:
                escape = False
            elif byte == 0x5C:
                escape = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte == 0x7B:
            stack.append(0x7D)
        elif byte == 0x5B:
            stack.append(0x5D)
        elif byte in (0x7D, 0x5D) and stack and stack[-1] == byte:
            stack.pop()
    out = bytearray(data)
    if in_string:
        out.append(0x22)
    while stack:
        out.append(stack.pop())
    return bytes(out)


# --------------------------------------------------------------------------
# URL: scheme://[userinfo@]host[:port][/path][?query]
# --------------------------------------------------------------------------

def run_url(data: bytes, budget: Budget) -> None:
    if not data:
        return
    _cov.COV.hit(50)
    sep = data.find(b"://")
    if sep <= 0:
        return
    _cov.COV.hit(51)
    for byte in data[:sep]:
        budget.tick()
        if not (0x61 <= byte <= 0x7A or 0x41 <= byte <= 0x5A):
            return
    rest = data[sep + 3 :]
    if not rest:
        return
    _cov.COV.hit(52)
    authority = rest.split(b"/", 1)[0].split(b"?", 1)[0]
    at_count = authority.count(b"@")
    if at_count > 1:
        # Userinfo split takes the first '@'; host validation takes the last.
        bug("url.userinfo_confusion")
    if at_count == 1:
        _cov.COV.hit(53)
        authority = authority.split(b"@", 1)[1]
    if not authority:
        return
    _cov.COV.hit(54)
    host = authority
    port = -1
    if b":" in authority and not authority.startswith(b"["):
        host, _, port_raw = authority.rpartition(b":")
        _cov.COV.hit(55)
        if port_raw and all(0x30 <= b <= 0x39 for b in port_raw):
            _cov.COV.hit(56)
            if len(port_raw) >= 5:
                port = int(port_raw)
                if port > 65535:
                    # 16-bit port field truncated instead of rejected.
                    bug("url.port_truncation")
            else:
                port = int(port_raw)
    if not host:
        return
    if b"%00" in host or b"\x00" in host:
        bug("url.nul_byte_host")
    _cov.COV.hit(57)
    if len(host) > 253:
        bug("url.host_too_long")
    if port == 0:
        _cov.COV.hit(59)
    if b"?" in rest:
        _cov.COV.hit(61)
        query = rest.split(b"?", 1)[1]
        pairs = 0
        for pair in query.split(b"&"):
            budget.tick()
            pairs += 1
            _cov.COV.hit(62)
            if b"=" not in pair:
                continue
            key, _, value = pair.partition(b"=")
            if not key:
                _cov.COV.hit(63)
            i = 0
            while i < len(value):
                budget.tick()
                if value[i] == 0x25:
                    _cov.COV.hit(64)
                    if i + 2 >= len(value):
                        _cov.COV.hit(65)
                        return
                    if value[i + 1] not in HEX or value[i + 2] not in HEX:
                        _cov.COV.hit(66)
                        return
                    i += 3
                    continue
                i += 1
        if pairs > 8:
            _cov.COV.hit(67)
    _cov.COV.hit(60)


def _url_fixup(data: bytes) -> bytes:
    if b"://" not in data:
        return b"http://" + data if data else data
    return data


# --------------------------------------------------------------------------
# Target registry
# --------------------------------------------------------------------------

@dataclass
class Target:
    name: str
    entry: Callable[[bytes, Budget], None]
    fixup: Callable[[bytes], bytes]
    seeds: list[bytes]
    dictionary: list[bytes]
    bugs: list[str] = field(default_factory=list)
    deep: list[str] = field(default_factory=list)

    def run(self, data: bytes, budget: Budget) -> None:
        self.entry(data, budget)


TLV_SEEDS = [
    b"TLV\x02\x01\x03abc\x00\x02\x02de\x00",
    b"TLV\x01\x40\x04data\x00",
    b"TLV\x03\x01\x00\x00\x02\x01\x00\x03\x02hi\x00",
]

JSON_SEEDS = [
    b'{"a":1,"b":[true,null,"x"]}',
    b'[1,2,{"k":"v"}]',
    b'{"name":"value","n":-1.5e3}',
]

URL_SEEDS = [
    b"https://example.com:443/a?b=c",
    b"http://user@host:80/",
    b"ftp://host/path?x=1&y=2",
]

TARGETS: dict[str, Target] = {
    "tlv": Target(
        name="tlv",
        entry=run_tlv,
        fixup=_tlv_fixup,
        seeds=TLV_SEEDS,
        dictionary=[b"TLV", b"\x00\x00", b"\xff", b"EOF", b"\x00\xff", b"\x80", b"\x00\x01"],
        bugs=[
            "tlv.zero_len_double_free",
            "tlv.crc_sentinel_bypass",
            "tlv.total_len_wrap",
            "tlv.nested_depth_unbounded",
        ],
        deep=["tlv.crc_sentinel_bypass", "tlv.total_len_wrap", "tlv.nested_depth_unbounded"],
    ),
    "json": Target(
        name="json",
        entry=run_json,
        fixup=_json_fixup,
        seeds=JSON_SEEDS,
        dictionary=[b'"', b"{", b"}", b"[", b"]", b"\\u", b"true", b"null", b"-0.0e9", b'":"'],
        bugs=[
            "json.depth_overflow",
            "json.duplicate_key",
            "json.number_buffer_overflow",
        ],
        deep=["json.depth_overflow", "json.number_buffer_overflow"],
    ),
    "url": Target(
        name="url",
        entry=run_url,
        fixup=_url_fixup,
        seeds=URL_SEEDS,
        dictionary=[b"://", b"@", b"%00", b":", b"?", b"&", b"=", b"65536"],
        bugs=[
            "url.userinfo_confusion",
            "url.port_truncation",
            "url.nul_byte_host",
            "url.host_too_long",
        ],
        deep=["url.port_truncation", "url.host_too_long"],
    ),
}
