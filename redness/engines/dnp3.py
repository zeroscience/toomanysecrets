r"""DNP3 engine - presence + outstation address discovery (read-only, TCP 20000).

DNP3 (IEEE 1815) runs electric / water / gas SCADA. Without DNP3 Secure Authentication it is
unauthenticated: reaching TCP/20000 means you can read (and, with control function codes, write)
an outstation. We send ONE read-only data-link **Request Link Status** frame (function 0x09) to
the self-address (0xFFFC); an outstation that answers reveals its real data-link address and
confirms DNP3. Nothing is written, no points are operated.

A listening port (connect succeeds) is already the exposure; a Link Status reply upgrades it to
confirmed and yields the outstation/master addresses. Reading Group 0 device attributes
(vendor / firmware / model) needs the application layer and the outstation's address, so it is
deferred to the gated enumeration tier + a real-outstation verify pass (same contract-first
caution as RBCD). The DNP3 outstation-address SCAN (0..65519) is likewise deferred - it can upset
old outstations. Findings use `Category.ICS`.
"""
from __future__ import annotations

import struct
from typing import Callable, Optional

from ..findings import Finding, Severity
from .base import Engine, Target
from .ics_common import ics_findings, tcp_connect

_SELF_ADDRESS = 0xFFFC                 # DNP3 self-address: an outstation replies with its real addr
_FUNC = {0x00: "Reset Link", 0x09: "Request Link Status", 0x0B: "Link Status",
         0x04: "Unconfirmed User Data", 0x03: "Test Link"}


def dnp3_crc(data: bytes) -> int:
    """DNP3 data-link CRC-16 (reflected poly 0xA6BC, final one's-complement). Transmitted LE."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def build_request_link_status(dest: int = _SELF_ADDRESS, src: int = 1) -> bytes:
    """A DNP3 Request Link Status frame (master -> outstation), CRC appended."""
    ctrl = 0xC9                                   # DIR=1, PRM=1, FCB=0, FCV=0, func=0x09
    header = bytes([0x05, 0x64, 0x05, ctrl]) + struct.pack("<HH", dest, src)
    return header + struct.pack("<H", dnp3_crc(header[2:]))   # CRC over LEN..SRC


def parse_link_frame(data: bytes) -> Optional[dict]:
    """Parse a DNP3 data-link frame header. Returns {func, src_addr, dest_addr} or None."""
    if len(data) < 10 or data[0] != 0x05 or data[1] != 0x64:
        return None
    ctrl = data[3]
    dest, src = struct.unpack_from("<HH", data, 4)
    func = ctrl & 0x0F
    return {"func": func, "func_name": _FUNC.get(func, f"0x{func:02X}"),
            "dest_addr": dest, "src_addr": src}


class Dnp3Engine(Engine):
    """DNP3 presence + outstation address. Port-gated to TCP/20000; read-only link-status probe."""

    name = "dnp3"

    def __init__(self, dest: int = _SELF_ADDRESS,
                 runner: Optional[Callable[[str], tuple[bool, bytes]]] = None):
        self.dest = dest
        self._run = runner or (lambda host: tcp_connect(host, 20000,
                                                         build_request_link_status(dest)))

    def is_available(self) -> bool:
        return True

    def run(self, target: Target) -> list[Finding]:
        connected, data = self._run(target.host)
        if not connected:
            return []
        impact = ("Unauthenticated DNP3 (no DNP3 Secure Authentication) lets a reachable attacker "
                  "read and operate SCADA points - directly affecting the physical process, and "
                  "DNP3 drives electric/water/gas utilities.")
        frame = parse_link_frame(data)
        if frame:                                 # confirmed DNP3: we have the outstation address
            device = {"vendor": "DNP3 outstation",
                      "product": f"outstation addr {frame['src_addr']}",
                      "extra": f"master addr {frame['dest_addr']}, {frame['func_name']}"}
            return ics_findings(
                target.host, protocol="DNP3", exposed_id="dnp3-exposed",
                exposed_title="DNP3 outstation exposed", severity=Severity.HIGH, impact=impact,
                device=device, inventory_id="dnp3-outstation",
                evidence=f"Link Status reply: outstation addr {frame['src_addr']}")
        # Port open but no link-layer reply (outstation likely needs its specific address).
        return ics_findings(
            target.host, protocol="DNP3", exposed_id="dnp3-exposed",
            exposed_title="DNP3 service exposed", severity=Severity.HIGH, impact=impact,
            evidence="TCP/20000 open (no Link Status reply; confirm the outstation address via the "
                     "gated DNP3 address scan)")
