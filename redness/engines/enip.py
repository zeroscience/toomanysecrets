r"""EtherNet/IP (CIP) engine - List Identity (read-only, TCP/UDP 44818).

EtherNet/IP is CIP over Ethernet (Allen-Bradley/Rockwell, Omron, and many others). The
**List Identity** encapsulation command (0x63) needs no session and no auth: one request returns
the device's vendor, product name/code, device type, revision, serial, and run/program state.
That is the perfect OT identity probe - a single read-only packet, nothing written.

We send it over TCP/44818 so the discovery dispatcher can port-gate it. Parsing is pure (struct
unpacking of the encapsulation header + CPF Identity item) and the socket probe is injectable, so
it unit-tests against captured bytes with no PLC. Findings use `Category.ICS`.

Request = a 24-byte encapsulation header, command 0x0063, zero length/session/status.
Response = that header echoed + a CPF item (type 0x000C) carrying the Identity object.
"""
from __future__ import annotations

import struct
from typing import Callable, Optional

from ..findings import Finding, Severity
from .base import Engine, Target
from .ics_common import ics_findings, tcp_probe

# A small ODVA vendor-id map (the full list is huge; cover the common ones, fall back to the id).
_VENDORS = {
    1: "Rockwell Automation/Allen-Bradley", 5: "Koyo", 10: "Omron", 26: "Festo",
    40: "WAGO", 47: "SEW Eurodrive", 48: "Phoenix Contact", 108: "Beckhoff",
    256: "Schneider Electric", 283: "HMS/Anybus", 356: "Moxa", 649: "Hilscher",
}
# CIP device type ids (subset).
_DEV_TYPES = {
    0x00: "Generic", 0x02: "AC Drive", 0x0C: "Communications Adapter",
    0x0E: "Programmable Logic Controller", 0x64: "Safety Discrete I/O",
    0x07: "General Purpose Discrete I/O", 0x2B: "ControlNet Adapter",
}
# Identity status word bit 0x0C..0x0F encode the controller run/program state on some devices.
_STATES = {0: "Nonexistent", 2: "Standby", 3: "Operational", 4: "Major Recoverable Fault",
           5: "Major Unrecoverable Fault"}


def build_list_identity() -> bytes:
    """The 24-byte List Identity encapsulation request (command 0x0063, empty body)."""
    return struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"\x00" * 8, 0)


def parse_list_identity(data: bytes) -> Optional[dict]:
    """Parse a List Identity reply into a device dict, or None if it is not a valid one.

    Returns at least {"_enip": True} when the encapsulation header echoes command 0x63 but no
    Identity item is present (the device spoke EtherNet/IP but gave no identity), so the caller
    can still raise an exposure finding.
    """
    if len(data) < 24:
        return None
    cmd, length, _sess, _status = struct.unpack_from("<HHII", data, 0)
    if cmd != 0x0063:
        return None
    body = data[24:24 + length] if length else data[24:]
    if len(body) < 2:
        return {"_enip": True}
    (item_count,) = struct.unpack_from("<H", body, 0)
    off = 2
    for _ in range(item_count):
        if off + 4 > len(body):
            break
        type_id, item_len = struct.unpack_from("<HH", body, off)
        off += 4
        item = body[off:off + item_len]
        off += item_len
        if type_id != 0x000C or len(item) < 33:
            continue
        # Identity item: encap ver(2) + sockaddr(16) + vendor(2) + devtype(2) + prodcode(2)
        #                + rev(2) + status(2) + serial(4) + name_len(1) + name(n) + state(1)
        vendor, devtype, prodcode = struct.unpack_from("<HHH", item, 18)
        rev_major, rev_minor = item[24], item[25]
        (status,) = struct.unpack_from("<H", item, 26)
        (serial,) = struct.unpack_from("<I", item, 28)
        name_len = item[32]
        name = item[33:33 + name_len].decode("latin-1", "replace").strip()
        state = item[33 + name_len] if len(item) > 33 + name_len else None
        dev = {
            "vendor": _VENDORS.get(vendor, f"Vendor {vendor}"),
            "vendor_id": vendor,
            "product": name or _DEV_TYPES.get(devtype, f"DeviceType {devtype}"),
            "device_type": _DEV_TYPES.get(devtype, f"0x{devtype:02X}"),
            "product_code": prodcode,
            "revision": f"{rev_major}.{rev_minor}",
            "serial": f"0x{serial:08X}",
        }
        if state is not None and state in _STATES:
            dev["state"] = _STATES[state]
        return dev
    return {"_enip": True}


class EnipEngine(Engine):
    """EtherNet/IP List Identity. Port-gated to TCP/44818; read-only single request."""

    name = "enip"

    def __init__(self, runner: Optional[Callable[[str], bytes]] = None):
        self._run = runner or (lambda host: tcp_probe(host, 44818, build_list_identity()))

    def is_available(self) -> bool:
        return True                               # pure socket, no external tool

    def run(self, target: Target) -> list[Finding]:
        dev = parse_list_identity(self._run(target.host))
        if dev is None:
            return []
        if dev.get("_enip"):                      # spoke ENIP but gave no identity
            return ics_findings(
                target.host, protocol="EtherNet/IP", exposed_id="enip-exposed",
                exposed_title="EtherNet/IP (CIP) endpoint exposed", severity=Severity.HIGH,
                impact="An unauthenticated EtherNet/IP endpoint lets anyone on the network read and "
                       "potentially write CIP objects - device configuration and, on a PLC, control "
                       "logic and run state.",
                evidence="List Identity answered (no identity object returned)")
        from .ics_common import device_summary
        return ics_findings(
            target.host, protocol="EtherNet/IP", exposed_id="enip-exposed",
            exposed_title="EtherNet/IP (CIP) endpoint exposed", severity=Severity.HIGH,
            impact="An unauthenticated EtherNet/IP endpoint lets anyone on the network read and "
                   "potentially write CIP objects - device configuration and, on a PLC, control "
                   "logic and run state.",
            device=dev, inventory_id="enip-device-identity",
            evidence=f"List Identity: {device_summary(dev)}")
