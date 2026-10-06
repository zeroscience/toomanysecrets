r"""BACnet/IP engine - Who-Is / I-Am device discovery (read-only, UDP/47808).

BACnet runs building automation (HVAC, lighting, access, energy). A **Who-Is** broadcast or
unicast prompts every device to answer with **I-Am**, revealing its device instance number and
vendor id - read-only discovery, nothing written. BACnet/IP is UDP, invisible to a TCP connect
scan, so this engine is not port-gated (it fires only under the opt-in `scan --ics`).

Parsing is pure (BVLC + NPDU + the I-Am APDU tags) and the socket probe is injectable, so it
unit-tests against captured bytes with no controller. Reading full device properties (object/model
name, firmware) via ReadProperty is a deliberate follow-on. Findings use `Category.ICS`.
"""
from __future__ import annotations

import struct
from typing import Callable, Optional

from ..findings import Finding, Severity
from .base import Engine, Target
from .ics_common import ics_findings, udp_probe

# A small ASHRAE BACnet vendor-id map (cover common ones, fall back to the id).
_VENDORS = {
    0: "ASHRAE", 2: "Honeywell", 3: "Trane", 5: "Johnson Controls", 8: "Delta Controls",
    9: "Siemens", 10: "Tridium", 24: "Reliable Controls", 36: "Automated Logic",
    42: "KMC Controls", 50: "Schneider Electric", 69: "Priva", 127: "Distech Controls",
}


def build_whois() -> bytes:
    """A unicast Who-Is (all devices): BVLC + NPDU + unconfirmed-request APDU Who-Is (0x08)."""
    bvlc = bytes([0x81, 0x0A, 0x00, 0x08])        # type, Original-Unicast-NPDU, length 8
    npdu = bytes([0x01, 0x00])                    # version 1, control 0 (no src/dest)
    apdu = bytes([0x10, 0x08])                    # unconfirmed request, service choice Who-Is
    return bvlc + npdu + apdu


def _apdu_offset(data: bytes) -> Optional[int]:
    """Offset of the APDU after BVLC(4) + NPDU, skipping any dest/source specifiers."""
    if len(data) < 6 or data[0] != 0x81:
        return None
    off = 4                                       # past the 4-byte BVLC header
    if data[off] != 0x01:                         # NPDU version
        return None
    control = data[off + 1]
    off += 2
    if control & 0x80:                            # network-layer message, not an APDU
        return None
    if control & 0x20:                            # destination present: DNET(2) DLEN(1) DADR(DLEN)
        if off + 3 > len(data):
            return None
        dlen = data[off + 2]
        off += 3 + dlen
    if control & 0x08:                            # source present: SNET(2) SLEN(1) SADR(SLEN)
        if off + 3 > len(data):
            return None
        slen = data[off + 2]
        off += 3 + slen
    if control & 0x20:                            # hop count follows when a destination was present
        off += 1
    return off if off <= len(data) else None


def _read_tag(data: bytes, off: int):
    """Read one BACnet application tag -> (tag_number, value_bytes, new_offset)."""
    tag = data[off]
    off += 1
    tag_num = tag >> 4
    length = tag & 0x07
    if length == 5:                               # extended length
        length = data[off]
        off += 1
    return tag_num, data[off:off + length], off + length


def parse_iam(data: bytes) -> Optional[dict]:
    """Parse an I-Am reply into {device_instance, vendor, vendor_id}, or None if not an I-Am."""
    off = _apdu_offset(data)
    if off is None or off + 2 > len(data):
        return None
    if data[off] != 0x10 or data[off + 1] != 0x00:   # unconfirmed request, service choice I-Am
        return None
    off += 2
    tags = []
    while off < len(data) and len(tags) < 4:
        try:
            tag_num, val, off = _read_tag(data, off)
        except IndexError:
            break
        tags.append((tag_num, val))
    if not tags or len(tags[0][1]) < 4:
        return None
    (objid,) = struct.unpack_from(">I", tags[0][1], 0)        # object identifier
    instance = objid & 0x3FFFFF
    obj_type = objid >> 22
    if obj_type != 8:                                         # must be a Device object
        return None
    vendor_id = int.from_bytes(tags[-1][1], "big") if tags[-1][1] else 0
    return {
        "device_instance": instance,
        "vendor_id": vendor_id,
        "vendor": _VENDORS.get(vendor_id, f"Vendor {vendor_id}"),
        "product": f"BACnet device {instance}",
    }


class BacnetEngine(Engine):
    """BACnet/IP Who-Is/I-Am. UDP/47808 (not port-gated); read-only single request."""

    name = "bacnet"

    def __init__(self, runner: Optional[Callable[[str], bytes]] = None):
        self._run = runner or (lambda host: udp_probe(host, 47808, build_whois()))

    def is_available(self) -> bool:
        return True

    def run(self, target: Target) -> list[Finding]:
        dev = parse_iam(self._run(target.host))
        if dev is None:
            return []
        return ics_findings(
            target.host, protocol="BACnet", exposed_id="bacnet-exposed",
            exposed_title="BACnet/IP device exposed", severity=Severity.MEDIUM, purdue=2,
            impact="An unauthenticated BACnet device answers on the network; BACnet has no "
                   "authentication, so anyone reachable can read and write building-automation "
                   "points (HVAC, lighting, access control, energy).",
            device=dev, inventory_id="bacnet-device-identity",
            evidence=f"I-Am: device {dev['device_instance']}, {dev['vendor']}")
