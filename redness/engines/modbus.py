r"""Modbus/TCP engine - Read Device Identification (read-only, TCP/502).

Modbus has no authentication or encryption whatsoever: if you can reach TCP/502 you can read
(and, with other function codes, write) the device. We send ONLY the read-only **Read Device
Identification** request (function 0x2B / MEI 0x0E) - it returns VendorName, ProductCode,
Revision, ProductName and never touches coils, registers or process data. A device that answers
at all (even an exception) proves Modbus is exposed.

Parsing is pure (MBAP header + the device-id object list) and the socket probe is injectable, so
it unit-tests against captured bytes with no PLC. The louder unit-id sweep (mapping serial RTUs
behind a Modbus/TCP gateway) is deliberately NOT done here - it waits behind its own opt-in.
Findings use `Category.ICS`.
"""
from __future__ import annotations

import struct
from typing import Callable, Optional

from ..findings import Finding, Severity
from .base import Engine, Target
from .ics_common import device_summary, ics_findings, tcp_probe

_TXID = 0x0001
# Read Device Identification object ids (MEI 0x0E).
_OBJ_VENDOR, _OBJ_CODE, _OBJ_REV, _OBJ_NAME, _OBJ_MODEL = 0x00, 0x01, 0x02, 0x04, 0x05


def build_read_device_id(unit: int = 1) -> bytes:
    """Read Device Identification (basic, object 0) request for one unit id."""
    pdu = bytes([0x2B, 0x0E, 0x01, 0x00])                 # fn, MEI, read-dev-id code, object id
    mbap = struct.pack(">HHHB", _TXID, 0, 1 + len(pdu), unit)   # txid, proto=0, len, unit
    return mbap + pdu


def parse_device_id(data: bytes) -> Optional[dict]:
    """Parse a Read Device Identification reply.

    Returns a device dict (vendor/product/revision) when objects are present; {"_modbus": True}
    when the device answered as Modbus but without identity (an exception, or an unparsable body);
    None if the bytes are not a Modbus/TCP reply at all.
    """
    if len(data) < 8:
        return None
    txid, proto, _length, _unit = struct.unpack_from(">HHHB", data, 0)
    if proto != 0:
        return None
    fn = data[7]
    if fn == 0xAB:                                        # 0x2B | 0x80 -> exception: Modbus, no id
        return {"_modbus": True}
    if fn != 0x2B or len(data) < 14 or data[8] != 0x0E:
        return {"_modbus": True}                          # answered as Modbus, but not a dev-id body
    num_objects = data[13]
    off = 14
    objs: dict[int, str] = {}
    for _ in range(num_objects):
        if off + 2 > len(data):
            break
        obj_id, obj_len = data[off], data[off + 1]
        off += 2
        objs[obj_id] = data[off:off + obj_len].decode("latin-1", "replace").strip()
        off += obj_len
    if not objs:
        return {"_modbus": True}
    dev = {}
    if objs.get(_OBJ_VENDOR):
        dev["vendor"] = objs[_OBJ_VENDOR]
    product = objs.get(_OBJ_NAME) or objs.get(_OBJ_MODEL) or objs.get(_OBJ_CODE)
    if product:
        dev["product"] = product
    if objs.get(_OBJ_REV):
        dev["revision"] = objs[_OBJ_REV]
    return dev or {"_modbus": True}


class ModbusEngine(Engine):
    """Modbus/TCP Read Device Identification. Port-gated to TCP/502; read-only single request."""

    name = "modbus"

    def __init__(self, unit: int = 1, runner: Optional[Callable[[str], bytes]] = None):
        self.unit = unit
        self._run = runner or (lambda host: tcp_probe(host, 502, build_read_device_id(unit)))

    def is_available(self) -> bool:
        return True

    def run(self, target: Target) -> list[Finding]:
        dev = parse_device_id(self._run(target.host))
        if dev is None:
            return []
        impact = ("Unauthenticated Modbus lets anyone on the network read process data and write "
                  "coils/registers - directly manipulating the physical process a PLC controls.")
        if dev.get("_modbus"):
            return ics_findings(
                target.host, protocol="Modbus", exposed_id="modbus-exposed",
                exposed_title="Modbus/TCP endpoint exposed", severity=Severity.HIGH, impact=impact,
                evidence="Modbus/TCP answered (no device identification returned)")
        return ics_findings(
            target.host, protocol="Modbus", exposed_id="modbus-exposed",
            exposed_title="Modbus/TCP endpoint exposed", severity=Severity.HIGH, impact=impact,
            device=dev, inventory_id="modbus-device-identity",
            evidence=f"Read Device Identification: {device_summary(dev)}")
