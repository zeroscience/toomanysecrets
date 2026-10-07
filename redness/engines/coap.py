r"""CoAP engine - resource discovery (read-only, UDP 5683).

CoAP (RFC 7252) is the constrained-device REST protocol for IoT. A GET to the well-known
`/.well-known/core` returns the device's resource list (CoRE link-format) - read-only discovery.
Plain CoAP on UDP/5683 is usually unauthenticated and unencrypted (DTLS/5684 is the secure
variant), so a response is both presence and an attack-surface map.

Parsing is pure (CoAP header + option delta decoding to confirm a response, payload after the
0xFF marker) and the socket probe is injectable, so it unit-tests against captured bytes with no
device. UDP, so not port-gated (runs un-gated like SNMP/BACnet). Findings use `Category.IOT`.
"""
from __future__ import annotations

import struct
from typing import Callable, Optional

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target
from .ics_common import udp_probe


def build_get_wellknown(msg_id: int = 1) -> bytes:
    """A confirmable CoAP GET /.well-known/core (two Uri-Path options)."""
    header = bytes([0x40, 0x01]) + struct.pack(">H", msg_id)        # ver1/CON/tkl0, GET, msg id
    opt = bytes([0xBB]) + b".well-known" + bytes([0x04]) + b"core"  # Uri-Path x2 (opt 11)
    return header + opt


def parse_coap(data: bytes) -> Optional[dict]:
    """Parse a CoAP response. Returns {code, success, payload} or None if not CoAP."""
    if len(data) < 4 or (data[0] >> 6) != 1:                        # version must be 1
        return None
    code = data[1]
    cls, detail = code >> 5, code & 0x1F
    payload = ""
    marker = data.find(b"\xff", 4)
    if marker != -1:
        payload = data[marker + 1:].decode("latin-1", "replace")
    return {"code": f"{cls}.{detail:02d}", "success": cls == 2, "payload": payload}


class CoapEngine(Engine):
    """CoAP /.well-known/core discovery. UDP/5683 (not port-gated); read-only GET."""

    name = "coap"

    def __init__(self, runner: Optional[Callable[[str], bytes]] = None):
        self._run = runner or (lambda host: udp_probe(host, 5683, build_get_wellknown()))

    def is_available(self) -> bool:
        return True

    def run(self, target: Target) -> list[Finding]:
        resp = parse_coap(self._run(target.host))
        if resp is None:
            return []
        res = resp["payload"][:400]
        return [Finding(
            id="coap-exposed",
            title="CoAP device exposed (unauthenticated)",
            severity=Severity.MEDIUM,
            category=Category.IOT,
            description=f"A CoAP endpoint at {target.host} answered a /.well-known/core query "
                        f"(response {resp['code']}). Plain CoAP has no authentication or "
                        f"encryption (DTLS/5684 is the secure variant).",
            impact="The device's resources are enumerable and, without DTLS, readable and writable "
                   "by anyone on the network - sensor data, actuators, and configuration.",
            remediation="Use CoAP over DTLS (coaps, UDP 5684) with credentials; restrict CoAP to "
                        "the device network; disable unauthenticated resources.",
            affected=[target.host],
            evidence=[Evidence(source="coap", detail=f"{resp['code']}; resources: {res}"
                               if res else f"{resp['code']}")],
            references=["https://datatracker.ietf.org/doc/html/rfc7252"],
            meta={"protocol": "CoAP", "resources": res},
        )]
