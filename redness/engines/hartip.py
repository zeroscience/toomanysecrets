r"""HART-IP engine - presence confirmation (read-only, TCP 5094).

HART-IP exposes HART field instrumentation over Ethernet, usually via a HART / WirelessHART
gateway (Emerson, Pepperl+Fuchs, ...) fronting many field devices in process industries
(oil/gas, chemical, water). It is frequently unauthenticated. We send ONE read-only **Session
Initiate** request; a valid HART-IP response confirms the gateway. Nothing is written.

Reading the gateway's field-device roster (HART Command 0 identity, long tags) rides a token-
passing PDU over an established session and - because public HART-IP captures are scarce - is
deferred to the gated enumeration tier and a real-gateway verify pass (contract-first, like RBCD /
DNP3 device attributes). A listening port is the exposure; a Session Initiate reply confirms it.
Findings use `Category.ICS`.

HART-IP header (8 bytes): version(1) msg_type(1) msg_id(1) status(1) seq(2 BE) byte_count(2 BE).
"""
from __future__ import annotations

import struct
from typing import Callable, Optional

from ..findings import Finding, Severity
from .base import Engine, Target
from .ics_common import ics_findings, tcp_connect

_VERSION = 1
_MT_REQUEST, _MT_RESPONSE = 0, 1
_MID_SESSION_INIT = 0


def build_session_initiate(seq: int = 1, timeout_ms: int = 30000) -> bytes:
    """A HART-IP Session Initiate request (master type = secondary, with an inactivity timeout)."""
    body = bytes([0x01]) + struct.pack(">I", timeout_ms)       # master type 1 + timeout
    header = struct.pack(">BBBBHH", _VERSION, _MT_REQUEST, _MID_SESSION_INIT, 0, seq,
                         8 + len(body))
    return header + body


def parse_hartip(data: bytes) -> Optional[dict]:
    """Parse a HART-IP header. Returns {version, msg_type, msg_id, status} or None if not HART-IP."""
    if len(data) < 8:
        return None
    version, msg_type, msg_id, status = data[0], data[1], data[2], data[3]
    if version != _VERSION or msg_type not in (_MT_RESPONSE, 2, 3):
        return None
    return {"version": version, "msg_type": msg_type, "msg_id": msg_id, "status": status}


class HartIpEngine(Engine):
    """HART-IP presence. Port-gated to TCP/5094; read-only Session Initiate probe."""

    name = "hart-ip"

    def __init__(self, runner: Optional[Callable[[str], tuple[bool, bytes]]] = None):
        self._run = runner or (lambda host: tcp_connect(host, 5094, build_session_initiate()))

    def is_available(self) -> bool:
        return True

    def run(self, target: Target) -> list[Finding]:
        connected, data = self._run(target.host)
        if not connected:
            return []
        impact = ("An unauthenticated HART-IP gateway exposes HART field instrumentation; a "
                  "reachable attacker can read and write field-device values and configuration "
                  "across every instrument behind the gateway.")
        hdr = parse_hartip(data)
        confirmed = "Session Initiate reply (HART-IP confirmed)" if hdr else \
                    "TCP/5094 open (no Session Initiate reply; confirm with the gated roster read)"
        return ics_findings(
            target.host, protocol="HART-IP", exposed_id="hart-ip-exposed",
            exposed_title="HART-IP gateway exposed", severity=Severity.HIGH, impact=impact,
            evidence=confirmed)
