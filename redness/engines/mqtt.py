r"""MQTT engine - anonymous broker access (read-only, TCP 1883).

MQTT is the default IoT/telemetry message bus. A broker that accepts an **anonymous** CONNECT
(no username/password) lets anyone subscribe to every topic (`#`) - sensor data, device state,
commands, and often credentials in payloads. We send ONE read-only CONNECT and read the CONNACK:
a success return code means anonymous access is allowed. We do NOT subscribe or read topic data
(that stays a gated, more-intrusive follow-on).

Parsing is pure (MQTT 3.1.1 CONNECT/CONNACK) and the socket probe is injectable, so it unit-tests
against captured bytes with no broker. Findings use `Category.IOT`. (8883/TLS is a follow-on.)
"""
from __future__ import annotations

import struct
from typing import Callable, Optional

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target
from .ics_common import tcp_probe

# MQTT CONNACK return codes (3.1.1): 0 accepted, 4 bad user/pass, 5 not authorized.
_RC = {0: "accepted", 1: "unacceptable protocol version", 2: "identifier rejected",
       3: "server unavailable", 4: "bad username or password", 5: "not authorized"}


def build_connect(client_id: str = "redness") -> bytes:
    """An anonymous MQTT 3.1.1 CONNECT (clean session, no credentials)."""
    var = b"\x00\x04MQTT" + bytes([0x04, 0x02]) + b"\x00\x3c"      # name, level 4, clean, keepalive
    payload = struct.pack(">H", len(client_id)) + client_id.encode()
    rest = var + payload
    return bytes([0x10, len(rest)]) + rest                         # CONNECT (len < 128)


def parse_connack(data: bytes) -> Optional[dict]:
    """Parse a CONNACK. Returns {return_code, accepted, meaning} or None if not a CONNACK."""
    if len(data) < 4 or (data[0] >> 4) != 0x02:                    # 0x20 = CONNACK
        return None
    rc = data[3]
    return {"return_code": rc, "accepted": rc == 0, "meaning": _RC.get(rc, f"rc {rc}")}


class MqttEngine(Engine):
    """MQTT anonymous-access check. Port-gated to TCP/1883; read-only CONNECT."""

    name = "mqtt"

    def __init__(self, runner: Optional[Callable[[str], bytes]] = None):
        self._run = runner or (lambda host: tcp_probe(host, 1883, build_connect()))

    def is_available(self) -> bool:
        return True

    def run(self, target: Target) -> list[Finding]:
        ack = parse_connack(self._run(target.host))
        if ack is None:
            return []
        if ack["accepted"]:
            return [Finding(
                id="mqtt-anonymous",
                title="MQTT broker allows anonymous access",
                severity=Severity.HIGH,
                category=Category.IOT,
                description=f"The MQTT broker at {target.host} accepted an anonymous CONNECT "
                            f"(no credentials).",
                impact="Anyone on the network can subscribe to every topic ('#') - sensor and "
                       "device telemetry, state, commands, and credentials often carried in "
                       "payloads - and publish rogue messages to connected devices.",
                remediation="Require authentication (allow_anonymous false); enforce per-topic "
                            "ACLs; use TLS (8883); restrict the broker to its device network.",
                affected=[target.host],
                evidence=[Evidence(source="mqtt", detail="anonymous CONNECT accepted (rc 0)")],
                references=["https://attack.mitre.org/techniques/T1133/"],
                meta={"protocol": "MQTT"},
            )]
        return [Finding(
            id="mqtt-exposed",
            title="MQTT broker exposed",
            severity=Severity.INFO,
            category=Category.IOT,
            description=f"An MQTT broker is reachable at {target.host} (anonymous access refused: "
                        f"{ack['meaning']}).",
            impact="The broker is network-reachable; credentialed or misconfigured ACL access may "
                   "still expose topic data.",
            remediation="Restrict the broker to its device network; enforce TLS and per-topic ACLs.",
            affected=[target.host],
            evidence=[Evidence(source="mqtt", detail=f"CONNACK rc {ack['return_code']} "
                               f"({ack['meaning']})")],
            meta={"protocol": "MQTT"},
        )]
