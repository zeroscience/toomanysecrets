r"""OT enumeration tier - louder, still read-only, explicitly opt-in (`scan --ics-enum`).

The default OT probes send ONE identity request per host. This tier *sweeps*: it maps the serial
RTUs behind a Modbus/TCP gateway (unit-id sweep) and the outstations on a DNP3 segment (address
scan). Still read-only (identity / link-status only, never writes a point), but a broad sweep can
upset fragile outstations, so it lives behind its own opt-in and reuses the already-tested parsers.

  * `ModbusSweepEngine` - Read Device Identification across unit ids -> `modbus-gateway-units`.
  * `Dnp3ScanEngine`     - Request Link Status across outstation addresses -> `dnp3-segment`.

Deferred to a real-device verify pass (public captures are scarce): DNP3 Group 0 device attributes
and the HART-IP field-device roster (both ride the application/session layer).
"""
from __future__ import annotations

from typing import Callable, Optional

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target
from .dnp3 import build_request_link_status, parse_link_frame
from .ics_common import device_summary, ics_findings, tcp_connect, tcp_probe
from .modbus import build_read_device_id, parse_device_id

# Modest default ranges (read-only but a sweep): widen via the constructor for a full enumeration.
_MODBUS_UNITS = tuple(range(1, 17))                 # serial RTUs behind a gateway (unit ids 1..16)
_DNP3_ADDRS = (0xFFFC, 0, 1, 2, 3, 4, 5, 10, 100, 1024)   # self-address + common outstation addrs


class ModbusSweepEngine(Engine):
    """Modbus unit-id sweep -> the serial RTUs behind a Modbus/TCP gateway. Port-gated to 502."""

    name = "modbus"

    def __init__(self, units=_MODBUS_UNITS,
                 runner: Optional[Callable[[str, int], bytes]] = None):
        self.units = list(units)
        self._run = runner or (lambda host, unit: tcp_probe(host, 502,
                                                            build_read_device_id(unit)))

    def is_available(self) -> bool:
        return True

    def run(self, target: Target) -> list[Finding]:
        found: list[tuple[int, Optional[dict]]] = []
        for unit in self.units:
            dev = parse_device_id(self._run(target.host, unit))
            if dev is not None:
                found.append((unit, None if dev.get("_modbus") else dev))
        if not found:
            return []
        units = [u for u, _ in found]
        impact = ("Unauthenticated Modbus lets anyone on the network read process data and write "
                  "coils/registers across every unit behind this gateway.")
        out = ics_findings(
            target.host, protocol="Modbus", exposed_id="modbus-exposed",
            exposed_title="Modbus/TCP gateway exposed", severity=Severity.HIGH, impact=impact,
            evidence=f"{len(units)} unit id(s) responding behind the gateway: {units}")
        devices = [{"unit": u, **(d or {})} for u, d in found]
        out.append(Finding(
            id="modbus-gateway-units",
            title=f"Modbus gateway fronts {len(units)} serial unit(s)",
            severity=Severity.INFO, category=Category.ICS,
            description=f"A Modbus/TCP gateway at {target.host} relays to {len(units)} serial unit "
                        f"id(s): {units}.",
            impact="Each unit is a separate field device reachable through the one gateway; map "
                   "them for targeted follow-up.",
            remediation="Restrict the gateway to its control network; see the Modbus exposure "
                        "finding.",
            affected=[target.host],
            evidence=[Evidence(source="modbus",
                               detail="; ".join(f"unit {u}: {device_summary(d) or 'responded'}"
                                                for u, d in found))],
            meta={"protocol": "Modbus", "purdue": 1, "units": devices},
        ))
        return out


class Dnp3ScanEngine(Engine):
    """DNP3 outstation-address scan -> the outstations on a DNP3 segment. Port-gated to 20000."""

    name = "dnp3"

    def __init__(self, addrs=_DNP3_ADDRS,
                 runner: Optional[Callable[[str, int], tuple[bool, bytes]]] = None):
        self.addrs = list(addrs)
        self._run = runner or (lambda host, addr: tcp_connect(host, 20000,
                                                              build_request_link_status(addr)))

    def is_available(self) -> bool:
        return True

    def run(self, target: Target) -> list[Finding]:
        connected_any = False
        outstations: list[int] = []
        for addr in self.addrs:
            connected, data = self._run(target.host, addr)
            connected_any = connected_any or connected
            frame = parse_link_frame(data) if connected else None
            if frame and frame["src_addr"] not in outstations:
                outstations.append(frame["src_addr"])
        if not connected_any:
            return []
        impact = ("Unauthenticated DNP3 (no Secure Authentication) lets a reachable attacker read "
                  "and operate SCADA points across every outstation on this segment.")
        out = ics_findings(
            target.host, protocol="DNP3", exposed_id="dnp3-exposed",
            exposed_title="DNP3 service exposed", severity=Severity.HIGH, impact=impact,
            evidence=(f"outstation address(es) discovered: {sorted(outstations)}" if outstations
                      else "TCP/20000 open (no Link Status reply across the scanned addresses)"))
        if outstations:
            out.append(Finding(
                id="dnp3-segment",
                title=f"DNP3 segment: {len(outstations)} outstation(s)",
                severity=Severity.INFO, category=Category.ICS,
                description=f"Request Link Status at {target.host} revealed outstation address(es) "
                            f"{sorted(outstations)}.",
                impact="Each address is a separate DNP3 outstation reachable at this endpoint.",
                remediation="Restrict DNP3 to its control network; enable DNP3 Secure "
                            "Authentication.",
                affected=[target.host],
                evidence=[Evidence(source="dnp3",
                                   detail=f"outstations: {sorted(outstations)}")],
                meta={"protocol": "DNP3", "purdue": 2, "outstations": sorted(outstations)},
            ))
        return out
