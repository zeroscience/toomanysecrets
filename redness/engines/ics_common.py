r"""Shared helpers for the ICS/OT field-protocol engines (Modbus / CIP / DNP3 / HART-IP / BACnet).

Every OT engine here follows one shape: a SINGLE read-only identity request to a control
protocol, yielding up to two findings - an **exposure** finding (an unauthenticated control
protocol is reachable; these protocols have no auth/crypto by design) and a **device-identity**
INFO (asset inventory: vendor / product / serial / firmware). Pure parsers plus an injected
socket probe, so parsers + findings unit-test against captured bytes with no live PLC.

SAFETY - read this before adding an engine:
  * Send ONE read-only identity request and read the reply. Never write a coil/register/point,
    never change controller state, never a "write-echo" liveness test.
  * Engines are port-gated by the discovery dispatcher (only probed when the port is open) and
    the whole pack is opt-in (`scan --ics`), because even a read request can upset fragile kit.
  * The louder enumeration tiers (Modbus unit-id sweep, DNP3 outstation-address scan, HART
    wireless-roster walk) stay behind their own explicit opt-in, not the default identity probe.

Findings use `Category.ICS` with `meta["protocol"]`, `meta["purdue"]` (Purdue model level), and,
when identity is read, `meta["device"]` (vendor / product / serial / revision).
"""
from __future__ import annotations

import socket
from typing import Optional

from ..findings import Category, Evidence, Finding, Severity

# MITRE ATT&CK for ICS: Remote Services (T0886), plus the general ICS guidance.
_MITRE_ICS = "https://attack.mitre.org/techniques/T0886/"
_CISA_ICS = "https://www.cisa.gov/topics/industrial-control-systems"

_REMEDIATION = (
    "Segment OT from IT behind a control-network boundary (Purdue model) with a DMZ/jump host; "
    "restrict the protocol to engineering workstations by firewall/ACL; disable unused services; "
    "enable device-side authentication where supported (e.g. DNP3 Secure Authentication, "
    "CIP Security). Control protocols must never be reachable from a general-purpose network."
)


def tcp_probe(host: str, port: int, payload: bytes, *, timeout: float = 4.0,
              recv: int = 4096) -> bytes:
    """One read-only TCP request/response. Returns the reply bytes, or b'' on any failure."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if payload:
                s.sendall(payload)
            return s.recv(recv)
    except OSError:
        return b""


def udp_probe(host: str, port: int, payload: bytes, *, timeout: float = 4.0,
              recv: int = 4096) -> bytes:
    """One read-only UDP request/response. Returns the reply bytes, or b'' on any failure."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(payload, (host, port))
        data, _ = s.recvfrom(recv)
        return data
    except OSError:
        return b""
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def device_summary(device: Optional[dict]) -> str:
    """Compact 'Vendor Product rev X.Y (serial ...)' line for evidence/labels."""
    if not device:
        return ""
    bits = [str(device[k]) for k in ("vendor", "product") if device.get(k)]
    if device.get("revision"):
        bits.append(f"rev {device['revision']}")
    if device.get("firmware"):
        bits.append(f"fw {device['firmware']}")
    s = " ".join(bits)
    if device.get("serial"):
        s += f" (serial {device['serial']})"
    return s.strip()


def ics_findings(host: str, *, protocol: str, exposed_id: str, exposed_title: str,
                 impact: str, severity: Severity = Severity.HIGH, purdue: int = 1,
                 device: Optional[dict] = None, inventory_id: str = "",
                 evidence: str = "") -> list[Finding]:
    """Build the standard OT pair: an exposure finding, plus a device-identity INFO when read.

    `device` is a dict (vendor / product / revision / firmware / serial / extra) when the
    identity probe succeeded; omit it when the protocol merely answered without identity.
    """
    meta = {"protocol": protocol, "purdue": purdue}
    if device:
        meta["device"] = device
    ev = [Evidence(source=protocol, detail=evidence or f"{protocol} endpoint reachable")]
    out = [Finding(
        id=exposed_id,
        title=exposed_title,
        severity=severity,
        category=Category.ICS,
        description=(f"An unauthenticated {protocol} control-protocol endpoint is reachable at "
                     f"{host}. OT field protocols carry no authentication or encryption by design, "
                     f"so network reachability is itself the exposure."),
        impact=impact,
        remediation=_REMEDIATION,
        affected=[host],
        evidence=ev,
        references=[_MITRE_ICS, _CISA_ICS],
        meta=meta,
    )]
    if device:
        summary = device_summary(device) or protocol
        out.append(Finding(
            id=inventory_id or f"{protocol.lower()}-device-identity",
            title=f"{protocol} device identity: {summary}",
            severity=Severity.INFO,
            category=Category.ICS,
            description=f"Read the {protocol} device identity from {host} (read-only identity query).",
            impact="Asset inventory. Vendor/product/firmware pinpoints a device and its known "
                   "vulnerabilities and default credentials for targeted follow-up.",
            remediation="Inventory and track OT assets; subscribe to the vendor's advisories and "
                        "patch/mitigate per the device's maintenance window.",
            affected=[host],
            evidence=[Evidence(source=protocol, detail=summary)],
            references=[_CISA_ICS],
            meta={"protocol": protocol, "purdue": purdue, "device": device},
        ))
    return out
