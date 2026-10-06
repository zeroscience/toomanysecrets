"""OT attack-path derivation: the OT analog of path-to-Domain-Admin.

Mirrors paths.py / relay.py. Two derivations from the ICS findings a scan produced:

  * **Process Impact** - every exposed, unauthenticated OT controller is a lead to physical impact
    (operate or disrupt the process it controls). Drawn as `controller -> Process Impact` (a
    `potential` lead: the capability is proven by exposure, the impact itself is not exercised).
  * **IT/OT segmentation failure** - when ONE scan reached both IT/AD findings and OT controllers,
    the enterprise network can route to the control network. Because OT protocols are
    unauthenticated, that reachability is a direct path to the process. Drawn as a solid
    `IT / Enterprise -> controller` edge (proven reachability) and recorded as a CRITICAL finding.

So the OT story reads `IT / Enterprise -> controller -> Process Impact`, the exact shape of
`entry -> owned -> Domain Admin`. Pure derivation (separate from emission) so it unit-tests with a
synthetic Report. ICS techniques reference the MITRE ATT&CK for ICS matrix.
"""
from __future__ import annotations

from .events import Event, EventBus, EventKind
from .findings import Category, Evidence, Finding, Report, Severity

GOAL = "Process Impact"                 # synthetic OT goal node (physical-process impact)
IT_NODE = "IT / Enterprise"             # synthetic source when IT can reach OT (segmentation fail)

# OT exposure finding id -> (graph node type, Purdue level, MITRE ATT&CK-ICS technique for impact).
_EXPOSED = {
    "enip-exposed":    ("plc", 1, "T0831"),        # Manipulation of Control
    "modbus-exposed":  ("plc", 1, "T0836"),        # Modify Parameter
    "dnp3-exposed":    ("rtu", 2, "T0836"),
    "bacnet-exposed":  ("controller", 2, "T0831"),
    "hart-ip-exposed": ("gateway", 0, "T0835"),     # Manipulate I/O Image
}
# IT/AD finding categories that, seen alongside OT, mean the scan crossed the IT/OT boundary.
_IT_CATEGORIES = {Category.SMB, Category.LDAP, Category.KERBEROS, Category.ADCS,
                  Category.PASSWORD, Category.TLS, Category.CONFIG, Category.SECRET}


# --------------------------------------------------------------------------- #
# Pure derivation (unit-testable)                                             #
# --------------------------------------------------------------------------- #
def ot_controllers(report: Report) -> list[tuple[str, str, int, str]]:
    """(host, node_type, purdue_level, technique) per exposed OT controller, deduped."""
    out: list[tuple[str, str, int, str]] = []
    seen: set[tuple[str, str]] = set()
    for f in report.findings:
        spec = _EXPOSED.get(f.id)
        if not spec:
            continue
        node_type, purdue, technique = spec
        for host in f.affected:
            if (host, node_type) in seen:
                continue
            seen.add((host, node_type))
            out.append((host, node_type, purdue, technique))
    return out


def it_surface(report: Report) -> bool:
    """True if the scan also produced IT/AD findings (not just OT and not just ENUM)."""
    return any(f.category in _IT_CATEGORIES for f in report.findings)


def segmentation_failure(report: Report) -> bool:
    """IT and OT both reachable from one scan: a Purdue-model segmentation violation."""
    return bool(ot_controllers(report)) and it_surface(report)


def build_ot_findings(report: Report) -> list[Finding]:
    """The derived segmentation finding (only when IT and OT are both reachable)."""
    ctrls = ot_controllers(report)
    if not ctrls or not it_surface(report):
        return []
    hosts = sorted({h for h, _, _, _ in ctrls})
    return [Finding(
        id="ot-it-segmentation",
        title="IT/OT segmentation failure: enterprise network reaches OT controllers",
        severity=Severity.CRITICAL,
        category=Category.ICS,
        description="A single scan reached both IT/AD services and OT control protocols, so the "
                    "enterprise network can route to the control network. OT protocols are "
                    "unauthenticated, so IT reachability is itself a path to the physical process.",
        impact="An attacker who lands anywhere on IT can reach these controllers and operate or "
               "disrupt the physical process (ICS impact: loss of control, availability, or "
               "safety).",
        remediation="Enforce the Purdue model: an IT/OT DMZ with a brokered jump host, deny direct "
                    "IT->OT routing, and allow only authenticated, logged access to the control "
                    "network.",
        affected=hosts,
        evidence=[Evidence(source="redness",
                           detail=f"{len(hosts)} OT controller(s) reachable alongside IT findings")],
        references=["https://attack.mitre.org/techniques/T0883/",
                    "https://www.cisa.gov/topics/industrial-control-systems"],
        meta={"controllers": hosts, "purdue_violation": True},
    )]


# --------------------------------------------------------------------------- #
# Emission (graph)                                                            #
# --------------------------------------------------------------------------- #
def _emit(bus: EventBus, kind: EventKind, **data) -> None:
    if bus is not None:
        bus.publish(Event(kind=kind, data=data, engine="ot"))


def emit_ot_paths(bus, report: Report, domain: str = "domain") -> list[Finding]:
    """Add the segmentation finding to the report and draw the OT attack path on the graph.

    Re-types each OT host to its controller node type (plc/rtu/gateway/controller), draws a dashed
    `controller -> Process Impact` lead, and - on a segmentation failure - a solid
    `IT / Enterprise -> controller` reachability edge. No-op without OT findings.
    """
    ctrls = ot_controllers(report)
    findings = build_ot_findings(report)
    report.findings.extend(findings)
    if not ctrls or bus is None:
        return findings
    seg = it_surface(report)
    _emit(bus, EventKind.NODE, id=GOAL, label=GOAL, type="process")
    if seg:
        _emit(bus, EventKind.NODE, id=IT_NODE, label=IT_NODE, type="owned")
    for host, node_type, _purdue, technique in ctrls:
        _emit(bus, EventKind.NODE, id=host, label=host, type=node_type)    # re-type host -> OT
        _emit(bus, EventKind.EDGE, src=host, dst=GOAL, label="operate/disrupt process",
              attack=True, potential=True, technique=technique)
        if seg:
            _emit(bus, EventKind.EDGE, src=IT_NODE, dst=host, label="crosses IT/OT boundary",
                  attack=True, technique="T0883")
    _emit(bus, EventKind.STATUS,
          message=(f"OT: {len(ctrls)} controller(s), "
                   + ("IT/OT segmentation failure -> Process Impact" if seg
                      else "exposed -> Process Impact")))
    return findings
