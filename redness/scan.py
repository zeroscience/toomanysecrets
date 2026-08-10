"""Scan orchestrator — run engines against targets, aggregate findings, feed the graph.

Ties the pieces together: for each target, run each available engine, collect the
normalized Findings into one Report, and (optionally) stream graph events onto an
EventBus so the live 3D view builds in real time.

The orchestrator owns *all* graph emission (nodes/edges/findings) so the picture is
consistent no matter which engine produced a finding — engines run headless here.
Reusable by the CLI today and the GUI later.
"""
from __future__ import annotations

from typing import Optional

from .engines import CertipyEngine, LdapEngine, NetExecEngine, TLSEngine
from .engines.base import Engine, Target
from .events import Event, EventBus, EventKind
from .findings import Category, Finding, Report


def default_engines() -> list[Engine]:
    """The engines a scan runs by default (order = execution order).

    TLS is pure-Python (always available), so a scan yields findings even on a box
    with neither nxc nor certipy installed. LdapEngine captures AS-REP/Kerberoast
    hashes (fed to redness.crack).
    """
    return [NetExecEngine(), LdapEngine(), CertipyEngine(), TLSEngine()]


def _emit(bus: Optional[EventBus], kind: EventKind, engine: str = "scan", **data) -> None:
    if bus is not None:
        bus.publish(Event(kind=kind, data=data, engine=engine))


def _node_type(f: Finding, affected: str, host: str) -> Optional[str]:
    """Infer a graph node type for a finding's affected id (None = reuse host node)."""
    if affected == host:
        return None
    c = f.category.value
    if c == "adcs":
        return "template"
    if c == "kerberos":
        return "user"
    if c == "smb" and "\\" in affected:
        return "share"
    if c == "enum":
        return "user"
    return "host"


def _emit_finding_graph(bus: Optional[EventBus], domain: str, host: str, f: Finding) -> None:
    if bus is None:
        return
    # FINDING lets the UI recolor affected nodes by severity.
    _emit(bus, EventKind.FINDING, finding=f.to_dict())
    for aff in f.affected:
        t = _node_type(f, aff, host)
        if t is None:
            continue                          # host-level finding: host node recolors
        _emit(bus, EventKind.NODE, id=aff, label=aff, type=t)
        _emit(bus, EventKind.EDGE, src=host, dst=aff, label=f.category.value)


def run_scan(
    targets: list[str],
    *,
    username: Optional[str] = None,
    password: Optional[str] = None,
    nthash: Optional[str] = None,
    domain: Optional[str] = None,
    kerberos: bool = False,
    engines: Optional[list[Engine]] = None,
    bus: Optional[EventBus] = None,
    engagement: str = "REDNESS assessment",
) -> Report:
    """Run engines across targets and return an aggregated Report.

    If `bus` is given, streams status/probe/node/edge/finding/done events for a live view.
    Engines whose underlying tool is not installed are skipped (reported via STATUS).
    """
    engines = engines if engines is not None else default_engines()
    report = Report(engagement=engagement, target=", ".join(targets))

    domain_label = domain or (targets[0] if targets else "scope")
    _emit(bus, EventKind.STATUS, message=f"Scan start: {len(targets)} target(s)")
    _emit(bus, EventKind.NODE, id=domain_label, label=domain_label, type="domain")

    for host in targets:
        tgt = Target(host=host, domain=domain, username=username,
                     password=password, nthash=nthash, kerberos=kerberos)
        _emit(bus, EventKind.NODE, id=host, label=host, type="host")
        _emit(bus, EventKind.EDGE, src=domain_label, dst=host, label="host")

        for eng in engines:
            if not eng.is_available():
                _emit(bus, EventKind.STATUS, engine=eng.name,
                      message=f"{eng.name}: not installed — skipping")
                continue
            _emit(bus, EventKind.STATUS, engine=eng.name, message=f"{eng.name}: scanning {host}")
            _emit(bus, EventKind.PROBE, engine=eng.name, target=host, test=eng.name)
            try:
                found = eng.run(tgt)
            except Exception as e:            # a broken engine must not abort the scan
                _emit(bus, EventKind.STATUS, engine=eng.name,
                      message=f"{eng.name}: error on {host}: {e}")
                found = []
            for f in found:
                report.findings.append(f)
                _emit_finding_graph(bus, domain_label, host, f)

    crit = sum(1 for f in report.findings if f.category != Category.ENUM)
    _emit(bus, EventKind.STATUS, message=f"Scan complete — {crit} finding(s)")
    _emit(bus, EventKind.DONE, engine="scan")
    return report
