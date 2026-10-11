"""Scan orchestrator - run engines against targets, aggregate findings, feed the graph.

Ties the pieces together: for each target, run each available engine, collect the
normalized Findings into one Report, and (optionally) stream graph events onto an
EventBus so the live 3D view builds in real time.

The orchestrator owns *all* graph emission (nodes/edges/findings) so the picture is
consistent no matter which engine produced a finding - engines run headless here.
Reusable by the CLI today and the GUI later.
"""
from __future__ import annotations

from typing import Callable, Optional

from .engines import (
    CertipyEngine, CoapEngine, DelegationEngine, ElasticsearchEngine, FtpEngine, GppEngine,
    HttpEngine, LdapEngine, MemcachedEngine, MongoEngine, MqttEngine, MssqlEngine, NetExecEngine,
    PrinterEngine, RdpEngine, RedisEngine, SnmpEngine, SshEngine, TLSEngine, WinRMEngine,
)
from .engines.base import Engine, Target
from .events import Event, EventBus, EventKind
from .findings import Category, Finding, Report


def default_engines() -> list[Engine]:
    """The engines a scan runs by default (order = execution order).

    TLS is pure-Python (always available), so a scan yields findings even on a box
    with neither nxc nor certipy installed. LdapEngine captures AS-REP/Kerberoast
    hashes (fed to redness.crack). GppEngine no-ops without domain creds. The remote-access
    engines (RDP/WinRM/MSSQL) read banners unauthenticated (RDP NLA + service exposure) and,
    when creds are supplied, confirm reachable lateral-movement paths - all passive, no lockout
    risk, so they belong in the default scan (unlike the gated poison/spray commands).
    """
    return [NetExecEngine(), LdapEngine(), CertipyEngine(), DelegationEngine(), GppEngine(),
            RdpEngine(), WinRMEngine(), MssqlEngine(), FtpEngine(), HttpEngine(),
            SnmpEngine(), TLSEngine(), MqttEngine(), CoapEngine(),
            RedisEngine(), MongoEngine(), ElasticsearchEngine(), MemcachedEngine(), PrinterEngine(),
            SshEngine()]


def ics_engines(enum: bool = False) -> list[Engine]:
    """OT/ICS field-protocol engines - opt-in only (`scan --ics`), never in the default scan.

    All send a SINGLE read-only identity request and are port-gated by discovery (except BACnet,
    which is UDP and un-gated). OT kit is fragile, so touching it is an explicit choice, not a
    default - hence the separate helper. When `enum` (`scan --ics-enum`), the Modbus and DNP3
    engines are swapped for the louder *sweep* variants that map units/outstations behind a
    gateway/segment - still read-only, but a broad sweep can upset fragile kit. See docs/ICS.md.
    """
    from .engines import (BacnetEngine, Dnp3Engine, EnipEngine, HartIpEngine, ModbusEngine)
    engines: list[Engine] = [EnipEngine(), BacnetEngine(), HartIpEngine()]
    if enum:
        from .engines.ics_enum import Dnp3ScanEngine, ModbusSweepEngine
        engines += [ModbusSweepEngine(), Dnp3ScanEngine()]
    else:
        engines += [ModbusEngine(), Dnp3Engine()]
    return engines


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
    if c == "secret":
        return "secret"
    if c == "web":
        return None            # web services are owned by webgraph.emit_web_nodes (host:port nodes)
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
    discover: bool = True,
    port_scanner: Optional[Callable[[str], set[int]]] = None,
    listen_secs: int = 0,
) -> Report:
    """Run engines across targets and return an aggregated Report.

    If `bus` is given, streams status/probe/node/edge/finding/done events for a live view.
    Engines whose underlying tool is not installed are skipped (reported via STATUS).

    When `discover` is True (the default "hail-mary" behaviour), each host is first
    TCP connect-scanned and only the engines whose service port is open are run - so a
    full-breadth scan stays fast and quiet. `port_scanner` (host -> set of open ports) is
    injectable for tests; it defaults to `discovery.open_ports`. `discover=False` runs
    every available engine regardless of open ports (the old behaviour).
    """
    from .discovery import describe, open_ports, should_run

    engines = engines if engines is not None else default_engines()
    report = Report(engagement=engagement, target=", ".join(targets))
    scanner = port_scanner or (lambda h: open_ports(h))

    # Capture the exact node/edge stream so the HTML report can mirror the live graph. When no
    # live bus is attached we still capture via an internal bus (the emits are cheap no-ops to
    # any other consumer).
    from .graphmodel import GraphCollector
    _graph = GraphCollector()
    if bus is None:
        from .events import EventBus
        bus = EventBus()
    bus.subscribe(_graph.on_event)

    domain_label = domain or (targets[0] if targets else "scope")
    _emit(bus, EventKind.STATUS, message=f"Scan start: {len(targets)} target(s)")
    _emit(bus, EventKind.NODE, id=domain_label, label=domain_label, type="domain")

    for host in targets:
        tgt = Target(host=host, domain=domain, username=username,
                     password=password, nthash=nthash, kerberos=kerberos)
        _emit(bus, EventKind.NODE, id=host, label=host, type="host")
        _emit(bus, EventKind.EDGE, src=domain_label, dst=host, label="host")

        open_set: Optional[set[int]] = None
        if discover:
            open_set = scanner(host)
            _emit(bus, EventKind.STATUS, message=f"{host}: open ports {describe(open_set)}")

        for eng in engines:
            if not eng.is_available():
                _emit(bus, EventKind.STATUS, engine=eng.name,
                      message=f"{eng.name}: not installed, skipping")
                continue
            if open_set is not None and not should_run(eng.name, open_set):
                _emit(bus, EventKind.STATUS, engine=eng.name,
                      message=f"{eng.name}: no open port on {host}, skipping")
                continue
            _emit(bus, EventKind.STATUS, engine=eng.name, message=f"{eng.name}: scanning {host}")
            _emit(bus, EventKind.PROBE, engine=eng.name, target=host, test=eng.name)
            try:
                if getattr(eng, "wants_adcs_context", False):
                    # pass whether an AD CS ESC path has already been found this scan
                    # (CertipyEngine runs earlier) - lets delegation escalate MAQ without
                    # duplicating ADCS detection. Only engines that opt in receive it.
                    adcs = any(f.category is Category.ADCS for f in report.findings)
                    found = eng.run(tgt, adcs_present=adcs)
                else:
                    found = eng.run(tgt)
            except Exception as e:            # a broken engine must not abort the scan
                _emit(bus, EventKind.STATUS, engine=eng.name,
                      message=f"{eng.name}: error on {host}: {e}")
                found = []
            for f in found:
                report.findings.append(f)
                _emit_finding_graph(bus, domain_label, host, f)

    # Optional passive link-local sweep: its poisonable (LLMNR/NBT-NS) findings become a second
    # source into the relay map below (poison -> relay -> target), alongside coercion.
    if listen_secs > 0:
        from .mcast import listen
        _emit(bus, EventKind.STATUS, message=f"passive listen: {listen_secs}s on the segment")
        lrep, _ = listen(listen_secs, bus=bus, emit_done=False)
        report.findings.extend(lrep.findings)

    # Derive attack-path edges from what we found and light them up in the graph.
    from .paths import emit_attack_paths
    emit_attack_paths(bus, report, domain=domain_label)
    # Correlate coercion + missing signing + ESC8 (+ LLMNR/NBT-NS poisoning) into relay chains.
    from .relay import emit_relay_paths
    emit_relay_paths(bus, report, domain=domain_label)
    # OT: exposed controllers -> Process Impact, and IT/OT segmentation failure (no-op without ICS).
    from .ot import emit_ot_paths
    emit_ot_paths(bus, report, domain=domain_label)
    # Re-type IoT/service hosts (broker/database/printer/iot) for the graph.
    from .graphtypes import emit_service_nodes
    emit_service_nodes(bus, report)
    # Draw nuclei web services (host:port) as their own nodes under each host.
    from .webgraph import emit_web_nodes
    emit_web_nodes(bus, report)

    crit = sum(1 for f in report.findings if f.category != Category.ENUM)
    _emit(bus, EventKind.STATUS, message=f"Scan complete: {crit} finding(s)")
    _emit(bus, EventKind.DONE, engine="scan")

    bus.unsubscribe(_graph.on_event)
    report.meta["graph"] = _graph.data()
    return report
