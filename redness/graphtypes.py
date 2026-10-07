"""Re-type host nodes to a specific role for the graph (broker / database / printer / iot).

IoT and exposed-service findings attach to the scanned host (affected == host), so by default the
host node just recolors by severity. For the graph - especially the world-map territory view -
those hosts read better as their own kind: an MQTT broker, a database, a printer, an IoT device.
This derivation (mirrors ot.py) emits a NODE event per such host, re-typing it. Pure wiring, no
findings-contract change; the node-type string is graph-only.
"""
from __future__ import annotations

from .events import Event, EventBus, EventKind
from .findings import Report

# finding id -> graph node type (the host that carries the finding becomes this kind).
_TYPE_BY_ID = {
    "mqtt-anonymous": "broker", "mqtt-exposed": "broker",
    "coap-exposed": "iot",
    "redis-unauth": "database", "redis-exposed": "database",
    "mongodb-no-auth": "database", "mongodb-exposed": "database",
    "elasticsearch-unauth": "database", "elasticsearch-exposed": "database",
    "memcached-exposed": "database",
    "printer-exposed": "printer",
}


def service_node_types(report: Report) -> dict[str, str]:
    """{host: node_type} for hosts carrying an IoT/service finding (first match wins)."""
    out: dict[str, str] = {}
    for f in report.findings:
        t = _TYPE_BY_ID.get(f.id)
        if not t:
            continue
        for host in f.affected:
            out.setdefault(host, t)
    return out


def emit_service_nodes(bus, report: Report) -> None:
    """Re-type IoT/service hosts on the graph (broker/database/printer/iot). No-op without a bus."""
    if bus is None:
        return
    for host, node_type in service_node_types(report).items():
        bus.publish(Event(kind=EventKind.NODE, engine="services",
                          data={"id": host, "label": host, "type": node_type}))
