"""Web-service graph nodes: each nuclei (Category.WEB) service hangs under its host.

Nuclei findings are keyed to a `host:port` web service. Rather than recolor the whole host, we
draw each distinct web service as its own node (type "web") with an edge from its host - so the
graph shows exactly which service, on which host, carries the finding (and a host with several
listeners gets one node per port). Pure wiring that mirrors graphtypes.py / ot.py; the node-type
string is graph-only, so there is no findings-contract change.

`scan._node_type` returns None for Category.WEB on purpose, leaving this module the single owner
of web-service nodes - which keeps the live scan, the captured graph, and the report fallback
consistent.
"""
from __future__ import annotations

from .events import Event, EventBus, EventKind
from .findings import Category, Report


def web_services(report: Report) -> dict[str, str]:
    """{service_id: host} for every `host:port` carrying a WEB finding (first seen wins)."""
    out: dict[str, str] = {}
    for f in report.findings:
        if f.category is not Category.WEB:
            continue
        for svc in f.affected:
            if not svc or svc in out:
                continue
            out[svc] = svc.rsplit(":", 1)[0] if ":" in svc else svc
    return out


def emit_web_nodes(bus, report: Report) -> None:
    """Draw each web service as its own node under its host. No-op without a bus."""
    if bus is None:
        return
    for svc, host in web_services(report).items():
        bus.publish(Event(kind=EventKind.NODE, engine="web",
                          data={"id": svc, "label": svc, "type": "web"}))
        if host and host != svc:
            bus.publish(Event(kind=EventKind.EDGE, engine="web",
                              data={"src": host, "dst": svc, "label": "web"}))
