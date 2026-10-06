"""Collect NODE/EDGE events into a static graph ({nodes, links}) for the HTML report.

The live 3D graph is built from a *stream* of NODE/EDGE events (redness/events.py). To ship a
self-contained HTML report that *mirrors* that graph, we need the same node/edge set as plain
data. Two ways in:

  * `GraphCollector` subscribes to a bus and accumulates the exact events a scan emits - so
    `run_scan` captures the real graph into `report.meta["graph"]` (an exact mirror).
  * `graph_from_report` reconstructs a graph from a saved `Report` alone (older findings.json
    with no captured graph, or the `report` command), by replaying the same derivation.

Link endpoints are (source, target) so the vendored 3d-force-graph renders them directly; extra
edge keys (attack/potential/technique/label) are preserved for styling.
"""
from __future__ import annotations

import copy
from typing import Optional

from .events import Event, EventKind
from .findings import Report

_NODE_KEEP = ("id", "label", "type", "meta")


class GraphCollector:
    """Accumulate NODE/EDGE events into a deduped {nodes, links} graph."""

    def __init__(self) -> None:
        self._nodes: dict[str, dict] = {}
        self._links: dict[tuple, dict] = {}

    def on_event(self, ev: Event) -> None:
        if ev.kind is EventKind.NODE:
            nid = ev.data.get("id")
            if nid is None:
                return
            node = self._nodes.setdefault(nid, {"id": nid})
            for k in _NODE_KEEP:
                if ev.data.get(k) is not None:
                    node[k] = ev.data[k]
        elif ev.kind is EventKind.EDGE:
            src, dst = ev.data.get("src"), ev.data.get("dst")
            if src is None or dst is None:
                return
            key = (src, dst, ev.data.get("label", ""))
            link = {"source": src, "target": dst}
            for k, v in ev.data.items():
                if k not in ("src", "dst"):
                    link[k] = v
            self._links[key] = link

    def data(self) -> dict:
        """The graph, with any link endpoint that never got its own NODE event backfilled."""
        nodes = dict(self._nodes)
        for link in self._links.values():
            for end in (link["source"], link["target"]):
                nodes.setdefault(end, {"id": end, "label": end, "type": "host"})
        return {"nodes": list(nodes.values()), "links": list(self._links.values())}


def graph_from_report(report: Report) -> dict:
    """Reconstruct a graph from a saved Report (no live capture available).

    Operates on a deep copy because the relay derivation appends findings; we never want to
    mutate the caller's report just to draw it. Affected assets anchor to the domain node (the
    per-host origin isn't recorded in a saved report), while the attack-path and relay overlays
    are exact.
    """
    from .events import EventBus
    from .paths import emit_attack_paths
    from .relay import emit_relay_paths
    from .scan import _emit_finding_graph

    rep = copy.deepcopy(report)
    bus = EventBus()
    gc = GraphCollector()
    bus.subscribe(gc.on_event)

    targets = [t.strip() for t in (rep.target or "").split(",") if t.strip()]
    domain_label = targets[0] if targets else (rep.target or "scope")
    bus.publish(Event(kind=EventKind.NODE,
                      data={"id": domain_label, "label": domain_label, "type": "domain"}))
    for host in targets:
        bus.publish(Event(kind=EventKind.NODE, data={"id": host, "label": host, "type": "host"}))
        bus.publish(Event(kind=EventKind.EDGE,
                          data={"src": domain_label, "dst": host, "label": "host"}))
    for f in rep.findings:
        _emit_finding_graph(bus, domain_label, domain_label, f)
    emit_attack_paths(bus, rep, domain=domain_label)
    emit_relay_paths(bus, rep, domain=domain_label)          # appends to the copy only
    from .ot import emit_ot_paths
    emit_ot_paths(bus, rep, domain=domain_label)             # OT controllers -> Process Impact
    return gc.data()


def graph_for(report: Report) -> dict:
    """The captured graph if a scan stored one, else a reconstruction from the report."""
    g = report.meta.get("graph") if isinstance(report.meta, dict) else None
    if isinstance(g, dict) and g.get("nodes"):
        return g
    return graph_from_report(report)
