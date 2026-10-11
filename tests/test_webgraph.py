"""Web-service graph nodes: parsing, emission, and the end-to-end scan graph.

A nuclei (Category.WEB) finding on host:port should become its own `web` node hanging under the
host - verified both at the derivation level and through run_scan's captured graph.

Run:  python -m pytest tests/test_webgraph.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.events import EventBus, EventKind  # noqa: E402
from redness.findings import Category, Finding, Report, Severity  # noqa: E402
from redness.webgraph import emit_web_nodes, web_services  # noqa: E402
from redness.engines.base import Engine, Target  # noqa: E402
from redness.scan import run_scan, _node_type  # noqa: E402


def _web_report():
    return Report(engagement="t", target="10.0.0.5", findings=[
        Finding(id="nuclei:git-config", title="Exposed .git", severity=Severity.MEDIUM,
                category=Category.WEB, affected=["10.0.0.5:8080"]),
        Finding(id="nuclei:log4j", title="Log4Shell", severity=Severity.CRITICAL,
                category=Category.WEB, affected=["10.0.0.5:8080", "10.0.0.5:443"]),
        Finding(id="smb-signing", title="SMB signing", severity=Severity.MEDIUM,
                category=Category.SMB, affected=["10.0.0.5"]),
    ])


def test_web_services_dedups_and_maps_host():
    svc = web_services(_web_report())
    assert svc == {"10.0.0.5:8080": "10.0.0.5", "10.0.0.5:443": "10.0.0.5"}  # SMB ignored


def test_emit_web_nodes_emits_node_and_host_edge():
    bus = EventBus()
    nodes, edges = [], []
    bus.subscribe(lambda ev: (nodes if ev.kind is EventKind.NODE else edges).append(ev.data)
                  if ev.kind in (EventKind.NODE, EventKind.EDGE) else None)
    emit_web_nodes(bus, _web_report())
    webnodes = [n for n in nodes if n["type"] == "web"]
    assert {n["id"] for n in webnodes} == {"10.0.0.5:8080", "10.0.0.5:443"}
    # each service has an edge FROM its host
    assert {"10.0.0.5", "10.0.0.5:8080", "web"} == {edges[0]["src"], edges[0]["dst"], edges[0]["label"]} \
        or any(e["src"] == "10.0.0.5" and e["dst"] == "10.0.0.5:8080" for e in edges)
    assert all(e["src"] == "10.0.0.5" for e in edges)


def test_emit_web_nodes_noop_without_bus():
    emit_web_nodes(None, _web_report())      # must not raise


def test_node_type_web_is_none():
    f = Finding(id="x", title="x", severity=Severity.LOW, category=Category.WEB,
                affected=["10.0.0.5:8080"])
    assert _node_type(f, "10.0.0.5:8080", "10.0.0.5") is None   # owned by webgraph, not generic path


class _StubNuclei(Engine):
    name = "nuclei"

    def is_available(self):
        return True

    def run(self, target):
        return [Finding(id="nuclei:git", title="Exposed .git", severity=Severity.HIGH,
                        category=Category.WEB, affected=[f"{target.host}:8080"])]


def test_run_scan_hangs_web_service_under_host():
    rep = run_scan(["10.0.0.5"], engines=[_StubNuclei()], discover=False)
    g = rep.meta["graph"]
    ids = {n["id"]: n for n in g["nodes"]}
    assert "10.0.0.5" in ids and ids["10.0.0.5"]["type"] == "host"
    assert "10.0.0.5:8080" in ids and ids["10.0.0.5:8080"]["type"] == "web"
    # the web service is linked to its host, not to the domain
    assert any(l for l in g["links"]
               if _end(l["source"]) == "10.0.0.5" and _end(l["target"]) == "10.0.0.5:8080")


def _end(v):
    return v["id"] if isinstance(v, dict) else v


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
    print("done")
