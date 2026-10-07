"""IoT/service host re-typing for the graph."""
from redness import graphtypes
from redness.events import EventBus, EventKind
from redness.findings import Category, Finding, Report, Severity


def _f(fid, host, cat=Category.SERVICE):
    return Finding(id=fid, title=fid, severity=Severity.HIGH, category=cat, affected=[host])


def test_service_node_types():
    r = Report(findings=[_f("mqtt-anonymous", "10.0.0.1", Category.IOT),
                         _f("redis-unauth", "10.0.0.2"),
                         _f("printer-exposed", "10.0.0.3"),
                         _f("coap-exposed", "10.0.0.4", Category.IOT),
                         _f("smb-signing", "10.0.0.5", Category.SMB)])
    assert graphtypes.service_node_types(r) == {
        "10.0.0.1": "broker", "10.0.0.2": "database",
        "10.0.0.3": "printer", "10.0.0.4": "iot"}


def test_emit_service_nodes():
    r = Report(findings=[_f("memcached-exposed", "10.0.0.9")])
    seen = []
    bus = EventBus()
    bus.subscribe(seen.append)
    graphtypes.emit_service_nodes(bus, r)
    nodes = [e for e in seen if e.kind is EventKind.NODE]
    assert len(nodes) == 1 and nodes[0].data == {"id": "10.0.0.9", "label": "10.0.0.9",
                                                  "type": "database"}


def test_emit_service_nodes_noop_without_matches():
    r = Report(findings=[_f("smb-signing", "10.0.0.1", Category.SMB)])
    seen = []
    bus = EventBus()
    bus.subscribe(seen.append)
    graphtypes.emit_service_nodes(bus, r)
    assert seen == []


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            passed += 1
    print(f"{passed} passed")
