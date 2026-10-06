"""OT attack paths: controllers -> Process Impact, and IT/OT segmentation failure."""
from redness import ot
from redness.events import EventBus, EventKind
from redness.findings import Category, Finding, Report, Severity


def _ics(fid, host, sev=Severity.HIGH):
    return Finding(id=fid, title=fid, severity=sev, category=Category.ICS, affected=[host],
                   meta={"protocol": "x"})


def _report(findings, engagement="plant"):
    return Report(engagement=engagement, target="10.20.0.0/24", findings=list(findings))


def test_ot_controllers_maps_type_purdue_technique():
    r = _report([_ics("enip-exposed", "10.20.0.5"), _ics("dnp3-exposed", "10.20.0.6"),
                 _ics("hart-ip-exposed", "10.20.0.7")])
    ctrls = {h: (t, p) for h, t, p, _tech in ot.ot_controllers(r)}
    assert ctrls["10.20.0.5"] == ("plc", 1)
    assert ctrls["10.20.0.6"] == ("rtu", 2)
    assert ctrls["10.20.0.7"] == ("gateway", 0)


def test_ot_controllers_dedupes_and_ignores_non_ics():
    r = _report([_ics("modbus-exposed", "10.20.0.5"), _ics("modbus-exposed", "10.20.0.5"),
                 Finding(id="smb-signing", title="x", severity=Severity.HIGH,
                         category=Category.SMB, affected=["10.0.0.1"])])
    assert [h for h, *_ in ot.ot_controllers(r)] == ["10.20.0.5"]


def test_it_surface_and_segmentation_failure():
    ot_only = _report([_ics("modbus-exposed", "10.20.0.5")])
    assert ot.it_surface(ot_only) is False
    assert ot.segmentation_failure(ot_only) is False
    mixed = _report([_ics("modbus-exposed", "10.20.0.5"),
                     Finding(id="smb-signing", title="x", severity=Severity.HIGH,
                             category=Category.SMB, affected=["10.0.0.1"])])
    assert ot.it_surface(mixed) is True and ot.segmentation_failure(mixed) is True
    # ENUM-only IT noise does not count as an IT surface
    enum = _report([_ics("modbus-exposed", "10.20.0.5"),
                    Finding(id="enum-users", title="x", severity=Severity.INFO,
                            category=Category.ENUM, affected=["a"])])
    assert ot.it_surface(enum) is False


def test_build_ot_findings_only_on_segmentation():
    mixed = _report([_ics("enip-exposed", "10.20.0.5"),
                     Finding(id="adcs-esc1", title="x", severity=Severity.CRITICAL,
                             category=Category.ADCS, affected=["CA"])])
    fs = ot.build_ot_findings(mixed)
    assert len(fs) == 1 and fs[0].id == "ot-it-segmentation"
    assert fs[0].severity is Severity.CRITICAL and fs[0].meta["purdue_violation"] is True
    assert "10.20.0.5" in fs[0].affected
    # OT-only: no segmentation finding
    assert ot.build_ot_findings(_report([_ics("enip-exposed", "10.20.0.5")])) == []


def test_emit_ot_paths_draws_process_goal_and_impact_edges():
    r = _report([_ics("modbus-exposed", "10.20.0.5")])
    seen = []
    bus = EventBus()
    bus.subscribe(seen.append)
    ot.emit_ot_paths(bus, r, domain="plant")
    # the Process Impact goal node + the host re-typed to a plc
    nodes = {e.data["id"]: e.data for e in seen if e.kind is EventKind.NODE}
    assert nodes[ot.GOAL]["type"] == "process"
    assert nodes["10.20.0.5"]["type"] == "plc"
    # a dashed (potential) impact edge host -> Process Impact
    impact = [e for e in seen if e.kind is EventKind.EDGE and e.data["dst"] == ot.GOAL]
    assert len(impact) == 1 and impact[0].data["potential"] is True
    assert impact[0].data["attack"] is True


def test_emit_ot_paths_segmentation_adds_it_node_and_solid_edge():
    r = _report([_ics("enip-exposed", "10.20.0.5"),
                 Finding(id="smb-signing", title="x", severity=Severity.HIGH,
                         category=Category.SMB, affected=["10.0.0.1"])])
    seen = []
    bus = EventBus()
    bus.subscribe(seen.append)
    fs = ot.emit_ot_paths(bus, r, domain="plant")
    assert any(f.id == "ot-it-segmentation" for f in fs)          # finding returned + appended
    assert any(f.id == "ot-it-segmentation" for f in r.findings)
    ids = {e.data.get("id") for e in seen if e.kind is EventKind.NODE}
    assert ot.IT_NODE in ids
    seg_edges = [e for e in seen if e.kind is EventKind.EDGE
                 and e.data["src"] == ot.IT_NODE and e.data["dst"] == "10.20.0.5"]
    assert len(seg_edges) == 1 and not seg_edges[0].data.get("potential")   # solid = proven reach


def test_emit_ot_paths_noop_without_ics():
    r = _report([Finding(id="smb-signing", title="x", severity=Severity.HIGH,
                         category=Category.SMB, affected=["10.0.0.1"])])
    seen = []
    bus = EventBus()
    bus.subscribe(seen.append)
    assert ot.emit_ot_paths(bus, r, domain="d") == []
    assert seen == []


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            passed += 1
    print(f"{passed} passed")
