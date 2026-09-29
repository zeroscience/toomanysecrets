"""Attack-path derivation tests - pure logic over a synthetic Report, no tools/DC.

Run:  python tests/test_paths.py   (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness import paths  # noqa: E402
from redness.events import EventBus, EventKind  # noqa: E402
from redness.findings import Category, Finding, Report, Severity  # noqa: E402


def _report():
    r = Report(engagement="t", target="acme.local")
    r.findings = [
        Finding(id="krb-asrep-roastable", title="AS-REP roastable", severity=Severity.HIGH,
                category=Category.KERBEROS, affected=["jdoe", "svc-sql"]),
        Finding(id="credential-cracked", title="Password recovered for svc-sql",
                severity=Severity.CRITICAL, category=Category.KERBEROS,
                affected=["svc-sql"], meta={"account": "svc-sql", "password": "Summer2024!"}),
        Finding(id="adcs-esc1", title="AD CS ESC1", severity=Severity.CRITICAL,
                category=Category.ADCS, affected=["UserAuth"], meta={"esc": 1}),
        Finding(id="enum-domain-users", title="users", severity=Severity.INFO,
                category=Category.ENUM, affected=["jdoe", "svc-sql", "krbtgt"]),
    ]
    return r


def test_compromised_and_roastable():
    r = _report()
    assert paths.compromised_accounts(r) == {"svc-sql"}
    assert paths.roastable_accounts(r) == {"jdoe", "svc-sql"}


def test_adcs_da_targets():
    assert paths.adcs_da_targets(_report()) == [("UserAuth", 1)]


def test_derive_edges():
    edges = {(e.src, e.dst, e.potential): e for e in paths.derive_attack_edges(_report(), "acme.local")}
    # svc-sql is cracked -> a solid "valid credential" edge (not potential)
    assert ("svc-sql", "acme.local", False) in edges
    # jdoe is roastable but not cracked -> a potential lead
    assert ("jdoe", "acme.local", True) in edges
    # svc-sql should NOT also appear as a potential lead (owned takes precedence)
    assert ("svc-sql", "acme.local", True) not in edges
    # ESC1 template -> Domain Admin goal
    esc = edges[("UserAuth", paths.GOAL, False)]
    assert "ESC1" in esc.label and esc.technique == "T1649"


def test_emit_streams_owned_goal_and_attack_edges():
    seen = []
    bus = EventBus()
    bus.subscribe(seen.append)
    paths.emit_attack_paths(bus, _report(), domain="acme.local")
    owned_nodes = [e for e in seen if e.kind is EventKind.NODE and e.data.get("type") == "owned"]
    goal_nodes = [e for e in seen if e.kind is EventKind.NODE and e.data.get("type") == "goal"]
    attack_edges = [e for e in seen if e.kind is EventKind.EDGE and e.data.get("attack")]
    assert any(e.data["id"] == "svc-sql" for e in owned_nodes)
    assert goal_nodes and goal_nodes[0].data["id"] == paths.GOAL
    assert len(attack_edges) == 3
    assert any(e.data.get("potential") for e in attack_edges)      # jdoe lead
    assert any(not e.data.get("potential") for e in attack_edges)  # cracked + ESC


def _deleg_report():
    r = Report(engagement="t", target="acme.local")
    r.findings = [
        Finding(id="delegation-unconstrained", title="Unconstrained delegation on non-DC",
                severity=Severity.HIGH, category=Category.LDAP,
                affected=["WS01", "APP02"], meta={"delegation": "unconstrained"}),
        Finding(id="delegation-unconstrained-dc", title="Unconstrained delegation on DC",
                severity=Severity.INFO, category=Category.LDAP,
                affected=["DC01"], meta={"delegation": "unconstrained", "expected": True}),
    ]
    return r


def test_delegation_unconstrained_non_dc_edges_to_da():
    edges = paths.delegation_edges(_deleg_report(), "acme.local")
    by_src = {e.src: e for e in edges}
    # each non-DC unconstrained host -> Domain Admin, as a potential lead
    assert set(by_src) == {"WS01", "APP02"}
    for e in edges:
        assert e.dst == paths.GOAL and e.potential is True
        assert e.label == "can impersonate any user to" and e.technique == "T1558"
    # the DC's unconstrained delegation (INFO/expected) produces NO edge
    assert "DC01" not in by_src


def test_delegation_edges_flow_through_derive_and_emit():
    r = _deleg_report()
    edges = paths.derive_attack_edges(r, "acme.local")
    assert ("WS01", paths.GOAL, True) in {(e.src, e.dst, e.potential) for e in edges}
    seen = []
    bus = EventBus()
    bus.subscribe(seen.append)
    paths.emit_attack_paths(bus, r, domain="acme.local")
    goal = [e for e in seen if e.kind is EventKind.NODE and e.data.get("type") == "goal"]
    deleg = [e for e in seen if e.kind is EventKind.EDGE
             and e.data.get("label") == "can impersonate any user to"]
    assert goal and len(deleg) == 2 and all(e.data.get("potential") for e in deleg)


def test_no_findings_no_paths():
    empty = Report(engagement="t", target="x")
    assert paths.derive_attack_edges(empty) == []
    bus = EventBus()
    seen = []
    bus.subscribe(seen.append)
    assert paths.emit_attack_paths(bus, empty) == []
    assert seen == []


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
