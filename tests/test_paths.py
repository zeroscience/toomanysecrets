"""Attack-path derivation tests - pure logic over a synthetic Report, no tools/DC.

Run:  python tests/test_paths.py   (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness import paths  # noqa: E402
from redness.bloodhound import BHGraph  # noqa: E402
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


def test_no_findings_no_paths():
    empty = Report(engagement="t", target="x")
    assert paths.derive_attack_edges(empty) == []
    bus = EventBus()
    seen = []
    bus.subscribe(seen.append)
    assert paths.emit_attack_paths(bus, empty) == []
    assert seen == []


# --- BloodHound reachability (pure; caller supplies the BHGraph + owned set) --- #
def _bh():
    g = BHGraph()
    g.nodes = {"JDOE": "user", "HELPDESK": "group", "DOMAIN ADMINS": "group",
               "DC01": "host", "BOB": "user", "FILESRV": "host"}
    g.edges = [
        ("JDOE", "HELPDESK", "MemberOf"),           # owned user -> group
        ("HELPDESK", "DOMAIN ADMINS", "MemberOf"),  # group -> DA group (reaches DA)
        ("HELPDESK", "DC01", "AdminTo"),            # group -> DC (dead-ends under v1 DA-group targets)
        ("BOB", "FILESRV", "AdminTo"),              # entirely off-path (BOB not owned)
    ]
    return g


def test_bloodhound_path_to_domain_admin():
    edges = paths.bloodhound_paths(_bh(), {"JDOE"})
    triples = {(e.src, e.dst, e.label) for e in edges}
    assert ("JDOE", "HELPDESK", "MemberOf") in triples
    assert ("HELPDESK", "DOMAIN ADMINS", "MemberOf") in triples
    assert ("DOMAIN ADMINS", paths.GOAL, "escalates to Domain Admin") in triples  # terminal -> goal
    assert all(e.potential for e in edges)                       # potential=True
    # off-path excluded: AdminTo-DC leg dead-ends (v1 targets = DA groups); BOB never starts owned
    assert ("HELPDESK", "DC01", "AdminTo") not in triples
    assert not any(e.src == "BOB" or e.dst == "FILESRV" for e in edges)


def test_bloodhound_no_owned_or_no_path():
    assert paths.bloodhound_paths(_bh(), set()) == []            # nothing owned
    assert paths.bloodhound_paths(_bh(), {"BOB"}) == []          # owned, but no path to a DA group


def test_bloodhound_explicit_da_target_lights_dc_path():
    # override targets to include the DC -> the AdminTo-DC leg lights (how DC/high-value
    # targeting will work once ingestion captures it)
    edges = paths.bloodhound_paths(_bh(), {"JDOE"}, da_targets={"DC01"})
    triples = {(e.src, e.dst, e.label) for e in edges}
    assert ("JDOE", "HELPDESK", "MemberOf") in triples
    assert ("HELPDESK", "DC01", "AdminTo") in triples
    assert ("DC01", paths.GOAL, "escalates to Domain Admin") in triples


def test_bloodhound_no_da_group_no_edges():
    g = _bh()
    del g.nodes["DOMAIN ADMINS"]                  # no name-matched DA target present
    assert paths.bloodhound_paths(g, {"JDOE"}) == []


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
