"""NTLM relay-path derivation - pure logic + emission, from synthetic Reports.

Run:  python tests/test_relay.py   (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness import relay  # noqa: E402
from redness.events import Event, EventBus, EventKind  # noqa: E402
from redness.findings import Category, Finding, Report, Severity  # noqa: E402


def _f(fid, affected, category=Category.CONFIG):
    return Finding(id=fid, title=fid, severity=Severity.HIGH, category=category, affected=affected)


def _report(*findings):
    r = Report(engagement="t", target="acme.local")
    r.findings = list(findings)
    return r


def test_no_avenues_no_chains():
    r = _report(_f("enum-users", ["a", "b"], Category.ENUM))
    assert relay.derive_relay_chains(r) == []
    assert relay.build_relay_findings(r) == []


def test_esc8_chain_generic_victim():
    r = _report(_f("adcs-web-enrollment", ["ca01"], Category.ADCS))
    chains = relay.derive_relay_chains(r)
    assert len(chains) == 1
    c = chains[0]
    assert c.kind == "adcs-esc8" and c.target == "ca01" and c.to_da is True and c.victim == ""
    fs = {f.id: f for f in relay.build_relay_findings(r)}
    assert fs["ntlm-relay-to-adcs"].severity is Severity.CRITICAL
    assert fs["ntlm-relay-to-adcs"].meta["relay"] == "adcs-esc8"


def test_smb_chain_high():
    r = _report(_f("smb-signing-not-required", ["10.0.0.1", "10.0.0.2"], Category.SMB))
    fs = {f.id: f for f in relay.build_relay_findings(r)}
    assert list(fs) == ["ntlm-relay-to-smb"]
    assert fs["ntlm-relay-to-smb"].severity is Severity.HIGH
    assert set(fs["ntlm-relay-to-smb"].affected) == {"10.0.0.1", "10.0.0.2"}


def test_confirmed_coercion_victim_used():
    r = _report(_f("adcs-web-enrollment", ["ca01"], Category.ADCS),
                _f("coercion-petitpotam", ["dc01"]))
    chains = relay.derive_relay_chains(r)
    assert all(c.victim == "dc01" for c in chains)          # the confirmed victim, not generic
    f = relay.build_relay_findings(r)[0]
    assert "dc01" in f.evidence[0].detail


def test_emit_adds_findings_and_draws_map():
    bus = EventBus()
    events = []
    bus.subscribe(lambda e: events.append(e))
    r = _report(_f("adcs-web-enrollment", ["ca01"], Category.ADCS),
                _f("smb-signing-not-required", ["10.0.0.9"], Category.SMB))
    relay.emit_relay_paths(bus, r, domain="acme.local")

    # findings landed in the report
    assert {"ntlm-relay-to-adcs", "ntlm-relay-to-smb"} <= {f.id for f in r.findings}
    # a RELAY node + a CA->goal edge were emitted
    nodes = [e for e in events if e.kind is EventKind.NODE]
    edges = [e for e in events if e.kind is EventKind.EDGE]
    assert any(n.data.get("id") == relay.RELAY and n.data.get("type") == "relay" for n in nodes)
    assert any(e.data.get("dst") == relay.GOAL and e.data.get("attack") for e in edges)
    assert any(e.data.get("label") == "relay: SMB (no signing)" for e in edges)
    # generic coercion: the domain feeds the relay node
    assert any(e.data.get("src") == "acme.local" and e.data.get("dst") == relay.RELAY for e in edges)


def test_emit_noop_when_nothing_to_relay():
    bus = EventBus()
    events = []
    bus.subscribe(lambda e: events.append(e))
    r = _report(_f("enum-users", ["a"], Category.ENUM))
    relay.emit_relay_paths(bus, r)
    assert events == [] and not any(f.id.startswith("ntlm-relay") for f in r.findings)


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
