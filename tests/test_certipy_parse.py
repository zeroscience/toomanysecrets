"""Certipy parser tests against captured `find -json` output - no certipy/DC needed.

Run:  python tests/test_certipy_parse.py    (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.engines import certipy as cp  # noqa: E402
from redness.events import EventBus, EventKind  # noqa: E402
from redness.engines.base import Target  # noqa: E402
from redness.findings import Category, Severity  # noqa: E402

# Shape mirrors Certipy 4.x `find -json` (indexed dicts + "[!] Vulnerabilities").
SAMPLE = {
    "Certificate Authorities": {
        "0": {
            "CA Name": "ACME-CA",
            "DNS Name": "ca01.acme.local",
            "[!] Vulnerabilities": {
                "ESC6": "Edit flag EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled"
            },
        }
    },
    "Certificate Templates": {
        "0": {
            "Template Name": "UserAuth",
            "Enabled": True,
            "Client Authentication": True,
            "Enrollee Supplies Subject": True,
            "[!] Vulnerabilities": {
                "ESC1": "'ACME\\\\Domain Users' can enroll, enrollee supplies subject, client auth"
            },
        },
        "1": {
            "Template Name": "WebServer",
            "Enabled": True,
            # no vulnerabilities key -> should not produce a finding
        },
    },
}


def _by_id(findings):
    return {f.id: f for f in findings}


def test_esc1_critical():
    f = _by_id(cp.parse_certipy_json(SAMPLE, credentialed=True))
    assert "adcs-esc1" in f
    assert f["adcs-esc1"].severity is Severity.CRITICAL
    assert f["adcs-esc1"].affected == ["UserAuth"]
    assert f["adcs-esc1"].meta["esc"] == 1


def test_esc6_on_ca():
    f = _by_id(cp.parse_certipy_json(SAMPLE))
    assert "adcs-esc6" in f
    assert f["adcs-esc6"].severity is Severity.CRITICAL
    assert f["adcs-esc6"].affected == ["ACME-CA"]


def test_clean_template_not_flagged():
    findings = cp.parse_certipy_json(SAMPLE)
    # WebServer has no vulns -> only appears (if at all) in the enum appendix, never as ESC
    assert not any("WebServer" in a for f in findings if f.category != Category.ENUM
                   for a in f.affected)


def test_enum_appendix():
    f = _by_id(cp.parse_certipy_json(SAMPLE))
    assert "enum-adcs" in f
    assert f["enum-adcs"].category is Category.ENUM


def test_accepts_json_string():
    import json
    findings = cp.parse_certipy_json(json.dumps(SAMPLE))
    assert any(f.id == "adcs-esc1" for f in findings)


def test_eventbus_streams_findings():
    """Engine emits live events onto a bus; a subscriber sees findings + graph."""
    seen = []
    bus = EventBus()
    bus.subscribe(seen.append)

    eng = cp.CertipyEngine()
    eng.bus = bus
    # Drive the streaming path directly (no certipy binary needed):
    findings = cp.parse_certipy_json(SAMPLE, credentialed=True)
    eng._stream_graph(Target(host="10.0.0.1", domain="acme.local"), findings)
    for f in findings:
        eng.emit_finding(f)
    eng.emit_done()

    kinds = [e.kind for e in seen]
    assert EventKind.NODE in kinds
    assert EventKind.EDGE in kinds
    assert EventKind.FINDING in kinds
    assert kinds[-1] is EventKind.DONE


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
