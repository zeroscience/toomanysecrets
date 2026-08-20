"""NetNTLMv2 poison orchestration - no Responder, root, or LAN required.

`run_poison` is driven by an injected `lines` source (fake Responder stdout), so the
whole path is exercised cross-platform. Run:
    python tests/test_poison.py    (or)    python -m pytest -q
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness import poison  # noqa: E402
from redness.engines import responder as rp  # noqa: E402
from redness.events import EventBus, EventKind  # noqa: E402
from redness.findings import Category, Severity  # noqa: E402

# Fake Responder console output: two victims, jdoe captured twice (dedupe), and an
# NTLMv1 line that must be ignored (only -m 5600 NetNTLMv2 is in scope).
LINES = [
    "[+] Listening for events...",
    "[SMB] NTLMv2-SSP Client   : 10.10.0.55",
    "[SMB] NTLMv2-SSP Hash     : jdoe::ACME:1122334455667788:6E9F3A1CFD5B4E2A9C0D7F8B1A2C3D4E:0101000000000000ABCD",
    "[HTTP] NTLMv2-SSP Hash    : svc_backup::ACME:99AABBCCDDEEFF00:AC3B7D2E1F0091C6B5A4938271605F3E:0101000000000000BEEF",
    "[SMB] NTLMv1-SSP Hash     : legacy::ACME:AAAA:BBBB:CCCC",
    "[SMB] NTLMv2-SSP Hash     : jdoe::ACME:1122334455667788:6E9F3A1CFD5B4E2A9C0D7F8B1A2C3D4E:0101000000000000ABCD",
]


# -- pure: responder_argv ---------------------------------------------------- #
def test_responder_argv_poison_mode():
    assert rp.responder_argv("eth0", binary="responder") == ["responder", "-I", "eth0"]


def test_responder_argv_analyze_mode():
    argv = rp.responder_argv("eth0", analyze=True, binary="responder")
    assert argv == ["responder", "-I", "eth0", "-A"]


# -- pure: build_findings ---------------------------------------------------- #
def test_build_findings_captured_and_poisoning():
    pairs = [("ACME\\jdoe", "jdoe::ACME:...a"), ("ACME\\svc", "svc::ACME:...b")]
    f = {x.id: x for x in poison.build_findings(pairs, poisoned=True)}
    assert f["netntlm-captured"].severity is Severity.HIGH
    assert f["netntlm-captured"].category is Category.SMB
    hashes = f["netntlm-captured"].meta["hashes"]
    assert {h["type"] for h in hashes} == {"netntlmv2"}
    assert f["netntlm-captured"].affected == ["ACME\\jdoe", "ACME\\svc"]  # sorted
    assert f["llmnr-nbtns-poisoning-possible"].severity is Severity.MEDIUM


def test_build_findings_analyze_has_no_poisoning_finding():
    pairs = [("ACME\\jdoe", "jdoe::ACME:...a")]
    ids = {x.id for x in poison.build_findings(pairs, poisoned=False)}
    assert ids == {"netntlm-captured"}          # observed, but poisoning not asserted


def test_build_findings_empty():
    assert poison.build_findings([], poisoned=True) == []


# -- orchestration: run_poison with injected lines --------------------------- #
def test_run_poison_streams_and_reports():
    bus = EventBus()
    events = []
    bus.subscribe(events.append)
    with tempfile.TemporaryDirectory() as td:
        report, crackres = poison.run_poison(
            "eth0", bus=bus, loot_dir=td, lines=list(LINES),
        )
        # jdoe logged twice -> one captured hash for it; svc_backup once => 2 total
        captured = {f.id: f for f in report.findings}
        hashes = captured["netntlm-captured"].meta["hashes"]
        assert len(hashes) == 2
        assert "llmnr-nbtns-poisoning-possible" in captured   # poison mode + captures
        # loot written for the netntlmv2 type
        assert any(os.path.basename(p) == "netntlmv2.txt" for p in crackres.loot_files)
        content = open(os.path.join(td, "netntlmv2.txt")).read()
        assert "jdoe::ACME:" in content and "svc_backup::ACME:" in content

    kinds = [e.kind for e in events]
    assert EventKind.EDGE in kinds and EventKind.FINDING in kinds
    edge_labels = {e.data.get("label") for e in events if e.kind is EventKind.EDGE}
    assert "poisoned" in edge_labels


def test_run_poison_analyze_mode_no_poisoning_finding():
    with tempfile.TemporaryDirectory() as td:
        report, _ = poison.run_poison(
            "eth0", analyze=True, loot_dir=td, lines=list(LINES),
        )
    ids = {f.id for f in report.findings}
    assert "netntlm-captured" in ids
    assert "llmnr-nbtns-poisoning-possible" not in ids


def test_run_poison_no_captures_is_clean():
    with tempfile.TemporaryDirectory() as td:
        report, crackres = poison.run_poison(
            "eth0", loot_dir=td, lines=["[+] Listening for events...", "nothing here"],
        )
    assert report.findings == []
    assert crackres.creds == []


def test_run_poison_forwards_builtin_flag():
    # run_poison must pass `builtin` through to run_cracking (so --no-crack works).
    from redness.crack import CrackResult
    seen = {}
    orig = poison.run_cracking

    def fake_run_cracking(report, **kw):
        seen["builtin"] = kw.get("builtin")
        return CrackResult()

    try:
        poison.run_cracking = fake_run_cracking
        with tempfile.TemporaryDirectory() as td:
            poison.run_poison("eth0", loot_dir=td, lines=list(LINES), builtin=False)
            assert seen["builtin"] is False
            poison.run_poison("eth0", loot_dir=td, lines=list(LINES))   # default
            assert seen["builtin"] is True
    finally:
        poison.run_cracking = orig


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
