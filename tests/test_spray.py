"""Password-spray parsers + safety math + findings - pure, no nxc/DC needed.

Fixtures mimic `nxc smb --pass-pol` and nxc spray stdout. Run:
    python tests/test_spray.py    (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.engines import spray  # noqa: E402
from redness.findings import Category, Severity  # noqa: E402

PASS_POL = r"""
SMB         10.10.0.10      445    DC01             [+] Dumping password info for domain: ACME
SMB         10.10.0.10      445    DC01             Minimum password length: 7
SMB         10.10.0.10      445    DC01             Password history length: 24
SMB         10.10.0.10      445    DC01             Maximum password age: 42 days
SMB         10.10.0.10      445    DC01             Reset Account Lockout Counter: 30 minutes
SMB         10.10.0.10      445    DC01             Locked Account Duration: 30 minutes
SMB         10.10.0.10      445    DC01             Account Lockout Threshold: 5
SMB         10.10.0.10      445    DC01             Forced Log off Time: Not Set
"""

PASS_POL_NONE = r"""
SMB         10.10.0.10      445    DC01             Minimum password length: 7
SMB         10.10.0.10      445    DC01             Account Lockout Threshold: None
"""

SPRAY = r"""
SMB         10.10.0.10      445    DC01             [-] ACME\alice:Spring2024! STATUS_LOGON_FAILURE
SMB         10.10.0.10      445    DC01             [-] ACME\bob:Spring2024! STATUS_LOGON_FAILURE
SMB         10.10.0.10      445    DC01             [+] ACME\jdoe:Spring2024!
SMB         10.10.0.10      445    DC01             [+] ACME\svc_admin:Spring2024! (Pwn3d!)
"""


def test_parse_pass_pol():
    pol = spray.parse_pass_pol(PASS_POL)
    assert pol.threshold == 5
    assert pol.observation_window == 30
    assert pol.lockout_duration == 30
    assert pol.min_length == 7


def test_parse_pass_pol_none_threshold():
    assert spray.parse_pass_pol(PASS_POL_NONE).threshold == 0


def test_parse_spray_hits():
    hits = spray.parse_spray_hits(SPRAY)
    assert [(h.username, h.password, h.admin) for h in hits] == [
        ("ACME\\jdoe", "Spring2024!", False),
        ("ACME\\svc_admin", "Spring2024!", True),
    ]  # [-] failures ignored


def test_safety_math():
    assert spray.safe_budget(spray.PassPolicy(threshold=5)) == 4      # threshold - margin
    assert spray.is_spray_safe(spray.PassPolicy(threshold=5)) is True
    assert spray.safe_budget(spray.PassPolicy(threshold=1)) == 0      # one attempt already unsafe
    assert spray.is_spray_safe(spray.PassPolicy(threshold=1)) is False
    assert spray.safe_budget(spray.PassPolicy(threshold=0)) == spray.NO_LOCKOUT
    assert spray.is_spray_safe(spray.PassPolicy(threshold=0)) is True


def test_spray_argv():
    assert spray.spray_argv("10.10.0.10", "users.txt", "Spring2024!") == [
        "smb", "10.10.0.10", "-u", "users.txt", "-p", "Spring2024!", "--continue-on-success"]


def test_build_findings_severity_and_stored_creds():
    findings = spray.build_findings(spray.parse_spray_hits(SPRAY),
                                    spray.parse_pass_pol(PASS_POL), host="10.10.0.10")
    hits = [f for f in findings if f.id == "spray-hit"]
    assert len(hits) == 2
    jdoe = hits[0]
    assert jdoe.severity is Severity.HIGH and jdoe.category is Category.PASSWORD
    assert jdoe.affected == ["ACME\\jdoe"]
    assert jdoe.meta["credentials"][0] == {
        "account": "ACME\\jdoe", "username": "jdoe", "kind": "password",
        "password": "Spring2024!", "source": "spray"}
    assert "Spring2024!" in jdoe.evidence[0].detail            # stored, not masked
    assert hits[1].severity is Severity.CRITICAL               # Pwn3d! admin -> CRITICAL
    # threshold 5 -> no policy-weakness finding here
    assert not any(f.id == "password-policy-no-lockout" for f in findings)


def test_no_lockout_policy_finding():
    findings = spray.build_findings([], spray.parse_pass_pol(PASS_POL_NONE), host="dc")
    assert [f.id for f in findings] == ["password-policy-no-lockout"]
    assert findings[0].severity is Severity.MEDIUM


# --- run_spray orchestration (inject the nxc boundary; no nxc/DC) --- #
import tempfile  # noqa: E402

from redness.spray import run_spray  # noqa: E402

PASS_POL_T1 = "SMB  10.10.0.10  445  DC01  Account Lockout Threshold: 1\n"


def _nxc_stub(passpol=PASS_POL, spray_out=SPRAY, *, forbid_spray=False):
    """Fake nxc_run keyed on argv: --pass-pol / --users / (the spray call)."""
    def _run(argv):
        if "--pass-pol" in argv:
            return passpol
        if "--users" in argv:
            return ""                       # user_file supplied in these tests
        if forbid_spray:
            raise AssertionError("spray must not run when refused")
        return spray_out
    return _run


def test_run_spray_proceeds_and_hits():
    report, res = run_spray(
        "10.10.0.10", "Spring2024!", username="u", auth_password="p",
        user_file="users.txt", loot_dir=tempfile.mkdtemp(), nxc_run=_nxc_stub())
    assert res.refused is False
    assert len(res.hits) == 2
    assert [f.id for f in report.findings] == ["spray-hit", "spray-hit"]


def test_run_spray_refuses_low_threshold():
    report, res = run_spray(
        "10.10.0.10", "Spring2024!", username="u", auth_password="p",
        user_file="users.txt", nxc_run=_nxc_stub(passpol=PASS_POL_T1, forbid_spray=True))
    assert res.refused and res.reason == "lockout-risk"     # threshold 1 -> budget 0
    assert report.findings == []


def test_run_spray_refuses_uncredentialed_without_force():
    called = {"n": 0}

    def _run(argv):
        called["n"] += 1
        return ""

    report, res = run_spray("10.10.0.10", "Spring2024!", user_file="users.txt", nxc_run=_run)
    assert res.refused and res.reason == "unknown-policy"
    assert called["n"] == 0                                 # no recon/spray when refused blind


def test_force_alone_insufficient_without_confirm():
    # --force set but no positive FORCE confirmation -> still refused
    _, res = run_spray("10.10.0.10", "Spring2024!", username="u", auth_password="p",
                       user_file="users.txt", force=True, confirm_force=lambda r: False,
                       nxc_run=_nxc_stub(passpol=PASS_POL_T1, forbid_spray=True))
    assert res.refused and res.reason == "lockout-risk"


def test_force_with_confirmation_overrides_and_sprays():
    seen = {"reason": None}

    def _confirm(reason):
        seen["reason"] = reason
        return True

    _, res = run_spray("10.10.0.10", "Spring2024!", username="u", auth_password="p",
                       user_file="users.txt", loot_dir=tempfile.mkdtemp(), force=True,
                       confirm_force=_confirm, nxc_run=_nxc_stub(passpol=PASS_POL_T1))
    assert res.refused is False and len(res.hits) == 2
    assert seen["reason"] == "lockout-risk"                 # the FORCE gate was consulted


def test_uncredentialed_force_without_user_file_refused_no_users():
    # override the unknown-policy gate, but there is still nothing to spray
    _, res = run_spray("10.10.0.10", "Spring2024!", force=True, confirm_force=lambda r: True,
                       nxc_run=_nxc_stub(forbid_spray=True))
    assert res.refused and res.reason == "no-users"


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
