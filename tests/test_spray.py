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


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
