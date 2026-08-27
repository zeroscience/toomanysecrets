"""Delegation-abuse parsers + findings - pure, no nxc/DC needed.

Fixtures mimic nxc ldap `--trusted-for-delegation` / `--find-delegation` / `-M maq` / `-M gmsa`
output. Run:  python tests/test_delegation.py   (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.engines import delegation as dg  # noqa: E402
from redness.findings import Category, Severity  # noqa: E402

UNCONSTRAINED = """
LDAP  10.10.0.10  389  DC01  DC01$        532480
LDAP  10.10.0.10  389  DC01  WEB01$       524288
LDAP  10.10.0.10  389  DC01  legacyapp    524288
"""   # 0x82000 (DC+deleg), 0x80000 (deleg) x2

FIND_DELEGATION = """
LDAP  10.10.0.10  389  DC01  sqlsvc         Constrained                          MSSQLSvc/db01.acme.local
LDAP  10.10.0.10  389  DC01  websvc         Constrained w/ Protocol Transition   HTTP/web01.acme.local
LDAP  10.10.0.10  389  DC01  FILE01$        Resource-Based Constrained           HOST/attacker01.acme.local
"""

MAQ_OUT = "LDAP  10.10.0.10  389  DC01  [*] ms-DS-MachineAccountQuota: 10\n"
MAQ_ZERO = "LDAP  10.10.0.10  389  DC01  [*] ms-DS-MachineAccountQuota: 0\n"
GMSA_OUT = ("LDAP  10.10.0.10  389  DC01  Account: gmsa_web$   NTLM: aad3b...:5835...\n"
            "LDAP  10.10.0.10  389  DC01  Account: gmsa_sql$   NTLM: aad3b...:e19c...\n")


# --- parsers --- #
def test_parse_unconstrained_flags_dc_by_uac():
    out = dg.parse_unconstrained(UNCONSTRAINED)
    by = {a.account: a.is_dc for a in out}
    assert by == {"DC01$": True, "WEB01$": False, "legacyapp": False}   # 0x2000 bit => DC


def test_parse_unconstrained_dc_by_name_hint():
    out = dg.parse_unconstrained("LDAP  x  389  y  DC02$\n", dc_names={"DC02"})
    assert out[0].is_dc is True


def test_parse_find_delegation_kinds_and_targets():
    out = dg.parse_find_delegation(FIND_DELEGATION)
    kinds = {e.account: e.kind for e in out}
    assert kinds == {"sqlsvc": "constrained", "websvc": "constrained-proto", "FILE01$": "rbcd"}
    assert out[0].to == ["MSSQLSvc/db01.acme.local"]


def test_parse_maq():
    assert dg.parse_maq(MAQ_OUT) == 10
    assert dg.parse_maq(MAQ_ZERO) == 0
    assert dg.parse_maq("nothing here") is None


def test_parse_gmsa():
    assert dg.parse_gmsa(GMSA_OUT) == ["gmsa_web$", "gmsa_sql$"]


# --- findings + severity model --- #
def test_unconstrained_severities_split_dc_vs_non_dc():
    fs = dg.build_findings(unconstrained=dg.parse_unconstrained(UNCONSTRAINED))
    by = {f.id: f for f in fs}
    assert by["delegation-unconstrained"].severity is Severity.HIGH
    assert set(by["delegation-unconstrained"].affected) == {"WEB01$", "legacyapp"}
    assert by["delegation-unconstrained-dc"].severity is Severity.INFO
    assert by["delegation-unconstrained-dc"].affected == ["DC01$"]


def test_constrained_proto_is_critical_plain_is_high():
    fs = dg.build_findings(delegation=dg.parse_find_delegation(FIND_DELEGATION))
    sev = {(f.affected[0]): f.severity for f in fs if f.id.startswith("delegation-")}
    assert sev["sqlsvc"] is Severity.HIGH
    assert sev["websvc"] is Severity.CRITICAL       # protocol transition
    assert sev["FILE01$"] is Severity.HIGH          # rbcd


def test_maq_is_informational_and_zero_is_silent():
    assert dg.build_findings(maq=10)[0].severity is Severity.INFO
    assert dg.build_findings(maq=10)[0].id == "machine-account-quota"
    assert dg.build_findings(maq=0) == []           # quota 0 -> no finding


def test_gmsa_and_shadow_are_high():
    fs = dg.build_findings(gmsa=["gmsa_web$"], shadow=["svc_kcl"])
    by = {f.id: f.severity for f in fs}
    assert by["gmsa-readable"] is Severity.HIGH and by["shadow-credentials"] is Severity.HIGH


def test_category_is_ldap_and_no_credentials_meta():
    fs = dg.build_findings(
        unconstrained=dg.parse_unconstrained(UNCONSTRAINED),
        delegation=dg.parse_find_delegation(FIND_DELEGATION),
        maq=10, gmsa=["gmsa_web$"], shadow=["svc_kcl"])
    assert fs, "expected findings"
    assert all(f.category is Category.LDAP for f in fs)
    assert all("credentials" not in f.meta for f in fs)     # enumeration, not cred recovery


def test_empty_inputs_yield_nothing():
    assert dg.build_findings() == []


def test_maq_escalates_to_critical_with_adcs():
    assert dg.build_findings(maq=10)[0].severity is Severity.INFO
    combo = dg.build_findings(maq=10, adcs_present=True)[0]
    assert combo.severity is Severity.CRITICAL and combo.meta["adcs_combo"] is True


# --- engine wiring (inject the runner seam; no nxc/DC) --- #
from redness.engines.base import Engine, Target  # noqa: E402


class _Proc:
    def __init__(self, stdout=""):
        self.stdout = stdout
        self.stderr = ""


def _fake_engine():
    def runner(cmd, **kw):
        if "--trusted-for-delegation" in cmd:
            return _Proc(UNCONSTRAINED)
        if "--find-delegation" in cmd:
            return _Proc(FIND_DELEGATION)
        if "gmsa" in cmd:
            return _Proc(GMSA_OUT)
        if "maq" in cmd:
            return _Proc(MAQ_OUT)
        return _Proc("")

    class _F(dg.DelegationEngine):
        def is_available(self):
            return True

        def _bin(self):
            return "nxc"
    return _F(runner=runner)


def test_run_wiring_produces_findings():
    tgt = Target(host="dc01.acme.local", domain="acme.local", username="u", password="p")
    ids = {f.id for f in _fake_engine().run(tgt)}
    assert {"delegation-unconstrained", "delegation-unconstrained-dc", "delegation-constrained",
            "delegation-rbcd", "machine-account-quota", "gmsa-readable"} <= ids


def test_run_noop_without_credentials():
    called = {"n": 0}

    class _F(dg.DelegationEngine):
        def is_available(self):
            return True

        def _invoke(self, extra, t):
            called["n"] += 1
            return ""

    assert _F().run(Target(host="dc", username="u")) == []      # no password -> not credentialed
    assert called["n"] == 0


def test_run_short_circuits_when_unavailable():
    class _Unavail(dg.DelegationEngine):
        def is_available(self):
            return False

        def _invoke(self, extra, t):
            raise AssertionError("must not invoke nxc when unavailable")

    assert _Unavail().run(Target(host="dc", username="u", password="p")) == []


def test_dc_names_from_host():
    assert dg._dc_names_from_host("DC01.acme.local") == {"dc01"}
    assert dg._dc_names_from_host("10.10.0.10") == set()      # IP -> rely on the UAC bit


def test_run_scan_passes_adcs_context_to_delegation():
    from redness.scan import run_scan
    from redness.findings import Finding

    class _AdcsEng(Engine):
        name = "certipy"

        def is_available(self):
            return True

        def run(self, t):
            return [Finding(id="adcs-esc1", title="ESC1", severity=Severity.CRITICAL,
                            category=Category.ADCS)]

    class _DelegProbe(Engine):
        name = "delegation"
        wants_adcs_context = True

        def __init__(self):
            self.seen = None

        def is_available(self):
            return True

        def run(self, t, adcs_present=False):
            self.seen = adcs_present
            return []

    probe = _DelegProbe()
    run_scan(["dc"], username="u", password="p", engines=[_AdcsEng(), probe], discover=False)
    assert probe.seen is True         # scan.py wired the ADCS-present flag through


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
