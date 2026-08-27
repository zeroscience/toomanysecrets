"""Offensive action (kerberoast-user) + arm/execute gating - pure, no nxc/DC/bridge.

Run:  python tests/test_actions_offensive.py   (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness import actions  # noqa: E402
from redness.engines.base import Target  # noqa: E402
from redness.findings import Category, Severity  # noqa: E402

# two roastable accounts; the action must keep only the requested principal's hash
SAMPLE_TGS = (
    "$krb5tgs$23$*svc_sql$ACME.LOCAL$aaaa1111bbbb2222\n"
    "$krb5tgs$23$*svc_web$ACME.LOCAL$cccc3333dddd4444\n"
)


def _reset():
    actions._ARM.clear()
    actions._ARM_TIMES.clear()


def _tgt():
    return Target(host="10.0.0.10", domain="ACME.LOCAL", username="u", password="p")


# --- the handler (reuses ldap.parse_kerberoast) --- #
def test_handler_filters_to_principal_and_marks_offensive():
    fs = actions._kerberoast_user("svc_sql", _tgt(), runner=lambda tgt: SAMPLE_TGS)
    assert len(fs) == 1
    f = fs[0]
    assert f.id == "kerberoast-user" and f.severity is Severity.HIGH
    assert f.category is Category.KERBEROS and f.affected == ["svc_sql"]
    assert f.meta["offensive"] is True and f.meta["action"] == "kerberoast-user"
    assert f.meta["hashes"] == [
        {"account": "svc_sql", "hash": "$krb5tgs$23$*svc_sql$ACME.LOCAL$aaaa1111bbbb2222",
         "type": "krb5tgs"}]                     # svc_web excluded


def test_handler_case_insensitive_principal_match():
    fs = actions._kerberoast_user("ACME\\SVC_SQL", _tgt(), runner=lambda tgt: SAMPLE_TGS)
    assert len(fs) == 1 and fs[0].affected == ["ACME\\SVC_SQL"]


# --- arm/execute gating --- #
def test_arm_then_execute_happy_path():
    _reset()
    log = []
    armed = actions.arm("kerberoast-user", "svc_sql", audit=log.append)
    rep = actions.execute_armed_action(
        "kerberoast-user", "svc_sql", _tgt(),
        arm_token=armed["arm_token"], confirm="kerberoast-user",
        audit=log.append, runner=lambda tgt: SAMPLE_TGS)
    assert [f.id for f in rep.findings] == ["kerberoast-user"]
    assert rep.findings[0].meta["offensive"] is True
    events = [r["event"] for r in log]
    assert "arm" in events and "execute" in events and "result" in events


def test_execute_without_arm_is_refused():
    _reset()
    log = []
    rep = actions.execute_armed_action(
        "kerberoast-user", "svc_sql", _tgt(), arm_token="bogus", confirm="kerberoast-user",
        audit=log.append, runner=lambda tgt: SAMPLE_TGS)
    assert rep.findings == []
    assert log[-1]["event"] == "refuse" and log[-1]["reason"] == "not-armed-or-bad-confirm"


def test_execute_wrong_confirm_is_refused():
    _reset()
    log = []
    armed = actions.arm("kerberoast-user", "svc_sql", audit=log.append)
    rep = actions.execute_armed_action(
        "kerberoast-user", "svc_sql", _tgt(), arm_token=armed["arm_token"], confirm="nope",
        audit=log.append, runner=lambda tgt: SAMPLE_TGS)
    assert rep.findings == []
    assert log[-1]["event"] == "refuse" and log[-1]["reason"] == "not-armed-or-bad-confirm"


def test_execute_missing_confirm_is_refused():
    _reset()
    log = []
    armed = actions.arm("kerberoast-user", "svc_sql", audit=log.append)
    rep = actions.execute_armed_action(
        "kerberoast-user", "svc_sql", _tgt(), arm_token=armed["arm_token"], confirm="",
        audit=log.append, runner=lambda tgt: SAMPLE_TGS)
    assert rep.findings == []
    assert log[-1]["event"] == "refuse" and log[-1]["reason"] == "not-armed-or-bad-confirm"


def test_arm_token_is_single_use():
    _reset()
    armed = actions.arm("kerberoast-user", "svc_sql")
    tok = armed["arm_token"]
    ok = actions.execute_armed_action("kerberoast-user", "svc_sql", _tgt(),
                                      arm_token=tok, confirm="kerberoast-user",
                                      runner=lambda tgt: SAMPLE_TGS)
    again = actions.execute_armed_action("kerberoast-user", "svc_sql", _tgt(),
                                         arm_token=tok, confirm="kerberoast-user",
                                         runner=lambda tgt: SAMPLE_TGS)
    assert len(ok.findings) == 1 and again.findings == []      # second use rejected


def test_arm_token_expires():
    _reset()
    armed = actions.arm("kerberoast-user", "svc_sql", now=0.0)
    # a consume far past the TTL fails
    assert actions._consume_arm(armed["arm_token"], "kerberoast-user", "svc_sql",
                                "kerberoast-user", now=actions.ARM_TTL + 1) is False


def test_arm_token_bound_to_action_and_target():
    _reset()
    armed = actions.arm("kerberoast-user", "svc_sql")
    # right token, wrong target -> no match
    assert actions._consume_arm(armed["arm_token"], "kerberoast-user", "svc_web",
                                "kerberoast-user") is False


def test_arm_rate_limited_sixth_within_window():
    _reset()
    log = []
    for _ in range(actions.ARM_RATE_MAX):                 # 5 arms at t=1000
        actions.arm("kerberoast-user", "svc_sql", now=1000.0, audit=log.append)
    # the 6th, still inside the 5-min window, is refused (and audited)
    try:
        actions.arm("kerberoast-user", "svc_sql",
                    now=1000.0 + actions.ARM_RATE_WINDOW - 1, audit=log.append)
        assert False, "expected ArmError"
    except actions.ArmError:
        pass
    assert log[-1]["event"] == "arm-refused" and log[-1]["reason"] == "rate-limited"
    # once the window elapses, arming is allowed again
    ok = actions.arm("kerberoast-user", "svc_sql", now=1000.0 + actions.ARM_RATE_WINDOW + 1)
    assert "arm_token" in ok


def test_arm_rejects_non_offensive_action():
    _reset()
    try:
        actions.arm("enum-smb", "10.0.0.10")
        assert False, "expected ArmError"
    except actions.ArmError:
        pass


def test_run_action_refuses_offensive():
    # the un-gated read-only path must never run an offensive action
    rep = actions.run_action("kerberoast-user", "svc_sql")
    assert rep.findings == []


def test_catalog_exposes_offensive_flag():
    entry = next(e for e in actions.catalog() if e["id"] == "kerberoast-user")
    assert entry["offensive"] is True and entry["node_types"] == ["user"]


# =========================================================================== #
# step 2: secretsdump-target + dcsync-user                                      #
# =========================================================================== #
SAMPLE_SAM = (
    "SMB  10.0.0.5  445  WS01  [+] Dumping SAM hashes\n"
    "SMB  10.0.0.5  445  WS01  Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
    "e19ccf75ee54e06b06a5907af13cef42:::\n"
    "SMB  10.0.0.5  445  WS01  Guest:501:aad3b435b51404eeaad3b435b51404ee:"
    "31d6cfe0d16ae931b73c59d7e0c089c0:::\n"                        # blank password -> dropped
    "SMB  10.0.0.5  445  WS01  svc_local:1001:aad3b435b51404eeaad3b435b51404ee:"
    "5835048ce94ad0564e29a924a03510ef:::\n"
)
SAMPLE_KRBTGT = ("SMB  10.0.0.10  445  DC01  ACME\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:"
                 "b4b9b02e6f09a9bd760f388b67351e2b:::\n")
SAMPLE_JDOE = ("SMB  10.0.0.10  445  DC01  ACME\\jdoe:1103:aad3b435b51404eeaad3b435b51404ee:"
               "5835048ce94ad0564e29a924a03510ef:::\n")
SAMPLE_ADMIN = ("SMB  10.0.0.10  445  DC01  ACME\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
                "e19ccf75ee54e06b06a5907af13cef42:::\n")


def test_parse_secretsdump_dedupes_and_drops_blank():
    out = actions.parse_secretsdump(SAMPLE_SAM)
    assert out == [("Administrator", "500", "e19ccf75ee54e06b06a5907af13cef42"),
                   ("svc_local", "1001", "5835048ce94ad0564e29a924a03510ef")]   # Guest dropped


def test_secretsdump_target_finding():
    fs = actions._secretsdump_target("10.0.0.5", _tgt(), runner=lambda tgt: SAMPLE_SAM)
    assert len(fs) == 1
    f = fs[0]
    assert f.id == "secretsdump-target" and f.severity is Severity.CRITICAL
    assert f.category is Category.SECRET and f.affected == ["10.0.0.5"]
    assert f.meta["offensive"] is True
    creds = f.meta["credentials"]
    assert [c["account"] for c in creds] == ["Administrator", "svc_local"]
    assert all(c["kind"] == "nthash" and c["source"] == "secretsdump" for c in creds)
    assert creds[0]["secret"] == "e19ccf75ee54e06b06a5907af13cef42"    # stored, not masked


def test_dcsync_krbtgt_is_critical_with_golden_ticket_impact():
    fs = actions._dcsync_user("ACME\\krbtgt", _tgt(), runner=lambda target, tgt: SAMPLE_KRBTGT)
    assert len(fs) == 1
    f = fs[0]
    assert f.id == "dcsync-user" and f.severity is Severity.CRITICAL
    assert "Golden Ticket" in f.impact
    assert f.meta["credentials"][0] == {
        "account": "ACME\\krbtgt", "kind": "nthash",
        "secret": "b4b9b02e6f09a9bd760f388b67351e2b", "source": "dcsync"}


def test_dcsync_regular_user_is_high():
    fs = actions._dcsync_user("ACME\\jdoe", _tgt(), runner=lambda target, tgt: SAMPLE_JDOE)
    assert fs[0].severity is Severity.HIGH and "Golden Ticket" not in fs[0].impact


def test_dcsync_builtin_admin_is_critical():
    fs = actions._dcsync_user("ACME\\Administrator", _tgt(), runner=lambda target, tgt: SAMPLE_ADMIN)
    assert fs[0].severity is Severity.CRITICAL       # RID 500


def test_dcsync_filters_to_target_principal():
    combined = SAMPLE_KRBTGT + SAMPLE_JDOE
    fs = actions._dcsync_user("jdoe", _tgt(), runner=lambda target, tgt: combined)
    assert len(fs) == 1 and fs[0].affected == ["jdoe"]
    assert fs[0].meta["credentials"][0]["secret"] == "5835048ce94ad0564e29a924a03510ef"


def test_arm_banner_scoped_per_target():
    _reset()
    kb = actions.arm("dcsync-user", "ACME\\krbtgt")["banner"]
    assert "Golden Ticket" in kb and "SOC/EDR" in kb
    _reset()
    ju = actions.arm("dcsync-user", "ACME\\jdoe")["banner"]
    assert "ACME\\jdoe" in ju and "Golden Ticket" not in ju
    _reset()
    sd = actions.arm("secretsdump-target", "10.0.0.5")["banner"]
    assert "local SAM" in sd


def test_arm_execute_dcsync_happy_path():
    _reset()
    log = []
    armed = actions.arm("dcsync-user", "ACME\\krbtgt", audit=log.append)
    rep = actions.execute_armed_action(
        "dcsync-user", "ACME\\krbtgt", _tgt(), arm_token=armed["arm_token"],
        confirm="dcsync-user", audit=log.append, runner=lambda target, tgt: SAMPLE_KRBTGT)
    assert [f.id for f in rep.findings] == ["dcsync-user"]
    assert rep.findings[0].meta["offensive"] is True
    assert {"arm", "execute", "result"} <= {r["event"] for r in log}


def test_step2_actions_in_catalog():
    cat = {e["id"]: e for e in actions.catalog()}
    assert cat["secretsdump-target"]["offensive"] is True
    assert cat["secretsdump-target"]["node_types"] == ["host"]
    assert cat["dcsync-user"]["offensive"] is True and cat["dcsync-user"]["node_types"] == ["user"]


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
