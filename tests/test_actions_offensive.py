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


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
