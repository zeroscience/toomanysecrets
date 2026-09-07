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
# asrep-roast (offensive; reuses ldap.parse_asrep; needs no credentials)        #
# =========================================================================== #
# two AS-REP roastable accounts; the action must keep only the requested principal's hash
SAMPLE_ASREP = (
    "$krb5asrep$23$svc-backup@ACME.LOCAL:aaaa1111$bbbb2222cccc3333\n"
    "$krb5asrep$23$jdoe@ACME.LOCAL:dddd4444$eeee5555ffff6666\n"
)


def test_asrep_roast_filters_to_principal_and_marks_offensive():
    fs = actions._asrep_roast("svc-backup", _tgt(), runner=lambda tgt: SAMPLE_ASREP)
    assert len(fs) == 1
    f = fs[0]
    assert f.id == "asrep-roast-user" and f.severity is Severity.HIGH
    assert f.category is Category.KERBEROS and f.affected == ["svc-backup"]
    assert f.meta["offensive"] is True and f.meta["action"] == "asrep-roast"
    assert f.meta["hashes"] == [
        {"account": "svc-backup",
         "hash": "$krb5asrep$23$svc-backup@ACME.LOCAL:aaaa1111$bbbb2222cccc3333",
         "type": "krb5asrep"}]                    # jdoe excluded
    assert f.credentialed is False                # AS-REP roasting needs no creds


def test_asrep_roast_case_insensitive_principal_match():
    fs = actions._asrep_roast("ACME\\SVC-BACKUP", _tgt(), runner=lambda tgt: SAMPLE_ASREP)
    assert len(fs) == 1 and fs[0].affected == ["ACME\\SVC-BACKUP"]


def test_asrep_roast_no_hash_returns_empty():
    fs = actions._asrep_roast("ghost", _tgt(), runner=lambda tgt: SAMPLE_ASREP)
    assert fs == []


def test_arm_execute_asrep_happy_path():
    _reset()
    log = []
    armed = actions.arm("asrep-roast", "svc-backup", audit=log.append)
    rep = actions.execute_armed_action(
        "asrep-roast", "svc-backup", _tgt(), arm_token=armed["arm_token"],
        confirm="asrep-roast", audit=log.append, runner=lambda tgt: SAMPLE_ASREP)
    assert [f.id for f in rep.findings] == ["asrep-roast-user"]
    assert rep.findings[0].meta["offensive"] is True
    assert {"arm", "execute", "result"} <= {r["event"] for r in log}


def test_asrep_roast_in_catalog():
    cat = {e["id"]: e for e in actions.catalog()}
    assert cat["asrep-roast"]["offensive"] is True and cat["asrep-roast"]["node_types"] == ["user"]


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


# =========================================================================== #
# adcs-esc1 (offensive; certipy req -> auth; CA auto-resolved from certipy find) #
# =========================================================================== #
SAMPLE_CERTIPY_AUTH = (
    "[*] Using principal: administrator@acme.local\n"
    "[*] Trying to get TGT...\n"
    "[*] Got TGT\n"
    "[*] Saved credential cache to 'administrator.ccache'\n"
    "[*] Trying to retrieve NT hash for 'administrator'\n"
    "[*] Got hash for 'administrator@acme.local': "
    "aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42\n"
)
# certipy `find -json` shape (index-keyed), matching engines/certipy._iter_objects/_name_of
SAMPLE_FIND = {
    "Certificate Templates": {
        "0": {"Template Name": "UserAuth", "Certificate Authorities": ["ACME-CA"]},
        "1": {"Template Name": "WebServer", "Certificate Authorities": ["ACME-CA"]},
    },
    "Certificate Authorities": {
        "0": {"CA Name": "ACME-CA", "DNS Name": "ca01.acme.local"},
    },
}


def test_parse_certipy_auth():
    assert actions.parse_certipy_auth(SAMPLE_CERTIPY_AUTH) == [
        ("administrator@acme.local", "e19ccf75ee54e06b06a5907af13cef42")]
    assert actions.parse_certipy_auth("no hash here") == []


def test_ca_for_template_resolves_name_and_host():
    assert actions.ca_for_template(SAMPLE_FIND, "UserAuth") == ("ACME-CA", "ca01.acme.local")
    assert actions.ca_for_template(SAMPLE_FIND, "userauth") == ("ACME-CA", "ca01.acme.local")  # ci
    assert actions.ca_for_template(SAMPLE_FIND, "Nonexistent") is None


def test_adcs_esc1_finding_shape():
    fs = actions._adcs_esc1("UserAuth", _tgt(), runner=lambda target, tgt: SAMPLE_CERTIPY_AUTH)
    assert len(fs) == 1
    f = fs[0]
    assert f.id == "adcs-esc1-abused" and f.severity is Severity.CRITICAL
    assert f.category is Category.ADCS and f.affected == ["administrator@acme.local"]
    assert f.meta["offensive"] is True and f.meta["action"] == "adcs-esc1"
    assert "esc" not in f.meta                       # omitted on purpose - keeps paths.py clean
    assert f.meta["credentials"] == [{
        "account": "administrator@acme.local", "kind": "nthash",
        "secret": "e19ccf75ee54e06b06a5907af13cef42", "source": "adcs-esc1"}]


def test_adcs_esc1_no_output_returns_empty():
    fs = actions._adcs_esc1("UserAuth", _tgt(), runner=lambda target, tgt: "req failed")
    assert fs == []


def test_arm_execute_adcs_esc1_happy_path():
    _reset()
    log = []
    armed = actions.arm("adcs-esc1", "UserAuth", audit=log.append)
    rep = actions.execute_armed_action(
        "adcs-esc1", "UserAuth", _tgt(), arm_token=armed["arm_token"],
        confirm="adcs-esc1", audit=log.append, runner=lambda target, tgt: SAMPLE_CERTIPY_AUTH)
    assert [f.id for f in rep.findings] == ["adcs-esc1-abused"]
    assert rep.findings[0].meta["offensive"] is True
    assert {"arm", "execute", "result"} <= {r["event"] for r in log}


def test_adcs_esc1_in_catalog():
    cat = {e["id"]: e for e in actions.catalog()}
    assert cat["adcs-esc1"]["offensive"] is True and cat["adcs-esc1"]["node_types"] == ["template"]


# =========================================================================== #
# pth-exec (offensive; fixed recon battery via pass-the-hash; no command input)  #
# =========================================================================== #
SAMPLE_PTH = (
    "SMB  10.0.0.5  445  WS01  [*] Windows 10 (name:WS01) (domain:ACME) (signing:False)\n"
    "SMB  10.0.0.5  445  WS01  [+] ACME\\Administrator:e19ccf75... (Pwn3d!)\n"
    "SMB  10.0.0.5  445  WS01  [+] Executed command via wmiexec\n"
    "SMB  10.0.0.5  445  WS01  acme\\administrator\n"
    "SMB  10.0.0.5  445  WS01  WS01\n"
    "SMB  10.0.0.5  445  WS01  Windows IP Configuration\n"
    "SMB  10.0.0.5  445  WS01  Host Name: WS01\n"
)
SAMPLE_PTH_NOADMIN = (
    "SMB  10.0.0.5  445  WS01  [*] Windows 10 (name:WS01) (domain:ACME) (signing:False)\n"
    "SMB  10.0.0.5  445  WS01  [-] ACME\\lowpriv:pw STATUS_ACCESS_DENIED\n"
)


def test_parse_pth_exec_success_strips_prefix_and_status():
    ok, output = actions.parse_pth_exec(SAMPLE_PTH)
    assert ok is True
    assert "acme\\administrator" in output and "Windows IP Configuration" in output
    assert "[+]" not in output and "Pwn3d" not in output   # nxc status lines dropped


def test_parse_pth_exec_non_admin_is_no_exec():
    assert actions.parse_pth_exec(SAMPLE_PTH_NOADMIN) == (False, "")


def test_pth_exec_finding_is_critical_no_credentials():
    fs = actions._pth_exec("10.0.0.5", _tgt(), runner=lambda tgt: SAMPLE_PTH)
    assert len(fs) == 1
    f = fs[0]
    assert f.id == "pth-exec" and f.severity is Severity.CRITICAL
    assert f.category is Category.SMB and f.affected == ["10.0.0.5"]
    assert f.meta["offensive"] is True and f.meta["action"] == "pth-exec"
    assert "credentials" not in f.meta                     # consumes a hash, recovers none
    assert "acme\\administrator" in f.evidence[0].detail    # proof-of-exec snippet


def test_pth_exec_no_exec_returns_empty():
    fs = actions._pth_exec("10.0.0.5", _tgt(), runner=lambda tgt: SAMPLE_PTH_NOADMIN)
    assert fs == []


def test_pth_exec_battery_is_whitelisted_recon_only():
    # the guardrail: only these four read-only commands can ever run - no arbitrary input path
    cmds = [c.strip().split()[0].lower() for c in actions.RECON_BATTERY.split("&")]
    assert set(cmds) == {"whoami", "hostname", "ipconfig", "systeminfo"}


def test_arm_execute_pth_exec_happy_path():
    _reset()
    log = []
    armed = actions.arm("pth-exec", "10.0.0.5", audit=log.append)
    rep = actions.execute_armed_action(
        "pth-exec", "10.0.0.5", _tgt(), arm_token=armed["arm_token"],
        confirm="pth-exec", audit=log.append, runner=lambda tgt: SAMPLE_PTH)
    assert [f.id for f in rep.findings] == ["pth-exec"]
    assert rep.findings[0].meta["offensive"] is True
    assert {"arm", "execute", "result"} <= {r["event"] for r in log}


def test_pth_exec_in_catalog():
    cat = {e["id"]: e for e in actions.catalog()}
    assert cat["pth-exec"]["offensive"] is True and cat["pth-exec"]["node_types"] == ["host"]


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
