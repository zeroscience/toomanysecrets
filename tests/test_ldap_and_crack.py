"""LDAP hash-capture parsers + crack orchestration — no nxc/hashcat/DC needed.

Run:  python tests/test_ldap_and_crack.py   (or)   python -m pytest -q
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.engines import ldap  # noqa: E402
from redness import crack  # noqa: E402
from redness.findings import Category, Report, Severity  # noqa: E402

ASREP = r"""
LDAP        10.10.0.15   389    DC01    [*] Total records returned: 1
LDAP        10.10.0.15   389    DC01    $krb5asrep$23$svc-backup@ACME.LOCAL:aa11bb22$ccddee...
"""
TGS = r"""
LDAP        10.10.0.15   389    DC01    [*] Total kerberoastable users : 1
LDAP        10.10.0.15   389    DC01    $krb5tgs$23$*svc-sql$ACME.LOCAL$svc-sql*$f00d$beef...
"""
USERS = r"""
LDAP        10.10.0.15   389    DC01    Administrator
LDAP        10.10.0.15   389    DC01    svc-backup
LDAP        10.10.0.15   389    DC01    [*] Total 2
"""


def test_parse_asrep():
    pairs = ldap.parse_asrep(ASREP)
    assert len(pairs) == 1
    assert pairs[0][0] == "svc-backup"
    assert pairs[0][1].startswith("$krb5asrep$23$svc-backup@ACME.LOCAL:")


def test_parse_kerberoast():
    pairs = ldap.parse_kerberoast(TGS)
    assert pairs[0][0] == "svc-sql"
    assert pairs[0][1].startswith("$krb5tgs$23$*svc-sql$")


def test_parse_users_skips_noise():
    users = ldap.parse_users(USERS)
    assert users == ["Administrator", "svc-backup"]


def test_parse_all_findings_carry_hashes():
    findings = ldap.parse_all(ASREP + TGS + USERS, credentialed=True)
    ids = {f.id: f for f in findings}
    assert "krb-asrep-roastable" in ids and "krb-kerberoastable" in ids
    meta = ids["krb-asrep-roastable"].meta["hashes"]
    assert meta[0]["type"] == "krb5asrep" and meta[0]["account"] == "svc-backup"


def _report_with_hashes():
    r = Report(engagement="t", target="dc")
    r.findings = ldap.parse_all(ASREP + TGS, credentialed=True)
    return r


def test_collect_hashes():
    creds = crack.collect_hashes(_report_with_hashes())
    assert {c.hash_type for c in creds} == {"krb5asrep", "krb5tgs"}


def test_write_loot():
    creds = crack.collect_hashes(_report_with_hashes())
    with tempfile.TemporaryDirectory() as td:
        paths = crack.write_loot(creds, td)
        names = sorted(os.path.basename(p) for p in paths)
        assert names == ["krb5asrep.txt", "krb5tgs.txt"]
        content = open(os.path.join(td, "krb5asrep.txt")).read()
        assert "$krb5asrep$" in content


def test_hashcat_show_prefix_mapping():
    creds = crack.collect_hashes(_report_with_hashes())
    asrep = next(c for c in creds if c.hash_type == "krb5asrep")
    # password contains a ':' to prove prefix-based mapping (not naive split)
    show = f"{asrep.value}:Sum:mer2024!"
    crack.parse_hashcat_show(show, creds)
    assert asrep.password == "Sum:mer2024!"


def test_crack_with_stub_runner_and_annotate():
    report = _report_with_hashes()
    creds = crack.collect_hashes(report)
    asrep = next(c for c in creds if c.hash_type == "krb5asrep")

    class _Proc:
        def __init__(self, stdout=""):
            self.stdout = stdout

    calls = []

    def fake_runner(cmd, **kw):
        calls.append(cmd)
        if "--show" in cmd and "18200" in cmd:      # hashcat show for asrep
            return _Proc(f"{asrep.value}:Password1")
        return _Proc("")

    with tempfile.TemporaryDirectory() as td:
        wl = os.path.join(td, "wl.txt")
        open(wl, "w").write("Password1\n")
        used = crack.crack(creds, wl, tool="hashcat", workdir=td, runner=fake_runner)
    assert used == "hashcat"
    assert asrep.password == "Password1"

    crack.annotate(report, [c for c in creds if c.password])
    cracked = [f for f in report.findings if f.id == "credential-cracked"]
    assert cracked and cracked[0].severity is Severity.CRITICAL
    assert cracked[0].category is Category.KERBEROS


def test_crack_noop_without_tool_or_wordlist():
    creds = crack.collect_hashes(_report_with_hashes())
    assert crack.crack(creds, "/nonexistent/wordlist", tool="hashcat") == ""


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
