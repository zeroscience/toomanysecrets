"""Remote-access engines (RDP / WinRM / MSSQL) - pure parsers, no nxc/host needed.

Fixtures mimic real `nxc rdp|winrm|mssql` stdout. Run:
    python tests/test_remote.py    (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.engines import remote  # noqa: E402
from redness.engines.base import Target  # noqa: E402
from redness.findings import Category, Severity  # noqa: E402
from redness.scan import default_engines  # noqa: E402

# --- RDP: NLA disabled + exposure + credentialed access --- #
RDP_NLA_OFF = (
    "RDP         10.10.0.15      3389   PC01             "
    "[*] Windows 10 or Windows Server 2016 Build 19041 (name:PC01) (domain:ACME.LOCAL) (nla:False)\n"
)
RDP_NLA_ON = (
    "RDP         10.10.0.30      3389   DC01             "
    "[*] Windows Server 2022 Build 20348 (name:DC01) (domain:ACME.LOCAL) (nla:True)\n"
)
RDP_OLD_HYBRID = (
    "RDP         10.10.0.20      3389   PC02             "
    "[*] Probably old, doesn't not support HYBRID or HYBRID_EX (nla:False)\n"
)
RDP_ACCESS_ADMIN = RDP_NLA_OFF + (
    "RDP         10.10.0.15      3389   PC01             [+] ACME.LOCAL\\administrator:Passw0rd! (Pwn3d!)\n"
)

# --- WinRM --- #
WINRM_EXPOSED = (
    "WINRM       10.10.0.15      5985   PC01             [*] Windows 10 (name:PC01) (domain:ACME.LOCAL)\n"
)
WINRM_SSL_EXPOSED = (
    "WINRM-SSL   10.10.0.16      5986   PC03             [*] Windows Server 2019 (name:PC03) (domain:ACME.LOCAL)\n"
)
WINRM_ACCESS = WINRM_EXPOSED + (
    "WINRM       10.10.0.15      5985   PC01             [+] ACME.LOCAL\\jdoe:Passw0rd!\n"
)
WINRM_ACCESS_ADMIN = WINRM_EXPOSED + (
    "WINRM       10.10.0.15      5985   PC01             [+] ACME.LOCAL\\svc_adm:Passw0rd! (Pwn3d!)\n"
)

# --- MSSQL --- #
MSSQL_EXPOSED = (
    "MSSQL       10.10.0.40      1433   SQL01            "
    "[*] Windows Server 2019 (Microsoft SQL Server 2019 15.0.2000) (name:SQL01) (domain:ACME.LOCAL) (encryption:False)\n"
)
MSSQL_ACCESS_ADMIN = MSSQL_EXPOSED + (
    "MSSQL       10.10.0.40      1433   SQL01            [+] ACME.LOCAL\\sa:Passw0rd! (Pwn3d!)\n"
)


# --------------------------------------------------------------------------- #
# Shared banner / access parsers                                              #
# --------------------------------------------------------------------------- #
def test_parse_banner_nla_and_facts():
    b = remote.parse_banner(RDP_NLA_OFF, "RDP")
    assert b.host == "10.10.0.15" and b.nla is False
    assert b.name == "PC01" and b.domain == "ACME.LOCAL"
    assert "Windows 10" in b.os


def test_parse_banner_old_hybrid_still_reads_nla():
    b = remote.parse_banner(RDP_OLD_HYBRID, "RDP")
    assert b.reachable and b.nla is False


def test_parse_banner_none_when_absent():
    assert remote.parse_banner(WINRM_EXPOSED, "RDP") is None   # wrong protocol token


def test_winrm_ssl_token_matches():
    b = remote.parse_banner(WINRM_SSL_EXPOSED, "WINRM")
    assert b is not None and b.host == "10.10.0.16"


def test_parse_access_admin_and_identity():
    acc = remote.parse_access(RDP_ACCESS_ADMIN, "RDP")
    assert acc.identity == "ACME.LOCAL\\administrator" and acc.admin is True


def test_parse_access_none_without_success_line():
    assert remote.parse_access(WINRM_EXPOSED, "WINRM") is None


def test_parse_access_ignores_empty_principal():
    # a bare "[+] DOM\:" (null-ish) must never register as access
    raw = "RDP  10.10.0.15  3389  PC01  [+] ACME.LOCAL\\:\n"
    assert remote.parse_access(raw, "RDP") is None


# --------------------------------------------------------------------------- #
# RDP findings                                                                #
# --------------------------------------------------------------------------- #
def test_rdp_nla_disabled_finding():
    fs = remote.parse_rdp(RDP_NLA_OFF)
    by = {f.id: f for f in fs}
    assert by["rdp-nla-disabled"].severity is Severity.MEDIUM
    assert by["rdp-nla-disabled"].category is Category.CONFIG
    assert by["rdp-exposed"].severity is Severity.INFO
    assert by["rdp-exposed"].category is Category.ENUM
    assert "rdp-access" not in by                              # no creds -> no access finding


def test_rdp_nla_enabled_no_weakness():
    ids = [f.id for f in remote.parse_rdp(RDP_NLA_ON)]
    assert "rdp-nla-disabled" not in ids and "rdp-exposed" in ids


def test_rdp_admin_access_high():
    by = {f.id: f for f in remote.parse_rdp(RDP_ACCESS_ADMIN, credentialed=True)}
    acc = by["rdp-access"]
    assert acc.severity is Severity.HIGH and acc.credentialed is True
    assert "administrator" in acc.title and "(Pwn3d!)" in acc.evidence[0].detail


# --------------------------------------------------------------------------- #
# WinRM / MSSQL findings                                                       #
# --------------------------------------------------------------------------- #
def test_winrm_exposed_only():
    ids = [f.id for f in remote.parse_winrm(WINRM_EXPOSED)]
    assert ids == ["winrm-exposed"]


def test_winrm_access_non_admin_high():
    by = {f.id: f for f in remote.parse_winrm(WINRM_ACCESS, credentialed=True)}
    assert by["winrm-access"].severity is Severity.HIGH


def test_winrm_access_admin_critical():
    by = {f.id: f for f in remote.parse_winrm(WINRM_ACCESS_ADMIN, credentialed=True)}
    assert by["winrm-access"].severity is Severity.CRITICAL


def test_mssql_admin_access_critical():
    by = {f.id: f for f in remote.parse_mssql(MSSQL_ACCESS_ADMIN, credentialed=True)}
    assert by["mssql-exposed"].severity is Severity.INFO
    assert by["mssql-access"].severity is Severity.CRITICAL
    assert by["mssql-access"].affected == ["10.10.0.40"]


# --------------------------------------------------------------------------- #
# Wiring: engines are in the default scan and passive by default              #
# --------------------------------------------------------------------------- #
def test_engines_registered_in_default_scan():
    names = {e.name for e in default_engines()}
    assert {"rdp", "winrm", "mssql"} <= names


def test_uncredentialed_engine_sends_no_auth_args():
    eng = remote.RdpEngine()
    assert eng._auth_args(Target(host="10.10.0.15")) == []            # pure banner read
    creds = Target(host="10.10.0.15", username="u", password="p", domain="ACME")
    assert eng._auth_args(creds) == ["-u", "u", "-p", "p", "-d", "ACME"]


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
