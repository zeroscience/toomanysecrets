"""Parser tests against captured NetExec SMB output — no nxc or DC required.

Run:  python -m pytest -q      (or)     python tests/test_netexec_parse.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.engines import netexec as nx  # noqa: E402
from redness.findings import Category, Severity  # noqa: E402

SAMPLE = r"""
SMB         10.10.0.15      445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:acme.local) (signing:False) (SMBv1:True)
SMB         10.10.0.22      445    FS01             [*] Windows Server 2016 Build 14393 x64 (name:FS01) (domain:acme.local) (signing:True) (SMBv1:False)
SMB         10.10.0.15      445    DC01             [+] acme.local\guest:
SMB         10.10.0.22      445    FS01             [+] acme.local\svc:Passw0rd (Pwn3d!)
SMB         10.10.0.22      445    FS01             [*] Enumerated shares
SMB         10.10.0.22      445    FS01             Share           Permissions     Remark
SMB         10.10.0.22      445    FS01             -----           -----------     ------
SMB         10.10.0.22      445    FS01             ADMIN$                          Remote Admin
SMB         10.10.0.22      445    FS01             C$                              Default share
SMB         10.10.0.22      445    FS01             IPC$            READ            Remote IPC
SMB         10.10.0.22      445    FS01             backups         READ,WRITE      Nightly backups
SMB         10.10.0.22      445    FS01             public          READ            Public files
"""


def _by_id(findings):
    return {f.id: f for f in findings}


def test_hosts_banner():
    hosts = nx.parse_hosts(SAMPLE)
    assert hosts["10.10.0.15"].signing is False
    assert hosts["10.10.0.15"].smbv1 is True
    assert hosts["10.10.0.22"].signing is True
    assert hosts["10.10.0.15"].domain == "acme.local"


def test_banner_findings():
    f = _by_id(nx.parse_banner_findings(SAMPLE))
    assert "smb-signing-not-required" in f
    assert f["smb-signing-not-required"].affected == ["10.10.0.15"]
    assert f["smb-signing-not-required"].severity is Severity.MEDIUM
    assert "smbv1-enabled" in f
    assert f["smbv1-enabled"].severity is Severity.HIGH


def test_null_session():
    f = _by_id(nx.parse_null_session(SAMPLE))
    assert "smb-null-or-guest-auth" in f
    assert any("10.10.0.15" in a for a in f["smb-null-or-guest-auth"].affected)


def test_null_session_deduped():
    # banner + shares runs repeat the same null-auth line; affected must not duplicate.
    dup = (
        "SMB  10.10.0.15  445  DC01  [+] acme.local\\:\n"
        "SMB  10.10.0.15  445  DC01  [+] acme.local\\:\n"
    )
    f = nx.parse_null_session(dup)[0]
    assert len(f.affected) == 1


def test_null_session_from_banner_field():
    # newer nxc reports anonymous access in the banner, not as a [+] auth line
    raw = ("SMB  10.10.0.15  445  DC01  [*] Windows Server 2022 Build 20348 x64 "
           "(name:DC01) (domain:acme.local) (signing:True) (SMBv1:None) (Null Auth:True)\n")
    f = nx.parse_null_session(raw)
    assert f and f[0].id == "smb-null-or-guest-auth"
    assert f[0].affected == ["10.10.0.15"]


def test_null_auth_false_not_flagged():
    raw = ("SMB  10.10.0.20  445  DC02  [*] Windows Server 2022 Build 20348 x64 "
           "(name:DC02) (domain:acme.local) (signing:True) (SMBv1:None) (Null Auth:False)\n")
    assert nx.parse_null_session(raw) == []


def test_hardened_dc_banner_no_false_positives():
    # signing:True + SMBv1:None (undetermined) must NOT yield signing/smbv1 findings
    raw = ("SMB  10.10.0.15  445  DC01  [*] Windows Server 2022 Build 20348 x64 "
           "(name:DC01) (domain:acme.local) (signing:True) (SMBv1:None) (Null Auth:True)\n")
    ids = {f.id for f in nx.parse_banner_findings(raw)}
    assert "smb-signing-not-required" not in ids
    assert "smbv1-enabled" not in ids


def test_shares():
    f = _by_id(nx.parse_shares(SAMPLE))
    assert "smb-writable-share" in f
    assert f["smb-writable-share"].affected == ["10.10.0.22\\backups"]
    # IPC$ is default -> not flagged writable/readable; 'public' READ is non-default
    assert "enum-smb-shares" in f
    assert f["enum-smb-shares"].category is Category.ENUM


def test_parse_all_smoke():
    findings = nx.parse_all(SAMPLE, credentialed=True)
    ids = {f.id for f in findings}
    assert {"smb-signing-not-required", "smbv1-enabled",
            "smb-null-or-guest-auth", "smb-writable-share"} <= ids


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
