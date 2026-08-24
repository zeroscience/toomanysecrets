"""GPP cpassword parser + findings - pure, no nxc/DC needed.

Fixture mimics `nxc smb <dc> -M gpp_password` stdout. Run:
    python tests/test_gpp.py    (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.engines import gpp  # noqa: E402
from redness.findings import Category, Severity  # noqa: E402

SAMPLE = r"""
SMB         10.10.0.10      445    DC01             [*] Windows Server 2019 Build 17763
SMB         10.10.0.10      445    DC01             [+] Found credentials in \\acme.local\SYSVOL\acme.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
SMB         10.10.0.10      445    DC01             Password: Local*Admin*2024!
SMB         10.10.0.10      445    DC01             Usernames: ['Administrator', 'localadmin']
SMB         10.10.0.10      445    DC01             [+] Found credentials in \\acme.local\SYSVOL\acme.local\Policies\{AAAAAAAA-1111-2222-3333-444444444444}\Machine\Preferences\Services\Services.xml
SMB         10.10.0.10      445    DC01             Password: Svc#Pass99
SMB         10.10.0.10      445    DC01             Username: svc_sql
SMB         10.10.0.10      445    DC01             [+] Found credentials in \\acme.local\SYSVOL\acme.local\Policies\{BBBBBBBB-0000-0000-0000-000000000000}\Machine\Preferences\Drives\Drives.xml
SMB         10.10.0.10      445    DC01             Password:
SMB         10.10.0.10      445    DC01             Usernames: ['mapdrive']
"""


def test_parse_extracts_creds_and_skips_empty():
    creds = gpp.parse_gpp_output(SAMPLE)
    assert [(c.username, c.password) for c in creds] == [
        ("Administrator", "Local*Admin*2024!"),
        ("localadmin", "Local*Admin*2024!"),
        ("svc_sql", "Svc#Pass99"),
    ]
    assert all(c.username != "mapdrive" for c in creds)   # empty cpassword block skipped


def test_parse_source_and_gpo():
    creds = gpp.parse_gpp_output(SAMPLE)
    assert creds[0].source == "Groups.xml"
    assert creds[0].gpo == "{31B2F340-016D-11D2-945F-00C04FB984F9}"
    assert creds[2].source == "Services.xml"             # singular "Username:" form parsed


def test_build_findings_shape_and_stored_password():
    findings = gpp.build_findings(gpp.parse_gpp_output(SAMPLE), host="10.10.0.10")
    assert len(findings) == 3
    f = findings[0]
    assert f.id == "gpp-cpassword" and f.severity is Severity.CRITICAL
    assert f.category is Category.SECRET
    assert f.affected == ["Administrator"]
    cred = f.meta["credentials"][0]
    assert cred == {
        "account": "Administrator", "username": "Administrator",
        "kind": "password", "password": "Local*Admin*2024!", "source": "gpp-Groups.xml",
    }
    # stored (not masked), per the credential-cracked precedent decision
    assert "Local*Admin*2024!" in f.evidence[0].detail


def test_empty_output():
    assert gpp.parse_gpp_output("") == []
    assert gpp.build_findings([]) == []


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
