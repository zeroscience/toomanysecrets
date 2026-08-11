"""Parser tests against a captured Responder session log — no Responder/root/LAN.

Run:  python -m pytest -q      (or)     python tests/test_responder_parse.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.engines import responder as rp  # noqa: E402

# Mimics logs/Responder-Session.log: several protocol tags, a leading timestamp on
# one line, an NTLMv1 capture that must be ignored, and jdoe captured twice (same
# hash) so de-duplication is exercised.
SAMPLE = r"""
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.0.55
[SMB] NTLMv2-SSP Username : ACME\jdoe
[SMB] NTLMv2-SSP Hash     : jdoe::ACME:1122334455667788:6E9F3A1CFD5B4E2A9C0D7F8B1A2C3D4E:0101000000000000C0653150DE09D201A1B2C3D40000000002000A00410043004D0045000000000000000000

[HTTP] NTLMv2-SSP Client   : 10.10.0.60
[HTTP] NTLMv2-SSP Username : ACME\svc_backup
[HTTP] NTLMv2-SSP Hash     : svc_backup::ACME:99AABBCCDDEEFF00:AC3B7D2E1F0091C6B5A4938271605F3E:0101000000000000AABBCCDDEEFF0011223344550000000002000A00410043004D0045000000000000000000

[SMB] NTLMv1-SSP Hash      : legacy::ACME:AAAAAAAAAAAAAAAA:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:CCCCCCCCCCCCCCCC

08/11/2026 09:14:22 - [MSSQL] NTLMv2-SSP Hash     : sqlsvc::ACME:0011223344556677:1234567890ABCDEF1234567890ABCDEF:01010000000000001A2B3C4D5E6F70810000000002000A00410043004D0045000000000000000000

[SMB] NTLMv2-SSP Hash     : jdoe::ACME:1122334455667788:6E9F3A1CFD5B4E2A9C0D7F8B1A2C3D4E:0101000000000000C0653150DE09D201A1B2C3D40000000002000A00410043004D0045000000000000000000
"""


def test_extracts_all_v2_captures():
    pairs = rp.parse_responder_log(SAMPLE)
    accounts = [a for a, _ in pairs]
    assert accounts == ["ACME\\jdoe", "ACME\\svc_backup", "ACME\\sqlsvc"]


def test_dedupes_repeated_hash():
    pairs = rp.parse_responder_log(SAMPLE)
    jdoe = [h for a, h in pairs if a == "ACME\\jdoe"]
    assert len(jdoe) == 1                      # logged twice, returned once


def test_ignores_ntlmv1():
    pairs = rp.parse_responder_log(SAMPLE)
    assert all("legacy" not in a for a, _ in pairs)
    assert all("::" in h for _, h in pairs)    # every result is a real NetNTLMv2 string


def test_account_and_hash_shape():
    by_account = dict(rp.parse_responder_log(SAMPLE))
    assert by_account["ACME\\jdoe"].startswith("jdoe::ACME:")
    # hashcat -m 5600 form: user::DOMAIN:chal:NTproof:blob -> 5 colon-separated fields
    assert by_account["ACME\\sqlsvc"].count(":") >= 4


def test_no_matches_returns_empty():
    assert rp.parse_responder_log("nothing to see here\n[+] Listening...\n") == []
    assert rp.parse_responder_log("") == []


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
