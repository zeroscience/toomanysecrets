"""Passive capture analysis: tshark credential + protocol-hierarchy parsing."""
from redness import capture
from redness.findings import Category, Severity

_TSHARK = """Running as user "root"...

===================================================================
Credentials
-------------------------------------------------------------------
Packet\tProtocol\tUsername\tInfo
-------------------------------------------------------------------
7\tFTP\tanonymous\tUsername in packet: 7
12\tHTTP\tadmin\tHTTP Basic auth
-------------------------------------------------------------------
===================================================================

===================================================================
Protocol Hierarchy Statistics
Filter:

eth                                      frames:100 bytes:12000
  ip                                     frames:100 bytes:12000
    tcp                                  frames:80 bytes:9000
      ftp                                frames:10 bytes:600
      http                               frames:20 bytes:3000
      telnet                             frames:5 bytes:200
    udp                                  frames:20 bytes:3000
      dns                                frames:20 bytes:3000
===================================================================
"""


def test_parse_credentials():
    creds = capture.parse_credentials(_TSHARK)
    assert [c["username"] for c in creds] == ["anonymous", "admin"]
    assert creds[0]["protocol"] == "FTP" and creds[1]["protocol"] == "HTTP"


def test_parse_protocols():
    protos = capture.parse_protocols(_TSHARK)
    assert {"ftp", "http", "telnet", "dns", "tcp"} <= protos


def test_build_findings():
    creds = capture.parse_credentials(_TSHARK)
    protos = capture.parse_protocols(_TSHARK)
    fs = capture.build_findings(creds, protos)
    ids = [f.id for f in fs]
    assert ids == ["cleartext-credentials", "cleartext-protocols"]
    assert fs[0].severity is Severity.CRITICAL and fs[0].category is Category.PASSWORD
    assert fs[1].severity is Severity.MEDIUM and fs[1].category is Category.CONFIG
    assert set(fs[1].affected) == {"ftp", "http", "telnet"}       # dns is not flagged
    assert fs[0].meta["count"] == 2


def test_creds_argv_pcap_and_live():
    assert capture.creds_argv("f.pcap") == ["tshark", "-r", "f.pcap", "-q", "-z", "credentials",
                                            "-z", "io,phs"]
    live = capture.creds_argv("eth0", live=True, duration=30)
    assert "-i" in live and "eth0" in live and "duration:30" in live


def test_run_capture_with_injected_runner():
    rep = capture.run_capture("f.pcap", runner=lambda argv, timeout: _TSHARK)
    assert rep.target == "f.pcap"
    assert {f.id for f in rep.findings} == {"cleartext-credentials", "cleartext-protocols"}


def test_run_capture_empty():
    rep = capture.run_capture("f.pcap", runner=lambda argv, timeout: "")
    assert rep.findings == []


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            passed += 1
    print(f"{passed} passed")
