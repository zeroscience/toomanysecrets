"""Advisor tests - detected-services extraction, rule suggestions, tiers, OT-safe exclusion.

Pure rule engine; no tools needed (availability is resolved via shutil.which but assertions
don't depend on what's installed).

Run:  python -m pytest tests/test_advisor.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.advisor import detected_services, ot_hosts, suggest  # noqa: E402
from redness.findings import Category, Evidence, Finding, Report, Severity  # noqa: E402


def _nmap_finding(host, services):
    return Finding(id="nmap-services", title="inv", severity=Severity.INFO, category=Category.ENUM,
                   affected=[host], meta={"services": services})


def _report():
    return Report(engagement="t", target="10.0.0.5", findings=[
        _nmap_finding("10.0.0.5", [
            {"host": "10.0.0.5", "port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.49"},
            {"host": "10.0.0.5", "port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.4"},
            {"host": "10.0.0.5", "port": 445, "service": "microsoft-ds", "product": "", "version": ""},
        ]),
        _nmap_finding("10.0.0.9", [
            {"host": "10.0.0.9", "port": 502, "service": "modbus", "product": "", "version": ""},
            {"host": "10.0.0.9", "port": 80, "service": "http", "product": "", "version": ""},
        ]),
        Finding(id="modbus-exposed", title="PLC", severity=Severity.HIGH, category=Category.ICS,
                affected=["10.0.0.9"]),
    ])


def test_detected_services_from_nmap_and_web_findings():
    rep = Report(findings=[
        _nmap_finding("10.0.0.5", [{"host": "10.0.0.5", "port": 22, "service": "ssh"}]),
        Finding(id="nuclei:x", title="x", severity=Severity.LOW, category=Category.WEB,
                affected=["10.0.0.7:8443"]),
    ])
    svcs = detected_services(rep)
    assert {"host": "10.0.0.5", "port": 22, "service": "ssh", "product": "", "version": ""} in svcs
    assert any(s["host"] == "10.0.0.7" and s["port"] == 8443 and s["service"] == "https" for s in svcs)


def test_ot_hosts_excluded():
    assert ot_hosts(_report()) == {"10.0.0.9"}
    sg = suggest(_report())
    # nothing should target the OT host 10.0.0.9 (even its web port) ...
    assert all(not s.target.startswith("10.0.0.9") and "10.0.0.9" not in s.command for s in sg)


def test_web_service_suggests_nuclei_and_sqlmap():
    tools = {(s.tool) for s in suggest(_report()) if s.target.startswith("http")}
    assert "nuclei" in tools and "sqlmap" in tools


def test_version_suggests_searchsploit_auto_and_metasploit():
    sg = suggest(_report())
    ss = [s for s in sg if s.tool == "searchsploit"]
    assert ss and ss[0].tier == "auto" and "Apache httpd 2.4.49" in ss[0].command
    assert any(s.tool == "metasploit" and s.tier == "suggest" for s in sg)


def test_ssh_and_smb_are_gated():
    sg = suggest(_report())
    brute = next(s for s in sg if s.tool == "redness brute" and "ssh" in s.command)
    spray = next(s for s in sg if s.tool == "redness spray")
    assert brute.tier == "gated" and spray.tier == "gated"
    assert brute.command.startswith("redness brute --target 10.0.0.5 --service ssh")


def test_ranked_auto_before_suggest_before_gated():
    tiers = [s.tier for s in suggest(_report())]
    order = {"auto": 0, "suggest": 1, "gated": 2}
    assert tiers == sorted(tiers, key=lambda t: order[t])


def test_wireless_finding_suggests_aircrack():
    rep = Report(findings=[Finding(id="wireless-weak-encryption", title="WPA", severity=Severity.HIGH,
                                   category=Category.CONFIG, affected=["CorpWiFi (WPA)"])])
    assert any(s.tool == "aircrack-ng" for s in suggest(rep))


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
    print("done")
