"""Nmap engine tests - pure XML parsing + the inventory finding. No nmap, no network.

Run:  python -m pytest tests/test_nmap.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.findings import Category, Severity  # noqa: E402
from redness.engines.nmap import NmapEngine, build_findings, parse_nmap  # noqa: E402
from redness.engines.base import Target  # noqa: E402

XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <status state="up"/>
  <address addr="10.0.0.5" addrtype="ipv4"/>
  <hostnames><hostname name="dc01.acme.local"/></hostnames>
  <ports>
   <port protocol="tcp" portid="22"><state state="open"/>
     <service name="ssh" product="OpenSSH" version="7.4" extrainfo="protocol 2.0"/></port>
   <port protocol="tcp" portid="80"><state state="open"/>
     <service name="http" product="Apache httpd" version="2.4.49">
       <cpe>cpe:/a:apache:http_server:2.4.49</cpe></service></port>
   <port protocol="tcp" portid="3389"><state state="closed"/>
     <service name="ms-wbt-server"/></port>
  </ports>
 </host>
</nmaprun>"""


def test_parse_open_ports_only_with_product_version():
    svcs = parse_nmap(XML)
    assert {s.port for s in svcs} == {22, 80}             # 3389 is closed -> skipped
    http = next(s for s in svcs if s.port == 80)
    assert http.host == "10.0.0.5" and http.product == "Apache httpd" and http.version == "2.4.49"
    assert http.cpes == ["cpe:/a:apache:http_server:2.4.49"]
    assert next(s for s in svcs if s.port == 22).banner == "OpenSSH 7.4 protocol 2.0"


def test_parse_bad_xml_returns_empty():
    assert parse_nmap("not xml") == []
    assert parse_nmap("") == []


def test_build_findings_inventory_carries_services_meta():
    fs = build_findings(parse_nmap(XML), "10.0.0.5")
    assert len(fs) == 1
    f = fs[0]
    assert f.severity is Severity.INFO and f.category is Category.ENUM
    assert f.affected == ["10.0.0.5"]
    svcs = f.meta["services"]
    assert len(svcs) == 2
    assert any(s["product"] == "Apache httpd" and s["version"] == "2.4.49" for s in svcs)
    assert len(f.evidence) == 2


def test_build_findings_empty_when_no_services():
    assert build_findings([], "10.0.0.5") == []


def test_engine_argv_and_unavailable():
    eng = NmapEngine()
    argv = eng._argv(Target(host="10.0.0.5"))
    assert "-sV" in argv and "-oX" in argv and "10.0.0.5" in argv
    assert "--top-ports" in argv


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
    print("done")
