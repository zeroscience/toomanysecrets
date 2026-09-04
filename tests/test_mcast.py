"""Passive link-local discovery - pure packet parsers + findings, no network needed.

DNS/NBT/SSDP packets are built by hand from the wire format (NetBIOS decode is checked against
the RFC1001 'FRED' example). Run:
    python tests/test_mcast.py   (or)   python -m pytest -q
"""
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness import mcast  # noqa: E402
from redness.findings import Category, Severity  # noqa: E402


# --- packet builders (RFC wire format) ------------------------------------- #
def _name(s):
    return b"".join(bytes([len(lbl)]) + lbl.encode() for lbl in s.split(".")) + b"\x00"


def _mdns_a(host, ip):
    hdr = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)          # response, 1 answer
    ans = _name(host) + struct.pack("!HHIH", 1, 1, 120, 4) + socket.inet_aton(ip)
    return hdr + ans


def _mdns_ptr(service, instance):
    hdr = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    rd = _name(instance)
    ans = _name(service) + struct.pack("!HHIH", 12, 1, 120, len(rd)) + rd
    return hdr + ans


def _llmnr_q(name):
    hdr = struct.pack("!HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)     # 1 question
    return hdr + _name(name) + struct.pack("!HH", 1, 1)


def _nbtns_q(nbname):
    raw = (nbname.ljust(15) + "\x00")[:16].encode("latin-1")     # 15 chars + 1 suffix byte
    enc = "".join(chr((b >> 4) + 0x41) + chr((b & 0xF) + 0x41) for b in raw)
    hdr = struct.pack("!HHHHHH", 0x4321, 0x0110, 1, 0, 0, 0)
    return hdr + bytes([0x20]) + enc.encode("latin-1") + b"\x00" + struct.pack("!HH", 0x20, 1)


SSDP_NOTIFY = (
    "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
    "NT: urn:schemas-upnp-org:device:MediaServer:1\r\n"
    "SERVER: Linux/3.4 UPnP/1.0 MiniDLNA/1.1\r\n"
    "LOCATION: http://10.10.0.50:8200/desc.xml\r\nUSN: uuid:abcd::urn\r\n\r\n"
)


# --- NetBIOS decode (grounded: RFC1001 example) ---------------------------- #
def test_netbios_decode_rfc_example():
    assert mcast.decode_netbios_name("EGFCEFEECACACACACACACACACACACACA") == "FRED"


def test_parse_nbtns_query():
    recs = mcast.parse_nbtns(_nbtns_q("FILESERVER"), "10.10.0.9")
    assert len(recs) == 1 and recs[0].proto == "nbtns"
    assert recs[0].name == "FILESERVER" and recs[0].kind == "query"


# --- DNS-based (mDNS + LLMNR) ---------------------------------------------- #
def test_parse_mdns_a_record():
    recs = mcast.parse_mdns(_mdns_a("nas.local", "10.10.0.50"), "10.10.0.50")
    host = [r for r in recs if r.kind == "host"]
    assert host and host[0].name == "nas.local" and host[0].ip == "10.10.0.50"


def test_parse_mdns_service_ptr():
    recs = mcast.parse_mdns(_mdns_ptr("_ipp._tcp.local", "HP-Printer._ipp._tcp.local"), "10.10.0.7")
    assert any(r.kind == "_ipp._tcp.local" and "Printer" in r.name for r in recs)


def test_parse_llmnr_query():
    recs = mcast.parse_llmnr(_llmnr_q("FILESERVER"), "10.10.0.22")
    assert recs and recs[0].proto == "llmnr" and recs[0].name == "FILESERVER"
    assert recs[0].kind == "query"


def test_parse_ssdp():
    recs = mcast.parse_ssdp(SSDP_NOTIFY, "10.10.0.50")
    assert len(recs) == 1
    assert recs[0].kind == "urn:schemas-upnp-org:device:MediaServer:1"
    assert "MiniDLNA" in recs[0].detail


# --- findings -------------------------------------------------------------- #
def _A(**kw):
    return mcast.Announce(**kw)


def test_findings_llmnr_nbtns_poisonable():
    fs = {f.id: f for f in mcast.build_findings([
        _A(proto="llmnr", src="10.10.0.22", name="FILESERVER", kind="query"),
        _A(proto="nbtns", src="10.10.0.9", name="WORKSTATION", kind="query"),
    ])}
    assert fs["llmnr-nbtns-poisonable"].severity is Severity.MEDIUM
    assert fs["llmnr-nbtns-poisonable"].category is Category.CONFIG
    assert "LLMNR" in fs["llmnr-nbtns-poisonable"].title and "NBT-NS" in fs["llmnr-nbtns-poisonable"].title


def test_findings_wpad_high():
    fs = {f.id: f for f in mcast.build_findings([
        _A(proto="llmnr", src="10.10.0.30", name="wpad", kind="query")])}
    assert fs["wpad-lookup-observed"].severity is Severity.HIGH
    assert "10.10.0.30" in fs["wpad-lookup-observed"].affected


def test_findings_inventory_and_ssdp():
    fs = {f.id: f for f in mcast.build_findings([
        _A(proto="mdns", src="10.10.0.50", name="nas.local", ip="10.10.0.50", kind="host"),
        _A(proto="ssdp", src="10.10.0.1", name="uuid:router", kind="InternetGatewayDevice",
           detail="RouterOS UPnP/1.1"),
    ])}
    assert fs["mcast-inventory"].severity is Severity.INFO
    assert fs["ssdp-upnp-devices"].severity is Severity.INFO


def test_no_announcements_no_findings():
    assert mcast.build_findings([]) == []


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
