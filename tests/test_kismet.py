"""Kismet ingest tests - .netxml parse, a constructed .kismet SQLite, findings + client PNL.

Run:  python -m pytest tests/test_kismet.py -q
"""
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.findings import Category, Severity  # noqa: E402
from redness import kismet  # noqa: E402

NETXML = """<?xml version="1.0"?>
<detection-run>
 <wireless-network number="1" type="infrastructure">
  <SSID><type>Beacon</type><ssid>CorpWiFi</ssid><encryption>WPA2</encryption></SSID>
  <BSSID>AA:BB:CC:00:11:22</BSSID><channel>6</channel>
  <wireless-client number="1"><client-mac>DE:AD:BE:EF:00:01</client-mac></wireless-client>
 </wireless-network>
 <wireless-network number="2" type="infrastructure">
  <SSID><type>Beacon</type><ssid>GuestOpen</ssid><encryption>None</encryption></SSID>
  <BSSID>AA:BB:CC:00:11:33</BSSID><channel>11</channel>
 </wireless-network>
 <wireless-network number="3" type="infrastructure">
  <SSID><type>Beacon</type><ssid>OldNet</ssid><encryption>WEP</encryption></SSID>
  <BSSID>AA:BB:CC:00:11:44</BSSID><channel>1</channel>
 </wireless-network>
</detection-run>"""


def _make_kismetdb(path):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE devices (devmac TEXT, type TEXT, device BLOB)")
    ap = {"kismet.device.base.type": "Wi-Fi AP", "kismet.device.base.macaddr": "11:22:33:44:55:66",
          "kismet.device.base.commonname": "LabAP", "kismet.device.base.channel": "6",
          "dot11.device": {"dot11.device.last_beaconed_ssid_record": {
              "dot11.advertisedssid.ssid": "LabAP", "dot11.advertisedssid.crypt_string": "WEP"}}}
    client = {"kismet.device.base.type": "Wi-Fi Client", "kismet.device.base.macaddr": "AA:00:00:00:00:01",
              "dot11.device": {"dot11.device.probed_ssid_map": [
                  {"dot11.probedssid.ssid": "HomeNet"}, {"dot11.probedssid.ssid": "AirportFree"}]}}
    for d in (ap, client):
        con.execute("INSERT INTO devices VALUES (?,?,?)",
                    (d["kismet.device.base.macaddr"], d["kismet.device.base.type"], json.dumps(d)))
    con.commit()
    con.close()


def test_netxml_parse_networks_and_clients():
    nets, clients = kismet.parse_netxml(NETXML)
    assert {n["ssid"] for n in nets} == {"CorpWiFi", "GuestOpen", "OldNet"}
    assert any(c["mac"] == "DE:AD:BE:EF:00:01" for c in clients)


def test_netxml_findings_flag_open_and_weak():
    fs = kismet.build_wireless_findings(*kismet.parse_netxml(NETXML))
    ids = {f.id for f in fs}
    assert "wireless-open" in ids          # GuestOpen
    assert "wireless-weak-encryption" in ids   # OldNet (WEP)
    assert "wireless-inventory" in ids


def test_kismetdb_parse_and_client_pnl(tmp_path):
    p = str(tmp_path / "cap.kismet")
    _make_kismetdb(p)
    nets, clients = kismet.load(p)                 # load() detects SQLite magic
    assert any(n["ssid"] == "LabAP" and "WEP" in n["encryption"] for n in nets)
    assert any(c["probed"] == ["HomeNet", "AirportFree"] for c in clients)
    fs = kismet.build_wireless_findings(nets, clients)
    pnl = next(f for f in fs if f.id == "wireless-client-pnl")
    assert pnl.severity is Severity.MEDIUM and pnl.category is Category.CONFIG
    assert "HomeNet" in pnl.affected and "AirportFree" in pnl.affected


def test_load_detects_netxml(tmp_path):
    p = tmp_path / "c.netxml"
    p.write_text(NETXML, encoding="utf-8")
    nets, _ = kismet.load(str(p))
    assert len(nets) == 3


def test_bad_inputs():
    assert kismet.parse_netxml("not xml") == ([], [])
    assert kismet.load("/no/such/file") == ([], [])


if __name__ == "__main__":
    import tempfile, pathlib
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
            except TypeError:
                fn(pathlib.Path(tempfile.mkdtemp()))
            print(f"  ok  {name}")
    print("done")
