"""aircrack-ng offline crack tests - pure stdout parsing + the finding. No aircrack needed.

Run:  python -m pytest tests/test_wifi_crack.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.findings import Category, Severity  # noqa: E402
from redness.wifi_crack import build_finding, parse_aircrack, run_handshake  # noqa: E402

WPA_OK = """
                               Aircrack-ng 1.7

      [00:00:12] 10/10 keys tested

                        KEY FOUND! [ Summer2025! ]

      Master Key     : CD EF ...
"""

NET_HEADER = """Opening handshake.cap
   #  BSSID              ESSID
   1  AA:BB:CC:00:11:22  CorpWiFi
KEY FOUND! [ hunter2hunter2 ]
"""

NO_KEY = "   [00:00:30] 5000/5000 keys tested\n\nPassphrase not in dictionary.\n"


def test_parse_wpa_key_found():
    r = parse_aircrack(WPA_OK, ssid="CorpWiFi")
    assert r.cracked and r.key == "Summer2025!" and r.ssid == "CorpWiFi"


def test_parse_extracts_ssid_bssid_from_table():
    r = parse_aircrack(NET_HEADER)
    assert r.cracked and r.key == "hunter2hunter2"
    assert r.bssid == "AA:BB:CC:00:11:22" and r.ssid == "CorpWiFi"


def test_parse_no_key():
    assert parse_aircrack(NO_KEY).cracked is False
    assert parse_aircrack("").cracked is False


def test_build_finding_critical_password():
    r = parse_aircrack(WPA_OK, ssid="CorpWiFi")
    f = build_finding(r, "handshake.cap")
    assert f.severity is Severity.CRITICAL and f.category is Category.PASSWORD
    assert f.affected == ["CorpWiFi"] and f.meta["key"] == "Summer2025!"


def test_build_finding_none_when_not_cracked():
    assert build_finding(parse_aircrack(NO_KEY), "x.cap") is None


def test_run_handshake_with_injected_runner(tmp_path):
    rep, res = run_handshake("hs.cap", "wl.txt",
                             runner=lambda cap, wl, bs: WPA_OK,
                             loot_dir=str(tmp_path))
    assert res.cracked and len(rep.findings) == 1
    assert (tmp_path / "wifi_keys.txt").read_text().strip().endswith("Summer2025!")


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
