"""Wireless survey: netsh / nmcli parsing + open / weak-encryption findings."""
from redness import wireless
from redness.findings import Category, Severity

_NETSH = """Interface name : Wi-Fi
There are 3 networks currently visible.

SSID 1 : CorpNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 90%
SSID 2 : GuestOpen
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 70%
SSID 3 : OldWEP
    Authentication          : WEP
    Encryption              : WEP
    BSSID 1                 : 77:88:99:aa:bb:cc
         Signal             : 50%
"""

_NMCLI = ("CorpNet:AA\\:BB\\:CC\\:DD\\:EE\\:FF:WPA2:90\n"
          "GuestOpen:11\\:22\\:33\\:44\\:55\\:66:--:70\n"
          "OldWEP:77\\:88\\:99\\:AA\\:BB\\:CC:WEP:50\n")


def test_parse_netsh():
    nets = wireless.parse_netsh(_NETSH)
    by = {n["ssid"]: n for n in nets}
    assert set(by) == {"CorpNet", "GuestOpen", "OldWEP"}
    assert by["CorpNet"]["auth"] == "WPA2-Personal" and by["CorpNet"]["bssid"] == "aa:bb:cc:dd:ee:ff"
    assert by["GuestOpen"]["auth"] == "Open"


def test_parse_nmcli_unescapes_bssid():
    nets = wireless.parse_nmcli(_NMCLI)
    by = {n["ssid"]: n for n in nets}
    assert by["CorpNet"]["bssid"] == "AA:BB:CC:DD:EE:FF" and by["CorpNet"]["auth"] == "WPA2"
    assert by["GuestOpen"]["auth"] == "Open"                      # nmcli '--' -> open
    assert by["OldWEP"]["auth"] == "WEP"


def test_build_findings_flags_open_and_weak():
    for sample, parser in ((_NETSH, wireless.parse_netsh), (_NMCLI, wireless.parse_nmcli)):
        fs = wireless.build_findings(parser(sample))
        ids = [f.id for f in fs]
        assert ids == ["wireless-open", "wireless-weak-encryption", "wireless-inventory"]
        opn, weak, inv = fs
        assert opn.severity is Severity.MEDIUM and "GuestOpen" in opn.affected
        assert weak.severity is Severity.HIGH and "OldWEP" in weak.affected
        assert inv.severity is Severity.INFO and inv.category is Category.CONFIG
        assert "CorpNet" not in opn.affected and "CorpNet" not in weak.affected  # WPA2 is fine


def test_run_wireless_injected():
    rep = wireless.run_wireless(runner=lambda: _NETSH, parser=wireless.parse_netsh)
    assert rep.target == "wireless"
    assert "wireless-open" in {f.id for f in rep.findings}


def test_no_networks_no_findings():
    assert wireless.build_findings([]) == []


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            passed += 1
    print(f"{passed} passed")
