# Wireless suite

Three wireless surfaces, all read-only / offline - the active steps (handshake capture, deauth,
WPS) stay out of REDNESS and are left to the operator (the advisor suggests the commands).

| command | what | tier |
|---------|------|------|
| `redness wifi` | survey networks in range via the OS tool (netsh / nmcli) | read-only |
| `redness kismet <file>` | ingest a Kismet capture (passive sensor) -> wireless findings | read-only (ingest) |
| `redness handshake --cap <f> --wordlist <w>` | offline WPA/WEP crack via aircrack-ng | offline |

## `redness wifi` - survey
Lists the Wi-Fi networks the adapter sees and flags open and weak-encryption (WEP/WPA1/TKIP)
SSIDs. See `redness/wireless.py`. No transmit, no deauth, no crack.

## `redness kismet` - ingest a passive capture
Kismet only listens, so ingesting its log fits REDNESS's read-only ethos (like the BloodHound
ingest). Supports the modern **`.kismet` SQLite** database and the legacy **`.netxml`** (auto-
detected by content). It reuses the same open / weak-encryption / inventory findings as `wifi`,
plus a **client preferred-network-list** finding: devices actively probing for named SSIDs reveal
their PNL, which is karma / evil-twin bait.

```bash
redness kismet capture-01.kismet --out wireless.docx --csv wireless.csv
redness kismet oldscan.netxml -v
```
`redness/kismet.py`: `parse_netxml`, `parse_kismetdb` (tolerant of Kismet's versioned device JSON),
`load` (format detection), `build_wireless_findings`.

## `redness handshake` - offline crack
The offline half of the WPA workflow. Capture the handshake yourself (active, out of scope for
REDNESS):
```bash
airodump-ng --bssid <BSSID> -c <CH> -w cap wlan0      # capture (active)
aireplay-ng --deauth 3 -a <BSSID> wlan0               # optional: force a re-handshake (active)
```
then crack it offline and fold the result into the report + loot:
```bash
redness handshake --cap cap-01.cap --wordlist rockyou.txt --bssid <BSSID> --out report.docx
```
A recovered passphrase is a **CRITICAL** `Category.PASSWORD` finding and is written to
`loot/wifi_keys.txt`. See `redness/wifi_crack.py` (`parse_aircrack`, `crack`, `run_handshake`).

## Why the split
Capturing a handshake, deauthing clients, and WPS brute (reaver/wifite) are **active and
client-disruptive** - they belong to the operator's judgment, not an auto-run. REDNESS does the
safe parts (survey, ingest, offline crack) and *suggests* the active ones via the advisor
(`docs/ADVISOR.md`). Tools are a separate install; `redness doctor` reports aircrack-ng readiness.

All parsers are pure and unit-tested with no wireless tools installed
(`tests/test_kismet.py`, `tests/test_wifi_crack.py`).
