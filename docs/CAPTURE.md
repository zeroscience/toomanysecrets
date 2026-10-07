# Passive capture + wireless - `redness capture` / `redness wifi`

Two passive recon surfaces that orchestrate the native tooling (REDNESS never reimplements it).
Both are read-only and produce normalized findings + a report.

## Capture - `redness capture` (drives tshark / Wireshark)
```bash
redness capture --pcap traffic.pcap --out report.docx     # analyze an existing capture
redness capture --iface eth0 --duration 120 --json cap.json  # live (authorized traffic only)
```
Uses tshark's own taps - `-z credentials` (recovered FTP/HTTP/IMAP/POP/SMTP usernames+passwords)
and `-z io,phs` (protocol hierarchy) - and turns them into:
- `cleartext-credentials` (CRITICAL) - credentials sent in the clear on the wire.
- `cleartext-protocols` (MEDIUM) - plaintext/sensitive protocols seen (telnet/ftp/http/pop/imap/
  smtp/snmp/ntlmssp/kerberos/...).

Needs `tshark` on PATH (Wireshark, or `apt install tshark`). The tshark argv is best-effort -
verify tap/field names on a box with Wireshark (same caution as the nxc flags). Parsers unit-test
against captured tshark output.

## Wireless - `redness wifi` (drives netsh / nmcli)
```bash
redness wifi --out wifi.docx
```
Surveys the Wi-Fi networks in range (netsh on Windows, nmcli on Linux) and flags:
- `wireless-open` (MEDIUM) - open/unencrypted SSIDs (eavesdrop + rogue-AP surface).
- `wireless-weak-encryption` (HIGH) - WEP / WPA1 / TKIP.
- `wireless-inventory` (INFO) - every SSID/BSSID/auth seen.

Read-only: it lists what the adapter already sees - it does not transmit, deauth, or crack.
Parsers unit-test against captured netsh/nmcli output.

Next in this direction: Stratoshark (syscall/log capture), per-endpoint inventory from a pcap,
and BSSID geolocation / rogue-AP correlation.
