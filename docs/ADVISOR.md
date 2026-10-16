# Advisor - "run the right tool for what we found"

REDNESS detects services and normalizes findings; the **advisor** turns that into a ranked list of
offensive next steps. For each detected service / finding it names a tool, says why it applies, and
gives a ready-to-run command - so you don't have to remember which tool fits which stack.

```bash
redness scan --target 10.0.0.0/24 --nmap --suggest --out report.docx
```

- `--nmap` runs `nmap -sV` (service/version/CPE detection) - the tech detector the advisor reasons
  over. Opt-in (nmap is an active scan). Without it the advisor still works off nuclei web findings,
  just with less detail.
- `--suggest` prints the "Suggested next steps" section after the scan and runs the read-only
  searchsploit lookups.

## Three tiers (mirrors REDNESS's passive -> opt-in -> gated posture)

| tier | meaning | examples |
|------|---------|----------|
| **auto** | read-only lookups REDNESS runs for you; results are added to the report | searchsploit |
| **suggest** | REDNESS prints the exact command; **you** decide and run it | nuclei, sqlmap, metasploit, aircrack-ng |
| **gated** | intrusive online brute / spray - run only through the consent + FORCE + audit path | hydra, `redness spray` |

REDNESS never auto-runs the suggest/gated tools. The suggest tier *is* the "would you like to use
tool X here?" prompt - a command you can copy, not an action taken for you.

## What drives a suggestion

| detected | suggests |
|----------|----------|
| web service (http/https, 80/443/8080/8443/...) | `nuclei` (template scan), `sqlmap` (SQLi) |
| a product + version (from `nmap -sV`) | `searchsploit` (auto lookup -> exploit candidates in the report), `metasploit` (module search) |
| SSH / FTP / RDP | `hydra` (online password guessing) - gated |
| SMB (445) | `redness spray` (lockout-aware) - gated |
| a WPA/WEP network (`wireless-weak-encryption`) | `aircrack-ng` (capture handshake + offline crack) |

Each suggestion is marked `[install <tool>]` when the tool is not on PATH, and the list is ranked
auto -> suggest -> gated.

## OT-safe
Any host carrying an ICS finding (`Category.ICS`) is **excluded** from every suggestion - the
advisor never points an active or exploit tool at fragile OT, matching the rest of REDNESS.

## Pieces
- `redness/engines/nmap.py` - `parse_nmap` (XML) + `NmapEngine` (`-sV`); one INFO inventory
  finding per host, `meta["services"]` carries the structured list.
- `redness/engines/searchsploit.py` - `parse_searchsploit` (JSON) + `search()` + the
  exploit-candidate finding builder. Local Exploit-DB, read-only.
- `redness/advisor.py` - `detected_services()`, `suggest()` (the pure rule engine),
  `run_autolookups()` (the auto tier). `ot_hosts()` drives the OT exclusion.

Tools are a separate install (`doctor` shows nmap / searchsploit / nuclei readiness). All parsing
is pure and unit-tested with no tools installed (`tests/test_nmap.py`, `test_searchsploit.py`,
`test_advisor.py`).

Roadmap: wire `hydra`/`medusa` as gated executors (reuse the spray gating), ingest
`amass`/`spiderfoot`/`kismet`, and a GUI right-click "Suggestions" surface.
