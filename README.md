<!-- markdownlint-disable MD013 MD033 -->
# REDNESS

**Red-team orchestrator + normalizer + reporter for network penetration tests.**
One tool that drives your existing arsenal - NetExec, Impacket, Certipy, nmap, nuclei, hydra,
aircrack-ng and more - folds everything they find into a single findings model, and renders it as a
Word/HTML report, a CSV, a JSON, and a live 3D graph of the engagement.

REDNESS does **not** reimplement protocols or exploits. It *orchestrates* best-of-breed tools,
*normalizes* their output into one schema, and *reports* it - across AD/Windows, OT/ICS, IoT,
exposed services, web and wireless.

> Codename REDNESS. By [Zero Science Lab](https://www.zeroscience.mk) - Anja Ivanovska & Gjoko Krstic.
> Authorized assessments only (see [Legal](#legal--ethics)).

<!-- SCREENSHOT: live 3D graph (docs/screenshots/live-graph.jpg) -->
![live 3D graph](docs/screenshots/live-graph.jpg)

<!-- SCREENSHOT: world-map / Risk-style territory view with chess pieces -->
<!-- ![world map](docs/screenshots/world-map.jpg) -->

<!-- SCREENSHOT: self-contained HTML report -->
<!-- ![HTML report](docs/screenshots/html-report.jpg) -->

---

## Contents
- [Why REDNESS](#why-redness)
- [What it covers](#what-it-covers)
- [Install](#install)
- [Quickstart](#quickstart)
- [Commands](#commands)
- [Output formats](#output-formats)
- [The advisor - "run the right tool for what we found"](#the-advisor)
- [Safety model](#safety-model)
- [The GUI](#the-gui)
- [Tools REDNESS orchestrates](#tools-redness-orchestrates)
- [Packaging (the .exe)](#packaging-the-exe)
- [Tests](#tests)
- [Legal / ethics](#legal--ethics)

---

## Why REDNESS
On a real engagement you run a dozen tools and end up with a dozen output formats, no single picture,
and a painful report-writing night. REDNESS is the layer on top:

- **Orchestrate** - one command runs the relevant engines against your scope, auto-dispatched by a
  quiet TCP service discovery (only the tools whose port is open actually run).
- **Normalize** - every engine emits the same `Finding` object (severity, category, impact,
  **remediation**, evidence, references). `redness/findings.py` is the contract.
- **Report** - a narrative `.docx`, a self-contained offline `.html` with the graph inlined, a
  `.json` (the raw contract, feeds retest diffs), and a `.csv` (one row per affected asset - pivot
  by IP or by finding).
- **Visualize** - a live 3D force-graph of the enumeration, with attack paths to Domain Admin lit
  up, plus a Risk-style "world-map" territory view.

---

## What it covers
| domain | engines / commands |
|--------|--------------------|
| **Active Directory / Windows** | SMB (signing, SMBv1, null/guest, shares), LDAP users + AS-REP/Kerberoast capture, AD CS ESC1-ESC16 (Certipy), delegation / RBCD / MAQ / gMSA, GPP cpassword, RDP/WinRM/MSSQL reach, FTP, SNMP, TLS |
| **Attack paths** | derived path-to-Domain-Admin edges, NTLM relay chains (coerce + no-signing + ESC8), BloodHound/SharpHound ingest |
| **OT / ICS** | EtherNet/IP (CIP), Modbus, BACnet, DNP3, HART-IP - read-only identity probes, opt-in; OT Process-Impact attack path + IT/OT segmentation |
| **IoT** | MQTT (anonymous), CoAP |
| **Exposed services** | Redis, MongoDB, Elasticsearch, Memcached, printers (IPP) |
| **Web** | nuclei (CVEs / panels / default-logins / misconfig), nmap -sV tech detection, searchsploit exploit lookup |
| **Credentials** | AS-REP/Kerberoast cracking (hashcat/john), GPP, password spray (lockout-aware), online brute (hydra/medusa), NetNTLMv2 capture (Responder) |
| **Passive** | link-local discovery (mDNS/LLMNR/NBT-NS/SSDP), tshark capture analysis (cleartext creds + plaintext protocols) |
| **Wireless** | survey (netsh/nmcli), Kismet ingest, offline WPA/WEP handshake crack (aircrack-ng) |
| **Advisor** | turns the detected stack into ranked next-step tool suggestions |

Findings schema `v1.4.0`. See [docs/](docs/) for per-area detail (ICS, IOT, SERVICES, NUCLEI,
ADVISOR, WIRELESS, CAPTURE, RETEST, REPORTING, ...).

---

## Install
Git clone, one command, then the `redness` console script:

```bash
# Linux / Kali
./scripts/install.sh
# Windows (PowerShell)
.\scripts\install.ps1
```

This makes a venv, `pip install ".[engines]"` (Certipy + Impacket), installs NetExec via pipx if
missing, and runs `redness doctor`. Or manually:

```bash
pip install -r requirements.txt          # core
pip install ".[engines]"                 # certipy-ad + impacket
pipx install netexec                      # nxc (no py3.12 wheel; pipx picks a compatible Python)
```

TLS is pure stdlib (always available). hashcat/john, nmap, nuclei, hydra, aircrack-ng, tshark,
Responder, searchsploit are separate native installs - put them on PATH, or point REDNESS at them
in the GUI's **Options** panel (saved to `~/.redness/config.json`). Run `redness doctor` any time to
see what is ready.

> Build note: the single-file `.exe` needs Python >= 3.10.1 (a 3.10.0 bug breaks PyInstaller).

---

## Quickstart
```bash
redness doctor                                        # what engines/tools are installed
redness demo --out report.docx --html report.html     # sample report, no DC needed
redness gui                                           # native window (live 3D graph)
redness live --demo                                   # same UI in a browser, simulated stream

# a real scan (auto-discovers services, runs only relevant engines)
redness scan --target 10.10.0.0/24 --out report.docx --live
redness scan --targets scope.txt -u USER -p PASS -d DOMAIN --wordlist rockyou.txt --html report.html
```

A scope file is one IP / hostname / CIDR per line (`#` comments allowed).

---

## Commands
Run `redness <command> --help` for the full option list. Output flags (`--out .docx`, `--json`,
`--csv`, `--html`, `-v`/`-q`) are available on every command that produces findings.

| command | what it does |
|---------|--------------|
| `demo` | render a sample report (no target) - to see the formats |
| `scan` | run the engines against targets -> report (+ optional live graph) |
| `report <findings.json>` | re-render a saved scan to `.docx`/`.html`/`.json`/`.csv` |
| `diff <baseline.json> <current.json>` | retest diff: new / fixed / unchanged / changed (exit 2 on regression) |
| `doctor` | check which engines/tools are installed + tool-path config |
| `gui` / `live` | native window / browser live 3D graph (`--demo` streams simulated data) |
| `listen` | passive link-local discovery (mDNS/LLMNR/NBT-NS/SSDP) |
| `capture` | tshark over a pcap or live iface: cleartext creds + plaintext protocols |
| `wifi` | Wi-Fi survey (open / weak encryption) via netsh / nmcli |
| `kismet <file>` | ingest a Kismet passive capture (`.kismet` SQLite / `.netxml`) |
| `handshake` | offline WPA/WEP crack via aircrack-ng (`--cap` + `--wordlist`) |
| `bloodhound <path>` | ingest a SharpHound/BloodHound collection into the graph |
| `trigger` | generate a forced-authentication UNC lure (html/scf/url) |
| `poison` | LLMNR/NBT-NS poisoning to capture NetNTLMv2 (**intrusive**, gated) |
| `spray` | lockout-aware password spraying (**intrusive**, gated) |
| `brute` | online password guessing via hydra/medusa (**intrusive**, gated) |
| `coerce` | RPC forced-auth coercion - PetitPotam/PrinterBug/DFSCoerce (**intrusive**, gated) |

### `scan` options (the main command)
```
--target HOST | --targets FILE      single target (IP/host/CIDR) and/or a scope file
-u -p -d -k / -H                    username / password / domain / kerberos / NT hash (PtH)
--wordlist FILE | --no-crack        crack captured AS-REP/Kerberoast hashes (hashcat/john)
--hunt-secrets | --hunt-content     spider readable SMB shares for secrets (Snaffler-style)
--ics | --ics-enum                  opt-in read-only OT field-protocol probes (+ louder enum tier)
--nuclei [--nuclei-profile light|full] [--nuclei-templates PATH]   opt-in ACTIVE web template scan
--nmap                              opt-in nmap -sV service/version detection (feeds --suggest)
--suggest                           print tool suggestions for the detected stack (+ searchsploit)
--no-discovery                      run every engine on every host (skip the service dispatch)
--listen SECONDS                    also run a passive link-local sweep; feeds the relay map
--out .docx | --json | --csv | --html   outputs    | -v verbose / -q quiet   console summary
--live [--host --port --no-open]    stream to the live 3D graph
```

---

## Output formats
Every findings command writes any combination of:

| flag | format |
|------|--------|
| `--out X.docx` | narrative Word report (exec summary + per-finding detail) |
| `--html X.html` | self-contained page: findings + the 3D graph, works offline (`scan`/`report`/`demo`) |
| `--json X.json` | the raw findings (the contract; feeds `diff`) |
| `--csv X.csv` | spreadsheet - one row per **(finding x affected asset)**; sort `asset` for by-IP, `id` for by-finding |

Console: default prints a severity summary + one line per finding; `-v` adds evidence + fix,
`-q` prints counts only. Retests: `redness diff baseline.json current.json` classifies
new/fixed/unchanged/changed and exits non-zero on a regression (CI-friendly). See
[docs/REPORTING.md](docs/REPORTING.md) and [docs/RETEST.md](docs/RETEST.md).

---

## The advisor
*"Run the right tool for what we found."* After a scan, REDNESS turns the detected services +
findings into ranked next-step suggestions, in three tiers:

```bash
redness scan --target 10.0.0.0/24 --nmap --suggest --out report.docx
```

- **auto** - read-only lookups REDNESS runs for you (searchsploit -> exploit candidates in the report)
- **suggest** - prints the exact command, you run it (nuclei, sqlmap, metasploit, aircrack-ng)
- **gated** - intrusive online brute / spray, via the consent + FORCE + audit path (hydra, `redness spray`)

OT-safe: hosts carrying any ICS finding are excluded from every suggestion. See
[docs/ADVISOR.md](docs/ADVISOR.md).

---

## Safety model
REDNESS is built to be safe to run on a client estate:

- **Passive / read-only by default.** The default scan reads banners and single probes; nothing
  destructive.
- **Opt-in for anything active.** OT/ICS probes (`--ics`), web scanning (`--nuclei`), nmap
  (`--nmap`) are explicit choices, never automatic.
- **Gated for anything intrusive.** `poison`, `spray`, `brute`, `coerce` print a danger banner, take
  a typed **YES**, and require a second typed **FORCE** to override a safety refusal (e.g. account
  lockout risk). Every run is written to the `loot/` audit log.
- **OT-safe by construction.** OT field probes are single read-only identity requests, port-gated,
  and the advisor never points an active/exploit tool at a host with an ICS finding.
- **Your data stays local.** Reports, findings JSON, loot and captures are git-ignored; REDNESS
  sends nothing anywhere.

---

## The GUI
`redness gui` (native window via pywebview; falls back to a browser) or `redness live` (browser):

- Live 3D force-graph of the enumeration, nodes colored by finding severity, attack paths to Domain
  Admin animated.
- **World-map view** - a Risk-style territory board where nodes land in continents by type
  (Directory / Compromise / OT-ICS / IoT-Services) and stand as 3D chess pieces by role.
- **Right-click actions** - enumeration actions on a node; gated offensive actions
  (Kerberoast / secretsdump / DCSync) unlock with `--enable-offensive` and a separate console token.
- **New scan** panel - run the real engines from the UI.
- **Options** panel - set the path to each external binary (nxc, john, nmap, ...) when they are not
  on PATH; saved to `~/.redness/config.json`.

---

## Tools REDNESS orchestrates
Put these on PATH (or set them in **Options**); `redness doctor` shows what is ready.

NetExec (nxc) - Impacket - Certipy - hashcat / john - Responder - tshark (Wireshark) - nmap -
nuclei - searchsploit (Exploit-DB) - aircrack-ng - hydra / medusa - snmpwalk - netsh / nmcli.

Only the tools you actually use need to be installed; TLS and all parsing are pure Python.

---

## Packaging (the .exe)
A single self-contained Windows executable is built with PyInstaller:

```bash
py -3 -m PyInstaller packaging/redness.spec          # needs Python >= 3.10.1
```

The `.exe` bundles REDNESS and its Python engines; the external native tools (nxc, nmap, ...) remain
separate installs you point at via **Options**. See `packaging/` for the spec and build script.

---

## Tests
Everything is unit-tested offline - pure parsers over captured tool output, no live DC or tools
needed:

```bash
python -m pytest -q          # ~460 tests
```

> **Field validation:** REDNESS is exhaustively tested offline but is still being validated against
> a live DC + real tooling on Kali. If a parser misses a real-world output format, add a captured
> sample to the matching `tests/` file. See `docs/VALIDATION.md`.

---

## Legal / ethics
For **authorized** security assessments only. Assume written scope and permission exist before you
run anything against any target. The intrusive commands can lock out accounts, coerce
authentication, and disrupt services - you are responsible for using them within scope.

REDNESS is BSD-2-Clause. Bundled/driven third-party tools keep their own licenses (see
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)).

---

*Zero Science Lab | powered by Silly Security Inc. - Anja Ivanovska & Gjoko Krstic.*
