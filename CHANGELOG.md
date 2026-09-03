# Changelog

All notable changes to REDNESS. Format loosely follows [Keep a Changelog](https://keepachangelog.com).
Zero Science Lab · powered by Silly Security Inc.

## [Unreleased]
### Added
- **New-node flash on right-click discovery:** when a right-click action (enum or offensive)
  turns up a host/IP that wasn't on the graph yet, an **expanding cyan ring** (a scanner-ping
  ripple, three rings over ~3 seconds) emanates from that node so the operator can immediately
  spot what the action discovered. Scoped to a window right after the action (the initial scan
  build doesn't flash), with a hard cleanup fallback so a node is never left mid-animation if the
  tab was backgrounded.
- **Demo right-click discovery:** in `live --demo`, right-clicking **Enumerate SMB** on a host now
  simulates a realistic discovery - readable shares on the host, plus an active session revealing
  a logged-on user and the workstation they came from (a new in-scope host) - so the new-node
  ring is visible without any tools installed. (What legitimately spawns a new in-scope node from
  an SMB enum: shares and session/logged-on data.)

### Changed
- **Ambient breathing on high-value nodes:** the Domain Admin goal and any owned (compromised)
  nodes now gently pulse in size continuously, so the compromise state stays visually alive and
  draws the eye even when the graph is at rest (desynced per node; yields to the replay finale).
- **Organic live-graph look:** nodes are now smooth **translucent orbs with a bright glowing
  core inside** - a glassy `nodeOpacity` 0.3 shell (`nodeResolution` 20, larger `nodeRelSize`)
  with a smaller emissive inner sphere added via the graph's own bundled three.js (reached
  through each mesh's `.constructor`, so no second three instance and no extra dependency); the
  core colour syncs from the shell so severity / owned / goal recolours carry through. Links
  curve and flow, and the layout has a gentle perpetual drift (low `d3AlphaTarget` + softer
  velocity decay / charge) so it quietly breathes instead of freezing into a rigid lattice.
  Also fixed the WebGL canvas to size to its container + track resizes, so the graph renders
  even when the page loads in a hidden/zero-sized host.

### Added
- **NTLM relay map + graph replay cinematic:** `redness/relay.py` correlates findings a scan
  already produced into concrete relay chains - AD CS Web Enrollment (ESC8) becomes a CRITICAL
  `ntlm-relay-to-adcs` chain to Domain Admin (coerce a DC -> relay to /certsrv -> DC cert ->
  DCSync), and signing-disabled hosts become a HIGH `ntlm-relay-to-smb`. Drawn on the graph as a
  central **NTLM Relay** node with coercion fan-in and relay fan-out. Pure derivation, no new
  tool, no schema change. Plus a **"Replay path to DA"** button that animates the attack/relay
  edges from entry point to the Domain Admin goal (edge lighting + particle bursts + camera fly +
  goal pulse) - the "how we'd own you" story for demos and report screenshots.
- **Offensive actions wired into the GUI (arm/execute HTTP framework):** the Phase-3 offensive
  actions (Kerberoast / secretsdump / DCSync) are now triggerable from the live graph via two new
  bridge endpoints - `POST /action/arm` (returns a single-use token + banner) and
  `POST /action/execute` (needs the token + an `X-Redness-Confirm` header). Gated hard:
  **off by default**, unlocked only with `redness gui|live --enable-offensive`, which mints a
  **separate operator-console token** (never embedded in the page) that must be pasted into the
  GUI; **loopback-bind only**; offensive actions stay hidden in the catalog until enabled. GUI
  flow is right-click -> arm -> confirm(banner) -> execute.
- **FTP / HTTP / SNMP engines (broader protocol coverage):** three passive engines in the
  default scan. **FTP** (`nxc ftp`) - anonymous login (`ftp-anonymous`) + exposure/banner.
  **HTTP** (pure stdlib, AD-scoped, *not* a general web scanner) - flags AD CS Web Enrollment
  `/certsrv` as an **ESC8** NTLM-relay target (`adcs-web-enrollment`, HIGH), plus OWA/EWS and a
  server banner. **SNMP** (`snmpwalk`) - default community strings (`snmp-default-community`,
  HIGH for `public`, CRITICAL for read-write `private`). All reuse existing categories - no
  schema change; parsers verified/injectable and unit-tested.
- **Service-discovery dispatch (the "hail-mary" default scan):** `redness/discovery.py` +
  `run_scan`. A default scan now runs every passive engine, but per host it first does a
  lightweight TCP connect-scan (stdlib sockets, no nmap) of the ports our engines care about
  and dispatches only the engines whose service is actually open - so a full-breadth scan stays
  fast and quiet ("according to the enumeration and logic"). Port knowledge is centralized in
  `discovery.ENGINE_PORTS`; engines not listed there are never gated (UDP/unknown engines keep
  full coverage). `--no-discovery` runs every available engine regardless. This is discovery,
  not exploitation (a plain TCP connect, nothing sent to the service).
- **Remote-access protocol engines (RDP / WinRM / MSSQL):** `redness/engines/remote.py` adds
  three passive nxc-backed engines to the default scan - the lateral-movement surfaces the
  SMB/LDAP/AD CS/TLS engines miss. **RDP** flags missing Network Level Authentication
  (`rdp-nla-disabled`, pre-auth surface / BlueKeep class) plus reachability; **WinRM** and
  **MSSQL** flag exposure and, when creds are supplied, confirm a reachable remote-exec path
  (`*-access`, HIGH, upgraded to CRITICAL on a `(Pwn3d!)` admin hit = remote code execution).
  Passive banner reads only (no lockout risk), so they run in `scan` unlike gated poison/spray.
  Findings reuse `Category.CONFIG` / `Category.ENUM` - no schema change. Parsers verified
  against NetExec's rdp/winrm/mssql output and unit-tested (no live host needed).
- **BloodHound ingest (`bloodhound` command):** load a SharpHound / BloodHound-CE collection
  (`.zip`, a directory of `.json`, or a single file) and stream real AD relationships
  (MemberOf / AdminTo / HasSession) into the graph - `redness/bloodhound.py`. Adds the
  structural context that turns findings into full paths to Domain Admin.
- **Report upgrades:** the `.docx` now includes an **Attack Paths** section (owned accounts,
  roastable leads, AD CS ESCn to Domain Admin, derived via `redness.paths`), a
  **MITRE ATT&CK** technique on each finding, and a **Compliance Mapping** appendix
  (indicative CIS Controls v8 / ISO 27001:2022 / NIS2 per finding) - `redness/report/mappings.py`.
- **Attack-path edges (the graph becomes an attack map):** `redness/paths.py` derives the
  relationships that matter from a scan's findings - cracked accounts become `owned` (red),
  roastable-but-uncracked become potential leads, and AD CS ESC1/2/3/6/8 point at a
  `Domain Admin` goal node. Streamed as distinct red/animated attack edges, wired into
  `run_scan`; each carries a MITRE technique id for the report.
- **Right-click node actions (GUI Phase 2, read-only):** `redness/actions.py` registry +
  token-gated `POST /action` + `GET /actions`; right-click a host/domain node in the graph
  to run Enumerate SMB / LDAP / AD CS / TLS against it, streamed back live. The channel every
  future action plugs into.
- **`trigger` command** - generate a forced-authentication UNC lure (`html` / `scf` / `url`)
  that coerces a victim to authenticate to us; the capture rides the existing `poison`/
  Responder pipeline (NetNTLM design Phase 2). Pure string generation, gated banner.
- **Built-in weak-password auto-crack** - when no `--wordlist` is given and hashcat/john is
  on PATH, `scan`/`poison` auto-try a small hand-curated weak-password list
  (`redness/wordlists.py`, ~370 entries, sub-second) across all hash types
  (AS-REP / Kerberoast / NetNTLMv2). `--no-crack` disables all cracking; explicit
  `--wordlist` is unchanged.
### Planned
- GUI Phase 3 offensive actions (Kerberoast / secretsdump / pass-the-hash / DCSync / ADCS
  abuse), gated like `poison`. Stream cracked creds to the graph. See [docs/GUI.md](docs/GUI.md).
  (ntlmrelayx live relay was considered and deliberately dropped as too heavy/intrusive -
  see [docs/NETNTLM.md](docs/NETNTLM.md).)

## [1.33.7] - 2026-08-13

### Added
- **Engines** (orchestrate, don't reimplement): SMB (NetExec) - signing, SMBv1,
  null/guest (incl. the `Null Auth:True` banner field), shares; LDAP (NetExec) -
  users, AS-REP roast, Kerberoast (hashes captured to loot); ADCS (Certipy) -
  ESC1–ESC17; TLS (stdlib) - legacy protocols, weak ciphers, cert expiry/self-signed.
- **`scan`** command - one/many targets (`--target` / `--targets` scope file),
  aggregated `.docx` report + `findings.json`, optional `--live` 3D graph.
- **Offline cracking** (`crack.py`) - captured AS-REP/Kerberoast/NetNTLMv2 hashes written
  to hashcat-ready loot files; `--wordlist` cracks via hashcat/john → CRITICAL
  `credential-cracked` findings.
- **`poison`** command - intrusive NetNTLMv2 capture via Responder (LLMNR/NBT-NS),
  gated (`--iface`, `--duration`, `type YES`/`--yes`, passive `--analyze`).
- **Live 3D graph GUI** - SSE bridge + vendored 3d-force-graph; token-gated `POST /scan`;
  `redness gui` native window (pywebview, browser fallback); branded About + Usage panels.
- **`doctor`** command - engine/tool availability + install hints.
- **Reporting** - table-driven `.docx` (exec summary, findings by severity, remediation).
- **Packaging** - lean and self-contained PyInstaller specs; certipy runs in-process in the
  frozen exe; `pip install .` (console script + GUI assets) and one-shot installers.

### Fixed
- LDAP `--users` parsed by real column format (verified vs NetExec source) instead of a
  guessed keyword blocklist - `Enumerated`/`No`/`Found`/`Skipping` no longer become users.
- De-duplicated SMB null/guest findings; tolerate nxc `--verbose/--log` line prefix.
- Frozen-exe entry point (absolute import); invalid-escape SyntaxWarning.

### Notes
- Verified against real tooling (NetExec/Certipy 5.x source, Certipy in-process) and a
  first live-DC run. See [docs/VALIDATION.md](docs/VALIDATION.md).
- Authorized assessments only.
