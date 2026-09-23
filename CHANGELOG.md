# Changelog

All notable changes to REDNESS. Format loosely follows [Keep a Changelog](https://keepachangelog.com).
Zero Science Lab · powered by Silly Security Inc.

## [Unreleased]
### Added
- `2026-09-23` **Depth & atmosphere (GUI + HTML report):** the graph now reads like an ops console,
  not a wireframe demo. Each node gets a **fake-bloom glow halo** (an additive-blended sphere
  bleeding light outward, brightness scaled by severity so criticals glow hardest) - real
  post-processing bloom isn't bundled, so this is done with reachable three primitives. The WebGL
  background is transparent over a CSS **starfield + centre-lit vignette** for depth. Pure
  front-end; no contract/schema change. Shared by `redness/live/web/index.html` and the
  self-contained HTML report.
- `2026-09-23` **Severity as physics (GUI + HTML report):** a finding's worst severity now drives
  the node's behaviour - critical nodes **swell larger**, **throb harder and faster** (ambient
  breathing amplitude/speed scale with severity), and a custom force **pulls them toward the
  centre** so the criticals cluster and draw the eye while low/info nodes drift to the periphery.
  Owned/goal nodes keep a breathing floor. GUI bumped to v1.35.0. Shared by
  `redness/live/web/index.html` and the self-contained HTML report; pure front-end, no
  contract/schema change.
- `2026-09-23` **Compromise-spread shockwaves (GUI + HTML report):** domain takeover now reads as a
  cascade - a red shock ring erupts from every compromised (owned) node, then a pulse travels
  outward hop by hop along the attack edges (BFS from the owned set), ringing each node the
  compromise reaches (orange as it spreads, gold when it hits the Domain Admin goal) with a
  particle burst on each traversed edge. Ambient and periodic (~every 4.2s once a compromise
  exists); pauses during the auto-tour so the two never fight for the stage. Shared by
  `redness/live/web/index.html` and the self-contained HTML report; pure front-end, no
  contract/schema change.
- `2026-09-23` **Cinematic auto-tour of the attack path (GUI + HTML report):** the graph now plays
  its own "how we'd reach Domain Admin" story - an establishing wide shot, then the camera flies
  the attack/relay edges entry -> owned -> Domain Admin in order, lighting each with a particle
  burst and a trail-following camera, pulsing owned nodes, and finishing on the goal with a pulse +
  slow orbit. Auto-plays once on scan-complete (live) / after layout settles (report) when a path
  to a goal exists; any drag/scroll skips it (operator intent wins), and the "Replay path to DA"
  button still triggers it. Shared by `redness/live/web/index.html` and the self-contained HTML
  report, so a client's offline report performs the same walk. GUI bumped to v1.34.0.
- `2026-09-23` **Self-contained HTML report (`--html`):** one offline `.html` that mirrors the
  `.docx` (severity summary + every finding with impact/remediation/evidence/references) **and
  embeds the live 3D attack-graph** - `redness/report/html_report.py`. It inlines the already
  vendored 3d-force-graph bundle, so a client just opens the file (no server, no network, no Word),
  spins the graph, and watches attack paths light up to Domain Admin. `scan --html out.html` and
  `report findings.json --html out.html`. To make it an exact mirror, `run_scan` now captures the
  node/edge stream into `report.meta["graph"]` (`redness/graphmodel.py`), with a fallback that
  reconstructs a graph from any older report. No new dependency, no schema change. See
  [docs/HTML_REPORT.md](docs/HTML_REPORT.md).
- `2026-09-23` **Unified audit log (`loot/audit.log`):** one timestamped JSONL timeline of every
  sensitive/active operation for blue-team de-confliction - `redness/audit.py`. `scan` / `poison`
  / `spray` now audit (start + done) where they logged nothing before; the offensive right-click
  actions route their arm/execute/refuse/result through it (retiring the separate
  `offensive-audit.log`); `coerce` adds a structured record while keeping its detailed per-vector
  `coerce_audit.log` sidecar. Params only, never secrets (booleans/counts/iface/target); best-effort
  writes never break a run; `loot/` stays gitignored. See [docs/AUDIT.md](docs/AUDIT.md).
- `2026-09-23` **Retest diff (`redness diff`):** compare a baseline `findings.json` to a current
  one and classify every finding as **new / fixed / unchanged / severity-changed** - the retest
  deliverable after a remediation round. `redness/diff.py` is pure over the findings model
  (identity = `id` + sorted `affected`, so the same issue on a different host reads as new+fixed,
  not unchanged); severity moves record the old severity. `diff baseline.json current.json`
  prints an operator summary, `--json` writes the classified delta, and the command exits `2` on a
  regression (any new finding or severity increase) so retests can gate CI. No schema change. See
  [docs/RETEST.md](docs/RETEST.md).
- `2026-09-14` **Phase-3 offensive catalog (three right-click actions):** `redness/actions.py`
  adds **asrep-roast** (user node, `nxc ldap --asreproast` -> `asrep-roast-user` HIGH, no creds
  needed), **adcs-esc1** (template node, `certipy find`->`req`->`auth` with the CA auto-resolved
  -> `adcs-esc1-abused` CRITICAL, recovers an NT hash), and **pth-exec** (host node,
  pass-the-hash `nxc smb -x` running a *fixed* read-only recon battery with no operator command
  input -> `pth-exec` CRITICAL). All ride the existing arm/confirm/audit offensive channel; pure
  parsers with injected runners, no `findings.py` / `paths.py` / schema change (reuses `Category`
  + `meta` keys). ESC8 deliberately held (it is live NTLM relay - see
  [docs/ADCS_ESC8_UNPLANNED.md](docs/ADCS_ESC8_UNPLANNED.md) and issue #60).
- `2026-09-04` **Passive link-local discovery (`listen` command):** `redness/mcast.py` listens for
  the broadcast/multicast "chatter" a WiFi/LAN segment leaks - **mDNS**, **LLMNR**, **NBT-NS**, and
  **SSDP/UPnP** - to inventory hosts and devices (printers, IoT, media, Apple/Android) with *no
  active scanning*, and to surface attack surface: `llmnr-nbtns-poisonable` (MEDIUM - spoofable
  name resolution, feeds `poison`) and `wpad-lookup-observed` (HIGH - WPAD spoofing -> credential
  theft). Pure-Python sockets (no new dependency), fully passive by default (`--active` sends one
  SSDP M-SEARCH), parsers unit-tested against hand-built packets. Findings reuse ENUM/CONFIG - no
  schema change.
- `2026-09-03` **NTLM relay map + graph replay cinematic:** `redness/relay.py` correlates findings
  a scan already produced into concrete relay chains - AD CS Web Enrollment (ESC8) becomes a
  CRITICAL `ntlm-relay-to-adcs` chain to Domain Admin (coerce a DC -> relay to /certsrv -> DC cert
  -> DCSync), and signing-disabled hosts become a HIGH `ntlm-relay-to-smb`. Drawn on the graph as
  a central **NTLM Relay** node with coercion fan-in and relay fan-out. Pure derivation, no new
  tool, no schema change. Plus a **"Replay path to DA"** button that animates the attack/relay
  edges from entry point to the Domain Admin goal (edge lighting + particle bursts + camera fly +
  goal pulse) - the "how we'd own you" story for demos and report screenshots.
- `2026-09-03` **New-node flash on right-click discovery:** when a right-click action (enum or
  offensive) turns up a host/IP that wasn't on the graph yet, an **expanding cyan ring** (a
  scanner-ping ripple, three rings over ~3 seconds) emanates from that node so the operator can
  immediately spot what the action discovered. Scoped to a window right after the action (the
  initial scan build doesn't flash), with a hard cleanup fallback so a node is never left
  mid-animation if the tab was backgrounded.
- `2026-09-03` **Demo right-click discovery:** in `live --demo`, right-clicking **Enumerate SMB**
  on a host now simulates a realistic discovery - readable shares on the host, plus an active
  session revealing a logged-on user and the workstation they came from (a new in-scope host) - so
  the new-node ring is visible without any tools installed. (What legitimately spawns a new
  in-scope node from an SMB enum: shares and session/logged-on data.)
- `2026-08-31` **Offensive actions wired into the GUI (arm/execute HTTP framework):** the Phase-3
  offensive actions (Kerberoast / secretsdump / DCSync) are now triggerable from the live graph
  via two new bridge endpoints - `POST /action/arm` (returns a single-use token + banner) and
  `POST /action/execute` (needs the token + an `X-Redness-Confirm` header). Gated hard:
  **off by default**, unlocked only with `redness gui|live --enable-offensive`, which mints a
  **separate operator-console token** (never embedded in the page) that must be pasted into the
  GUI; **loopback-bind only**; offensive actions stay hidden in the catalog until enabled. GUI
  flow is right-click -> arm -> confirm(banner) -> execute.
- `2026-08-27` **FTP / HTTP / SNMP engines (broader protocol coverage):** three passive engines in
  the default scan. **FTP** (`nxc ftp`) - anonymous login (`ftp-anonymous`) + exposure/banner.
  **HTTP** (pure stdlib, AD-scoped, *not* a general web scanner) - flags AD CS Web Enrollment
  `/certsrv` as an **ESC8** NTLM-relay target (`adcs-web-enrollment`, HIGH), plus OWA/EWS and a
  server banner. **SNMP** (`snmpwalk`) - default community strings (`snmp-default-community`,
  HIGH for `public`, CRITICAL for read-write `private`). All reuse existing categories - no
  schema change; parsers verified/injectable and unit-tested.
- `2026-08-27` **Service-discovery dispatch (the "hail-mary" default scan):** `redness/discovery.py`
  + `run_scan`. A default scan now runs every passive engine, but per host it first does a
  lightweight TCP connect-scan (stdlib sockets, no nmap) of the ports our engines care about and
  dispatches only the engines whose service is actually open - so a full-breadth scan stays fast
  and quiet ("according to the enumeration and logic"). Port knowledge is centralized in
  `discovery.ENGINE_PORTS`; engines not listed there are never gated (UDP/unknown engines keep
  full coverage). `--no-discovery` runs every available engine regardless. This is discovery, not
  exploitation (a plain TCP connect, nothing sent to the service).
- `2026-08-26` **Remote-access protocol engines (RDP / WinRM / MSSQL):** `redness/engines/remote.py`
  adds three passive nxc-backed engines to the default scan - the lateral-movement surfaces the
  SMB/LDAP/AD CS/TLS engines miss. **RDP** flags missing Network Level Authentication
  (`rdp-nla-disabled`, pre-auth surface / BlueKeep class) plus reachability; **WinRM** and
  **MSSQL** flag exposure and, when creds are supplied, confirm a reachable remote-exec path
  (`*-access`, HIGH, upgraded to CRITICAL on a `(Pwn3d!)` admin hit = remote code execution).
  Passive banner reads only (no lockout risk), so they run in `scan` unlike gated poison/spray.
  Findings reuse `Category.CONFIG` / `Category.ENUM` - no schema change. Parsers verified against
  NetExec's rdp/winrm/mssql output and unit-tested (no live host needed).
- `2026-08-21` **BloodHound ingest (`bloodhound` command):** load a SharpHound / BloodHound-CE
  collection (`.zip`, a directory of `.json`, or a single file) and stream real AD relationships
  (MemberOf / AdminTo / HasSession) into the graph - `redness/bloodhound.py`. Adds the structural
  context that turns findings into full paths to Domain Admin.
- `2026-08-21` **Report upgrades:** the `.docx` now includes an **Attack Paths** section (owned
  accounts, roastable leads, AD CS ESCn to Domain Admin, derived via `redness.paths`), a
  **MITRE ATT&CK** technique on each finding, and a **Compliance Mapping** appendix (indicative
  CIS Controls v8 / ISO 27001:2022 / NIS2 per finding) - `redness/report/mappings.py`.
- `2026-08-21` **Attack-path edges (the graph becomes an attack map):** `redness/paths.py` derives
  the relationships that matter from a scan's findings - cracked accounts become `owned` (red),
  roastable-but-uncracked become potential leads, and AD CS ESC1/2/3/6/8 point at a `Domain Admin`
  goal node. Streamed as distinct red/animated attack edges, wired into `run_scan`; each carries a
  MITRE technique id for the report.
- `2026-08-14` **`trigger` command** - generate a forced-authentication UNC lure (`html` / `scf` /
  `url`) that coerces a victim to authenticate to us; the capture rides the existing `poison`/
  Responder pipeline (NetNTLM design Phase 2). Pure string generation, gated banner.
- `2026-08-14` **Built-in weak-password auto-crack** - when no `--wordlist` is given and
  hashcat/john is on PATH, `scan`/`poison` auto-try a small hand-curated weak-password list
  (`redness/wordlists.py`, ~370 entries, sub-second) across all hash types
  (AS-REP / Kerberoast / NetNTLMv2). `--no-crack` disables all cracking; explicit `--wordlist` is
  unchanged.
- `2026-08-13` **Right-click node actions (GUI Phase 2, read-only):** `redness/actions.py` registry
  + token-gated `POST /action` + `GET /actions`; right-click a host/domain node in the graph to
  run Enumerate SMB / LDAP / AD CS / TLS against it, streamed back live. The channel every future
  action plugs into.

### Changed
- `2026-09-04` **New Scan panel:** added an ✕ in the header to close/cancel the panel (e.g. if you
  opened it or a scope import by mistake) without starting a scan.
- `2026-09-04` **Trimmed the CLI banners:** dropped the "Authorized, in-scope engagements only /
  assume written authorization" boilerplate from the `spray` / `poison` / `coerce` / `trigger`
  banners, the offensive-channel notice, and the `listen` line - kept the operational danger info
  (INTRUSIVE, can lock out accounts, affects other hosts, loud to a SOC).
- `2026-09-04` **About window copy:** dropped the "Authorized security assessments only." footer and
  tightened the blurb (removed the dash-aside phrasing) so it reads in our own voice.
- `2026-09-04` **Relay map now accepts poisoning as a source:** `redness/relay.py` treats spoofable
  LLMNR/NBT-NS name resolution (from `listen`) as a second way to obtain the NTLM auth a relay
  needs, alongside coercion. When both a relay target (ESC8 / signing-off host) and poisonable name
  resolution are present, the graph draws a `LLMNR/NBT-NS poison` node feeding the `NTLM Relay`
  node, and the relay findings note the poisoning source. `scan --listen SECONDS` folds a passive
  sweep into a scan so the two combine into one report/relay map automatically.
- `2026-09-03` **Ambient breathing on high-value nodes:** the Domain Admin goal and any owned
  (compromised) nodes now gently pulse in size continuously, so the compromise state stays visually
  alive and draws the eye even when the graph is at rest (desynced per node; yields to the replay
  finale).
- `2026-09-03` **Organic live-graph look:** nodes are now smooth **translucent orbs with a bright
  glowing core inside** - a glassy `nodeOpacity` 0.3 shell (`nodeResolution` 20, larger
  `nodeRelSize`) with a smaller emissive inner sphere added via the graph's own bundled three.js
  (reached through each mesh's `.constructor`, so no second three instance and no extra dependency);
  the core colour syncs from the shell so severity / owned / goal recolours carry through. Links
  curve and flow, and the layout has a gentle perpetual drift (low `d3AlphaTarget` + softer velocity
  decay / charge) so it quietly breathes instead of freezing into a rigid lattice. Also fixed the
  WebGL canvas to size to its container + track resizes, so the graph renders even when the page
  loads in a hidden/zero-sized host.

### Planned
- ntlmrelayx live relay was considered and deliberately dropped as too heavy/intrusive (see
  [docs/NETNTLM.md](docs/NETNTLM.md)). Next directions live in [docs/ROADMAP.md](docs/ROADMAP.md)
  and the open issue tracker.

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
