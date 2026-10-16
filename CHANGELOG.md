# Changelog

All notable changes to REDNESS. Format loosely follows [Keep a Changelog](https://keepachangelog.com).
Zero Science Lab | powered by Silly Security Inc.

## [Unreleased]
### Added
- `2026-10-16` **Advisor: "run the right tool for what we found" (`scan --nmap --suggest`).** A new
  recommendations layer that turns detected services + findings into a ranked list of offensive
  next steps - each a tool, why it applies, and a ready-to-run command - in three tiers mirroring
  REDNESS's posture: **auto** (read-only `searchsploit` lookups REDNESS runs, added to the report),
  **suggest** (prints the command - nuclei/sqlmap/metasploit/aircrack - you run it), **gated**
  (hydra / `redness spray`, via the consent+FORCE+audit path). New `--nmap` runs `nmap -sV`
  (service/version/CPE) as the tech detector; `--suggest` prints the "Suggested next steps" section.
  OT-safe: hosts with any ICS finding are excluded from every suggestion. `redness/engines/nmap.py`
  + `searchsploit.py` (pure parsers) and `redness/advisor.py` (pure rule engine); `doctor` reports
  nmap/searchsploit/nuclei readiness. 15 tests. No schema change. See [docs/ADVISOR.md](docs/ADVISOR.md).
- `2026-10-11` **Nuclei web services as graph nodes under each host.** Each distinct nuclei
  `host:port` web service now draws as its own `web` node with an edge from its host (a host with
  several web ports gets one node per port), instead of recolouring the whole host. New pure
  derivation `redness/webgraph.py` (`emit_web_nodes`, mirrors `graphtypes.py`) owns these nodes;
  `scan._node_type` returns None for `Category.WEB` so the live scan, the captured graph, and the
  report fallback agree. nuclei's asset id always carries a port now (inferred from the scheme when
  omitted), so a service never collapses onto its host, and the GUI re-types the node to `web` (it
  lands in the IoT/SERVICES territory). 5 tests (incl. an end-to-end run_scan graph check).
- `2026-10-11` **Nuclei engine (`scan --nuclei`): template-based web/network vuln scanning.**
  Wraps ProjectDiscovery's nuclei (CVEs, exposed panels, default logins, misconfig, tech-detect,
  takeovers). `redness/engines/nuclei.py` parses `-jsonl`, grouping matches by template into one
  `Finding` per template (N affected host:port, one evidence per match). New **`Category.WEB`**
  (**SCHEMA_VERSION 1.3.0 -> 1.4.0**). The first ACTIVE engine, so it is handled carefully: opt-in
  only (never in the default scan), port-gated to web ports (80/443/8080/8443) so it never touches
  OT/ICS, always `-exclude-tags intrusive,dos,fuzz,brute` + rate-limited, and the binary/templates
  are a separate install surfaced in `doctor`. `--nuclei-profile light|full`, `--nuclei-templates
  PATH`. Remediation fallback guarantees every finding carries one. `web` graph node type
  (IoT/SERVICES territory). 10 tests. See [docs/NUCLEI.md](docs/NUCLEI.md).
- `2026-10-11` **Real 3D chess pieces on the world map (live GUI + HTML report).** In the map
  view every node now renders as an actual turned chess figure instead of a sphere-on-a-disc:
  **king** = Domain Admin / Process Impact (goal), **queen** = domain, **rook** = compromised
  (owned), **bishop** = OT / IoT units, **knight** = NTLM relay, **pawn** = the rank-and-file AD
  assets (host/user/share/template/CA/secret/...). No new dependency and no three.js import: we
  reach the vendored bundle's OWN `BufferGeometry` (prototype of a node's `SphereGeometry`) and
  `Float32BufferAttribute`, then GENERATE the geometry by hand - each piece is a lathe (surface of
  revolution of a 2D profile), except the knight, a horse-head silhouette extruded with a small
  ear-clipping triangulator. Same three instance as the renderer, so no version mismatch. Wired
  via `nodeThreeObject` only in map mode (graph view keeps the fast spheres); `CHESS_PIECES` flag
  to fall back. Pure front-end, no schema change. (The knight was later refined to a cleaner,
  less chunky horse-head profile - 24-point silhouette, thinner extrusion.)
- `2026-10-08` **CSV export + console verbosity, on every reporting command.** A new `--csv`
  output (`redness/report/csv_report.py`) writes one row per **(finding x affected asset)** - a
  finding touching three hosts becomes three rows - so the same file reads **by IP** (sort the
  `asset` column; `asset_kind` tags ip/host/account/share/object) or **by finding** (sort
  `severity`/`id`). UTF-8 BOM so Excel opens it clean. Added alongside `--out`/`--json`/`--html`
  to `demo / report / scan / capture / wifi / listen / poison / spray / coerce` via one shared
  helper (the per-command output blocks were de-duplicated). New `-v/--verbose` (evidence + fix
  under each finding) and `-q/--quiet` (counts only) control the console summary. 5 tests. See
  [docs/REPORTING.md](docs/REPORTING.md).
- `2026-10-08` **Role-differentiated map pieces.** In the world-map view each node now reads as a
  distinct Risk piece by role: the objective (Domain Admin / Process Impact) stands as a tall thin
  **spire**, compromise nodes as **pawns**, the domain as a broad **monument**, OT/IoT kit as mid
  standing **units**, and everything else as a wide low **chip** (pedestal width + body height +
  column thickness all vary). Live GUI + HTML report. Pure front-end, no schema change.
- `2026-10-08` **Brand + world-map polish.** The new orbital REDNESS logo is now the browser
  **favicon** and the badge atop the **About** modal (and already the HUD/report header mark). The
  world-map view gets a visual pass on both the live GUI and the HTML report: territories render as
  **ragged landmasses** (a core disc + deterministic rim blobs over a lighter shallow-water shelf)
  instead of plain circles, the ocean board gains a four-ring **graticule**, and every node stands
  as a **Risk-style game piece** (a pedestal disc at board level + a thin column rising to the
  floating node). Deterministic per-territory RNG keeps coastlines stable across rebuilds; live map
  adds trigger a debounced board rebuild. Refreshed `docs/screenshots/live-graph.jpg`. Pure
  front-end, no schema change.
- `2026-10-07` **World-map / Risk-style territory view (live GUI + HTML report).** A second layout toggled with the "Map view" button: nodes land in labelled **territories by type** - **DIRECTORY / COMPROMISE / OT-ICS / IoT-SERVICES** - spread like continents over an ocean board with graticule rings; each freshly discovered node **wobbles** into its slot, important pieces **stand taller** (Risk-army style), and attack paths arc high across the board. IoT/service hosts get their own node types (broker/database/printer/iot via `redness/graphtypes.py`) so they form their own territory. Ported to the HTML report too. Pure front-end + graph-only node types; no schema change. See docs/DECISIONS.md.
- `2026-10-07` **SSH crypto/version audit.** `engines/ssh_audit.py` reads the SSH banner and the
  server's KEXINIT algorithm offer and flags weak key-exchange (SHA-1/group1/14-sha1), ciphers (CBC
  /3des/arcfour/blowfish), MACs (md5/sha1/-96), and host keys (ssh-rsa/ssh-dss): `ssh-server`
  (INFO) + `ssh-weak-crypto` (MEDIUM). Read-only (no authentication); default scan, port-gated to
  TCP/22. No schema change. 6 tests + a real-socket smoke.
- `2026-10-07` **Passive capture + wireless recon (`redness capture` / `redness wifi`).** Two new
  passive surfaces that orchestrate native tools. **capture** drives tshark over a pcap or a live
  interface (`-z credentials` + `-z io,phs`) -> `cleartext-credentials` (CRITICAL) and
  `cleartext-protocols` (MEDIUM). **wifi** drives netsh (Windows) / nmcli (Linux) to survey Wi-Fi
  in range -> `wireless-open` (MEDIUM), `wireless-weak-encryption` (HIGH, WEP/WPA1/TKIP), and an
  inventory. Both read-only (analyze authorized traffic; list visible SSIDs - no transmit/deauth/
  crack); no schema change (reuse PASSWORD/CONFIG). Pure parsers, 11 tests. See
  [docs/CAPTURE.md](docs/CAPTURE.md).
- `2026-10-07` **OT enumeration tier (`scan --ics-enum`):** the gated, louder OT sweep.
  `ModbusSweepEngine` maps the serial RTUs behind a Modbus/TCP gateway (unit-id sweep ->
  `modbus-gateway-units`) and `Dnp3ScanEngine` enumerates a DNP3 segment (outstation-address scan
  -> `dnp3-segment`). Still read-only (identity / link-status only, never writes a point), but a
  broad sweep can upset fragile kit, so it is behind its own opt-in (`--ics-enum`, implies `--ics`)
  with a loud warning. Reuses the tested parsers; 6 tests. DNP3 Group 0 attributes + HART roster
  stay deferred to a real-device verify pass. See [docs/ICS.md](docs/ICS.md).
- `2026-10-07` **Exposed-service engines: Redis / MongoDB / Elasticsearch / Memcached / printers.**
  The classic unauthenticated-service findings (`Category.SERVICE`), in the default scan, read-only,
  port-gated: `redis-unauth` (CRITICAL), `mongodb-no-auth` (CRITICAL), `elasticsearch-unauth`
  (HIGH), `memcached-exposed` (HIGH), `printer-exposed` (MEDIUM: leaks jobs + stored scan/LDAP
  creds) - each distinguishing reachable from reachable-without-authentication. No data dumped,
  nothing written (`redness/engines/netsvc.py`). 10 tests + a real-socket smoke. See
  [docs/SERVICES.md](docs/SERVICES.md).
- `2026-10-07` **IoT engines: MQTT + CoAP** (expansion past OT toward a general network-PT tool).
  **MQTT** (TCP 1883): a read-only anonymous CONNECT; `mqtt-anonymous` (HIGH) when the broker
  accepts a no-credential connect (anyone can subscribe to every topic), else `mqtt-exposed`
  (INFO). **CoAP** (UDP 5683): a read-only GET `/.well-known/core`; `coap-exposed` (MEDIUM) with
  the device's resource list. New `Category.IOT` + `Category.SERVICE` (**SCHEMA_VERSION 1.2.0 ->
  1.3.0**, additive). Both run in the default scan (MQTT port-gated, CoAP un-gated UDP). 10 tests +
  a real-socket smoke. See [docs/IOT.md](docs/IOT.md).
- `2026-10-07` **OT graph + Process Impact attack path:** the ICS pack now has a visual story -
  `redness/ot.py` (mirrors paths.py/relay.py) draws the OT analog of path-to-Domain-Admin. Each
  exposed OT controller gets a dashed `controller -> Process Impact` lead to a new **Process
  Impact** goal node, and when one scan reaches both IT/AD and OT - a Purdue **segmentation
  failure** - a solid `IT / Enterprise -> controller` edge plus an `ot-it-segmentation` CRITICAL
  finding (`IT / Enterprise -> controller -> Process Impact`, the shape of entry -> owned -> DA).
  OT hosts are re-typed to their controller role (plc/rtu/gateway/controller by protocol + Purdue
  level); the GUI + HTML report get OT node colors, legend rows, and the auto-tour/replay now reach
  the Process Impact goal like Domain Admin. No schema change. 7 tests; verified both surfaces
  in-browser. See [docs/ICS.md](docs/ICS.md).
- `2026-10-07` **ICS pack: DNP3 + HART-IP engines.** Extends `scan --ics` to the SCADA/process
  layer. **DNP3** (TCP 20000) sends a read-only Request Link Status; a listening port is
  `dnp3-exposed` (HIGH) and a Link Status reply adds `dnp3-outstation` (INFO) with the discovered
  outstation address. **HART-IP** (TCP 5094) sends a read-only Session Initiate -> `hart-ip-exposed`
  (HIGH). Both are opt-in + port-gated like the rest of the pack; full device attributes (DNP3
  Group 0, HART Command 0 roster) and the outstation-address scan are deferred to the gated
  enumeration tier + a real-device verify pass. Includes the DNP3 CRC-16. 12 more tests (30 total)
  + a real-socket smoke. See [docs/ICS.md](docs/ICS.md).
- `2026-10-06` **ICS / OT field-protocol pack (`scan --ics`):** first expansion beyond AD - read-only
  enumeration of industrial control systems. Three engines: **EtherNet/IP (CIP)** List Identity
  (TCP 44818), **Modbus/TCP** Read Device Identification (TCP 502), and **BACnet/IP** Who-Is/I-Am
  (UDP 47808). Each sends ONE read-only identity request (never writes a coil/register/point),
  emits a `*-exposed` finding (an unauthenticated control protocol is reachable) plus an INFO
  `*-device-identity` inventory (vendor/product/revision/serial). New `Category.ICS`
  (**SCHEMA_VERSION 1.1.0 -> 1.2.0**, additive) with `meta["protocol"]` / `meta["purdue"]` /
  `meta["device"]`. OT-safe by construction: opt-in (off by default), port-gated (TCP engines run
  only when the port is open), louder enumeration tiers deferred. Pure parsers unit-tested against
  hand-built packets (18 tests) + a real-socket smoke. See [docs/ICS.md](docs/ICS.md). DNP3 + HART-IP
  and OT graph node types / attack paths are the next steps.
- `2026-09-28` **Hover-to-focus + idle camera drift (GUI):** hovering a node keeps it and its
  direct (1-hop) neighbours and their links bright and dims everything else (nodes grey, glow cores
  x0.15, non-incident links near-invisible); mouse-out resets. After ~5s with no input the camera
  slowly orbits the graph (~90s/rev) from its current position, and any input stops it instantly.
  Both layer under the "Replay path to DA" cinematic (focus is skipped during a tour; idle drift is
  kept separate from the auto-tour latch so it never suppresses the one-shot tour). Front-end only
  (`redness/live/web/index.html`); no contract/schema change. GUI bumped to v1.36.0. (anjaiv, #80)
- `2026-09-28` **Delegation attack-path edges (unconstrained, non-DC):** `paths.py:delegation_edges()`
  turns `delegation-unconstrained` (HIGH, non-DC) findings into `host -> Domain Admin` attack edges
  so delegation shows on the attack map, not just as findings. `potential=True` (a preconditioned
  lead: gain SYSTEM on the host first) so it never fabricates a proven path and marks nothing owned;
  `delegation-unconstrained-dc` (INFO, a DC legitimately delegating) is ignored. RBCD edges are
  deliberately deferred to the real-nxc Kali verification pass (SPN-valued meta + inverse direction,
  unverifiable offline). Backend-only, reuses the existing AttackEdge/EDGE contract; no findings.py
  or schema change. Issue #60 option 3. (anjaiv, #79)
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
- `2026-09-24` **CI: pytest on push/PR (`.github/workflows/ci.yml`):** GitHub Actions runs the
  offline test suite on every push to `main` and every PR, across a matrix of
  ubuntu-latest + windows-latest x Python 3.10/3.12. Windows is in the matrix on purpose - the
  live bridge uses raw sockets and has had Windows-only races - so regressions there get caught
  automatically. Base install only (`pip install . pytest`); no engines/DC needed.

### Fixed
- `2026-09-24` **Flaky live-bridge tests on Windows (`WinError 10054`):** the offensive
  bridge / GUI-scan tests failed transiently when the full suite ran repeatedly. Two
  distinct Windows socket races, both fixed in `redness/live/bridge.py` without
  changing any test assertion:
  - **Early error returns reset the connection.** A gated `POST` (bad/empty token)
    called `send_error(403)` *before* reading the request body; closing a socket with
    an unread body makes Windows send an RST, so the client saw a connection reset
    instead of the `403`. `do_POST` now drains the request body up-front (`_drain_body`)
    before any token/route check, so the close is always graceful. (Dominant cause.)
  - **Address-reuse port collisions.** `http.server` sets `allow_reuse_address = 1`
    (SO_REUSEADDR) unconditionally; on Windows that lets a *second* socket bind a port
    already in use, so two short-lived `port=0` servers could share one ephemeral port.
    A new `_LiveHTTPServer` subclass takes the port exclusively on Windows
    (`SO_EXCLUSIVEADDRUSE`, `allow_reuse_address = False`) while keeping SO_REUSEADDR on
    POSIX for clean restarts of the fixed production port.
  - `LiveServer.stop()` now joins the serve thread for deterministic, idempotent
    teardown. Verified with a 1500-iteration bridge stress harness (23 anomalies -> 0)
    and the suite looped 25x.

### Changed
- `2026-10-08` **New REDNESS logo** (orbital/atom mark on a transparent background). Replaces the
  placeholder ZeroScience wordmark in the live GUI brand (`web/logo.png`) and is embedded as a
  self-contained data-URI in the HTML report header. (Old `logo.svg` removed.)
- `2026-09-29` **Vendored-lib provenance + security note:** recorded in `THIRD_PARTY_LICENSES.md`
  that the vendored `3d-force-graph` is **1.80.0** (current latest; bundles three.js r183), with a
  dated review confirming no known applicable CVEs and a reminder that a vendored bundle is not
  covered by `npm audit` and must be re-checked by hand on a bump.
- `2026-09-29` **ASCII-only glyphs across the codebase:** replaced every non-ASCII character in
  source and docs with a plain-keyboard equivalent (arrows -> `->`, en/em-dashes -> `-`, middot
  separators -> `|`, ellipses -> `...`, the GUI's play/close/plus/flag/warning glyphs -> `>` / `x`
  / `+` / `[!]` / `!`, box-drawing -> `-`/`|`, emoji dropped). 16 files; verified the live GUI and
  HTML report still render and the suite stays green.
- `2026-09-04` **New Scan panel:** added an x in the header to close/cancel the panel (e.g. if you
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
  ESC1-ESC17; TLS (stdlib) - legacy protocols, weak ciphers, cert expiry/self-signed.
- **`scan`** command - one/many targets (`--target` / `--targets` scope file),
  aggregated `.docx` report + `findings.json`, optional `--live` 3D graph.
- **Offline cracking** (`crack.py`) - captured AS-REP/Kerberoast/NetNTLMv2 hashes written
  to hashcat-ready loot files; `--wordlist` cracks via hashcat/john -> CRITICAL
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
