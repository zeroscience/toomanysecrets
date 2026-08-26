# REDNESS roadmap - what's missing, what makes us different

> Where do we go next? Two lenses: **parity** (what adscan / nxc / BloodHound / PingCastle
> already do that we don't yet) and **differentiators** (things no tool does well that our
> live-graph + one-place + report design can own). Ordered by value, with ownership.
> GUI polish & animations come *after* capability - see docs/GUI.md.

## Where we already win
- **Live 3D graph** of the assessment (native window or browser) - nobody else has this.
- **"Everything in one place"** - right-click a node to act (Phase 2 enum shipped).
- **The deliverable** - a real `.docx` with severity + remediation, not raw stdout.
- **Zero-friction** - `doctor`, one-command install, built-in weak-pw auto-crack, offline exe.

## Tier 1 - our differentiators (double down here)
These turn the graph from an *enumeration picture* into an *attack-path map*, and make the
"one place" actually offensive. This is the moat.

1. **Attack-path edges in the graph** *(Gjoko)* - draw the *relationships that matter*:
   `user -Kerberoastable→ hash -cracked→ password -local admin on→ host -→ Domain Admin`.
   BloodHound-style reachability, but **live and 3D** as findings land. Pull the raw edges
   from a **BloodHound collection** (`nxc ldap --bloodhound`) and/or derive them from our own
   findings. *This is the single most differentiating feature.*
2. **Phase 3 right-click offensive actions** *(Anja engines + Gjoko plumbing)* - the payoff of
   the `/action` channel: Kerberoast-this-user, secretsdump, DCSync, pass-the-hash exec,
   ADCS ESC abuse (`certipy req/auth`). Each gated like `poison`. "Everything in one place."
3. **Share secret-hunting (Snaffler-style)** *(Anja)* - spider readable shares for passwords,
   keys, connection strings, `web.config`, `unattend.xml`, `*.kdbx`, scripts. Surface each
   secret as a **graph node + finding**. Almost no orchestrator does this well; it's often the
   fastest path to DA and it reads *great* in a report. **BUILT** - `scan --hunt-secrets`
   (filename rules) / `--hunt-content` (content inspection, redacted) via engines/sharehunt.py
   + `Category.SECRET`; on `feat/sharehunt`, pending Gjoko's schema review. See docs/SHAREHUNT.md.
4. **Report upgrades** *(Gjoko)* - attack-path narrative ("how we'd reach DA"), **MITRE ATT&CK**
   technique IDs per finding (we already store some), and a **compliance map** (NIS2 / ISO 27001
   / CIS) like adscan. Optional self-contained **HTML report** mirroring the graph.

## Tier 2 - parity (what other tools have, we lack)
Steady, high-value coverage. Mostly Anja's engine lane; each is a small wrapper + parser + test.
- **Password spraying** - controlled, **lockout-aware** (read `--pass-pol` first). `nxc` spray.
  **BUILT** - gated `redness spray` command (never in `scan`); refuses unless lockout-safe,
  double-gated `--force`. See docs/SPRAY.md.
- **GPP `cpassword` / SYSVOL secrets** - decrypt Groups.xml; classic easy DA. **BUILT** -
  `GppEngine` wraps `nxc -M gpp_password`, in the default scan; recovers `account:password` +
  `meta["credentials"]`. See docs/GPP.md.
- **Delegation abuse enum** - unconstrained / constrained / **RBCD**, plus **machine-account
  quota (MAQ)** and **gMSA / shadow credentials** readability.
- **Coercion** - PetitPotam / PrinterBug / DFSCoerce → feeds `trigger`/`poison` (and, if we ever
  reconsider, relay). Kali-native.
- **RDP / WinRM / MSSQL remote-access surfaces** - the lateral-movement services we were blind
  to. **BUILT** - `redness/engines/remote.py` (RdpEngine/WinRMEngine/MssqlEngine) in the default
  scan: RDP NLA + exposure (unauthenticated), WinRM/MSSQL exposure + credentialed remote-exec
  reach (CRITICAL on `Pwn3d!`). Passive, no schema change. See docs/REMOTE.md. Follow-ups on
  MSSQL: linked-server hopping + xp_cmdshell exec (offensive, would be gated).

## Tier 3 - operator / OPSEC (professional polish)
- **Session save/resume** - reopen a graph from `findings.json` (partly via `report`); persist
  creds/scope as an **engagement profile**.
- **Audit log** - timestamped record of every action for **de-confliction** with the blue team.
- **Diff mode** - re-scan and show *what changed* (hardening regression / retest).

## Ownership split (avoid collisions)
- **Anja - `redness/engines/` + attacks:** Phase 3 actions, secret-hunting engine, spraying,
  GPP, delegation/MAQ/gMSA, coercion, MSSQL.
- **Gjoko - graph / report / orchestration / GUI:** attack-path edges, BloodHound ingest,
  report upgrades, session/audit/diff, HTML report.
- Contract first for anything crossing the line (`/action` params, new `Finding` shapes, the
  `meta` keys secret-hunting emits) - same as the crack.py contract in docs/NETNTLM.md.

## Not doing (decided)
- ntlmrelayx **live relay** - too heavy/intrusive (see docs/NETNTLM.md).
- Reimplementing any protocol tool - we orchestrate nxc/impacket/certipy, always.

## Then: the fun part
Once capability is deep, the GUI/animation pass - smoother, more organic motion, OS-adaptive
node shapes, themes (docs/GUI.md "future"). Capability first, polish second. 😉
