# Architecture Decision Log

Append-only. Each entry: date, decision, why. This is how the other researcher's
agent catches up on *why* things are the way they are.

## 2026-08-09 - Orchestrate, don't reimplement
Wrap NetExec / Impacket / Certipy rather than rebuild protocol tooling. The attacks
are solved; our value is deployment (single .exe), normalization, and reporting.

## 2026-08-09 - Python orchestrator
Chosen over Go so we stay in the same ecosystem as impacket/certipy (direct library
access, no output re-parsing). Ship a single Windows `.exe` later via PyInstaller/Nuitka.

## 2026-08-09 - findings.py is the contract
`Finding` / `Report` schema is the interface between engines (Person A) and reporting
(Person B). Split ownership by directory so both halves progress in parallel.

## 2026-08-09 - NetExec SMB engine: parse stdout, keep parsing pure
Parse nxc's line-oriented stdout with regex (version-tolerant) rather than depend on
JSON output. Parsers are pure functions separated from subprocess execution so they
unit-test against captured output with no nxc/DC (see tests/test_netexec_parse.py).

## 2026-08-09 - PyInstaller one-file build
`packaging/redness.spec` uses `collect_all("docx")` so the bundled default.docx template
is present in the frozen exe. Requires Python >= 3.10.1 (3.10.0's `dis` bug crashes
PyInstaller analysis).

## 2026-08-09 - docx report, no template
Plain, table-driven, classic pentest report: exec summary (severity counts),
findings most-severe-first with impact/remediation/evidence, enumeration appendix.

## 2026-08-10 - Certipy engine parses JSON, not text
`certipy find -json` emits a per-object "[!] Vulnerabilities" map. We parse that
(robust) rather than scrape the text report. ESC1-ESC16 mapped to severity+remediation;
unknown ESCs default HIGH. Parsing pure + testable (tests/test_certipy_parse.py).

## 2026-08-10 - EventBus seam for a future live 3D graph
Added redness/events.py (EventBus + Event kinds: status/finding/node/edge/probe/done)
and Engine.emit_* helpers. Engines can stream as they enumerate so the SAME normalized
stream feeds both the docx report and a later 3D GUI, decoupled from any renderer.
Bus swallows subscriber errors (a broken UI can't break a scan). See docs/LIVE_GRAPH.md.

## 2026-08-10 - Live graph: stdlib SSE + vendored 3d-force-graph
Bridge uses stdlib http.server + Server-Sent Events (one-directional engine->UI, no
dependency, bundles into the exe) with a replay buffer so a browser rebuilds the full
graph on connect/refresh. 3d-force-graph vendored locally (v1.80.0, bundles three.js)
for offline/field use; web assets bundled via the spec's datas walk; bridge._web_dir()
is sys._MEIPASS-aware. preserveDrawingBuffer:true on the renderer so frames can be
captured for docs screenshots.

## 2026-08-10 - Packaging entry is outside the package
Frozen entry is packaging/entry.py (absolute `from redness.cli import main`), not
redness/__main__.py - PyInstaller runs the entry as top-level __main__ with no package
context, so a relative import crashes at runtime. pathex=<repo root> so analysis resolves.

## 2026-08-10 - scan command + scope orchestration
redness/scan.py run_scan() runs each available engine per target, aggregates Findings
into one Report, and (if given a bus) owns ALL graph emission so the picture is uniform
regardless of which engine found what (engines run headless in a scan). Missing tools
are skipped, not fatal; a crashing engine can't abort the scan. redness/scope.py parses
`--targets` files and merges with `--target`; shared with the future GUI file picker.

## 2026-08-10 - TLS engine is pure stdlib (no hard dep)
Protocol + cipher checks force each ssl.TLSVersion and read ss.cipher(); cert
expiry/self-signed via stdlib ssl (get_server_certificate + _test_decode_cert). SHA1/MD5
signature and <2048-bit key checks only when `cryptography` happens to be importable.
Always-available engine so a scan yields findings with no nxc/certipy present.

## 2026-08-10 - Hash capture + cracking scope (like adscan, minus poisoning)
LdapEngine captures AS-REP (krb5asrep) and Kerberoast (krb5tgs) hashes during LDAP enum,
stashing them in finding.meta["hashes"]. crack.py collects them, always writes hashcat-
ready loot files, and (if hashcat/john on PATH + --wordlist) cracks and annotates the
report with CRITICAL credential-cracked findings. hashcat mapping is prefix-based (hash
values can contain ':'). NetNTLMv2 CAPTURE needs an active LLMNR/NBT-NS poisoner - kept
OUT of scope for now (intrusive; separate gated feature).

## 2026-08-10 - GUI controls: token-gated POST /scan
The live bridge gained a POST /scan endpoint that runs the real engines (run_scan) in a
thread streaming to the bus. Guarded by a per-server CSRF token injected into index.html
(a cross-origin page can't read it, so it can't forge scans); bound to 127.0.0.1. The GUI
adds the ZeroScience logo (web/logo.svg - placeholder, swap for the real one), a targets
textarea + .txt scope loader (client-side FileReader), and optional creds. `redness live`
now waits for a GUI-initiated scan; `--demo` streams the simulated data (old default).

## 2026-08-10 - Bundle engines as deps, don't copy adscan
Do NOT vendor adscan's source (it's a peer orchestrator - copying invites license
entanglement and is redundant). Instead depend on the real engines: netexec/impacket/
certipy-ad (requirements-engines.txt), which our engines already shell out to. Added a
`doctor` command that reports engine/tool availability + install hints (answers the
"why 0 findings?" question). Two build modes: packaging/redness.spec (lean, expects
nxc/certipy on PATH) and packaging/redness-full.spec (self-contained: collect_all the
engine packages into one ~100MB exe - scaffold, needs validation on a deps-installed box
because nxc loads modules dynamically and PyInstaller misses those without hidden-imports).

## 2026-08-10 - Full self-contained exe: validated, partially blocked
Validated packaging/redness-full.spec on Windows/py3.12. Findings:
- BUILD works (~29MB exe with impacket-lib + certipy + ldap3) after excluding
  impacket.examples (Defender locks those hacktool scripts -> [Errno 22] on read).
- RUNTIME gap: engines shell out to certipy/nxc binaries (shutil.which); a frozen exe
  won't find them on PATH even though the modules are bundled. TODO: in-process
  invocation (call certipy.entry:main with patched sys.argv) to actually use them.
- Windows Defender quarantines core impacket files (impacket/krb5/constants.py + all
  examples) -> pip install and the build fail until the venv/project folder is a
  Defender exclusion (USER action; we can't modify AV/security settings).
- NetExec has no PyPI release for py3.12 -> install via pipx/git, not pip.
Net: a working batteries-included exe needs (1) Defender exclusion + clean reinstall,
(2) netexec via pipx/git, (3) in-process engine invocation. The lean packaging/
redness.spec (nxc/certipy on PATH) remains the supported default.

## 2026-08-10 - certipy bundles in-process; netexec stays external (pipx)
Validated after the Defender exclusion: certipy + impacket install clean on py3.12 and
bundle into redness-full.exe; CertipyEngine runs certipy in-process (certipy.entry:main)
so the frozen exe executes it with nothing on PATH (proven: banner + real LDAP attempt
from inside the exe). NetExec, however, has no py3.12 wheel and its git build also fails
on 3.12 -> it is NOT bundled; recommended install is `pipx install netexec` (isolated
compatible Python, `nxc` on PATH) and our shell-out NetExec/LDAP engines use it. So:
certipy = batteries-included/in-process; netexec = external tool via pipx.

## 2026-08-10 - pip-installable (pyproject.toml) + one-shot installers
Added pyproject.toml so `pip install .` gives a `redness` console script and ships the
live GUI assets (package-data: live/web incl. vendored 3d-force-graph). Engines are an
extra: `pip install ".[engines]"` = certipy-ad + impacket (both have py3.12 wheels).
NetExec is intentionally NOT a dependency (no py3.12 wheel) - scripts/install.sh|ps1
install it via pipx, or use a box where nxc is already on PATH (Kali). Validated: the
installed `redness` runs from outside the repo and `redness live` serves index/logo/vendor
(1.3MB) from site-packages. Flow: git clone -> ./scripts/install.sh -> redness doctor/scan.

## 2026-08-11 - NetNTLMv2 capture: a gated `poison` command, not an engine
Built the intrusive NetNTLMv2 feature (docs/NETNTLM.md) as a standalone `redness poison`
command driving Responder (LLMNR/NBT-NS/mDNS) - deliberately NOT an Engine and NOT in
default_engines(), so `scan` can never trigger it. Gated: `--iface` required, `--duration`
time-box (default 600s), a `type YES` confirmation (+ `--yes`), a passive `--analyze`
(responder -A) mode, an authorization banner, and loot to git-ignored `loot/`.

Design decisions:
- Read Responder's **stdout** live rather than tailing logs/Responder-Session.log - no
  log-dir discovery, and the pure parser (engines/responder.py) feeds a `run_poison` that
  takes an injectable line source, so tests need no Responder/root/LAN.
- Findings reuse **Category.SMB** (NTLM relay/signing already live there) - **no
  SCHEMA_VERSION bump**, findings.py contract untouched. Emits `netntlm-captured` (HIGH,
  carries `meta["hashes"]` type `netntlmv2`) and `llmnr-nbtns-poisoning-possible` (MEDIUM,
  only when poisoning was active AND a host took the bait).
- Cracking flows through the existing pipeline: `netntlmv2` -> hashcat 5600 / john
  netntlmv2 (crack.py), yielding `credential-cracked` (CRITICAL) unchanged.
- `doctor` gained a `responder` check in its own optional section (not the engine-ready
  count, since poison isn't a scan engine).

Known caveat / follow-up: crack.py's `annotate()` hardcodes `Category.KERBEROS` on
`credential-cracked`, so a cracked NetNTLMv2 credential is mislabeled Kerberos in the
report. Pre-existing; left as-is (a fix also touches the AS-REP/Kerberoast path). Follow-up:
derive that finding's category from the source hash_type. Also still open: stream crack
results to the live graph; ntlmrelayx *relay* mode (NETNTLM.md Phase 2).

## 2026-08-13 - GUI Phase 2: token-gated action channel
redness/actions.py = an Action registry (id/label/node_types/engine, offensive flag) + run_action()
that runs one engine against one target and streams to the bus like a scan (reuses scan's
_emit_finding_graph). Bridge gained GET /actions (serves the catalog) and POST /action (same CSRF
token gate + off-thread dispatch as /scan). Front-end: Graph.onNodeRightClick -> per-node-type
menu -> POST /action; results stream to the graph/log. Phase 2 is READ-ONLY enum (SMB/LDAP/ADCS/
TLS on host/domain nodes); Phase 3 offensive actions register here with offensive=True + gating
(anjaiv's engines). Verified end-to-end in-browser (menu renders, POST 202, action streams back).

## 2026-08-13 - NetNTLMv2 Phase 2: `trigger` link generator (relay dropped)
Phase 2 of docs/NETNTLM.md shipped as `redness trigger`, NOT the ntlmrelayx relay originally
sketched. Rationale: live relay is heavy and far more intrusive (direct access to a
third-party service, AD-mutating attack modes like RBCD/add-computer/ADCS ESC8); we wanted
the simplest useful thing - a forced-authentication lure. `redness/trigger.py` is pure stdlib
string generation: `unc_path()` + html/scf/url builders (lnk deferred - binary) + a FORMATS
registry; `redness trigger --host <us> [--format] [--out]` prints the artifact to stdout or
writes `--out`, with the banner/hints on **stderr** so `> lure.html` redirects cleanly.

It's a helper, not an Engine: it produces an artifact, not Findings - no scan/default_engines
involvement, no doctor check, no network/subprocess. Capture reuses Phase 1 wholesale: the
victim's coerced SMB auth lands in the same Responder listener (run `redness poison` normally)
-> parse_responder_log -> build_findings (`netntlm-captured`) -> crack (`netntlmv2`). So
**findings.py and crack.py are untouched** and no new findings are defined. "Flag if signing
isn't enforced" reuses the existing `smb-signing-not-required` finding via `scan`. Deferred: a
poisoning-off `--capture-only` listen mode on `poison` (needs Kali validation that Responder
captures incoming SMB auth with poisoning disabled).

## 2026-08-13 - Built-in wordlist: auto-crack weak creds by default (opt-out)
Added redness/wordlists.py (BASIC_WORDLIST - ~370 hand-curated weak/default/seasonal
candidates, NOT derived from rockyou or any leaked/licensed list, so no provenance concern).
crack.run_cracking() falls back to it (materialized to loot/_basic_wordlist.txt) when no
--wordlist is given AND a cracker (hashcat/john) is on PATH, so scan/poison auto-crack
egregiously weak passwords with no operator wordlist. This is a **default behavior change**
(cracking was previously off without --wordlist) - but it only fires when a cracker is
installed, so CI/test boxes (no hashcat/john) are unaffected, and it is sub-second (a few
hundred candidates). Explicit --wordlist is unchanged (the built-in is never consulted).
New --no-crack flag on scan+poison hard-disables ALL cracking (forces no wordlist AND
builtin=False), even overriding --wordlist - clearest semantics for a flag named "no crack".
CrackResult.used_builtin drives honest messaging ("via hashcat (built-in wordlist)").
findings.py untouched; poison threads `builtin` through run_poison to run_cracking.

## 2026-08-21 - Category.SECRET for share secret-hunting (SCHEMA_VERSION 1.1.0)
Share secret-hunting (docs/SHAREHUNT.md, ROADMAP Tier 1 #3) emits a new finding class:
`Category.SECRET` = credential material found on readable SMB shares. Bumped
**SCHEMA_VERSION 1.0.0 -> 1.1.0** (additive; a consumer predating it must tolerate an
unknown category - report/graph should default-handle). `scan.py:_node_type` maps
`secret` -> a new `"secret"` graph node type; **GUI coloring/shape for it is Gjoko's
front-end follow-up** (web/), default styling until then.

Because findings.py is the engine<->reporting/graph contract, **this change needs Gjoko's
review before merge**, and must stay compatible with the attack-path graph
(redness/paths.py, PR #33, merged). Findings use a single id `share-secret`
(severity per rule) + `meta["kind"]`; secrets ride in `meta["secrets"]`, mirroring
`meta["hashes"]`: {host, share, path, unc, rule, kind, size, match} - `match` is ALWAYS
masked/truncated (full secrets never enter the report/findings.json; raw files stay in
git-ignored loot/ only).

OPEN (for Gjoko): should a *recovered credential* extracted from a secret get a
distinct shape so paths.py can build attack-path edges - a per-secret `entry["credential"]`
{username, kind, secret_masked} sub-field, or a separate top-level `meta["credentials"]`
list (parallel to meta["hashes"], which crack.py already consumes)? Phase 1 emits only
file-match secrets (no credential field); the shape is forward-compatible either way, so
this does not block the engine.

Update (paths.py now merged): recommended shape is a top-level `meta["credentials"]` list
mirroring `meta["hashes"]` (entries {account, username, domain?, kind, secret_masked,
source}); paths.py consumes it by extending compromised_accounts() to also union those
accounts (a ~3-line change) so a share-recovered credential becomes an `owned` node with a
`valid credential -> domain` edge, exactly like a cracked hash. Still Gjoko's call.

## 2026-08-21 - Share secret-hunting engine: orchestrate nxc spider_plus + pure classifier
Built the share secret-hunting engine (docs/SHAREHUNT.md, ROADMAP Tier 1 #3) - opt-in, NOT
in default_engines(). It orchestrates nxc's `-M spider_plus` module (NOT Snaffler, NOT our
own SMB spider) for the share walk, then applies a pure Snaffler-style classifier:
- Phase 1 (`scan --hunt-secrets`): filename/path/extension rules over the spider_plus JSON
  inventory (DOWNLOAD_FLAG=False - no content read). One `share-secret` finding per hit
  (severity per rule) + an `enum-share-spider` INFO; secrets ride in `meta["secrets"]`.
- Phase 2 (`scan --hunt-content`, more intrusive): downloads candidate files (DOWNLOAD_FLAG=
  True + PATTERN derived from the filename rules + MAX_FILE_SIZE cap) into git-ignored
  `<loot_dir>/sharehunt/<host>/`, then regexes contents (private keys, GPP cpassword, DB
  connection strings, password/api-key assignments, AWS keys).
Redaction is a firm invariant (test-locked): the `match` field only ever holds a masked
snippet (`password=<redacted:14>`), never the raw value - full secrets stay in the git-
ignored loot files. The engine's only impure methods are `_spider` / `_spider_content`
(subprocess + JSON/file walk, validated on Kali); the parser + classifiers + findings are
pure and unit-tested (no nxc/DC). Findings use `Category.SECRET` -> a `secret` graph node
(see the 2026-08-21 schema entry, which still needs Gjoko's review + resolves the open
credential-field question).

## 2026-08-21 - GPP cpassword engine: wrap nxc -M gpp_password, first meta["credentials"] producer
Built the GPP cpassword / SYSVOL-secrets engine (docs/GPP.md, ROADMAP Tier 2 parity).
`redness/engines/gpp.py` `GppEngine` wraps `nxc smb <dc> -M gpp_password` (nxc walks SYSVOL and
decrypts the cpasswords with the Microsoft-published key - decryption, not cracking, so no AES
dependency on our side) and parses its stdout with a pure `parse_gpp_output`. In
default_engines() alongside netexec/ldap/certipy; no-ops without domain creds (needs an authed
SYSVOL read) or without nxc.

Findings: one `gpp-cpassword` CRITICAL per recovered credential, `Category.SECRET` (reuse the
merged secret node type - no schema bump). Unlike sharehunt's redaction, GPP creds are STORED
(account:password in evidence, like `credential-cracked`) - they are discrete usable credentials,
not raw file blobs. Each recovered cred also rides in `meta["credentials"]` - GppEngine is the
FIRST producer of that shape (proposed 2026-08-21 for paths.py), so a recovered GPP cred becomes
an `owned` attack-path node once paths.py's compromised_accounts() unions meta["credentials"]
(Gjoko's ~3-line change). Username is used as-is (GPP creds are often LOCAL/fleet-wide - no
fabricated DOMAIN\ prefix). References: MITRE T1552.006 + MS14-025. Complementary to sharehunt's
`content-gpp-cpassword` rule (which only FLAGS the file; gpp RECOVERS the credential).

## 2026-08-25 - Password spraying: gated CLI command (poison precedent), lockout-safe by refusal
Built lockout-aware password spraying (docs/SPRAY.md, ROADMAP Tier 2 parity). Like `poison`, it
is an opt-in, confirmation-gated CLI command that NEVER runs in `scan` and is NOT in
default_engines() - spraying can lock out accounts (a DoS against the client). Pure parts
(`parse_pass_pol`, `parse_spray_hits`, safety math, `build_findings`) live in
`engines/spray.py` (no Engine subclass, mirroring engines/responder.py); the gated `run_spray`
orchestration lives in `redness/spray.py`, with a single injectable `nxc_run(argv)` boundary.

Orchestration: read `--pass-pol` (+ `nxc ldap --users`) first, compute a safe budget
(`threshold - margin`, margin 1), then spray ONE password `--continue-on-success` (v1; multi-
round deferred). A run is REFUSED unless proven safe. Findings: `spray-hit` HIGH, upgraded to
CRITICAL on a `(Pwn3d!)` admin hit; `password-policy-no-lockout` MEDIUM when threshold==0.
`Category.PASSWORD` (no schema bump). Recovered creds are stored (account:password, like
`credential-cracked`/`gpp`) and ride in `meta["credentials"]` - spray is the SECOND producer of
that shape (after gpp), same paths.py `compromised_accounts()` union pending (Gjoko). Ref MITRE
T1110.003.

Two safety measures beyond the usual `poison`-style gate: (1) overriding a safety refusal
requires BOTH `--force` AND a second, distinct typed "FORCE" confirmation (a `confirm_force`
callback the CLI wires to a prompt `--yes` never skips), so `--force --yes` together can never
silently bypass both checks; (2) the danger banner always prints to stderr even in scripted
mode. Uncredentialed spraying (lockout policy unknown - the most dangerous path) is allowed only
with `--user-file` AND `--force` behind a loud, unmissable warning. Deferred: per-account
`badPwdCount` skipping (needs an `ldap.parse_users` change); primary safety is the budget gate +
one-password-per-run + the confirmation gates.

## 2026-08-26 - Remote-access protocol engines (RDP/WinRM/MSSQL): passive, in the default scan
Added `redness/engines/remote.py` - three nxc-backed engines for the lateral-movement surfaces
the SMB/LDAP/AD CS/TLS engines miss. One module (not three files) because all three share nxc's
`PROTO host port name <body>` line format and the same exposure/access finding shape; parsers
stay pure and unit-tested against captured nxc output (verified the exact banner/`[+]` strings
against NetExec's rdp/winrm/mssql protocols first - RDP prints `(nla:True|False)`, all three
print `[+] dom\user:secret (Pwn3d!)` on a credentialed success).

Key call: these run in `default_engines()`, unlike the gated `poison`/`spray` commands. They are
PASSIVE - connect, read the banner, and (only if the operator supplied creds) try those exact
creds once. No guessing, no lockout risk, nothing written to the target, so they belong in a
normal `scan`. RDP even works fully unauthenticated (NLA + exposure from the banner).

Findings reuse existing categories - NO `SCHEMA_VERSION` bump (still 1.1.0): `Category.CONFIG`
for a misconfig (`rdp-nla-disabled`, MEDIUM) or a reachable-with-creds path (`*-access`),
`Category.ENUM` for plain exposure (`*-exposed`, INFO). Severity ladder: RDP access
MEDIUM/HIGH(admin) - interactive logon; WinRM + MSSQL access HIGH/CRITICAL(admin) - both are
code-exec surfaces (remote PowerShell; xp_cmdshell). No new graph node type - all findings are
host-level (affected == host), so the host node recolors by severity. doctor gains rdp/winrm/
mssql hints (same nxc binary). Access findings do NOT ride `meta["credentials"]` - they confirm
reach with creds we already hold, they do not recover a new credential (unlike spray/gpp).

## 2026-08-27 - Service-discovery dispatch: the "hail-mary" default scan runs only relevant engines
Added `redness/discovery.py` + wired it into `run_scan`. The default scan now runs EVERYTHING
passive, but per host it first does a lightweight TCP connect-scan (stdlib sockets, no nmap dep)
of the ports our engines care about and dispatches only the engines whose service is actually
open ("according to the enumeration and logic"). An `nxc mssql` no longer fires at a host with
no 1433 open; a full-breadth scan stays fast and quiet.

Design: port knowledge lives centrally in `discovery.ENGINE_PORTS` (keyed by `Engine.name`),
NOT as a per-engine attribute - keeps the dispatch logic in one place (orchestration/Gjoko's
lane) and leaves the engine files (Anja's lane) untouched. An engine NOT in ENGINE_PORTS is
never gated (always runs), so unknown or UDP-only engines (e.g. a future SNMP/161 engine, which
a TCP connect-scan cannot see) keep full coverage until they are explicitly added. `open_ports`
takes an injectable `checker` and `run_scan` an injectable `port_scanner`, so all dispatch logic
unit-tests with no real sockets.

This is discovery, not exploitation - a plain TCP connect (nothing sent to the service), well
inside the passive envelope. `--no-discovery` / `run_scan(discover=False)` restores the old
"run every available engine" behaviour. Discovery only decides WHICH engines run; the engines
still own their own findings and graph emission.

## 2026-08-27 - FTP / HTTP(AD) / SNMP engines: broaden coverage, stay on-theme
Added three engines for the protocol coverage gaps (issue #32), each passive and in the default
scan (dispatched by discovery where TCP-visible). All reuse existing categories - no schema bump.

- **FTP** (`engines/ftp.py`, wraps `nxc ftp`): `ftp-anonymous` (MEDIUM, anon login = classic
  unauth foothold), `ftp-exposed` (INFO, banner/version), `ftp-access` (LOW, supplied creds).
  Probes anonymous by default (`-u anonymous -p ''`) when no creds. Verified vs NetExec ftp
  output (`[*] Banner:`, `[+] anonymous: - Anonymous Login!`); FTP has no Pwn3d. Gated on port 21.

- **HTTP** (`engines/http_ad.py`, pure stdlib): deliberately NOT a general web scanner - probes
  only AD-relevant surfaces. `/certsrv` + `/certsrv/certfnsh.asp` -> `adcs-web-enrollment` HIGH
  (Category.ADCS): this is **ESC8**, an NTLM-relay target that ties into the certipy story.
  `/owa` + `/ews` -> `exchange-owa-exposed` LOW; `/` -> `http-exposed` INFO with Server banner.
  HTTPS uses an unverified TLS context (AD web endpoints are self-signed; the TLS engine judges
  the cert). The network fetch is injectable for tests. Gated on ports 80/443.

- **SNMP** (`engines/snmp.py`, wraps net-snmp `snmpwalk`): default community strings.
  `snmp-default-community` HIGH for `public` (read; leaks config/routes/ARP/creds), CRITICAL for
  `private` (usually read-WRITE = device takeover). SNMP is UDP/161, invisible to a TCP
  connect-scan, so it is deliberately NOT in discovery.ENGINE_PORTS (un-gated: runs whenever
  snmpwalk is installed, which is_available() checks). Tool runner injectable for tests.

Rationale for scope: FTP/HTTP/SNMP are common on Windows/appliance estates and each maps to a
real AD path (esp. ESC8). DNP3/ICS-OT was explicitly parked (scope creep - different assessment
domain). See issue #32.

## 2026-08-27 - Phase 3 offensive actions: arm/confirm gating + first three actions
Offensive right-click actions (docs/GUI.md, issue #49) register in `redness/actions.py` with
`offensive=True` and a `handler`; they NEVER run through the read-only `run_action` path
(`run_action` refuses them). Because a POST has no TTY, poison/spray's typed YES/FORCE becomes a
two-step web handshake: `arm(action, target)` issues a single-use, TTL-120s, action+target-bound
`arm_token` (+ a target-specific banner); `execute_armed_action(action, target, tgt: Target, ...)`
runs only against that token AND an `X-Redness-Confirm` header equal to the action id. `--force`
has no analogue here - the confirmation is mandatory, never bypassable.

Safety rails: arming is rate-limited (5 per 300s / 5 min; the 6th within the window is refused),
tokens are single-use and expire, and every arm / execute / refuse / rate-limit is AUDITED
(JSON lines -> `loot/offensive-audit.log`; injectable sink). The two bridge endpoints
(`POST /action/arm`, `POST /action/execute`) + the GUI arm->confirm->execute modal are Gjoko's
`live/` follow-up.

Findings carry `meta["offensive"]=True` + `meta["action"]=<id>` (additive meta - NO findings.py
schema bump; still SCHEMA_VERSION 1.1.0). Recovered material rides the existing shapes:
Kerberoast -> `meta["hashes"]` (feeds crack.py); secretsdump/DCSync NT hashes ->
`meta["credentials"]` with `kind:"nthash"` (stored, like credential-cracked; feeds the pending
paths.py compromised_accounts() union). The three actions:
- **kerberoast-user** (user node) - HIGH; reuses ldap.parse_kerberoast, filters to the principal.
- **secretsdump-target** (host node) - CRITICAL; `nxc smb --sam --lsa` local SAM/LSA on one host.
- **dcsync-user** (user node) - targeted one principal via `nxc -M drsuapi -o USER=<account>`.
  **Severity CRITICAL for krbtgt (RID 502) or builtin Administrator (RID 500), else HIGH** (broader
  Domain Admins membership needs enum/BloodHound - out of scope). The confirm banner is
  target-specific: **krbtgt gets an explicit Golden Ticket warning** ("...enables Golden Ticket
  forgery, full and persistent domain compromise; extremely loud, will almost certainly trigger
  SOC/EDR") vs a generic "replicates the password hash for '<account>'" for regular accounts;
  secretsdump's is lighter (one host's local SAM/LSA). A shared parse_secretsdump handles the
  `account:rid:LM:NT:::` format (dedupe, drops blank-password hashes). Deferred: a domain-wide
  `dcsync` (all accounts), AS-REP-roast, PtH-exec, ADCS req/auth.

Caveat: `nxc -M drsuapi -o USER=` could not be introspected offline (nxc not installed) - verify
against real nxc; the format-based parser/findings are unaffected.

## 2026-08-27 - Delegation abuse enum: one engine, balanced severities, AD CS cross-engine wiring
Delegation abuse enumeration (docs/DELEGATION.md, ROADMAP Tier 2) is a single `DelegationEngine`
(engines/delegation.py, mirroring ldap.py: one engine, several `nxc ldap` reads, pure parsers),
in `default_engines()`, no-ops without domain creds/nxc. Findings use `Category.LDAP` (reuse, no
schema bump) and carry descriptive `meta["delegation"]` but **no `meta["credentials"]`** - this
is enumeration, not credential recovery.

Severity model (balanced to avoid alert fatigue - informational baseline, CRITICAL only for the
urgent cases): unconstrained = **HIGH on non-DC** (the attack primitive), **INFO on a DC**
(expected - DCs legitimately have it; a separate `delegation-unconstrained-dc` finding for
context). constrained = HIGH, **CRITICAL only with protocol transition**. RBCD = HIGH. MAQ > 0 =
**INFO** baseline. gMSA readable + shadow-credentials = HIGH.

AD CS cross-engine wiring (no duplicated ADCS detection): the MAQ finding escalates to CRITICAL
only when an AD CS ESC path was also found this scan. Rather than re-detect ADCS inside the
delegation engine, `run_scan` passes an `adcs_present` bool to any engine exposing
`wants_adcs_context = True` (duck-typed - no isinstance/import coupling), computed as
`any(f.category is Category.ADCS for f in report.findings)` at the point that engine runs.
`DelegationEngine` is ordered **after** `CertipyEngine` in `default_engines()` so certipy's
findings are present first; the bool flows through `build_findings(adcs_present=...)`. This is a
reusable pattern for any future engine that needs cross-engine context without owning the
detection.

Follow-ups (deferred, tracked):
- **nxc flag/module names unverified offline** (nxc not installable in the sandbox): verify
  `--trusted-for-delegation` / `--find-delegation` / `-M maq` / `-M gmsa` against real nxc and add
  captured samples to tests/ if formats differ. The pure parsers are the tested core, so the fix
  is localized to the thin invokers.
- **shadow-creds invocation deferred**: `parse_shadow_creds` is done + tested, but no verified nxc
  module dumps `msDS-KeyCredentialLink`, so `run` passes `shadow=None` (we do not invent a flag).
  Wire a verified source later.
- **DC detection is best-effort**: UAC SERVER_TRUST bit when present, else a hostname-derived name
  hint; against a bare IP without UAC a DC could mis-classify as non-DC (HIGH vs INFO).
- **Attack-path edges are NOT built here**: unconstrained-host -> DA (and constrained/RBCD ->
  target) are `paths.py`'s job (Gjoko) and need a `meta` contract agreed first; findings carry
  `meta["delegation"]={kind,to}` for that future consumption. Contract-first, same as crack.py.
## 2026-08-27 - Coercion: gated `coerce` command (PetitPotam/PrinterBug/DFSCoerce)
Active RPC forced-authentication, the machine-side sibling of `trigger` (issue #49 Tier-2).
Wraps nxc `-M coerce_plus -o LISTENER=<us>`; pure parser/argv/findings in `engines/coerce.py`,
gated orchestration in `redness/coerce.py` (mirrors poison.py/spray.py). It only TRIGGERS the
auth - a separately-run `redness poison` (Responder) listener captures it via the existing
`netntlm-captured` -> crack pipeline; `coerce` recovers no credential itself. Per-vector
`coercion-*` findings, `Category.CONFIG` (no schema bump), CRITICAL on a DC / HIGH elsewhere.
See docs/COERCION.md.

Design decisions from the pre-build security review (agreed with the repo owner):
- **DC validation, not DC-restriction.** Coercion is refused unless the target looks like a DC
  (AD LDAP/389-636 is DC-only), overridable with `--target-not-dc-ok` (findings then HIGH). This
  catches fat-finger/wrong-host typos without blocking legitimate non-DC targets. The check is an
  injectable `dc_check` callable (LDAP port probe by default) so `run_coerce` tests with no DC.
- **Double-gate mirrors `spray`.** Normal (credentialed) run = banner + typed `YES`. The riskier
  **uncredentialed** path (no creds, relies on an unpatched target) is a safety refusal overridden
  only by BOTH `--force` AND a second, distinct typed `FORCE` confirmation that `--yes` never
  skips. Coercion has no lockout math, so `--force` guards the uncredentialed path (spray's guards
  the lockout budget) - same shape, different hazard. CLI double-gate, NOT the GUI `/action`
  arm/confirm channel (this is an operator-run network command, not a right-click node action).
- **Method selection.** `--method` default `all` (full coverage for the report - "which vectors
  are open" IS the finding); a single method (petitpotam/printerbug/dfscoerce/shadowcoerce) is
  selectable to limit detection noise.
- **Audit logging.** Every attempt - per method result AND every refusal - is appended to
  `loot/coerce_audit.log` (git-ignored) for post-engagement blue-team de-confliction (ROADMAP
  Tier-3 precedent). A unified cross-command audit log (with offensive actions) stays Gjoko's
  Tier-3 lane; this is the forward-compatible local start.
- **Stateless RPC = no cleanup.** PetitPotam (MS-EFSR), PrinterBug (MS-RPRN), ShadowCoerce
  (MS-FSRVP) are transient calls that leave no persistent state on the target; DFSCoerce
  (MS-DFSNM) is the one vector calling DFS-management RPCs (NetrDfsAddStdRoot/RemoveStdRoot) - the
  coercion generally errors after the auth fires so no DFS root is created, but it is the vector
  to watch; verify coerce_plus's method on Kali. All vectors leave an auth/RPC event in the
  target's logs (detection footprint, stated in the banner) - but nothing to clean up.
- **No rate limiting** (no lockout/DoS risk on the target; a CLI invocation is one deliberate
  RPC per method, not an automatable channel like the HTTP arm endpoint).

Carry-forward follow-ups: `coerce_plus` output lines + option keys (`LISTENER`/`METHOD`) are
unverified in-sandbox (nxc has no py3.12 wheel) - the test fixture is the source of truth, verify
on Kali; the poisoning-off `poison --capture-only` listen mode (docs/NETNTLM.md) would be the
cleaner pairing for both `trigger` and `coerce`; an integrated `--capture` (coerce starts its own
listener) was deliberately deferred to keep the trigger/poison capture seam clean.

## 2026-08-31 - Offensive /action HTTP framework: arm/execute endpoints + --enable-offensive gate
Wired the Phase-3 offensive actions (built in #50) into the live bridge so the GUI can actually
trigger them - the plumbing half of the #49 split (Gjoko's lane). Two new endpoints in
`redness/live/bridge.py`: `POST /action/arm` (synchronous, returns the single-use `arm_token` +
banner from `actions.arm`) and `POST /action/execute` (async, runs `execute_armed_action` on a
worker thread; the confirmation rides an `X-Redness-Confirm` header, never the body).

Defence in depth beyond the read-only channel (contract answer #5 on #49):
- **Off by default.** The offensive channel exists only when the operator launches
  `redness gui|live --enable-offensive`.
- **Separate, more-privileged token.** Enabling mints a distinct `offensive_token`
  (`secrets.token_urlsafe(24)`) that is **NOT injected into the page** - it is printed to the
  console (stderr), and the operator pastes it into the GUI. So page access alone (even with the
  read CSRF token) can never fire an offensive action; you also need terminal access. Both
  offensive endpoints require `X-Redness-Offensive: <token>`; neither accepts the read token.
- **Loopback only.** `LiveServer(enable_offensive=True)` raises unless the bind host is loopback
  (`_is_loopback`) - the offensive channel refuses `0.0.0.0`.
- **Hidden until armed.** `GET /actions` filters out `offensive=True` entries unless the channel
  is enabled, so the GUI shows them (in red) only when unlocked.
Audit/rate-limit/single-use/TTL all live in `actions.py` (from #50) and are unchanged. GUI flow
(web/index.html): right-click an offensive action -> arm -> `window.confirm(banner)` -> execute
with the arm_token + confirm header. Tests: 8 new (loopback guard, token gating, 403-when-disabled,
arm 200 / 429-on-rate, execute routing with the confirm header, catalog show/hide) - 249 total.

## 2026-08-31 - NTLM relay map (derivation) + live-graph "Replay path to DA" cinematic
Two paired features - a capability and its visualization.

Relay map (`redness/relay.py`, mirrors paths.py): correlates findings a scan already produced
into the concrete NTLM relay chains an operator would run. ESC8 (`adcs-web-enrollment`) ->
CRITICAL `ntlm-relay-to-adcs` (coerce a DC, relay to /certsrv, DC cert -> DCSync -> Domain
Admin); `smb-signing-not-required` -> HIGH `ntlm-relay-to-smb`. `coercion-*` findings (from the
`coerce` command) supply confirmed victims; absent those it derives from a generic "a coercible
DC", since ESC8 + missing signing are relay-able on their own. Findings are `Category.CONFIG`
(no schema bump). Emission draws a central `NTLM Relay` node with coercion fan-in and relay
fan-out (ESC8 CA -> Domain Admin goal; signing-off hosts). Wired into `run_scan` AFTER
`emit_attack_paths` so the goal node exists; `emit_relay_paths` also appends its findings to the
report. Pure derivation, no new tool; unit-tested with synthetic Reports.

Graph glow-up (`live/web/index.html`): a "Replay path to DA" button plays the attack+relay edges
from entry point toward the goal (order = reverse-BFS depth from the goal node), lighting each
edge bright white + thick, emitting particle bursts (`Graph.emitParticles`), flying the camera to
each hop, then pulsing the Domain Admin node - the "how we'd own you" story for demos/report
screenshots. Added the `relay` node type/colour + legend rows. A `highlightLinks` set drives the
transient link styling; `refreshLinks()` re-applies the accessors. Verified in-browser against
`redness live --demo` (no console errors).

## 2026-09-04 - Passive link-local discovery (`listen`): the broadcast/multicast layer
Added `redness/mcast.py` + a `listen` command for the passive discovery layer the active scan
misses: the multicast/broadcast "chatter" a WiFi/LAN segment leaks. Pure-Python sockets (no new
dependency), parsing kept pure and separate from the socket loop (unit-tested against hand-built
packets; NetBIOS decode grounded on the RFC1001 'FRED' example).

Protocols: mDNS (5353/224.0.0.251), LLMNR (5355/224.0.0.252), NBT-NS (137 broadcast), SSDP
(1900/239.255.255.250). Fully **passive by default** (sends nothing); `--active` fires a single
SSDP M-SEARCH. Sockets that can't bind (privileges / port in use - NBT-NS 137 needs admin on
some OSes) are skipped with a STATUS, never fatal.

Findings reuse ENUM/CONFIG - no schema bump: `mcast-inventory` (INFO, hosts/devices seen with no
active scanning), `ssdp-upnp-devices` (INFO), `llmnr-nbtns-poisonable` (MEDIUM - name resolution
falling back to LLMNR/NBT-NS is spoofable; feeds `poison`), `wpad-lookup-observed` (HIGH - a
`wpad` lookup means WPAD spoofing -> credential theft). Graph: discovered devices hang off a
`link-local segment` node. Complements the active TCP connect-scan (catches printers/IoT/Apple/
media the port-scan misses) and ties into the existing `poison`/`trigger` NetNTLM story. Segment-
local + observes other hosts' traffic, so authorized-scope only.

## 2026-09-04 - Relay map gains poisoning as a source; `scan --listen` folds in the passive sweep
Wired `listen`'s poisonable findings into the relay map. A relay needs two things: a target that
does not enforce signing/EPA (SMB signing-off or ESC8), and a way to OBTAIN NTLM auth to relay.
We already modeled coercion as that source; LLMNR/NBT-NS poisoning (surfaced by `listen`, finding
`llmnr-nbtns-poisonable` / `wpad-lookup-observed`) is the other. `relay.poisoning_present()` gates
it: when present alongside a relay target, `emit_relay_paths` draws a `LLMNR/NBT-NS poison` node
into the `NTLM Relay` node, and `build_relay_findings` notes the poisoning source in the ESC8/SMB
relay findings' impact + meta (`poison_source`). Pure derivation, no schema change.

Because the two live in separate commands (`scan` vs `listen`), `run_scan` gained `listen_secs`
(CLI `scan --listen SECONDS`): an optional passive sweep whose findings are merged into the scan
report BEFORE the relay derivation, so a single command produces a relay map that connects
poison -> relay -> target -> Domain Admin. `listen(emit_done=False)` when embedded so it does not
prematurely signal DONE.

## 2026-09-23 - Retest diff (`redness diff`): the retest deliverable
Added `redness/diff.py` + a `diff` command to compare two `findings.json` (baseline vs current)
and classify every finding as new / fixed / unchanged / severity-changed - the standard retest
artifact a client expects after a remediation round. Pure over the findings model (no I/O, no
tools), so it unit-tests against hand-built Reports and can also feed a future retest report.

Finding identity is `(id, sorted(affected))` - the same stable id on the same host/account is the
same issue; the same id on a *different* asset is correctly a new finding + a fixed one, not an
unchanged one. Severity moves are their own bucket (records the old severity) so a downgrade reads
differently from a fix. `DiffResult.regressed()` is true on any new finding or severity increase,
and `cmd_diff` exits 2 when regressed so a retest can gate CI/scripts. No schema change; reuses
`Report.from_json` / `Finding.to_dict`.

## 2026-09-23 - Unified audit log (`loot/audit.log`)
Added `redness/audit.py`: one timestamped JSONL timeline of every sensitive/active operation, so
blue teams and our own de-confliction have a single file to answer "what did REDNESS do, when,
against what?" `audit.record(event, *, loot_dir="loot", sink=None, **fields)` writes
`{ts (ISO8601 UTC), event, **fields}` to `loot/audit.log`; an injected `sink` (tests, or a future
bridge capture) gets the same dict instead of disk. Best-effort like the EventBus - an unwritable
loot/ never breaks a run.

Wiring: `scan` (scan-start/scan-done), `poison` (poison-start/poison-done), `spray`
(spray-start/spray-done) now audit where they had nothing; offensive right-click actions
(`actions.py`) route their existing arm/execute/refuse/result through it (retired the separate
`offensive-audit.log`); `coerce` writes a structured `coerce` record to the unified log while
keeping its detailed per-vector `coerce_audit.log` sidecar (its format is human-friendly and
tested). Params only, never secrets: booleans like `credentialed`, counts, iface/target - no
passwords or hashes. loot/ is gitignored, so the log never reaches git.

## 2026-09-23 - Self-contained HTML report (`--html`) + graph capture in report.meta
Added `redness/report/html_report.py`: a single offline `.html` that mirrors the `.docx` content
(severity summary + every finding with impact/remediation/evidence/references) AND embeds the same
3D attack-graph the live GUI shows. It inlines the already-vendored 3d-force-graph bundle (MIT,
bundles three) so the file needs no server and no network - a client just opens it, spins the
graph, watches attack paths light up, and reads the findings. Colours/link styling are kept in
sync with `live/web/index.html`. No new dependency (reuses the vendored lib); no schema change.

To make the report an *exact* mirror, `run_scan` now captures the live node/edge event stream into
`report.meta["graph"]` via `redness/graphmodel.GraphCollector` (an internal EventBus is used even
without `--live`, so the capture is unconditional; the collector is unsubscribed before return).
`report.meta` is free-form, so this is not a findings-contract change and needs no SCHEMA_VERSION
bump. For a saved report that predates this (or the `report` command on an old findings.json),
`graphmodel.graph_from_report` reconstructs a graph from the findings on a deep copy (the relay
derivation appends findings, so we never mutate the caller's report just to draw it); affected
assets anchor to the domain while the attack-path/relay overlay stays exact. `graph_for(report)`
picks the captured graph when present, else the reconstruction. Wired to `scan --html` and
`report --html`.

## 2026-09-23 - Cinematic auto-tour (GUI + HTML report) [v1.34.0]
Turned the manual "Replay path to DA" button into a self-playing cinematic. On scan-complete
(live GUI, on the DONE event) or after the layout settles (HTML report, ~2.8s), if an attack path
to a Domain Admin goal exists, the camera plays the story automatically: an establishing wide
shot, then it flies the attack/relay edges entry -> owned -> Domain Admin in path order (BFS depth
from the goal, farthest-first), lighting each edge with a particle burst and a trail-following
camera pose (`tourCamFor`: sit behind the target along the direction just travelled), pulsing
owned nodes as they're reached, and finishing with a goal pulse + slow orbit before zooming back
to fit.

OPSEC/UX: the tour is one-shot (`tourPlayed`) and yields to the operator - any pointerdown/wheel on
the renderer cancels an in-progress tour and suppresses the auto-play (their intent beats the
show); a top-center toast says it's running and "click/drag to skip"; the Replay button still
triggers it on demand. Shared across both surfaces: the live `redness/live/web/index.html` and the
self-contained HTML report (`redness/report/html_report.py`) run the same choreography, so the
report a client opens performs the same "how we'd own you" walk offline. Pure front-end (camera +
link highlight + particles); no findings-contract or schema change. GUI version 1.33.7 -> 1.34.0.

## 2026-09-23 - Compromise-spread shockwaves (GUI + HTML report)
Made domain takeover read as a visual cascade. A reusable `shockRing(node, colour, dur, maxScale)`
adds a short-lived expanding+fading wireframe ring built from the node mesh's own three (its
`.constructor`), marked `__shock` so it is independent of the discovery flash's `__ring`/`__flashing`
guard - waves stack and coexist with a right-click flash. `spreadWave()` BFS-walks the compromise
outward from every owned node along the attack edges: it erupts a red ring at the owned origins,
then for each hop emits particles along the outgoing attack edges and, after the pulse travels
(~520ms), rings the newly-reached nodes (orange while spreading, gold + bigger when it reaches the
Domain Admin goal). An ambient interval (~4.2s) launches a wave whenever an owned node exists, and
it is gated on the tour's `touring` flag so the cinematic auto-tour and the shockwaves never run at
once. Shared verbatim (modulo the two files' variable names) between the live
`redness/live/web/index.html` and the self-contained HTML report (`redness/report/html_report.py`),
so a client's offline report shows the same cascade. Pure front-end (ring meshes + particles); no
findings-contract or schema change. Verified both surfaces in-browser (rings cascade, gold burst at
the goal, no console errors).

## 2026-09-23 - Severity as physics (GUI + HTML report) [v1.35.0]
Made a node's worst-affecting severity drive its physical presence, so the eye is pulled to the
most critical findings without reading a single label. Three coupled effects, keyed by severity
(SEV_SIZE / SEV_AMP / SEV_SPD / SEV_PULL):
  - **Size:** `baseVal(n)` adds a severity term to the type-based node size (critical +4.5 ... info
    +0), so a critical node visibly swells.
  - **Throb:** the ambient breathing loop now breathes every node with a finding, amplitude AND
    speed scaling with severity (critical throbs hard + fast); owned/goal keep a breathing floor so
    the compromise state stays alive.
  - **Layout force:** a custom d3 force (`Graph.d3Force('severity', ...)`) pulls each node toward
    the origin proportional to its severity weight (gentle, 0.09 * alpha * weight), so criticals
    gravitate inward and cluster while low/info drift outward. It biases the layout, it does not
    collapse it (charge/link still shape the graph).
Live uses the streamed `worstSev` map; the HTML report reads the `sev` baked onto each graph node
(`_sev_by_node`), so both surfaces behave identically. The report's finale `pulse()` now sets
`__burst` so the severity-throb loop yields to it (no size fight). Pure front-end; no
findings-contract or schema change. Verified both surfaces in-browser (criticals larger + central,
no console errors). GUI 1.34.0 -> 1.35.0.

## 2026-09-23 - Depth & atmosphere: fake-bloom glow + starfield vignette (GUI + HTML report)
Pushed the graph from "wireframe demo" toward "ops console" within the hard constraint that we
cannot load external three.js addons (CSP on the live page + the HTML report must stay a single
self-contained file) and the vendored 3d-force-graph bundle ships NO post-processing bloom pass
(grep: no UnrealBloomPass) and does not expose THREE (so Fog/Sprite/Points classes are
unreachable). Two effects, both built only from primitives reachable via a node mesh's own
constructors:
  - **Fake bloom:** a per-node additive-blended halo sphere (a second child of the shell, radius
    ~1.42x, `material.blending = 2` = AdditiveBlending, no depthWrite) that bleeds light outward.
    Opacity scales with severity (SEV_GLOW; owned/goal get a floor) so the critical nodes glow the
    hardest - reinforcing the severity-as-physics cue. A uniform sphere can't do gradient falloff
    (that needs a sprite/shader we can't reach), so values are tuned low to read as a glow, not a
    disc. Maintained in the same 400ms `_ensureCore` pass as the glowing core.
  - **Atmosphere:** the WebGL background is set transparent (`backgroundColor('rgba(0,0,0,0)')`) and
    a CSS layer behind it paints a sparse starfield (layered 1px radial-gradients) over a
    centre-lit vignette (radial-gradient) - depth and mood with zero GPU cost and no post-process.
Live reads `worstSev`; the report reads the `sev` baked onto each node. Pure front-end; no
findings-contract or schema change. Verified both surfaces in-browser (glowing orbs, vignette
depth, no console errors). Kept under GUI v1.35.0 (same in-progress animation version).

## 2026-09-28 - Delegation -> attack-path edges (unconstrained non-DC; RBCD deferred)
Realizes the contract deferred in the 2026-08-27 delegation entry ("attack-path edges are
paths.py's job, meta contract first"). `paths.py:delegation_edges()` turns `delegation-unconstrained`
(HIGH, non-DC) findings into attack-path edges to the `Domain Admin` goal node, wired into
`derive_attack_edges` so they flow through the existing graph + the GUI's client-side reachability
walk (`links.filter(l => l.attack)` BFS). `delegation-unconstrained-dc` (INFO - a DC legitimately
delegating) is ignored. Edges are `potential=True`: a preconditioned lead (you must gain SYSTEM on
the host first), drawn dashed, marking nothing `owned` - so it never fabricates a proven path to DA.
Backend-only: reuses the existing `AttackEdge`/EDGE-event contract that both the live GUI and
graphmodel.py already render generically - no findings.py, GUI, or schema change. Issue #60 option 3.

RBCD deferred (deliberately). Building `rbcd_edges()` offline is unsafe: `delegation-rbcd`'s
`meta["to"]` is a list of SPNs (not host node-ids), RBCD's LDAP attribute
(msDS-AllowedToActOnBehalfOfOtherIdentity) is the *inverse* of constrained delegation so the edge
direction is likely principal->resource (not the account->to first sketched), and the
`nxc --find-delegation` output the parser depends on is unverified offline. A wrong-direction edge
corrupts the path-to-DA story, so it waits for the real-nxc Kali verification pass. When built:
MAQ>0 double-guard (only when a machine-account-quota maq>0 finding is also present), SPN->host
normalization, known-host guard (both endpoints already graph nodes), principal->resource direction.
Correct direction > completeness. Contract-first, same as crack.py.

## 2026-10-06 - Category.ICS: OT field-protocol pack (SCHEMA_VERSION 1.2.0)
First expansion beyond AD: enumerate industrial control systems (OT). Contract-first, so this is
the one deliberate change to findings.py.

**SCHEMA_VERSION 1.1.0 -> 1.2.0** (additive): new `Category.ICS` for OT/ICS findings. A consumer
predating it must tolerate an unknown category string (the report/graph already render generically
by severity, so nothing breaks). ICS findings carry `meta["protocol"]`, `meta["purdue"]` (Purdue
model level 0-3), and `meta["device"]` (vendor/product/revision/serial) when identity was read.

**Engines (read-only, single request each):** `engines/enip.py` (EtherNet/IP List Identity, TCP
44818), `engines/modbus.py` (Modbus Read Device Identification, TCP 502), `engines/bacnet.py`
(BACnet Who-Is/I-Am, UDP 47808). Shared helpers + the exposure/inventory finding builder live in
`engines/ics_common.py`. Pure parsers (struct unpacking of each wire format) + injected socket
probes, unit-tested against hand-built packets; a real-socket smoke confirmed the live path.

**OT-safe by construction (the whole pitch):** each engine sends ONE read-only identity request -
never writes a coil/register/point or changes controller state. The pack is **opt-in** (`scan
--ics`), not in `default_engines()`, because touching fragile OT is an explicit scope decision; the
TCP engines are **port-gated** by discovery (`ENGINE_PORTS` gains enip/modbus; BACnet is UDP so it
is un-gated like SNMP). The louder enumeration tiers (Modbus unit-id sweep, DNP3 address scan, HART
wireless roster) are deferred behind their own future opt-in. Standard finding is `*-exposed`
(unauthenticated control protocol reachable) + an INFO `*-device-identity` inventory. See
docs/ICS.md.

**Deferred (next):** DNP3 (needs the DNP3 CRC-16) and HART-IP engines; OT graph node types
(plc/rtu/gateway/field-device) grouped by Purdue level; and an `IT -> controller -> Process Impact`
attack path (the OT analog of path-to-DA) in a new ot.py mirroring paths.py/relay.py. Longer-term
non-AD directions raised with this: printers, IoT (MQTT/CoAP), capture integration
(Wireshark/Stratoshark), and wireless detection.

## 2026-10-07 - ICS pack: DNP3 + HART-IP engines (no schema change; still 1.2.0)
Extended the OT pack (Category.ICS, 1.2.0) to the SCADA/process layer. No findings-contract change
- reuses the exposure/inventory shape from ics_common.py. `engines/dnp3.py`: a read-only data-link
Request Link Status (func 0x09) to the self-address 0xFFFC; includes the DNP3 CRC-16 (reflected
poly 0xA6BC, final complement). A listening TCP/20000 is `dnp3-exposed`; a Link Status reply adds
`dnp3-outstation` with the discovered outstation/master addresses. `engines/hartip.py`: a read-only
HART-IP Session Initiate; a listening TCP/5094 (reply or not) is `hart-ip-exposed`.

Both use a new `ics_common.tcp_connect` that returns (connected, reply) so a listening port
(exposure) is distinguished from a protocol confirmation (reply) - no false negatives when an
outstation only answers to its specific address or a gateway needs a full session. Full device
identity (DNP3 Group 0 device attributes; HART Command 0 identity + the gateway's field-device
roster) and the DNP3 outstation-address scan / Modbus unit-id sweep are deliberately deferred to
the gated enumeration tier + a real-device verify pass, because they ride the application/session
layer and public captures are scarce - correctness over completeness, same as RBCD. Both engines
are opt-in (`scan --ics`) and port-gated (ENGINE_PORTS gains dnp3 20000, hart-ip 5094). Parsers
unit-tested against hand-built frames + a real-socket smoke.

## 2026-10-07 - OT graph + Process Impact attack path (ot.py)
The OT analog of path-to-Domain-Admin, so the ICS pack has a visual story in the graph + report.
`redness/ot.py` mirrors paths.py/relay.py: pure derivation from the ICS findings, separate from
emission. No findings-contract change (the one derived finding, `ot-it-segmentation`, is
Category.ICS, already 1.2.0).

Two derivations. (1) **Process Impact** - every exposed OT controller draws a dashed
`controller -> Process Impact` edge (`potential=True`: the capability is proven by exposure, the
impact is not exercised) to a synthetic `Process Impact` goal node (graph type `process`). (2)
**IT/OT segmentation failure** - when one scan produced both IT/AD findings (SMB/LDAP/ADCS/... not
ENUM) and OT controllers, `IT / Enterprise -> controller` is drawn solid (proven reachability) and
an `ot-it-segmentation` CRITICAL finding is added. So the story reads
`IT / Enterprise -> controller -> Process Impact`, the exact shape of `entry -> owned -> DA`.

Wired after emit_relay_paths in run_scan (appends the finding to the real report) and in
graphmodel.graph_from_report (on the deep copy, so an old findings.json re-derives without
mutating the caller). Each OT host is re-typed to its controller role (plc/rtu/gateway/controller
by protocol + Purdue level); impact techniques reference MITRE ATT&CK for ICS (T0831/T0836/T0835).

GUI + HTML report: new TYPE_COLOR entries (plc/rtu/gateway/controller amber/orange, Process Impact
magenta), a `GOAL_TYPES` set so the auto-tour, replay, sizing, breathing and shockwave treat
`process` as a goal exactly like `goal`, `addNode` upgrades a generic host to its OT type, and
legend rows for OT controller + Process Impact. Verified both surfaces in-browser (OT nodes +
Process Impact render, normal AD path unaffected, no console errors). Next: the gated enumeration
tier (DNP3 Group 0 / HART roster / address+unit sweeps) on a real-device verify pass.

## 2026-10-07 - Category.IOT + Category.SERVICE (SCHEMA_VERSION 1.3.0); MQTT + CoAP
Expanding past OT toward a general network-PT tool. Contract-first: **SCHEMA_VERSION 1.2.0 -> 1.3.0**
(additive) adds `Category.IOT` (MQTT/CoAP) and `Category.SERVICE` (exposed unauthenticated
services - used by the next batch: Redis/Mongo/Elasticsearch/Memcached/printers). Both additive; a
pre-1.3.0 consumer tolerates the unknown category (render is generic).

`engines/mqtt.py`: read-only anonymous MQTT 3.1.1 CONNECT; `mqtt-anonymous` (HIGH) when the broker
accepts a no-credential connect (anyone can subscribe to `#`), else `mqtt-exposed` (INFO). We do
NOT subscribe/read topics (gated follow-on). `engines/coap.py`: read-only CoAP GET
/.well-known/core; `coap-exposed` (MEDIUM) with the resource list. Both in the default scan - MQTT
port-gated (TCP 1883), CoAP un-gated (UDP 5683, one GET per host like SNMP/BACnet). Pure parsers
unit-tested + real-socket smoke. These are standard network-service checks, so default (not opt-in
like the fragile OT pack). See docs/IOT.md.

## 2026-10-07 - Exposed-service engines (Category.SERVICE; no new schema bump)
Redis / MongoDB / Elasticsearch / Memcached / printer(IPP) in `engines/netsvc.py` - the classic
unauthenticated-service findings, making REDNESS a general network-PT tool. Reuses `Category.SERVICE`
(added with 1.3.0), so no schema change. Each sends ONE read-only probe and reports reachable vs
reachable-without-auth: Redis INFO (redis-unauth CRITICAL when INFO answers with no auth, else
redis-exposed), Mongo listDatabases OP_QUERY (byte-scan the OP_REPLY for the `databases` marker ->
mongodb-no-auth CRITICAL), Elasticsearch GET / (elasticsearch-unauth HIGH on a 200 cluster doc),
Memcached stats (memcached-exposed HIGH; no auth by design), printer HTTP banner on 631
(printer-exposed MEDIUM). All in the default scan, port-gated by discovery (6379/27017/9200/11211/
631 added to ENGINE_PORTS). Read-only: no data is dumped and nothing is written - keyspace/collection
sampling and full IPP Get-Printer-Attributes are deferred to a gated tier. Pure parsers over a raw
HTTP helper + injected probes; unit-tested + real-socket smoke. See docs/SERVICES.md.

## 2026-10-07 - OT enumeration tier (scan --ics-enum)
The gated, louder OT tier. `engines/ics_enum.py` reuses the already-tested parsers:
`ModbusSweepEngine` sweeps Modbus unit ids (default 1..16) to map serial RTUs behind a Modbus/TCP
gateway (`modbus-gateway-units` INFO with per-unit identity), and `Dnp3ScanEngine` sends Request
Link Status across outstation addresses (default self-address + common addrs) to enumerate a DNP3
segment (`dnp3-segment` INFO with the outstation addresses). Still read-only (identity / link
status only, never writes a point), but a broad sweep can upset fragile outstations, so it lives
behind its own opt-in `--ics-enum` (implies --ics) with a loud stderr warning; ranges widen via the
constructor. In `ics_engines(enum=True)` the single Modbus/DNP3 engines are swapped for the sweep
variants. No schema change. Still deferred to a real-device verify pass: DNP3 Group 0 device
attributes and the HART-IP field-device roster (application/session layer, scarce captures).

## 2026-10-07 - Passive capture (tshark) + wireless (netsh/nmcli); no schema change
Two passive-recon surfaces, orchestrating native tools (no reimplementation), reusing existing
categories so no schema bump. `redness/capture.py` + `redness capture`: drives tshark over a pcap
or a live interface and parses its own taps - `-z credentials` -> `cleartext-credentials`
(CRITICAL, Category.PASSWORD) and `-z io,phs` -> `cleartext-protocols` (MEDIUM, Category.CONFIG).
`redness/wireless.py` + `redness wifi`: drives `netsh wlan show networks` (Windows) / `nmcli dev
wifi` (Linux) and flags open (`wireless-open` MEDIUM) and weak WEP/WPA1/TKIP
(`wireless-weak-encryption` HIGH) networks + an inventory, all Category.CONFIG.

Both read-only (analyze authorized traffic; list visible SSIDs - no transmit/deauth/crack). The
tested core is the pure parsers over captured tshark/netsh/nmcli output; the tool argv is
best-effort and flagged for a field-verify pass (same honest-leftover pattern as the nxc flags).
Deferred: Stratoshark (syscall/log capture), pcad endpoint inventory, BSSID geolocation.

## 2026-10-07 - SSH crypto/version audit (Category.CONFIG; no schema change)
`engines/ssh_audit.py` reads the SSH identification banner and the server's unauthenticated
SSH_MSG_KEXINIT (the algorithm offer) and flags weak key-exchange (SHA-1 / group1/14-sha1), ciphers
(CBC modes / 3des / arcfour / blowfish / cast128), MACs (md5 / sha1 / -96 / umac-64) and host-key
types (ssh-rsa SHA-1 sig / ssh-dss). Read-only: never authenticates, just reads the banner + the
KEXINIT every client receives. `ssh-server` (INFO banner) + `ssh-weak-crypto` (MEDIUM). Pure
parsers (banner regex + KEXINIT name-list layout) unit-tested + real-socket smoke; in the default
scan, port-gated to TCP/22. No schema change (reuses Category.CONFIG).

## 2026-10-07 - World-map / Risk-style territory view (live GUI, experimental v1)
A second layout mode for the live graph, toggled with "Map view" (default stays the organic force
graph). Instead of a force-directed cloud, nodes land in fixed TERRITORIES by type - continents:
Directory (AD node types), Compromise (owned/goal/relay), OT/ICS (plc/rtu/gateway/controller/
process), and Other - arranged across a tilted board. A freshly discovered node WOBBLES into its
slot (elastic-out spring on fx/fy/fz, with x/y/z set directly so a cooled sim still renders it);
attack edges arc high over the board like Risk connection lines. Territory "discs" are flattened
spheres (scale.y small) built from the node mesh constructors and added to Graph.scene(); the
camera tilts to a board perspective.

Implementation notes: entering map mode pins every node via fx/fy/fz and calls d3ReheatSimulation
so the fixed positions take effect; the auto-tour and idle-drift are suppressed while in map mode;
exiting clears fx/fy/fz, removes the discs, and reheats to resume the organic graph. Golden-angle
phyllotaxis spreads nodes within a territory. Pure front-end (index.html); no contract/schema
change. v1 verified in-browser (nodes spread to territories, arcs span the board, toggle back is
clean, no console errors). Follow-ons: territory labels, OT/IoT/service node typing so those get
their own territories, tuning the continent layout toward a true world-map silhouette, and porting
the mode to the HTML report (static wobble-on-load).

## 2026-10-07 - World-map view v2: labels, continents, service node types, pieces, report port
Polished the Risk-style map (all surfaces). (1) Territory LABELS: HTML overlays projected from the
3D board each frame via graph2ScreenCoords. (2) World-map SILHOUETTE: continents spread wider (NW
Directory -> top Compromise -> E OT/ICS -> S IoT/Services), over a large ocean "board" disc plus
two faint wireframe graticule rings (flattened spheres built from node mesh constructors). (3) More
TERRITORIES: a new graphtypes.py re-types IoT/service hosts to broker/database/printer/iot (mirrors
ot.py; wired after emit_ot_paths in run_scan + graph_from_report), so they form their own continent
instead of recoloring the host; added to TYPE_COLOR + the upgradable-host set + legend. (4) PIECES
STAND: per-type board height (_PIECE_H) so goals/owned stand taller like Risk armies. (5) Report
PORT: the same map module + a "# Map" toggle in the HTML report (static wobble-on-load), so the
offline deliverable carries the view.

No findings-contract/schema change (the new node types are graph-only strings). Both surfaces
verified in-browser (four labeled territories, ocean/graticule, standing pieces, arcs across the
board, clean toggle back, no console errors). 3 backend tests; node --check clean on index.html and
the rendered report. Still experimental/tunable (continent geometry, a true coastline texture would
need a reachable canvas texture).

## 2026-10-11 - Nuclei engine (opt-in, ACTIVE web/network scan); schema 1.3.0 -> 1.4.0

Added `redness/engines/nuclei.py` wrapping ProjectDiscovery's nuclei (template-based web/network
scanning: CVEs, exposed panels, default logins, misconfig, tech-detect, takeovers). `parse_nuclei`
is pure over `-jsonl`, grouping matches by template-id (one Finding, N affected host:port, one
Evidence per match). New `Category.WEB` -> **SCHEMA_VERSION 1.3.0 -> 1.4.0**.

Why it is handled differently from everything else: nuclei is the first ACTIVE engine (it sends
real crafted requests, not a passive/read-only probe). So, deliberately: (1) OPT-IN only
(`scan --nuclei`), never in default_engines(); (2) PORT-GATED to web ports (80/443/8080/8443) via
discovery, so it never touches OT/ICS field ports; (3) always `-exclude-tags
intrusive,dos,fuzz,brute` + rate-limited, keeping the default run detection-oriented; (4) the
binary AND its template store are a separate install (not bundled), surfaced in `doctor`.

Remediation fallback: every REDNESS finding must carry a remediation, but nuclei templates do not
always include one - so we use `info.remediation` when present, else synthesize (CVE -> patch/
upgrade; else restrict/patch + see references). Graph: `web` node type (colour #c77dff) in the
IoT/SERVICES territory; recolours by severity like other findings. 10 tests (captured JSONL, no
nuclei/network); end-to-end verified through docx/html/csv. NOT yet field-verified against a live
nuclei run - that joins the real-gear/Kali verify pass (argv, template-store paths, large-output
timeout tuning).

## 2026-10-16 - Advisor: context-aware tool suggestions (nmap -sV + searchsploit); no schema change

Added a recommendations layer so REDNESS can say "detected X -> run tool Y here". Three new pieces:
`engines/nmap.py` (`nmap -sV` service/version/CPE detection -> one INFO inventory finding per host
whose meta carries the structured service list), `engines/searchsploit.py` (read-only local
Exploit-DB lookup: product+version -> public exploit candidates as INFO findings + EDB refs), and
`advisor.py` (pure rule engine: detected services + findings -> ranked `Suggestion`s). Both new
engines emit existing categories (ENUM / WEB), so NO contract/schema change.

Design decision - three tiers matching REDNESS's passive->opt-in->gated posture, and crucially
REDNESS does NOT auto-run intrusive tools: **auto** = read-only lookups REDNESS runs (searchsploit);
**suggest** = print the exact command, operator runs it (nuclei/sqlmap/metasploit/aircrack); **gated**
= online brute/spray via the existing consent+FORCE+audit path (hydra / redness spray). This keeps
REDNESS an assessment/orchestration tool, not an auto-exploiter, while delivering the "right tool
for the stack" prompt. OT-safe: hosts with any Category.ICS finding are excluded from all
suggestions (advisor.ot_hosts). Why tiers over just running everything: hydra/sqlmap/msf are
intrusive and client-disruptive; auto-running them would break the scope-careful contract.

CLI: `scan --nmap` (opt-in active detection) + `scan --suggest` (print suggestions + run the
read-only searchsploit auto-lookups, adding exploit-candidate findings to the report). doctor
reports nmap/searchsploit/nuclei readiness. 15 tests (pure parsers + rule engine, no tools needed).
Chosen as phase 1 of the broader tool-orchestration ask (nmap/sqlmap/hydra/medusa/msf/amass/
spiderfoot/kismet/wifite/aircrack/reaver) because tech detection + the advisor is the foundation
every later tool hangs off. nmap -sV + the advisor were field-verified against real nmap XML
(localhost scan: parsed msrpc/microsoft-ds/Microsoft-HTTPAPI 2.0, produced correct suggestions);
searchsploit's `--json` shape across exploitdb versions still wants a live check on Kali.
