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
(robust) rather than scrape the text report. ESC1–ESC16 mapped to severity+remediation;
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
→ parse_responder_log → build_findings (`netntlm-captured`) → crack (`netntlmv2`). So
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
