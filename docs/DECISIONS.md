# Architecture Decision Log

Append-only. Each entry: date, decision, why. This is how the other researcher's
agent catches up on *why* things are the way they are.

## 2026-08-09 — Orchestrate, don't reimplement
Wrap NetExec / Impacket / Certipy rather than rebuild protocol tooling. The attacks
are solved; our value is deployment (single .exe), normalization, and reporting.

## 2026-08-09 — Python orchestrator
Chosen over Go so we stay in the same ecosystem as impacket/certipy (direct library
access, no output re-parsing). Ship a single Windows `.exe` later via PyInstaller/Nuitka.

## 2026-08-09 — findings.py is the contract
`Finding` / `Report` schema is the interface between engines (Person A) and reporting
(Person B). Split ownership by directory so both halves progress in parallel.

## 2026-08-09 — NetExec SMB engine: parse stdout, keep parsing pure
Parse nxc's line-oriented stdout with regex (version-tolerant) rather than depend on
JSON output. Parsers are pure functions separated from subprocess execution so they
unit-test against captured output with no nxc/DC (see tests/test_netexec_parse.py).

## 2026-08-09 — PyInstaller one-file build
`packaging/redness.spec` uses `collect_all("docx")` so the bundled default.docx template
is present in the frozen exe. Requires Python >= 3.10.1 (3.10.0's `dis` bug crashes
PyInstaller analysis).

## 2026-08-09 — docx report, no template
Plain, table-driven, classic pentest report: exec summary (severity counts),
findings most-severe-first with impact/remediation/evidence, enumeration appendix.

## 2026-08-10 — Certipy engine parses JSON, not text
`certipy find -json` emits a per-object "[!] Vulnerabilities" map. We parse that
(robust) rather than scrape the text report. ESC1–ESC16 mapped to severity+remediation;
unknown ESCs default HIGH. Parsing pure + testable (tests/test_certipy_parse.py).

## 2026-08-10 — EventBus seam for a future live 3D graph
Added redness/events.py (EventBus + Event kinds: status/finding/node/edge/probe/done)
and Engine.emit_* helpers. Engines can stream as they enumerate so the SAME normalized
stream feeds both the docx report and a later 3D GUI, decoupled from any renderer.
Bus swallows subscriber errors (a broken UI can't break a scan). See docs/LIVE_GRAPH.md.

## 2026-08-10 — Live graph: stdlib SSE + vendored 3d-force-graph
Bridge uses stdlib http.server + Server-Sent Events (one-directional engine->UI, no
dependency, bundles into the exe) with a replay buffer so a browser rebuilds the full
graph on connect/refresh. 3d-force-graph vendored locally (v1.80.0, bundles three.js)
for offline/field use; web assets bundled via the spec's datas walk; bridge._web_dir()
is sys._MEIPASS-aware. preserveDrawingBuffer:true on the renderer so frames can be
captured for docs screenshots.

## 2026-08-10 — Packaging entry is outside the package
Frozen entry is packaging/entry.py (absolute `from redness.cli import main`), not
redness/__main__.py — PyInstaller runs the entry as top-level __main__ with no package
context, so a relative import crashes at runtime. pathex=<repo root> so analysis resolves.

## 2026-08-10 — scan command + scope orchestration
redness/scan.py run_scan() runs each available engine per target, aggregates Findings
into one Report, and (if given a bus) owns ALL graph emission so the picture is uniform
regardless of which engine found what (engines run headless in a scan). Missing tools
are skipped, not fatal; a crashing engine can't abort the scan. redness/scope.py parses
`--targets` files and merges with `--target`; shared with the future GUI file picker.

## 2026-08-10 — TLS engine is pure stdlib (no hard dep)
Protocol + cipher checks force each ssl.TLSVersion and read ss.cipher(); cert
expiry/self-signed via stdlib ssl (get_server_certificate + _test_decode_cert). SHA1/MD5
signature and <2048-bit key checks only when `cryptography` happens to be importable.
Always-available engine so a scan yields findings with no nxc/certipy present.

## 2026-08-10 — Hash capture + cracking scope (like adscan, minus poisoning)
LdapEngine captures AS-REP (krb5asrep) and Kerberoast (krb5tgs) hashes during LDAP enum,
stashing them in finding.meta["hashes"]. crack.py collects them, always writes hashcat-
ready loot files, and (if hashcat/john on PATH + --wordlist) cracks and annotates the
report with CRITICAL credential-cracked findings. hashcat mapping is prefix-based (hash
values can contain ':'). NetNTLMv2 CAPTURE needs an active LLMNR/NBT-NS poisoner — kept
OUT of scope for now (intrusive; separate gated feature).

## 2026-08-10 — GUI controls: token-gated POST /scan
The live bridge gained a POST /scan endpoint that runs the real engines (run_scan) in a
thread streaming to the bus. Guarded by a per-server CSRF token injected into index.html
(a cross-origin page can't read it, so it can't forge scans); bound to 127.0.0.1. The GUI
adds the ZeroScience logo (web/logo.svg — placeholder, swap for the real one), a targets
textarea + .txt scope loader (client-side FileReader), and optional creds. `redness live`
now waits for a GUI-initiated scan; `--demo` streams the simulated data (old default).

## 2026-08-10 — Bundle engines as deps, don't copy adscan
Do NOT vendor adscan's source (it's a peer orchestrator — copying invites license
entanglement and is redundant). Instead depend on the real engines: netexec/impacket/
certipy-ad (requirements-engines.txt), which our engines already shell out to. Added a
`doctor` command that reports engine/tool availability + install hints (answers the
"why 0 findings?" question). Two build modes: packaging/redness.spec (lean, expects
nxc/certipy on PATH) and packaging/redness-full.spec (self-contained: collect_all the
engine packages into one ~100MB exe — scaffold, needs validation on a deps-installed box
because nxc loads modules dynamically and PyInstaller misses those without hidden-imports).

## 2026-08-10 — Full self-contained exe: validated, partially blocked
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

## 2026-08-10 — certipy bundles in-process; netexec stays external (pipx)
Validated after the Defender exclusion: certipy + impacket install clean on py3.12 and
bundle into redness-full.exe; CertipyEngine runs certipy in-process (certipy.entry:main)
so the frozen exe executes it with nothing on PATH (proven: banner + real LDAP attempt
from inside the exe). NetExec, however, has no py3.12 wheel and its git build also fails
on 3.12 -> it is NOT bundled; recommended install is `pipx install netexec` (isolated
compatible Python, `nxc` on PATH) and our shell-out NetExec/LDAP engines use it. So:
certipy = batteries-included/in-process; netexec = external tool via pipx.

## 2026-08-10 — pip-installable (pyproject.toml) + one-shot installers
Added pyproject.toml so `pip install .` gives a `redness` console script and ships the
live GUI assets (package-data: live/web incl. vendored 3d-force-graph). Engines are an
extra: `pip install ".[engines]"` = certipy-ad + impacket (both have py3.12 wheels).
NetExec is intentionally NOT a dependency (no py3.12 wheel) — scripts/install.sh|ps1
install it via pipx, or use a box where nxc is already on PATH (Kali). Validated: the
installed `redness` runs from outside the repo and `redness live` serves index/logo/vendor
(1.3MB) from site-packages. Flow: git clone -> ./scripts/install.sh -> redness doctor/scan.

## 2026-08-11 — NetNTLMv2 capture: a gated `poison` command, not an engine
Built the intrusive NetNTLMv2 feature (docs/NETNTLM.md) as a standalone `redness poison`
command driving Responder (LLMNR/NBT-NS/mDNS) — deliberately NOT an Engine and NOT in
default_engines(), so `scan` can never trigger it. Gated: `--iface` required, `--duration`
time-box (default 600s), a `type YES` confirmation (+ `--yes`), a passive `--analyze`
(responder -A) mode, an authorization banner, and loot to git-ignored `loot/`.

Design decisions:
- Read Responder's **stdout** live rather than tailing logs/Responder-Session.log — no
  log-dir discovery, and the pure parser (engines/responder.py) feeds a `run_poison` that
  takes an injectable line source, so tests need no Responder/root/LAN.
- Findings reuse **Category.SMB** (NTLM relay/signing already live there) — **no
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
