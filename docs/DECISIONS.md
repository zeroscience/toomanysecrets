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
