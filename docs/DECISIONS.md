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
