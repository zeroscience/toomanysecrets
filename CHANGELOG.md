# Changelog

All notable changes to REDNESS. Format loosely follows [Keep a Changelog](https://keepachangelog.com).
Zero Science Lab · powered by Silly Security Inc.

## [Unreleased]
### Added
- **Right-click node actions (Phase 2, read-only):** `redness/actions.py` registry +
  token-gated `POST /action` + `GET /actions`; right-click a host/domain node in the graph
  to run Enumerate SMB / LDAP / AD CS / TLS against it, streamed back live. The channel every
  future action plugs into.
### Planned
- Phase 3 offensive actions (Kerberoast / secretsdump / pass-the-hash / DCSync / ADCS abuse),
  gated like `poison`. NetNTLM relay mode (ntlmrelayx). Stream cracked creds to the graph.
  See [docs/GUI.md](docs/GUI.md).

## [1.33.7] — 2026-08-13

### Added
- **Engines** (orchestrate, don't reimplement): SMB (NetExec) — signing, SMBv1,
  null/guest (incl. the `Null Auth:True` banner field), shares; LDAP (NetExec) —
  users, AS-REP roast, Kerberoast (hashes captured to loot); ADCS (Certipy) —
  ESC1–ESC17; TLS (stdlib) — legacy protocols, weak ciphers, cert expiry/self-signed.
- **`scan`** command — one/many targets (`--target` / `--targets` scope file),
  aggregated `.docx` report + `findings.json`, optional `--live` 3D graph.
- **Offline cracking** (`crack.py`) — captured AS-REP/Kerberoast/NetNTLMv2 hashes written
  to hashcat-ready loot files; `--wordlist` cracks via hashcat/john → CRITICAL
  `credential-cracked` findings.
- **`poison`** command — intrusive NetNTLMv2 capture via Responder (LLMNR/NBT-NS),
  gated (`--iface`, `--duration`, `type YES`/`--yes`, passive `--analyze`).
- **Live 3D graph GUI** — SSE bridge + vendored 3d-force-graph; token-gated `POST /scan`;
  `redness gui` native window (pywebview, browser fallback); branded About + Usage panels.
- **`doctor`** command — engine/tool availability + install hints.
- **Reporting** — table-driven `.docx` (exec summary, findings by severity, remediation).
- **Packaging** — lean and self-contained PyInstaller specs; certipy runs in-process in the
  frozen exe; `pip install .` (console script + GUI assets) and one-shot installers.

### Fixed
- LDAP `--users` parsed by real column format (verified vs NetExec source) instead of a
  guessed keyword blocklist — `Enumerated`/`No`/`Found`/`Skipping` no longer become users.
- De-duplicated SMB null/guest findings; tolerate nxc `--verbose/--log` line prefix.
- Frozen-exe entry point (absolute import); invalid-escape SyntaxWarning.

### Notes
- Verified against real tooling (NetExec/Certipy 5.x source, Certipy in-process) and a
  first live-DC run. See [docs/VALIDATION.md](docs/VALIDATION.md).
- Authorized assessments only.
