# CLAUDE.md — context for AI agents working on REDNESS

This file is how *both* researchers' Claude instances stay in sync. Read it first,
then `docs/DECISIONS.md` (the why) and `docs/LIVE_GRAPH.md` (the GUI plan).

## What this is
Red-team **orchestrator + normalizer + reporter** for AD/Windows assessments.
It does NOT reimplement protocols — it drives NetExec, Impacket, Certipy, normalizes
their output into one findings model, renders a `.docx` report, and can stream a live
3D graph of the enumeration. Codename REDNESS; will be renamed later.

## The one rule that keeps two agents from colliding
`redness/findings.py` is **the contract**. Engines produce `Finding`s; the reporter
consumes them. Change it only deliberately, bump `SCHEMA_VERSION`, and log it in
`docs/DECISIONS.md`.

## Current status (2026-08-10)
PRs #1–#4 all merged to `main`. Working, tested (21 tests), builds to a single offline
`.exe` with `demo / report / live / scan`. Real findings need `nxc` + `certipy` on PATH.

![live 3D graph](docs/screenshots/live-graph.jpg)

## Layout
```
redness/
  findings.py     # normalized findings model  <-- THE CONTRACT (schema v1.0.0)
  events.py       # EventBus (status/finding/node/edge/probe/done) — live-graph seam
  scan.py         # run_scan(): engines x targets -> Report (+ stream to bus)
  scope.py        # parse --targets scope file (IP/host/CIDR per line, # comments)
  crack.py        # capture AS-REP/Kerberoast hashes -> loot files -> crack (hashcat/john)
  cli.py          # entrypoint: demo / report / live / scan
  engines/        # tool wrappers -> List[Finding]  (Person A)
    base.py       #   Engine ABC + Target + emit_* helpers
    netexec.py    #   nxc SMB: signing, SMBv1, null/guest, shares
    ldap.py       #   nxc LDAP: users + AS-REP/Kerberoast hash capture (meta["hashes"])
    certipy.py    #   AD CS ESC1-ESC16 (parses `certipy find -json`)
    tls.py        #   TLS: legacy proto, weak ciphers, cert expiry/self-signed (pure stdlib)
  report/         # List[Finding] -> .docx  (Person B)
  live/           # 3D live GUI: SSE bridge + web UI + demo driver  (Person B)
    bridge.py     #   SSE stream + POST /scan (CSRF-token gated) + static serving
    demo.py, web/index.html, web/logo.svg, web/vendor/3d-force-graph.min.js
packaging/        # PyInstaller: entry.py + redness.spec + build.ps1
tests/            # pure-parser / orchestration tests, no DC/tools needed
docs/             # DECISIONS.md, LIVE_GRAPH.md, screenshots/
examples/scope.txt
```

## Ownership seams (work in parallel, avoid merge conflicts)
- **Person A — `redness/engines/`** : tool wrappers that emit `Finding`s. Keep parsing
  pure and separate from subprocess exec (see netexec.py/certipy.py) so it unit-tests.
- **Person B — `redness/report/` + `redness/live/` + packaging.**
Touch the other's directory only via a PR they review.

## Install (git clone -> one command -> `redness`)
`./scripts/install.sh` (Linux/Kali) or `.\scripts\install.ps1` (Windows): makes a venv,
`pip install ".[engines]"` (certipy+impacket via pyproject.toml, console script `redness`),
installs NetExec via pipx if missing, runs `redness doctor`. Kali with `nxc` already on PATH
is the easy operator box.

## Making real findings flow (the "why 0 findings?" answer)
REDNESS *orchestrates* external tools; install them so engines light up, then check:
```bash
pip install ".[engines]"    # certipy-ad + impacket (netexec: pipx, no py3.12 wheel)
redness doctor              # shows which engines/tools are ready
```
TLS is stdlib (always ready). hashcat/john are separate native installs for `--wordlist`.
Self-contained build (bundles the engines into one exe): `packaging/redness-full.spec`
(scaffold — validate on a box with requirements-engines.txt installed).

## Run it
```bash
pip install -r requirements.txt

python -m redness.cli demo --out report.docx            # sample report, no DC
python -m redness.cli live                               # GUI: logo + 'New scan' panel
python -m redness.cli live --demo                        # GUI streaming simulated data
python -m redness.cli scan --target 10.10.0.15 -u U -p P -d dom --out report.docx
python -m redness.cli scan --targets examples/scope.txt --live
python -m redness.cli scan --target dc -u U -p P -d dom --wordlist rockyou.txt
```
Hash capture is automatic (AS-REP/Kerberoast via LdapEngine) → written to `loot/`.
`--wordlist` cracks them if hashcat/john is on PATH; otherwise the loot files remain
for offline cracking. NetNTLMv2 *capture* (LLMNR/NBT-NS poisoning) is out of scope.
Build the exe (needs Python >= 3.10.1): `py -3 -m PyInstaller packaging/redness.spec`

## Adding an engine (the common task)
1. Subclass `Engine` in `redness/engines/`; implement `is_available()` + `run(target)`.
2. Keep a pure `parse_*` function; `run()` shells out and feeds it. Add a test with
   captured tool output (no live DC).
3. Return `Finding`s with stable `id`, severity, category, impact, **remediation**,
   evidence, references. `run_scan` auto-includes any engine in `default_engines()`.

## Workflow
- Feature branches + PRs into `main`. Never commit to `main` directly.
- The other human (or their Claude) reviews before merge. Prefer `--merge` for stacked
  PRs (squashing a stack causes conflict cascades).
- Keep secrets and any client/engagement output OUT of git (`.gitignore` blocks
  `*.docx`, `findings*.json`, loot, hashes, ccache).

## Conventions
- Every finding carries **remediation** — this is a *report* tool, not just a scanner.
- The EventBus swallows subscriber errors: a broken UI can never break a scan.
- Commit a fresh `docs/screenshots/live-graph.jpg` when the GUI changes meaningfully.

## Next up (not started)
NetNTLMv2 capture via an LLMNR/NBT-NS poisoner (intrusive — separate, gated feature);
stream crack results to the live graph; replace web/logo.svg with the real lab logo;
"download report" button in the GUI.
Done recently: TLS scanner, LDAP/Kerberos hash capture + offline cracking (crack.py),
and the GUI (logo + scope-file loader + token-gated POST /scan that runs real engines).

## Legal / ethics
Authorized assessments only. Assume written scope exists before running against any target.
