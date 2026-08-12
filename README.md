# REDNESS

**v1.33.7** — Zero Science Lab · powered by Silly Security Inc.
Developed by **Anja Ivanovska** & **Gjoko Krstic** — anja@zeroscience.mk · gjoko@zeroscience.mk

> Working codename — the tool may be renamed later.

Red-team **orchestrator + normalizer + reporter** for Active Directory / Windows
network assessments. REDNESS does **not** reimplement protocol tooling — it drives
existing, battle-tested engines (NetExec, Impacket, Certipy), normalizes their output
into a single **findings model**, and renders it as a clean **.docx report** and a
**live 3D graph** (native window or browser).

## Why this exists

The attacks are a solved problem (NetExec, Impacket, Certipy, BloodHound). What is
*not* solved cleanly:

1. **Deployment** — a single self-contained `.exe` you can drop on a locked-down jump box.
2. **The deliverable** — a client-ready report with severity tables and remediation.
3. **Orchestration & de-duplication** — run the credentialed *and* uncredentialed sweep,
   merge results from several tools into one normalized findings set, watch it live.

## Scope of assessment

| Area | Engine(s) | Cred / No-cred |
|------|-----------|----------------|
| SMB: shares, sessions, signing, null/guest | NetExec | both |
| LDAP: users, groups, policies | NetExec | both |
| Kerberos: AS-REP roast, Kerberoast (+ crack) | NetExec / Impacket | cred |
| ADCS: ESC1–ESC17 certificate issues | Certipy | cred |
| TLS: weak protocols/ciphers, cert issues | (stdlib) | no-cred |
| NetNTLMv2 capture (LLMNR/NBT-NS poisoning) | Responder | intrusive, opt-in |

## Commands

| Command | What it does |
|---------|--------------|
| `redness doctor` | Report which engines/tools are installed and how to enable the rest |
| `redness scan` | Run the engines against one/many targets → report + live graph (+ crack) |
| `redness gui` | **Native desktop window** (Windows/Linux) around the live 3D graph |
| `redness live` | The same UI in a browser (`--demo` for simulated data) |
| `redness poison` | LLMNR/NBT-NS poisoning to capture NetNTLMv2 (intrusive; opt-in) |
| `redness report` | Re-render a `.docx` from a saved `findings.json` |
| `redness demo` | Render a sample report, no DC needed |

## Install (git clone → one command → `redness`)

**Linux / Kali** (recommended operator box — `nxc` runs natively here):
```bash
git clone https://github.com/zeroscience/toomanysecrets.git
cd toomanysecrets
./scripts/install.sh        # venv + engines; installs NetExec via pipx if missing
source .venv/bin/activate
redness doctor              # confirms which engines are ready
```

**Windows** (PowerShell):
```powershell
git clone https://github.com/zeroscience/toomanysecrets.git
cd toomanysecrets
.\scripts\install.ps1
.\.venv\Scripts\redness.exe doctor
```

Under the hood that's `pip install ".[engines]"` (certipy + impacket) plus the `redness`
command. **NetExec has no Python 3.12 wheel**, so the installer adds it via `pipx`; if you
already have `nxc` on PATH (e.g. a Kali box) it's used as-is. For the native window:
`pip install ".[gui]"` (pywebview) — without it, `redness gui` falls back to the browser.
TLS + reporting + the GUI need no external tools.

## Usage

```bash
# Full assessment: scan a scope file, capture+crack hashes, report, watch the graph
redness scan --targets scope.txt -u user -p pass -d acme.local \
  --wordlist /usr/share/wordlists/rockyou.txt --out report.docx --json findings.json --live

# One target, no creds (SMB / TLS / AS-REP)
redness scan --target 10.0.0.10 --out report.docx

# Native GUI window (drive scans from the '+ New scan' panel)
redness gui

# NetNTLMv2 capture (intrusive; --analyze to observe only)
redness poison --iface eth0 --duration 600 --wordlist rockyou.txt --live
```

Auth: `-u/--username`, `-p/--password`, `-H/--hash` (pass-the-hash), `-d/--domain`,
`-k/--kerberos`. Output: `--out report.docx`, `--json findings.json`, loot to `loot/`.
`--wordlist` cracks captured AS-REP/Kerberoast/NetNTLMv2 hashes (needs hashcat/john).
Engines whose tool isn't installed are skipped and noted — a scan never hard-fails.
Run `redness <command> -h` for all flags; the GUI has **About** and **Usage** panels.

## Layout

```
redness/
  findings.py     # normalized findings model  <-- THE CONTRACT (schema v1.0.0)
  events.py       # EventBus — live-graph stream seam
  scan.py         # run_scan(): engines x targets -> Report
  scope.py        # --targets scope-file parsing
  crack.py        # hash loot + offline cracking (hashcat/john)
  poison.py       # NetNTLMv2 capture orchestration (redness poison)
  doctor.py       # engine/tool availability report
  cli.py          # entrypoint: demo/report/doctor/gui/live/scan/poison
  engines/        # tool wrappers -> List[Finding]  (Anja)
    base.py netexec.py ldap.py certipy.py tls.py responder.py
  report/         # List[Finding] -> .docx  (Gjoko)
  live/           # 3D GUI: SSE bridge + web UI + demo driver
docs/             # DECISIONS · GUI · NETNTLM · VALIDATION · LIVE_GRAPH · screenshots
packaging/        # PyInstaller specs (lean + self-contained) + installers
```
See [CHANGELOG.md](CHANGELOG.md) for what's new and [docs/](docs/) for design notes
(architecture decisions, the GUI roadmap, validation checklist).

## Legal

For **authorized** security assessments only. Use requires written permission
(engagement contract / scope) from the owner of the target environment. The `poison`
command actively affects other hosts on the segment — in-scope engagements only.
