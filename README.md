# REDNESS

> Working codename — the tool will be renamed later.

Red-team **orchestrator + normalizer + reporter** for Active Directory / Windows
network assessments. REDNESS does **not** reimplement protocol tooling — it drives
existing, battle-tested engines (NetExec, Impacket, Certipy), normalizes their
output into a single **findings model**, and renders a clean **.docx report**
(findings, weak configs, TLS, remediation).

## Why this exists

The attacks are a solved problem (NetExec, Impacket, Certipy, BloodHound). What is
*not* solved cleanly:

1. **Deployment** — a single self-contained Windows `.exe` you can drop on a locked-down
   jump box, instead of a Python-dependency install.
2. **The deliverable** — a client-ready report with severity tables and remediation,
   not raw stdout.
3. **Orchestration & de-duplication** — run the credentialed *and* uncredentialed sweep,
   merge results from several tools into one normalized findings set.

REDNESS is those three things. Everything else, it delegates.

## Scope of assessment

| Area | Engine(s) | Cred / No-cred |
|------|-----------|----------------|
| SMB: shares, sessions, signing | NetExec | both |
| LDAP: users, groups, policies, delegation | NetExec / Impacket | both |
| Kerberos: AS-REP roast, Kerberoast | Impacket / NetExec | both |
| ADCS: ESC1–ESC17 certificate issues | Certipy | both |
| Password policy / spraying | NetExec | both |
| TLS / service config weaknesses | (native) | no-cred |

## Architecture (the two seams)

```
  engines/                report/
  (Person A owns)         (Person B owns)
  nxc / impacket   --->   findings.json   --->   report.docx
  / certipy wrappers      (THE CONTRACT)         (python-docx)
```

The `Finding` schema in `redness/findings.py` is the interface between the two halves.
Agree on it, and both sides can be built in parallel without touching each other's files.

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

Under the hood that's just `pip install ".[engines]"` (certipy + impacket) — which also
gives you the `redness` command. **NetExec has no Python 3.12 wheel**, so the installer
adds it via `pipx` (its own compatible Python); if you already have `nxc` on PATH (e.g. a
Kali box), it's used as-is. TLS + reporting + the live GUI need no external tools.

## Quick start (no install)

```bash
python -m venv .venv && .venv\Scripts\activate     # Windows
pip install -r requirements.txt
python -m redness.cli demo --out report.docx       # sample report, no DC needed
```

## Usage

```bash
# Scan one target, write a report (nxc/certipy provide the real findings)
redness scan --target 10.10.0.15 -u user -p pass -d acme.local --out report.docx

# Scan a scope file (one IP/hostname/CIDR per line, # comments), stream to the live 3D graph
redness scan --targets examples/scope.txt --live

# Just watch the live 3D graph with simulated data (no targets/tools needed)
redness live --demo
```
(Without installing, prefix any of these with `python -m redness.cli` instead of `redness`.)

Auth options: `-u/--username`, `-p/--password`, `-H/--hash` (pass-the-hash),
`-d/--domain`, `-k/--kerberos`. Output: `--out report.docx`, `--json findings.json`.
Engines whose tool isn't installed are skipped and noted, so a scan never hard-fails.

## Legal

For **authorized** security assessments only. Use requires written permission
(engagement contract / scope) from the owner of the target environment.

## Layout

```
redness/
  findings.py        # normalized findings model  <-- the collaboration contract
  cli.py             # entrypoint
  engines/           # tool wrappers -> List[Finding]
    base.py
    netexec.py
  report/
    docx_report.py   # List[Finding] -> .docx
docs/
  DECISIONS.md       # architecture decision log (how each other's agent catches up)
```
