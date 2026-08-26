# Remote-access protocol engines - RDP / WinRM / MSSQL

`redness/engines/remote.py` adds three engines for the **lateral-movement surfaces** the core
scan (SMB / LDAP / AD CS / TLS) was blind to: the services an operator actually pivots through.
Each wraps one nxc protocol and normalizes its banner + any credentialed-auth line into findings.

## Why they run in the default scan (unlike poison / spray)
These are **passive enumeration**: connect, read the banner, and - only if the operator supplied
creds - try those exact creds once. No password guessing, no lockout risk, nothing written to the
target. That is fundamentally different from `poison` (network poisoning) and `spray` (can lock
out accounts), which stay gated CLI commands. So RDP/WinRM/MSSQL sit in `default_engines()` and
light up on a normal `redness scan`. RDP even works fully unauthenticated (NLA + exposure come
straight off the banner).

## What each flags

| Finding | Sev | Category | Meaning |
|---------|-----|----------|---------|
| `rdp-nla-disabled` | MEDIUM | CONFIG | RDP accepts connections without Network Level Authentication - pre-auth attack surface (BlueKeep / CVE-2019-0708 class on unpatched hosts, rogue-RDP credential harvesting) |
| `rdp-exposed` | INFO | ENUM | RDP reachable (inventory + graph node) |
| `rdp-access` | MEDIUM / **HIGH** (admin) | CONFIG | supplied creds log on interactively over RDP |
| `winrm-exposed` | INFO | ENUM | WinRM (5985/5986) reachable |
| `winrm-access` | HIGH / **CRITICAL** (admin) | CONFIG | supplied creds reach WinRM = remote PowerShell command execution (admin = direct RCE) |
| `mssql-exposed` | INFO | ENUM | MSSQL (1433) reachable |
| `mssql-access` | HIGH / **CRITICAL** (admin) | CONFIG | supplied creds authenticate to MSSQL; sysadmin (Pwn3d) -> xp_cmdshell RCE |

Admin is nxc's `(Pwn3d!)` marker. Access findings only appear when the operator passes creds and
they actually work - they confirm a *reachable* lateral-movement path from a given credential.

## Contract notes
- **No `SCHEMA_VERSION` bump.** Findings reuse `Category.CONFIG` (misconfig / access path) and
  `Category.ENUM` (exposure). All findings are host-level (`affected == host`), so the graph
  recolors the host node by severity - no new node type.
- Access findings do **not** ride `meta["credentials"]`: they demonstrate reach with a credential
  we already hold, they do not recover a new one (that shape is for spray / gpp / cracked creds).

## Parsing is verified, not guessed
The parsers were written against NetExec's actual `rdp` / `winrm` / `mssql` protocol output:
```
RDP     <host> 3389 <name> [*] Windows 10 ... (name:PC01) (domain:CORP.LOCAL) (nla:False)
WINRM   <host> 5985 <name> [*] Windows ... (name:PC01) (domain:CORP.LOCAL)
WINRM   <host> 5985 <name> [+] CORP.LOCAL\jdoe:Passw0rd (Pwn3d!)
MSSQL   <host> 1433 <name> [+] CORP.LOCAL\sa:Passw0rd (Pwn3d!)
```
`mark_pwned()` renders `(Pwn3d!)`; `WINRM-SSL` is the TLS variant of the `WINRM` token (both
matched). Parsing stays pure and separate from subprocess exec, unit-tested in `tests/test_remote.py`
against captured output - no live host or nxc install needed (same discipline as `netexec.py`).

## Usage
```bash
# Unauthenticated: RDP NLA + exposure across a scope (runs inside a normal scan)
redness scan --target 10.10.0.15

# Credentialed: also confirms WinRM / MSSQL / RDP reach for that account
redness scan --target 10.10.0.15 -u jdoe -p 'Passw0rd!' -d acme.local --out report.docx
```
No new command - they are part of `scan`. Needs `nxc` on PATH (`redness doctor` shows readiness).

## Deferred
- MSSQL **linked-server hopping** and **xp_cmdshell** execution (offensive; would be gated like
  `poison`/`spray`, not part of the passive scan).
- Screenshotting RDP (`nxc rdp --screenshot`) as report evidence.
