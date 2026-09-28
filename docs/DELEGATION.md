# Delegation abuse enumeration - design note

> Status: **BUILT** (feat/delegation-abuse, steps 1-2). ROADMAP Tier 2 - parity. Owner: **anjaiv**
> (engines lane). Read `CLAUDE.md`, `docs/DECISIONS.md`, and `engines/ldap.py` (the multi-read
> engine it mirrors) first.

## What it is
Enumerates the Kerberos delegation abuse family from LDAP attributes on the DC: unconstrained /
constrained / RBCD delegation, machine-account quota (MAQ), gMSA readability, and shadow
credentials. All are read-only LDAP reads, so it is credentialed + passive and belongs in the
default scan (unlike the gated poison/spray commands).

## Approach - one engine, several nxc ldap reads (mirrors engines/ldap.py)
`DelegationEngine` (engines/delegation.py) is in `default_engines()` but no-ops without domain
creds or nxc. It runs several `nxc ldap <dc> <auth> ...` reads, each fed to a pure `parse_*`:
- `--trusted-for-delegation` -> `parse_unconstrained`
- `--find-delegation`        -> `parse_find_delegation` (constrained / +protocol-transition / RBCD)
- `-M maq`                   -> `parse_maq`
- `-M gmsa`                  -> `parse_gmsa`
Parsing is pure and unit-tested against captured output (no nxc/DC); the injectable `runner`
seam is the only impure part.

## Severity model (deliberately balanced - avoid alert fatigue)
Informational baseline; CRITICAL reserved for the genuinely urgent cases, so the report does not
bury the urgent combos under conservative noise.

| id | severity |
|----|----------|
| `delegation-unconstrained` | **HIGH** (non-DC - the attack primitive) |
| `delegation-unconstrained-dc` | **INFO** (a DC legitimately has it - context, not a finding) |
| `delegation-constrained` | HIGH; **CRITICAL** only with protocol transition (impersonate ANY user) |
| `delegation-rbcd` | HIGH |
| `machine-account-quota` | **INFO** alone; **CRITICAL** only with an AD CS ESC path (see below) |
| `gmsa-readable` | HIGH |
| `shadow-credentials` | HIGH |

Findings use `Category.LDAP` (reuse; no schema bump) and carry descriptive `meta["delegation"]`
but **no `meta["credentials"]`** - this is enumeration, not credential recovery (gMSA is flagged
as readable, not dumped).

## AD CS cross-engine wiring (no duplicated ADCS detection)
MAQ alone is not urgent; MAQ + an AD CS ESC path is a real escalation (create a machine account,
abuse the vulnerable template -> DA). Rather than re-detect ADCS inside this engine, `run_scan`
passes `adcs_present` to any engine that sets `wants_adcs_context = True` (duck-typed, no import
coupling), computed from whether a `Category.ADCS` finding is already in the report this scan.
`DelegationEngine` runs **after** `CertipyEngine` in `default_engines()` so certipy's findings
exist first; the engine forwards `adcs_present` to `build_findings`, which escalates only the
MAQ finding.

## Follow-ups (deliberately deferred - see docs/DECISIONS.md)
- **nxc flags unverified offline** - `--trusted-for-delegation` / `--find-delegation` / `-M maq` /
  `-M gmsa` were not introspectable in the dev sandbox; verify against real nxc and drop captured
  samples into tests/ if a format differs.
- **shadow-creds invocation deferred** - `parse_shadow_creds` is written + tested, but no verified
  nxc module dumps `msDS-KeyCredentialLink` yet, so `run` passes `shadow=None` (never invents a
  flag). Wire a verified source (nxc module / certipy / impacket) later.
- **DC detection is best-effort** - a DC is recognised by the UAC SERVER_TRUST bit when present,
  else by a hostname-derived name hint; against an IP with no UAC in the output a DC could
  mis-flag as non-DC (HIGH vs INFO). Tighten against real output.
- **Attack-path edges** - `delegation-unconstrained` (non-DC) now feeds `paths.py:delegation_edges()`
  as a `potential` edge to the Domain Admin goal (feat/delegation-paths, issue #60 option 3).
  **RBCD edges deferred** to the real-nxc Kali pass: `meta["to"]` is SPN-valued and the direction is
  the inverse of constrained delegation, unverifiable offline. See docs/DECISIONS.md (2026-09-28).

## Legal / ethics
Authorized, in-scope engagements only. Read-only LDAP enumeration with the tested principal's
own credentials.
