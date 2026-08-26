# GPP cpassword / SYSVOL secrets engine - design note

> Status: **design; not built.** Group Policy Preferences (GPP) `cpassword` recovery
> (docs/ROADMAP.md Tier 2 - parity). Owner: **anjaiv** (engines area). Read `CLAUDE.md`,
> `docs/DECISIONS.md`, and `docs/SHAREHUNT.md` first, then this.

## What it is (and why it's separate)
Group Policy Preferences let admins push passwords for local accounts, services, scheduled
tasks, mapped drives, and data sources. Those passwords live in XML files under **SYSVOL**
(`\\<domain>\SYSVOL\<domain>\Policies\{GUID}\{Machine,User}\Preferences\<type>\<file>.xml`) as
`cpassword="..."` - across `Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, `DataSources.xml`,
`Printers.xml`, `Drives.xml`. SYSVOL is readable by **any authenticated domain user**, and GPP
frequently set the **same local-admin password fleet-wide**, so one recovered `cpassword` is
often lateral movement across many hosts -> Domain Admin. It is the classic easy DA win.

MS14-025 stopped admins *creating* new GPP passwords, but legacy GPOs still leak them.

## Approach: orchestrate, don't reimplement (wrap nxc's module)
`cpassword` is **not cracked** - it is AES-256-CBC encrypted with a **32-byte key Microsoft
published in MS-GPPREF** (zero IV). Recovery is deterministic and instant (base64-decode, AES
decrypt with the public key, UTF-16LE); no hashcat/john, no wordlist.

We wrap the tool that already does the SYSVOL walk + decryption:
- **`nxc smb <target> -M gpp_password`** locates the GPP XMLs under SYSVOL, extracts + decrypts
  every `cpassword`, and prints the recovered `username` / `password` pairs. Kali-native,
  already a dependency, no new `doctor` entry, and **no AES dependency on our side**.

We add a **pure `parse_gpp_output(stdout)`** that turns nxc's line-oriented output into recovered
credentials - separated from the subprocess so it unit-tests against captured stdout with no
nxc/DC, exactly like `engines/netexec.py`. (nxc also has `-M gpp_autologin` for registry
autologon creds; out of scope for v1.)

## It's its own engine, in the default scan
`redness/engines/gpp.py` `GppEngine`. **In `default_engines()`** (alongside netexec/ldap/certipy):
it is read-only, cheap (one module call against the DC), high-value, and no-ops without creds or
nxc - so a normal credentialed scan gets it for free.

Complementary to sharehunt, not duplicative: sharehunt's `content-gpp-cpassword` rule *flags*
"there is a GPP secret here"; `GppEngine` *recovers* "...and it decrypts to `svc_deploy:Summer2024!`".
Distinct finding ids; keep both.

## The contract with `paths.py` - `meta["credentials"]`
A recovered GPP credential is a discrete, usable credential (like a cracked hash), so - per the
`credential-cracked` precedent - we **store the recovered `account:password`** in the finding
(evidence + meta), rather than masking it (contrast sharehunt's redaction of raw file blobs).
Raw artifacts (if any) still go to git-ignored `loot/`.

Each recovered credential also rides in **`meta["credentials"]`** (the shape proposed in
docs/DECISIONS.md, 2026-08-21, for the attack-path graph):
```
{ "account":  "ACME\\svc_deploy",   # node id paths.py keys on
  "username": "svc_deploy",
  "domain":   "ACME",               # optional
  "kind":     "password",
  "password": "Summer2024!",        # stored (usable credential, like credential-cracked)
  "source":   "gpp-Groups.xml" }
```
`GppEngine` is the **first producer** of `meta["credentials"]`. The finding is self-contained
(report + graph work standalone); it becomes an `owned` attack-path node once paths.py's
`compromised_accounts()` unions `meta["credentials"]` accounts (the ~3-line change already
recommended in DECISIONS) - **coordinate with Gjoko** since that is his lane.

No `findings.py` schema change: reuse **`Category.SECRET`** (the merged `secret` node type).

## Findings to emit
| id | severity | when |
|----|----------|------|
| `gpp-cpassword` | CRITICAL | a `cpassword` decrypted to a usable credential |
| `enum-gpp-files` | INFO | GPP preference XMLs present in SYSVOL (context; optional) |

`gpp-cpassword`: `Category.SECRET`, `affected=[account]`, `meta["credentials"]` as above, GPO
GUID + SYSVOL path in evidence. **Remediation:** remove the GPP-stored password; delete the
legacy preference from the GPO; rotate the exposed account; deploy LAPS; ensure MS14-025 is
applied. **References:** MITRE **T1552.006** (Group Policy Preferences), MS14-025.

## Safety / gating
Read-only enumeration of SYSVOL with the tested principal's own credentials - no writes, no
coercion, no lockout risk. Not intrusive; hence default-on (unlike sharehunt's opt-in spidering
or the gated `poison`). The recovered password is a real credential: handle the report per the
engagement's data-handling rules.

## Dependencies
- **nxc** with the bundled **`gpp_password`** module (Kali-native; already covered by
  `redness doctor`'s netexec check - no new dependency, no crypto library).

## Build order (suggested)
1. Pure `parse_gpp_output(stdout) -> [recovered creds]` + `build_findings` (`meta["credentials"]`,
   stored account:password). Tests against captured `nxc -M gpp_password` output. **No nxc/DC.**
2. `GppEngine.run` (subprocess seam) + registration in `engines/__init__.py` and
   `default_engines()`.
3. Docs: DECISIONS entry, ROADMAP Tier-2 tick, CLAUDE.md; confirm the paths.py
   `meta["credentials"]` union with Gjoko.

## Legal / ethics
Authorized, in-scope engagements only. A recovered GPP password is a live credential; treat the
report accordingly (the engagement's data-handling rules apply).
