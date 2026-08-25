# Password spraying - design note

> Status: **design; not built.** Lockout-aware password spraying (docs/ROADMAP.md Tier 2 -
> parity). Owner: **anjaiv** (engines/CLI lane). Read `CLAUDE.md`, `docs/DECISIONS.md`,
> `docs/GPP.md`, and `redness/poison.py` (the gated-command precedent) first, then this.

## What it is (and why it is a gated command, not an engine)
Try one password against many accounts to find valid domain credentials, staying under the
account-lockout threshold. Spraying is **active and dangerous**: too many attempts locks
accounts (a denial of service against the client) and it is loud to a SOC. So - exactly like
`poison` - it is an **opt-in, confirmation-gated CLI command that NEVER runs as part of
`scan`** and is NOT in `default_engines()`. Contrast `gpp`/`sharehunt`, which are read-only and
default-on.

## Approach: orchestrate nxc in two phases (recon, then spray)
1. **Policy read first (mandatory when credentialed):** `nxc smb <dc> -u U -p P --pass-pol`
   for the lockout policy, and `nxc ldap ... --users` for the target list. `engines/ldap.py`
   `parse_users` already returns the user list *and* parses the `badPwdCount` column, so we can
   skip accounts near lockout for free.
2. **The spray:** `nxc smb <dc> -u users.txt -p '<OnePassword>' --continue-on-success` - one
   password across many users (default cartesian = exactly one attempt per user),
   `--continue-on-success` so we collect *all* valid hits, not just the first.

Parsing is pure (`parse_pass_pol`, `parse_spray_hits`) and separate from the gated orchestration,
so it unit-tests against captured nxc output with no nxc/DC - like `engines/responder.py` vs
`poison.py`.

## Lockout-awareness (the core of the feature)
Spraying one password adds +1 to each wrong account's `badPwdCount`, so it is safe only while
attempts-per-user-per-observation-window stays under the threshold. The command enforces this:
- **Read the policy first** and parse `lockoutThreshold`, `lockoutObservationWindow`,
  `lockoutDuration`.
- **Safe budget** = `lockoutThreshold - margin` (margin default 1, a buffer). A run that would
  exceed the budget within one observation window is **refused unless `--force`**.
- **v1 = one password per invocation** (1 attempt/user/window) - inherently safe when
  `threshold >= 2`. Multiple passwords (which need spacing >= the observation window) are
  **deferred**; v1 runs one round and prints when it is safe to run again.
- **Skip risky accounts:** skip users whose `badPwdCount` is at/near `threshold - margin`, and
  skip disabled accounts.
- **`lockoutThreshold == 0` (no lockout):** spray freely, but emit `password-policy-no-lockout`.
- Knobs: `--delay` between attempts, `--yes` (skip the prompt), `--force` (override the budget
  refusal - loud warning).

## Uncredentialed spray - allowed, but impossible-to-miss warning
Without creds we cannot read `--pass-pol` or enumerate users, so **the lockout policy is
unknown** - spraying blind can lock every account it touches. It is allowed only with an
explicit `--user-file` AND `--force`, behind a **loud, unmissable warning** (banner +
confirmation) that the lockout policy is unknown and accounts may be locked out. This is the
single most dangerous path in the tool; treat it accordingly.

## Findings to emit
| id | severity | when |
|----|----------|------|
| `spray-hit` | **HIGH** | a sprayed password validated for an account |
| `password-policy-no-lockout` | MEDIUM | `lockoutThreshold == 0` |
| `password-policy-weak` | LOW/MEDIUM | weak min length / long observation window (optional) |

`spray-hit`: **HIGH** (a validated hit is a real foothold but usually low-privileged; reserve
CRITICAL for confirmed privileged access). Stores the recovered `account:password` in evidence
(a discrete usable credential, like `credential-cracked`/`gpp` - not masked) and rides each hit
in **`meta["credentials"]`**. **Remediation:** reset the account, enforce a strong password
policy and MFA, and configure/verify account lockout. **References:** MITRE **T1110.003**
(Password Spraying). The `--pass-pol` read yields `password-policy-no-lockout` even when the
spray finds nothing - useful on its own.

## The contract with `paths.py` - `meta["credentials"]`
Same pattern as `gpp` (docs/DECISIONS.md, 2026-08-21): each recovered credential rides in
`meta["credentials"]` (`{account, username, kind:"password", password, source:"spray"}`) and
becomes an `owned` attack-path node once `paths.py`'s `compromised_accounts()` unions
`meta["credentials"]` (Gjoko's ~3-line change). Self-contained meanwhile (report works
standalone). No `findings.py` schema change.

## Structure (mirrors `poison`)
- **`redness/engines/spray.py`** - pure `parse_pass_pol`, `parse_spray_hits`, `build_findings`,
  `safe_budget()`, `spray_argv()` (no `Engine` subclass, not registered as a default engine).
- **`redness/spray.py`** - `run_spray()`: read policy -> compute budget -> refuse-or-proceed ->
  run nxc -> parse hits -> `Report`. Injectable runner (testable), optional `--live`.
- **`cmd_spray`** in `redness/cli.py` - confirmation prompt (`Type YES to spray <dc> ...`),
  lockout/uncredentialed banner, `--yes` / `--force`.

## Dependencies
- **nxc** (Kali-native; already covered by `redness doctor`'s netexec check). No crypto/AES,
  no new dependency.

## Build order (suggested)
1. Pure parsers + safety math: `parse_pass_pol`, `parse_spray_hits`, `safe_budget`,
   `build_findings` (+ `spray_argv`). Tests against captured `--pass-pol` / spray output.
   **No nxc/DC.**
2. `run_spray()` orchestrator (gated, injectable runner) + `cmd_spray` + argparse wiring +
   the confirmation/warning banners.
3. Docs: DECISIONS entry, ROADMAP Tier-2 tick, CLAUDE.md; confirm the paths.py
   `meta["credentials"]` union with Gjoko.

## Legal / ethics
Authorized, in-scope engagements only. Spraying can lock out accounts (a DoS against the
client) - only run it with written authorization and, ideally, the client's awareness of the
lockout policy. The uncredentialed path is especially hazardous; see above.
