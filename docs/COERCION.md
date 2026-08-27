# Coercion (PetitPotam / PrinterBug / DFSCoerce) - design note

> Status: **BUILT** (branch `feat/coercion`, steps 1-3; docs/ROADMAP.md Tier 2 - parity;
> last item of issue #49). Owner: **anjaiv** (engines/CLI lane). Read `CLAUDE.md`,
> `docs/DECISIONS.md`, `docs/NETNTLM.md` (the `poison`/`trigger` capture pipeline this
> feeds), and `docs/SPRAY.md` + `redness/poison.py` (the gated-command precedent) first,
> then this.

## What it is (and why it's a gated command, not an engine)
Active **RPC forced-authentication**: send an RPC call to a target (usually a DC or a
Windows server) over **MS-EFSR** (PetitPotam), **MS-RPRN** (PrinterBug), or **MS-DFSNM**
(DFSCoerce) that makes the *target's machine account* authenticate to a listener we
control - immediately, no human, no waiting. Because it **actively touches a target over
RPC** it is intrusive: exactly like `poison`/`spray`, it is an **opt-in,
confirmation-gated CLI command that NEVER runs as part of `scan`** and is NOT in
`default_engines()`. Contrast `gpp`/`remote`, which are read-only and default-on.

## Where it sits in the NetNTLMv2 family (docs/NETNTLM.md)
Three ways to make something authenticate to us; all feed the *same* capture pipeline:

| | `poison` (built) | `trigger` (built) | **`coerce` (this)** |
|---|---|---|---|
| mechanism | LLMNR/NBT-NS poisoning | file lure (html/scf/url) | **active RPC** (EFSR/RPRN/DFSNM) |
| victim | whoever resolves a name | a **human** opens a file | a **machine account**, forced now |
| we initiate? | passive listen | passive (out-of-band delivery) | **active - RPC to the target** |
| wraps a tool? | Responder | none (pure stdlib) | **yes (nxc `coerce_plus`)** |
| captures the hash? | **yes** | no (`poison` does) | no (`poison` does) |

So `coerce` is a **trigger** (like `trigger.py`) - it *causes* an authentication but does
**not** capture it. It differs from `trigger.py` in being an **active RPC against a machine**
(intrusive, wraps a tool, forces a computer account immediately) rather than a passive file a
human must open.

## Approach: orchestrate nxc, don't reimplement
Wrap NetExec's **`coerce_plus`** module - one module that bundles PetitPotam / PrinterBug /
DFSCoerce / ShadowCoerce / MS-EVEN and has a check mode:

```
nxc smb <target> -u U -p P -M coerce_plus -o LISTENER=<us> [-o METHOD=PetitPotam]
```

House pattern (mirrors `gpp`'s `-M gpp_password`), Kali-native, already covered by
`redness doctor`'s netexec check. Alternatives considered and rejected: standalone
**Coercer**, impacket `PetitPotam.py`/`dfscoerce.py` - several tools vs one module.

> **Verify against real nxc.** The exact module name/option keys (`coerce_plus`, `LISTENER`,
> `METHOD`) could not be introspected in-sandbox (nxc has no py3.12 wheel; not installable
> here). The **pure parser is the tested core**; the thin invoker gets a "verify on Kali"
> note, same as `gpp`/`spray`. If the module/flags differ, only `coerce_argv()` changes.

Parsing is pure (`parse_coerce_plus`) and separate from the gated orchestration, so it
unit-tests against captured nxc output with no nxc/DC - like `engines/responder.py` vs
`poison.py`.

## How it plugs into the capture flow: it needs a listener already running
Coercion **delivers** an authentication to whatever IP we pass as `LISTENER`; it does **not**
capture. So the operator runs the existing gated **`redness poison`** (Responder) at
`--listener <us>` first, then fires `redness coerce --target <dc> --listener <us>`. The
coerced NetNTLMv2 lands in that Responder listener and flows through the **identical existing
pipeline**: `parse_responder_log` -> `build_findings` (`netntlm-captured`) -> `crack.py`
(`netntlmv2`). This mirrors the `trigger`/`poison` split exactly - `coerce` fires the RPC,
`poison` captures.

- **No LLMNR/NBT-NS poisoning needed** (like `trigger`): coercion delivers auth straight to
  `LISTENER`. The poisoning-off `--capture-only` listen mode deferred in docs/NETNTLM.md would
  be the *cleaner* pairing for both `trigger` and `coerce`; until it lands, pair with full
  `poison`.
- **Capture stays a separate command** (`coerce` does not spawn Responder) - same clean seam
  the NetNTLM docs established. An integrated `--capture` (start listener + coerce in one) is a
  possible later enhancement, **deferred**.

## The honest limitation: capture-only, no relay
Coercion's real payoff is **relay** (coerce `DC$` -> relay to LDAP / **ADCS ESC8** -> Domain
Admin), which REDNESS **deliberately does not do** (docs/NETNTLM.md; docs/ROADMAP.md "Not
doing"). Capture-only coercion of a DC yields a **machine-account** NetNTLMv2 (`DC01$`) whose
password is random ~120 chars - **not crackable**. So this feature's deliverable is
**detecting and demonstrating the coercion vulnerability** (a legit, PingCastle-grade report
finding), *not* obtaining a usable credential. The captured hash is **proof-of-coercion**, not
loot. This is consistent with the relay decision: we surface the finding, we don't weaponize
it.

## Findings to emit
`coerce` emits the **vulnerability** findings; the captured-hash finding (`netntlm-captured`,
HIGH) still comes from the `poison` listener, not from here.

| id | severity | when | remediation (per-vector) |
|----|----------|------|--------------------------|
| `coercion-petitpotam` | **CRITICAL** if target is a DC, else **HIGH** | MS-EFSR coerced auth succeeded | patch KB5005413 + EFSRPC filtering; SMB signing + LDAP channel-binding/EPA |
| `coercion-printerbug` | **CRITICAL** if DC, else **HIGH** | MS-RPRN (spooler) coerced | disable the Print Spooler on DCs/servers |
| `coercion-dfscoerce` | **CRITICAL** if DC, else **HIGH** | MS-DFSNM coerced | apply DFS coercion patches; signing/EPA |
| `coercion-shadowcoerce` *(optional)* | **HIGH** | MS-FSRVP coerced | disable VSS-over-SMB / FSRVP |

**Per-vector ids** (not one aggregated `coercion-possible`) because the remediation genuinely
differs per vector - a spooler-disable does not fix PetitPotam. Evidence on each carries the
method + the `LISTENER` IP the auth hit. **DC targets are CRITICAL**: coercing `DC$` is the
relay->ADCS-ESC8/LDAP->DA primitive - the reason these CVEs are severe - even though we don't
relay; non-DC hosts are HIGH. All reuse **`Category.CONFIG`** - **no `findings.py` schema
change / no `SCHEMA_VERSION` bump**. **No `meta["credentials"]`** (coerce recovers no usable
credential). **References:** MITRE **T1187** (Forced Authentication) + the per-vector CVEs.

## Safety / gating (CLI double-gate + DC validation - not the HTTP arm/confirm)
This is an **operator-run CLI command** (like `poison`/`spray`/`trigger`), not a right-click
node action, so it uses the **CLI gate**, not the GUI `/action` arm/confirm channel (that
exists for browser-triggered node actions with no TTY). Two gates, both refuse **before any
RPC touches the target** (agreed in the pre-build security review, see docs/DECISIONS.md):

- **DC validation.** Coercion is **refused unless the target looks like a Domain Controller**
  (AD LDAP on 389/636 is DC-only), overridable with **`--target-not-dc-ok`** (findings then
  HIGH not CRITICAL). This catches fat-finger/wrong-host typos without over-restricting
  legitimate non-DC targets. The check is an injectable `dc_check` callable (LDAP port probe by
  default) - a non-AD LDAP server would be a false positive, hence the override. It is **not**
  a "must be a DC" restriction: coercing a member server / CA host is legitimate.
- **Uncredentialed double-gate.** Normal (credentialed) run = authorization banner naming
  target + listener -> `Type YES to coerce <target> to authenticate to <listener>` -> `--yes`
  to script (banner still prints to **stderr** in scripted mode). The riskier **uncredentialed**
  path (no `-u/-p`, relying on an unpatched target) is a safety refusal **overridden only by
  BOTH `--force` AND a second, distinct typed `FORCE` confirmation** that `--yes` never skips -
  exactly `spray`'s `--force` double-gate. Coercion has no lockout math, so `--force` guards the
  *uncredentialed* path rather than a lockout budget.
- **Target-scoped:** `--target` and `--listener` required; the coerced auth only goes to
  `--listener`. **Warning-only listener pre-flight** (see below).

## Method selection (`--method`, default all)
`--method` picks the coercion vector; default **`all`** (nxc `coerce_plus` runs its full set -
typically PetitPotam/PrinterBug/DFSCoerce and any others it supports). Full coverage is the
right default because *"which vectors are open"* is the deliverable finding. A single method
(`petitpotam` / `printerbug` / `dfscoerce` / `shadowcoerce`) is selectable to **limit detection
noise** on OPSEC-constrained engagements - `all` means several distinct-protocol RPC calls, each
a separate log/IDS signature on the target.

## Audit logging (`loot/coerce_audit.log`)
Every attempt is appended, one line per **method result** *and* per **refusal**, for
post-engagement blue-team **de-confliction** (ROADMAP Tier-3 precedent):

```
<ISO-8601-UTC> target=<t> listener=<l> method=<m> auth=<credentialed|uncredentialed> result=<coerced|not-vulnerable|no-output|refused-uncredentialed|refused-not-a-dc>
```

git-ignored (under `loot/`). A **unified** cross-command audit log (with offensive actions)
stays Gjoko's Tier-3 lane; this is the forward-compatible local start.

## Side effects / cleanup (stateless RPC - nothing to clean up)
The coercion RPCs leave **no persistent state** to undo:
- **PetitPotam (MS-EFSR)**, **PrinterBug (MS-RPRN)**, **ShadowCoerce (MS-FSRVP)** are transient
  calls (open-file / print-change-notification / VSS path query) - the target authenticates
  outbound and nothing is written or configured on it.
- **DFSCoerce (MS-DFSNM)** is the exception to watch: it calls DFS-namespace *management* RPCs
  (`NetrDfsAddStdRoot`/`RemoveStdRoot`). In practice the coercion fires because the target
  authenticates to reach the attacker path *before* the operation completes/errors, so a DFS
  root is generally **not** actually created - but it is the only vector invoking state-mutating
  admin RPCs. Verify `coerce_plus`'s method choice on Kali before trusting it in production.
- **All vectors** leave an **authentication / RPC event in the target's logs** (the machine
  account authenticating outbound) - a detection footprint, surfaced in the banner. Not
  persistent state; nothing to clean up.

## Pre-flight listener check: warning-only (no rate limiting)
Coercion depends on a listener (`redness poison`) already running at `--listener`, but we
**cannot reliably verify a listener on another machine** (and a naive TCP probe gives false
confidence). So the command prints an **unmissable reminder** ("a listener MUST be running at
`<listener>` - run `redness poison` there first; this command only TRIGGERS the auth") and
relies on the typed confirmation naming the listener. There is **no rate limiting**: coercing a
machine account carries no lockout/DoS risk on the target, and a CLI invocation is one
deliberate RPC per method - not an automatable channel like the HTTP arm endpoint.

## Structure (mirrors `poison`/`spray`)
- **`redness/engines/coerce.py`** (pure) - `parse_coerce_plus(stdout) -> [CoerceResult]`
  (negative-verdict-wins, first-seen order), `coerce_argv(host, listener, method=, auth...)`,
  `build_findings(results, *, target, is_dc, listener, credentialed)`. No `Engine` subclass,
  not a default engine.
- **`redness/coerce.py`** - `run_coerce(target, listener, *, method, auth..., target_not_dc_ok,
  force, confirm_force, nxc_run, dc_check, ...)`: gate (uncredentialed + DC) -> fire nxc
  `coerce_plus` -> parse -> `build_findings` -> `Report`; append the audit log; stream to the
  `EventBus` (target node, `coerced (<vector>)` edges, findings). `nxc_run`/`dc_check` injectable.
- **`cmd_coerce`** in `redness/cli.py` - args `--target`, `--listener`, auth (`-u/-p/-d/-H/-k`),
  `--method {all,petitpotam,printerbug,dfscoerce,shadowcoerce}` (default all),
  `--target-not-dc-ok`, `--force`, `--yes`, `--out/--json/--live`; banner (always to stderr) +
  listener reminder + uncredentialed block + `Type YES` + the `FORCE` double-gate.

## Dependencies
- **nxc** (Kali-native; already covered by `redness doctor`'s netexec check). A one-line
  `coerce` hint in `doctor` (reusing the netexec check). No crypto, no new dependency.
- A **listener** (`redness poison` / Responder) running at `--listener` to catch the auth -
  operator-run, same as `trigger`.

## Build order (done)
1. **DONE** - pure parser + findings: `parse_coerce_plus`, `build_findings`, `coerce_argv` +
   tests against captured `-M coerce_plus` output (DC->CRITICAL, non-DC->HIGH, per-vector ids,
   no coercion->no findings). No nxc/DC.
2. **DONE** - `run_coerce()` orchestrator (uncredentialed + DC gates, injectable `nxc_run`/
   `dc_check`, audit log) + `cmd_coerce` + argparse + banner/listener-reminder/double-gate.
3. **DONE** - docs: this note, DECISIONS entry, ROADMAP Tier-2 tick, CLAUDE.md refresh.

Deferred follow-ups: verify `coerce_plus` output/flags on Kali (the test fixture is the source
of truth); `poison --capture-only` listen mode (docs/NETNTLM.md) as the cleaner pairing; an
integrated `--capture` (coerce starts its own listener) - kept separate on purpose.

## Legal / ethics
Coercion actively forces **another machine** (often a DC) to authenticate to us over RPC. Run
only against targets you are **explicitly authorized** to test, within the agreed scope and
window. It is active exploitation, not enumeration; treat it accordingly.
