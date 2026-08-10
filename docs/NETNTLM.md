# NetNTLMv2 capture engine — design note

> Status: **design only, not built.** This is the intrusive "capture a hash by
> poisoning" feature. Owner: **anjaiv** (engines area). Read `CLAUDE.md` and
> `docs/DECISIONS.md` first, then this. Coordinate with the repo owner before coding —
> especially the `crack.py` meta contract below.

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
- **[ntlmrelayx](https://github.com/fortra/impacket)** (impacket) — *relay* instead of
  capture (SMB/LDAP/HTTP). **Phase 2**; start with capture only.

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

## Build order (suggested)
1. Pure parser: `parse_responder_log(text) -> list[(account, netntlmv2_hash)]` + tests
   against a captured `Responder-Session.log` sample. (No root, no network.)
2. `crack.py`: add the two `netntlmv2` map entries (+ a test).
3. `redness poison` command: subprocess Responder, tail its logs, emit findings/graph,
   confirmation + duration + iface gating.
4. `doctor`: add the `responder` availability check.
5. Docs: DECISIONS entry; a note in CLAUDE.md "Next up".

## Legal / ethics
Poisoning coerces authentication from **other machines** on the LAN. Run only on a
network you are **explicitly authorized** to test, within the agreed scope and window.
