# AD CS ESC8 offensive action - deliberately unbuilt (coordination needed)

> Status: **NOT BUILT - blocked on coordination with Gjoko (issue #60).** The other three
> Phase-3 catalog actions (`asrep-roast`, `adcs-esc1`, `pth-exec`) shipped on
> `feat/offensive-catalog-2`; `adcs-esc8` was deliberately held. This note records *why* and
> the open questions, so the decision isn't silently lost. Read `docs/COERCION.md`,
> `docs/NETNTLM.md`, and `redness/relay.py` first.

## Why it's not just another catalog action
Unlike ESC1 (a direct, creds-based `certipy req` - one actor, request/response, fits the
arm/execute `/action` channel), **executing ESC8 is live NTLM relay**:

1. stand up a relay server targeting `http://<ca>/certsrv/certfnsh.asp` for a
   `DomainController`/`Machine` template,
2. coerce a DC to authenticate to it (our `redness coerce`),
3. the relay obtains a certificate for `DC$`,
4. `certipy auth` -> `DC$` hash / TGT -> DCSync -> Domain Admin.

That is a **two-actor, long-running** operation (a server that waits for the coerced auth) -
shaped like `poison`/`coerce` (a gated CLI command), **not** a snappy right-click `/action`.

## The blocker: it reopens a standing decision
Live NTLM relay is **explicitly "Not doing"** - `docs/NETNTLM.md` dropped ntlmrelayx relay as
"too heavy/intrusive," and `docs/ROADMAP.md` lists it under *Not doing (decided)*. Building an
executing `adcs-esc8` **reverses that documented decision**, so it needs an explicit
`DECISIONS.md` entry and sign-off - it is not a quiet code change.

**`relay.py` cannot execute it.** `redness/relay.py` is pure *derivation*: it reads findings
(`coercion-*`, `adcs-web-enrollment`, `smb-signing-not-required`) and draws the
coercion -> relay -> ESC8 -> DA **chain on the graph** + a report finding. It stands up no relay
server. So ESC8 execution can only *compose with* the map relay.py already draws, not reuse it.

## Options (the A/B/C decision for #60)
- **A - Execute via `certipy relay`, as a gated CLI command.** `certipy relay` is the
  ADCS-scoped, single-command alternative (much narrower than general `ntlmrelayx`). Ships as a
  `poison`/`coerce`-style command (not an `ACTIONS[...]` entry). Emits `adcs-esc8-abused`
  (CRITICAL, `meta["credentials"]` = `DC$` NT hash). **Requires a `DECISIONS.md` entry scoping
  the no-relay reversal to "ADCS ESC8 via certipy's own relay only."** Most intrusive capability
  in the tool; payoff is a *complete* DC takeover (the cert is usable via `certipy auth`, unlike
  coerce's capture-only machine hash).
- **B - Don't execute; keep ESC8 as detection + relay-map (honor no-relay).** ESC8 is already
  *detected* (`adcs-web-enrollment`) and *mapped* (`relay.py`). Drop the executing action; the
  catalog is `asrep-roast` + `adcs-esc1` + `pth-exec`. Cleanest, zero new risk.
- **C - Non-executing stage-helper action.** Live-confirms `/certsrv` is still relay-vulnerable
  and emits the exact `certipy relay` / `redness coerce` commands to run - guidance, not a
  takeover. Weakest value; stays within no-relay.

## Open coordination questions for Gjoko (contract-first, #60)
1. **Policy:** do we reverse/scope the no-relay decision for ESC8 (option A), or hold the line
   (B)? This is a shared call - `relay.py` and the relay policy are Gjoko's lane.
2. **Shape:** if A, it's a long-running gated **command**, not a right-click `/action` - agreed?
3. **relay.py / background state:** does an executed `adcs-esc8-abused` feed the existing relay
   map, and who owns that wiring?
4. **Finding contract:** `adcs-esc8-abused` (CRITICAL, `meta["credentials"]` DC$ hash) - confirm
   the shape before coding, same as every other `/action` / findings contract.

Until 1-4 are agreed on #60, `adcs-esc8` stays unbuilt.
