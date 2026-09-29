# REDNESS GUI - design & roadmap

> The vision: **everything in one place** - a branded, retro-futuristic control surface
> where you scan, watch the 3D graph, click a result, and right-click a target to launch
> further enumeration or attacks (Kerberoast, secretsdump, pass-the-hash, DCSync, ...).
> Native window on Windows/Linux, or browser. This note is the north star; build it in
> phases. Branding/authors are fixed (see below); don't rename without the owners' say.

## Native window vs browser (decided)
One UI, two front ends - **no rewrite**:
- **`redness gui`** -> a **native desktop window** via **pywebview** (Windows: Edge WebView2,
  already present on Win10/11; Linux/Kali: WebKitGTK). Same HTML/JS/3D-graph we already have.
  `pip install ".[gui]"` adds pywebview; without it, `gui` falls back to the browser.
- **`redness live`** -> the same UI in a browser.
- **`redness scan --live`** -> drive from the CLI, watch in either.

Rejected: Qt/PySide (full rewrite, and the 3D graph would need an embedded webview anyway),
Electron/Tauri (Node toolchain, heavy). pywebview reuses everything.

## Branding (fixed)
- Name/version: **REDNESS v1.33.7**
- Line: **Zero Science Lab | powered by Silly Security Inc.**
- Authors: **Anja Ivanovska & Gjoko Krstic** - anja@zeroscience.mk | gjoko@zeroscience.mk
- Logo: `web/logo.svg` (swap the placeholder for the real ZeroScience mark).
- **About** and **Usage** modals live in the HUD (shipped). Bump the version string in
  `web/index.html` (`#ver`, the About card) and `pyproject.toml` together on release.

## Look & feel
Dark, neon-accent, monospace, "not hackerish" - modern/retro-futuristic. Nodes colored by
finding severity. Future: OS-adaptive, more organic/smooth animations & node shapes
(different per platform) - deferred, we'll iterate.

## The big one: right-click actions ("further attacks in one place")
The graph already emits node events and the bridge already accepts an authenticated POST
(`/scan`). Generalize that into an **action** channel:

```
right-click a node -> context menu (per node type) -> POST /action {token, action, target, creds}
                       ^                                        |
   results stream back to the graph/log <-- EventBus <-- run the matching engine/attack
```

- **Bridge:** add `POST /action` (same CSRF-token gate as `/scan`) -> dispatch to an
  `on_action(params)` handler -> run the engine -> stream `status/finding/node/edge` back.
- **Front end:** `Graph.onNodeRightClick(node => showMenu(node))`; menu items depend on
  `node.type` (host / user / share / template / domain).
- **Engines:** each action maps to an existing tool capability (anjaiv's area). Keep the
  pure-parser + injectable-subprocess pattern; add a `Finding` (+ loot) like everything else.

### Action catalog (adscan-style parity - build incrementally)
| Node | Action | Backed by |
|------|--------|-----------|
| host | enumerate shares / sessions / loggedon | nxc smb |
| host | secretsdump (SAM/LSA/NTDS) | impacket secretsdump |
| host | pass-the-hash exec / spray | nxc `-H` |
| host | coerce (PetitPotam/PrinterBug) -> relay | impacket (Phase 2) |
| user | Kerberoast / AS-REP roast this account | nxc / impacket -> crack.py |
| user | shadow credentials / targeted Kerberoast | certipy / impacket |
| domain | DCSync | impacket secretsdump `-just-dc` |
| domain | BloodHound collection | nxc `--bloodhound` |
| template/CA | ADCS ESC abuse (request cert) | certipy req/auth |
| any | add to scope / re-scan / open in report | internal |

## Phased roadmap
1. **Done** - branded GUI (logo, version, tagline), About + Usage modals, `redness gui`
   native window (pywebview + browser fallback), in-tool Usage reference.
2. **Done** - read-only right-click enum. `redness/actions.py` registry + token-gated
   `POST /action` + `GET /actions`; the graph's `onNodeRightClick` builds a per-node-type
   menu (host/domain -> Enumerate SMB / LDAP / AD CS / TLS) that runs the matching engine
   against that target and streams results back. This is the channel every Phase 3 action
   plugs into - add an `Action(..., offensive=True)` with its gating.
3. **Offensive actions** - Kerberoast/AS-REP/secretsdump/PtH/DCSync, each **gated** like
   `poison` (confirmation, authorization banner) and streamed to loot/report/graph.
4. **Parity & polish** - RBCD, gMSA, shadow creds, NTLM relay/coercion (Phase 2 of NETNTLM),
   result detail panels, click-through evidence, export.
5. **Future** - OS-adaptive animations/forms, wiki docs (usage/examples), themes.

## Docs
- In-tool **Usage** modal (shipped) - quick command reference.
- Future: a GitHub **wiki** (usage, examples, per-action walkthroughs) linked from About/Usage.
- CLI `-h` on every command stays the source of truth for flags.

## Safety
Offensive right-click actions are intrusive - gate each exactly like `poison`
(confirmation + authorization banner), bind the bridge to `127.0.0.1`, keep the CSRF token.
Authorized, in-scope engagements only. Never auto-run an attack from a node click without
an explicit confirm.

## Ownership
GUI shell / action plumbing / bridge = the reporting side; the attack **engines** behind
each action = anjaiv (engines/). Agree the `/action` params shape + each action's `Finding`
before wiring, same as the crack.py contract in docs/NETNTLM.md.
