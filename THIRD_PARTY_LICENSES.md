# Third-party licenses

REDNESS is a red-team **orchestrator**: it drives existing tools rather than
reimplementing them. This file records the license obligations for third-party
components, split by how REDNESS uses each one, because that distinction determines
what applies.

REDNESS itself is licensed under **BSD 2-Clause** (see `LICENSE`).

---

## 1. Redistributed code (obligations apply to REDNESS distributions)

These are shipped inside this repository and/or the self-contained PyInstaller
executable (`packaging/redness-full.spec` -> `redness-full.exe`). Their notices must
travel with any REDNESS distribution.

### Vendored in the repository
| Component | License | Where |
|-----------|---------|-------|
| **3d-force-graph** (Vasco Asturiano) | MIT | `redness/live/web/vendor/3d-force-graph.min.js` |
| -> bundles **three.js** (three.js authors) | MIT | (inside the minified file) |
| -> bundles **d3-force / d3-* modules** (Mike Bostock) | ISC / BSD-3-Clause | (inside the minified file) |

The full MIT text and copyright for the vendored bundle live alongside it in
`redness/live/web/vendor/3d-force-graph.LICENSE.txt`.

### Bundled into `redness-full.exe` (only when that self-contained exe is built/shipped)
| Component | License | Note |
|-----------|---------|------|
| **certipy-ad** (ly4k) | MIT | reproduce the MIT notice in the distribution |
| **impacket** (Fortra / SecureAuth) | Apache-1.1 (modified "Impacket" license) | reproduce its NOTICE / copyright header |
| **ldap3** (Giovanni Cannata) | **LGPL-3.0** | copyleft-lite: a frozen exe must honor the LGPL relink / offer-source obligation for this library |
| python-docx | MIT | base dependency, also present in the lean build |
| pywebview (optional `[gui]`) | BSD-3-Clause | only if the GUI extra is bundled |

> **LGPL note (ldap3).** LGPL-3.0 permits use in a larger work, but if we distribute
> a binary that statically embeds ldap3 (which PyInstaller effectively does), we must
> enable the recipient to relink against a modified ldap3 - in practice: provide the
> ldap3 source (or object files) and the LGPL text, or link it dynamically. The lean
> `packaging/redness.spec` build avoids this by expecting `nxc`/`certipy` on PATH and
> bundling nothing.

---

## 2. Invoked as separate programs (mere aggregation - no derivative-work obligation)

REDNESS calls these via `subprocess` as standalone tools the operator installs
separately. Running a separate program does not create a derivative work, so their
licenses (including the GPL ones) do **not** propagate to REDNESS - **provided they are
never bundled into a REDNESS binary.**

| Tool | License | Invoked by |
|------|---------|-----------|
| **NetExec** (`nxc`) | BSD-2-Clause | engines/netexec, ldap, gpp, remote, spray |
| **Responder** | **GPL-3.0** | `redness poison` (never bundle) |
| **hashcat** | MIT | `redness/crack.py` |
| **John the Ripper** (jumbo) | GPL-2.0 (+ other) | `redness/crack.py` (never bundle) |

**Hard rule:** do not bundle Responder or John the Ripper (GPL) into `redness-full.exe`
or any distributed REDNESS binary - that would force the whole distribution under the
GPL. Keep them subprocess-only.

---

## Maintenance
When adding a dependency, record it here and decide up front: **bundled** (obligations
apply - especially avoid new GPL in the exe) or **invoked** (aggregation, keep it
external). Verify each license from the upstream project before shipping a release;
the summaries above are a maintenance aid, not legal advice.
