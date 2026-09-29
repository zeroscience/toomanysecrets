# Live 3D graph during enumeration - design note

> Future GUI phase. This note exists so we build toward it now instead of
> retrofitting later. The seam is already in the codebase: `redness/events.py`.

## The idea
While REDNESS enumerates, show a live, animated 3D graph: the domain at the center,
hosts / users / shares / CA templates spawning as nodes, edges lighting up as each
protocol is probed, nodes flaring red the instant a misconfig (ESC1, SMB signing,
AS-REP...) is confirmed. It's a scan you can *watch*.

## Why it's cheap to support (we already did the hard part)
Every engine normalizes to `Finding` and can **stream** events onto an `EventBus`
(`redness/events.py`) as work happens - status, probe, node, edge, finding, done.
The engines know nothing about any UI. So the *same* stream that renders the `.docx`
report can drive a live view. Nothing about the batch pipeline changes.

```
  engines  --emit-->  EventBus  --+--> docx reporter   (batch, today)
   (nxc,                          |
    certipy, ...)                 +--> live bridge  --ws-->  3D GUI  (later)
```

## Data model (already emitted)
| Event  | Fields | Graph meaning |
|--------|--------|---------------|
| NODE   | id, label, type, meta | a domain / host / user / share / template / CA |
| EDGE   | src, dst, label | relationship or "which ESC/finding links them" |
| PROBE  | target, test | *currently testing X* -> pulse/animate that node |
| FINDING| finding (dict) | color the node by `severity`; open a detail card |
| STATUS | message | log line / progress toast |
| DONE   | engine | stop the spinner for that engine |

Node `type` -> color/shape; `finding.severity` -> node emissive color
(critical=deep red ... info=grey, matching the report's palette).

## Recommended stack (when we build it)
- **Transport:** a thin bridge subscribes to the bus and pushes events as JSON frames
  over **WebSocket** (or SSE). Python side: `websockets`/`fastapi`. Keep it one file.
- **Renderer:** **[3d-force-graph](https://github.com/vasturiano/3d-force-graph)**
  (three.js + d3-force under the hood) - purpose-built for exactly this: incremental
  `graphData` updates, node coloring, link particles for the "probe" animation.
  Alternative: **react-three-fiber** if the GUI goes React.
- **Packaging:** ship the GUI as a local web app the `.exe` serves on `127.0.0.1`,
  or wrap with **pywebview** / Tauri for a desktop window. Decide at GUI phase.

## Build order (later)
1. `redness/live/bridge.py` - subscribe to `default_bus`, serve events over WS.
2. `redness/live/web/` - static `3d-force-graph` page consuming the WS.
3. `redness.cli live` - run an enum with the bridge on, open the browser.

## Guardrails
- The bus swallows subscriber exceptions (`EventBus.publish`) - a broken UI can never
  break a scan.
- No engagement data leaves localhost; the WS binds `127.0.0.1` only.
- Live view is a convenience layer; the authoritative output stays the `.docx` report.

## Status today
Seam shipped: `events.py` + `Engine.emit_*` helpers, and `CertipyEngine` emits
status/probe/node/edge/finding/done.

**Working prototype shipped** (`redness/live/`):
- `bridge.py` - stdlib SSE server + capped replay buffer, binds 127.0.0.1.
- `web/index.html` - 3d-force-graph page: nodes by type, recolor by finding severity,
  probe pulses, live log, auto-fit camera.
- `demo.py` - simulated enumeration that streams a realistic AD sweep.
- CLI: `python -m redness.cli live` (`--loop`, `--no-open`, `--port`).
- Verified end-to-end in a browser (SSE connected, WebGL live, 10 nodes/9 edges/5 findings).

**Done:**
1. ~~Vendor `3d-force-graph` locally~~ - `redness/live/web/vendor/3d-force-graph.min.js`
   (v1.80.0, bundles three.js). Page loads it from `/vendor/...`; fully offline.
2. ~~Add `redness/live/web/` to the PyInstaller spec `datas`~~ - bundled; `bridge._web_dir()`
   is frozen-aware (`sys._MEIPASS`). Verified: `dist/redness.exe live` serves index +
   vendored JS + SSE from inside the exe, renders in-browser (10 nodes/9 edges/5 findings).

**Still TODO:**
3. Wire the *real* engines (not just `demo`) to a bus + a `live` real scan.

## GUI phase - captured requirements (from the field)
- **Branding:** ZeroScience lab logo in the HUD header (drop an SVG/PNG into
  `redness/live/web/` and reference it; it'll bundle via the same `datas` walk).
- **Scope input:** load a `.txt` with **one IP / CIDR / host per line** as the target
  set to enumerate (ignore blank lines and `#` comments). This feeds the real-scan
  path (TODO #3) - a `--targets examples/scope.txt` flag on a future `scan`/`live` real run, and
  a file picker in the GUI. Keep parsing in one small helper so CLI + GUI share it.
