# Unified audit log - `loot/audit.log`

Every sensitive or active operation REDNESS runs appends a structured record to a single file,
so you (and a client's blue team) can answer **"what did the tool do, when, and against what?"**
from one place - useful for de-confliction during an engagement and for the report appendix.

## Where and what
- **File:** `loot/audit.log` (the `loot/` dir is git-ignored - it never reaches the repo).
- **Format:** JSONL - one JSON object per line, e.g.
  ```json
  {"ts": "2026-09-23T14:02:11Z", "event": "scan-start", "engagement": "acme", "targets": 12, "credentialed": true, "live": false}
  {"ts": "2026-09-23T14:07:48Z", "event": "scan-done", "engagement": "acme", "findings": 34}
  ```
- **Fields are params only, never secrets** - counts, booleans (`credentialed`), interface/target
  names. No passwords, hashes, or captured material ever land here.

## Events by surface
| command | events |
|---|---|
| `scan` | `scan-start`, `scan-done` |
| `poison` | `poison-start`, `poison-done` |
| `spray` | `spray-start`, `spray-done` |
| `coerce` | `coerce` (one per vector attempt/refusal) |
| offensive right-click actions | `arm`, `execute`, `refuse`, `result` |

`coerce` also keeps a detailed, human-readable per-vector sidecar at `loot/coerce_audit.log`; the
unified `audit.log` is the cross-surface timeline.

## Reading it
```bash
# everything, oldest first
cat loot/audit.log

# just the offensive actions
grep -E '"event": *"(arm|execute|result|refuse)"' loot/audit.log

# pretty-print with jq
jq -c '{ts,event,target,engagement}' loot/audit.log
```

Writes are best-effort: if `loot/` can't be written, the operation still runs (the audit log
never breaks a scan, same rule as the live-graph EventBus).
