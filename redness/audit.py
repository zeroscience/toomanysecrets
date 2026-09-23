"""Unified audit log - one timestamped timeline of every sensitive operation.

Blue teams (and our own de-confliction) want a single file that answers "what did REDNESS do,
against what, and when?" This is that file: `loot/audit.log`, one JSON object per line
(JSONL - greppable and machine-readable). Every gated/active surface writes here:

  * `scan`   -> scan-start / scan-done
  * `poison` -> poison-start / poison-done
  * `spray`  -> spray-start / spray-done
  * `coerce` -> coerce (per attempt; a detailed per-vector sidecar also lives in coerce_audit.log)
  * offensive right-click actions -> arm / execute / result / refuse (redness/actions.py)

Writing is best-effort: an unwritable loot/ never breaks a scan (mirrors the EventBus rule).
Records are structured data written by us, but the log itself may capture attacker-controlled
strings (hostnames, share names) - treat it as data if you ever read it back.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Callable, Optional

AUDIT_LOG = "audit.log"          # basename inside the loot dir
DEFAULT_LOOT_DIR = "loot"


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append(loot_dir: str, rec: dict) -> None:
    """Append one JSONL record to <loot_dir>/audit.log. Best-effort; swallows I/O errors."""
    try:
        os.makedirs(loot_dir, exist_ok=True)
        with open(os.path.join(loot_dir, AUDIT_LOG), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def record(event: str, *, loot_dir: str = DEFAULT_LOOT_DIR,
           sink: Optional[Callable[[dict], None]] = None, **fields) -> dict:
    """Build a `{ts, event, **fields}` record and log it.

    With `sink` given (tests, or a bridge that captures records), the record is handed to the
    sink instead of being written to disk - the exact same dict either way. Returns the record.
    """
    rec = {"ts": _iso_now(), "event": event, **fields}
    if sink is not None:
        sink(rec)
    else:
        _append(loot_dir, rec)
    return rec
