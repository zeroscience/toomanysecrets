# Retest diff - `redness diff`

After a client remediates, a retest has to answer one question: **what moved?** `redness diff`
compares two `findings.json` snapshots and classifies every finding, so you can show exactly what
was fixed, what is still open, and what got worse.

## Usage
```bash
# 1. baseline scan (keep the JSON)
redness scan --targets examples/scope.txt -u USER -p PASS -d acme.local --json baseline.json

# ... client remediates ...

# 2. retest scan
redness scan --targets examples/scope.txt -u USER -p PASS -d acme.local --json retest.json

# 3. diff them
redness diff baseline.json retest.json                 # operator summary to stdout
redness diff baseline.json retest.json --json diff.json # machine-readable delta too
```

## What you get
Each finding lands in exactly one bucket:

| bucket | meaning |
|---|---|
| **new** | present now, absent in the baseline - a regression or newly-found issue |
| **fixed** | present in the baseline, gone now - remediated |
| **unchanged** | present in both at the same severity - still open |
| **changed** | present in both but the severity moved (records the old severity) |

Identity is `(finding id, sorted affected assets)`: the same issue on the **same** host/account is
the same finding; the same issue on a **different** host is correctly counted as one new + one
fixed, not "unchanged".

## Exit code
`diff` exits **`2`** when the retest **regressed** - any new finding, or any severity increase -
and `0` otherwise. That lets a retest gate a pipeline:
```bash
redness diff baseline.json retest.json || echo "regressions found"
```

Pure over the findings model - no tools or network needed to diff two saved reports.
