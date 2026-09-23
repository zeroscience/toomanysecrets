"""Unified audit log: structured JSONL, best-effort writes, and cross-surface wiring."""
import json
import os
import tempfile

from redness import audit


def _read_log(loot_dir):
    with open(os.path.join(loot_dir, audit.AUDIT_LOG), encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_record_to_sink_returns_dict_and_skips_disk():
    d = tempfile.mkdtemp()
    got = []
    rec = audit.record("scan-start", loot_dir=d, sink=got.append, targets=3)
    assert rec["event"] == "scan-start" and rec["targets"] == 3 and "ts" in rec
    assert got == [rec]
    assert not os.path.exists(os.path.join(d, audit.AUDIT_LOG))   # sink bypasses disk


def test_record_appends_jsonl_to_audit_log():
    d = tempfile.mkdtemp()
    audit.record("scan-start", loot_dir=d, engagement="acme", targets=2)
    audit.record("scan-done", loot_dir=d, engagement="acme", findings=7)
    rows = _read_log(d)
    assert [r["event"] for r in rows] == ["scan-start", "scan-done"]
    assert rows[0]["targets"] == 2 and rows[1]["findings"] == 7
    assert rows[0]["ts"].endswith("Z")                            # ISO8601 UTC


def test_record_is_best_effort_on_unwritable_loot_dir():
    # a regular file where the loot dir should be: makedirs raises OSError, swallowed
    fd, path = tempfile.mkstemp()
    os.close(fd)
    rec = audit.record("scan-start", loot_dir=path, targets=1)    # must not raise
    assert rec["event"] == "scan-start"


def test_offensive_actions_default_to_unified_log():
    # actions._audit with no injected sink writes an arm record to loot/audit.log
    import redness.actions as actions
    d = tempfile.mkdtemp()
    cwd = os.getcwd()
    try:
        os.chdir(d)                                              # loot/ is relative to cwd
        actions._audit(None, "arm", action="kerberoast-user", target="svc")
        rows = _read_log("loot")
    finally:
        os.chdir(cwd)
    assert rows and rows[0]["event"] == "arm" and rows[0]["action"] == "kerberoast-user"


def test_coerce_also_writes_unified_record():
    from redness.coerce import _audit
    d = tempfile.mkdtemp()
    _audit(d, "10.0.0.5", "10.0.0.240", "petitpotam", credentialed=True, result="coerced")
    # detailed sidecar still written...
    with open(os.path.join(d, "coerce_audit.log"), encoding="utf-8") as fh:
        assert "method=petitpotam" in fh.read()
    # ...and a structured record lands in the unified log
    rows = _read_log(d)
    assert rows[0]["event"] == "coerce" and rows[0]["method"] == "petitpotam"
    assert rows[0]["result"] == "coerced" and rows[0]["credentialed"] is True


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            passed += 1
    print(f"{passed} passed")
