"""Node-action registry + run_action — no external tools/DC needed.

Run:  python tests/test_actions.py    (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness import actions  # noqa: E402
from redness.engines.base import Engine, Target  # noqa: E402
from redness.events import EventBus, EventKind  # noqa: E402
from redness.findings import Category, Finding, Severity  # noqa: E402


def test_catalog_and_node_types():
    ids = {a["id"] for a in actions.catalog()}
    assert {"enum-smb", "enum-ldap", "enum-adcs", "enum-tls"} <= ids
    host_ids = {a.id for a in actions.actions_for("host")}
    assert "enum-smb" in host_ids and "enum-tls" in host_ids
    # Phase 2 is read-only: no offensive actions, and user nodes get none yet.
    assert all(not a["offensive"] for a in actions.catalog())
    assert actions.actions_for("user") == []


class _FakeEng(Engine):
    name = "fake"

    def is_available(self):
        return True

    def run(self, target: Target):
        return [Finding(id="enum-smb-shares", title="shares",
                        severity=Severity.INFO, category=Category.ENUM,
                        affected=[f"{target.host}\\backups"])]


def _with_test_action(fn):
    actions.ACTIONS["_test"] = actions.Action("_test", "Test", ("host",), _FakeEng)
    try:
        return fn()
    finally:
        actions.ACTIONS.pop("_test", None)


def test_run_action_streams_and_returns_report():
    def body():
        seen = []
        bus = EventBus()
        bus.subscribe(seen.append)
        report = actions.run_action("_test", "10.0.0.1", domain="acme.local", bus=bus)
        assert len(report.findings) == 1
        kinds = [e.kind for e in seen]
        assert EventKind.NODE in kinds and EventKind.FINDING in kinds
        assert kinds[-1] is EventKind.DONE
        # the share affected id should have spawned a node
        assert any(e.kind is EventKind.NODE and "backups" in e.data.get("id", "") for e in seen)
    _with_test_action(body)


def test_unknown_action_is_safe():
    bus = EventBus()
    seen = []
    bus.subscribe(seen.append)
    report = actions.run_action("does-not-exist", "10.0.0.1", bus=bus)
    assert report.findings == []
    assert any(e.kind is EventKind.STATUS for e in seen)


def test_unavailable_engine_skips_gracefully():
    class _MissingEng(Engine):
        name = "missing"
        def is_available(self): return False
        def run(self, t): raise AssertionError("must not run")
    actions.ACTIONS["_miss"] = actions.Action("_miss", "Miss", ("host",), _MissingEng)
    try:
        report = actions.run_action("_miss", "10.0.0.1")
        assert report.findings == []
    finally:
        actions.ACTIONS.pop("_miss", None)


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
