"""Scope parsing + scan orchestration tests — no nxc/certipy/DC required.

Run:  python tests/test_scope_and_scan.py    (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness import scope  # noqa: E402
from redness.scan import run_scan  # noqa: E402
from redness.engines.base import Engine, Target  # noqa: E402
from redness.events import EventBus, EventKind  # noqa: E402
from redness.findings import Category, Finding, Severity  # noqa: E402


# --- scope parsing --------------------------------------------------------- #
def test_parse_scope_comments_blanks_dedupe():
    text = """
    # header comment
    10.0.0.1        # DC
    dc01.acme.local

    10.0.0.1        # duplicate -> dropped
    10.0.0.0/24
    """
    assert scope.parse_scope(text) == ["10.0.0.1", "dc01.acme.local", "10.0.0.0/24"]


def test_merge_targets_single_plus_file(tmp_path=None):
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
        fh.write("10.0.0.2\n10.0.0.3  # host\n")
        path = fh.name
    try:
        merged = scope.merge_targets("10.0.0.1", path)
        assert merged == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    finally:
        os.unlink(path)


# --- fake engines for the orchestrator ------------------------------------- #
class _FakeEngine(Engine):
    name = "fake"

    def is_available(self):
        return True

    def run(self, target: Target):
        return [Finding(
            id="smb-signing-not-required", title="SMB signing not required",
            severity=Severity.MEDIUM, category=Category.SMB, affected=[target.host],
            credentialed=target.credentialed,
        ), Finding(
            id="smb-writable-share", title="Writable share",
            severity=Severity.HIGH, category=Category.SMB,
            affected=[f"{target.host}\\backups"],
        )]


class _MissingEngine(Engine):
    name = "missing"

    def is_available(self):
        return False

    def run(self, target: Target):
        raise AssertionError("must not run an unavailable engine")


def test_run_scan_aggregates_findings():
    report = run_scan(["10.0.0.1", "10.0.0.2"], engines=[_FakeEngine()], engagement="T")
    assert len(report.findings) == 4                 # 2 findings x 2 hosts
    assert report.target == "10.0.0.1, 10.0.0.2"


def test_run_scan_skips_unavailable():
    report = run_scan(["10.0.0.1"], engines=[_MissingEngine(), _FakeEngine()])
    assert len(report.findings) == 2                 # only the available engine ran


def test_run_scan_streams_graph():
    seen = []
    bus = EventBus()
    bus.subscribe(seen.append)
    run_scan(["10.0.0.1"], engines=[_FakeEngine()], bus=bus)
    kinds = [e.kind for e in seen]
    assert EventKind.NODE in kinds                   # domain + host + share nodes
    assert EventKind.EDGE in kinds
    assert EventKind.FINDING in kinds
    assert EventKind.PROBE in kinds
    assert kinds[-1] is EventKind.DONE
    # the writable-share finding should have spawned a 'share' node
    share_nodes = [e for e in seen if e.kind is EventKind.NODE and e.data.get("type") == "share"]
    assert any("backups" in e.data["id"] for e in share_nodes)


def test_run_scan_engine_error_is_contained():
    class _Boom(Engine):
        name = "boom"
        def is_available(self): return True
        def run(self, t): raise RuntimeError("kaboom")
    # should not raise; just yields no findings from the boom engine
    report = run_scan(["10.0.0.1"], engines=[_Boom(), _FakeEngine()])
    assert len(report.findings) == 2


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
