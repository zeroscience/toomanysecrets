"""Service-discovery dispatch - pure logic + run_scan gating, no real sockets.

`open_ports` takes an injectable `checker`; `run_scan` takes an injectable `port_scanner`.
Run:  python tests/test_discovery.py   (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness import discovery  # noqa: E402
from redness.discovery import ENGINE_PORTS, open_ports, should_run  # noqa: E402
from redness.engines.base import Engine, Target  # noqa: E402
from redness.findings import Category, Finding, Severity  # noqa: E402
from redness.scan import run_scan  # noqa: E402


def test_should_run_gating():
    assert should_run("netexec", {445}) is True
    assert should_run("netexec", {3389}) is False          # SMB engine, only RDP open
    assert should_run("rdp", {3389}) is True
    assert should_run("winrm", {5986}) is True             # either winrm port counts
    assert should_run("mssql", set()) is False             # nothing open


def test_ungated_engine_always_runs():
    # an engine we do not know the ports for (e.g. a future UDP/SNMP engine) is never gated
    assert "snmp" not in ENGINE_PORTS
    assert should_run("snmp", set()) is True


def test_open_ports_uses_injected_checker():
    listening = {445, 389}

    def fake(host, port, timeout):
        return port in listening

    got = open_ports("10.0.0.1", [445, 389, 3389, 1433], checker=fake)
    assert got == {445, 389}


def test_open_ports_empty_when_nothing_listens():
    assert open_ports("10.0.0.1", [445, 1433], checker=lambda h, p, t: False) == set()


def test_describe_is_readable():
    assert discovery.describe({445, 3389}) == "445(smb), 3389(rdp)"
    assert discovery.describe(set()) == "none"


# --- run_scan dispatch ----------------------------------------------------- #
class _Spy(Engine):
    def __init__(self, name):
        self.name = name
        self.ran = False

    def is_available(self):
        return True

    def run(self, target: Target):
        self.ran = True
        return [Finding(id=f"{self.name}-f", title=self.name,
                        severity=Severity.INFO, category=Category.ENUM, affected=[target.host])]


def test_run_scan_dispatches_by_open_ports():
    smb, rdp, mssql = _Spy("netexec"), _Spy("rdp"), _Spy("mssql")
    run_scan(["10.0.0.1"], engines=[smb, rdp, mssql],
             port_scanner=lambda h: {445, 3389})           # 1433 closed
    assert smb.ran and rdp.ran
    assert not mssql.ran                                    # gated out: no MSSQL port


def test_run_scan_no_discovery_runs_all():
    smb, mssql = _Spy("netexec"), _Spy("mssql")
    run_scan(["10.0.0.1"], engines=[smb, mssql], discover=False)
    assert smb.ran and mssql.ran                            # discovery off: no gating


def test_run_scan_ungated_engine_runs_even_with_no_ports():
    custom = _Spy("some-udp-engine")                        # not in ENGINE_PORTS
    run_scan(["10.0.0.1"], engines=[custom], port_scanner=lambda h: set())
    assert custom.ran


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
