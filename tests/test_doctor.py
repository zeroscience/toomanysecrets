"""doctor command tests — engine/tool availability reporting. No external tools needed.

Run:  python tests/test_doctor.py    (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness import doctor  # noqa: E402
from redness.cli import main  # noqa: E402


def test_engine_checks_cover_defaults():
    checks = doctor.check_engines()
    names = {c.name for c in checks}
    assert {"netexec", "netexec-ldap", "certipy", "tls"} <= names


def test_tls_always_available():
    tls = next(c for c in doctor.check_engines() if c.name == "tls")
    assert tls.available is True


def test_report_text_mentions_engines_and_readiness():
    txt = doctor.report_text()
    assert "Engines:" in txt
    assert "tls" in txt
    assert "engines ready" in txt


def test_crackers_reported():
    names = {c.name for c in doctor.check_crackers()}
    assert names == {"hashcat", "john"}


def test_responder_check_reported():
    names = {c.name for c in doctor.check_poison()}
    assert names == {"responder"}


def test_cli_doctor_runs(capsys=None):
    # Exercise the CLI path end-to-end (exit code 0).
    rc = main(["doctor"])
    assert rc == 0


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
