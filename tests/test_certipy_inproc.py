"""In-process certipy invocation — the path a self-contained exe takes.

Injects a fake `certipy.entry` module so we can prove CertipyEngine invokes the
entrypoint (patched sys.argv) and parses its -output JSON, with no real certipy and
no binary on PATH. Run: python tests/test_certipy_inproc.py
"""
import json
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.engines.certipy import CertipyEngine  # noqa: E402
from redness.engines.base import Target  # noqa: E402


def _install_fake_certipy(record):
    """Register a fake certipy/certipy.entry that writes a Certipy JSON like the real CLI."""
    def fake_main():
        argv = sys.argv
        record["argv"] = list(argv)
        prefix = argv[argv.index("-output") + 1]
        data = {"Certificate Templates": {"0": {
            "Template Name": "UserAuth",
            "[!] Vulnerabilities": {"ESC1": "enrollee supplies subject; client auth"},
        }}}
        with open(prefix + "_Certipy.json", "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        raise SystemExit(0)                 # certipy/argparse exits like the real CLI

    entry = types.ModuleType("certipy.entry")
    entry.main = fake_main
    pkg = types.ModuleType("certipy")
    pkg.entry = entry
    sys.modules["certipy"] = pkg
    sys.modules["certipy.entry"] = entry


def _uninstall_fake_certipy():
    sys.modules.pop("certipy.entry", None)
    sys.modules.pop("certipy", None)


def test_inproc_invokes_entry_and_parses():
    record = {}
    _install_fake_certipy(record)
    try:
        eng = CertipyEngine()
        eng._bin = lambda: None            # force the in-process path (no CLI on PATH)
        assert eng.is_available() is True  # available via the (fake) bundled module
        findings = eng.run(Target(host="10.0.0.1", domain="acme.local",
                                  username="u", password="p"))
        ids = {f.id for f in findings}
        assert "adcs-esc1" in ids
        # entrypoint was called CLI-style with our args
        assert record["argv"][0] == "certipy"
        assert "find" in record["argv"] and "-vulnerable" in record["argv"]
        assert "10.0.0.1" in record["argv"]
    finally:
        _uninstall_fake_certipy()


def test_argv_restored_after_inproc():
    record = {}
    _install_fake_certipy(record)
    before = list(sys.argv)
    try:
        eng = CertipyEngine()
        eng._bin = lambda: None
        eng.run(Target(host="10.0.0.2"))
    finally:
        _uninstall_fake_certipy()
    assert sys.argv == before               # engine must restore sys.argv


def test_unavailable_without_binary_or_module():
    eng = CertipyEngine()
    eng._bin = lambda: None
    # no certipy module present in this interpreter -> not available, run() is a no-op
    if CertipyEngine._module_available():
        return                              # skip if certipy really is installed here
    assert eng.is_available() is False
    assert eng.run(Target(host="10.0.0.3")) == []


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
