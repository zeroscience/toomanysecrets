"""Built-in wordlist tests - pure, no cracker/network needed.

Run:  python tests/test_wordlists.py    (or)   python -m pytest -q
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness import wordlists  # noqa: E402


def test_basic_wordlist_is_substantial():
    # small but not trivial - a few hundred high-signal candidates
    assert len(wordlists.BASIC_WORDLIST) >= 200


def test_no_duplicates():
    wl = wordlists.BASIC_WORDLIST
    assert len(wl) == len(set(wl))


def test_entries_are_clean_tokens():
    for w in wordlists.BASIC_WORDLIST:
        assert isinstance(w, str) and w, "entries must be non-empty strings"
        # a wordlist is line-oriented: no interior whitespace/newlines that would
        # split one candidate into two (or produce a blank line) when written out.
        assert w == w.strip()
        assert not any(c.isspace() for c in w)


def test_seasonal_patterns_present():
    # sanity: the programmatic seasonal block made it in
    assert "Summer2024!" in wordlists.BASIC_WORDLIST
    assert "Winter2025" in wordlists.BASIC_WORDLIST


def test_write_basic_wordlist_roundtrips():
    with tempfile.TemporaryDirectory() as td:
        path = wordlists.write_basic_wordlist(td)
        assert os.path.basename(path) == "_basic_wordlist.txt"
        lines = open(path, encoding="utf-8").read().splitlines()
        assert lines == list(wordlists.BASIC_WORDLIST)


def test_write_creates_missing_dir():
    with tempfile.TemporaryDirectory() as td:
        nested = os.path.join(td, "loot", "sub")
        path = wordlists.write_basic_wordlist(nested)
        assert os.path.isfile(path)


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
