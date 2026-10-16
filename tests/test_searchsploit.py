"""Searchsploit tests - pure JSON parsing + the exploit-candidate finding. No exploitdb.

Run:  python -m pytest tests/test_searchsploit.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.findings import Category, Severity  # noqa: E402
from redness.engines.searchsploit import Exploit, finding_for, parse_searchsploit  # noqa: E402

JSON = """{"SEARCH":"apache 2.4.49","RESULTS_EXPLOIT":[
 {"Title":"Apache 2.4.49 - Path Traversal & RCE","EDB-ID":"50383","Type":"webapps","Platform":"multiple","Path":"/x/50383.sh"},
 {"Title":"Apache 2.4.49 - Path Traversal","EDB-ID":"50406","Type":"remote","Platform":"linux","Path":"/x/50406.py"},
 {"Title":"","EDB-ID":"0","Type":"","Platform":"","Path":""}
],"RESULTS_SHELLCODE":[]}"""


def test_parse_drops_empty_titles_and_maps_fields():
    ex = parse_searchsploit(JSON)
    assert len(ex) == 2                                   # the empty-title row is dropped
    assert ex[0].edb_id == "50383" and ex[0].etype == "webapps"
    assert ex[0].url == "https://www.exploit-db.com/exploits/50383"


def test_parse_bad_json():
    assert parse_searchsploit("nope") == []
    assert parse_searchsploit("") == []


def test_finding_for_builds_info_with_refs():
    ex = parse_searchsploit(JSON)
    f = finding_for("Apache httpd", "2.4.49", ex, "10.0.0.5")
    assert f.severity is Severity.INFO and f.category is Category.WEB
    assert f.affected == ["10.0.0.5"]
    assert f.meta["exploit_count"] == 2
    assert "https://www.exploit-db.com/exploits/50383" in f.references
    assert any("Path Traversal" in e.detail for e in f.evidence)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
    print("done")
