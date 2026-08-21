"""BloodHound ingest tests: parse + load (dir/zip) + emit. Synthetic collector JSON.

Run:  python tests/test_bloodhound.py   (or)   python -m pytest -q
"""
import json
import os
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness import bloodhound as bh  # noqa: E402
from redness.events import EventBus, EventKind  # noqa: E402

S = "S-1-5-21-111-222-333-"
_JDOE, _SVC, _DA, _DC = S + "1104", S + "1105", S + "512", S + "1000"


def _collection():
    return {
        "users": [
            {"Properties": {"name": "JDOE@ACME.LOCAL", "objectid": _JDOE}},
            {"Properties": {"name": "SVC@ACME.LOCAL", "objectid": _SVC}},
        ],
        "groups": [
            {"Properties": {"name": "DOMAIN ADMINS@ACME.LOCAL", "objectid": _DA},
             "Members": [{"ObjectIdentifier": _JDOE, "ObjectType": "User"}]},
        ],
        "computers": [
            {"Properties": {"name": "DC01.ACME.LOCAL", "objectid": _DC},
             "LocalAdmins": {"Results": [{"ObjectIdentifier": _DA, "ObjectType": "Group"}]},
             "Sessions": {"Results": [{"ObjectIdentifier": _SVC, "ObjectType": "User"}]}},
        ],
    }


def test_short_name():
    assert bh.short_name("JDOE@ACME.LOCAL") == "JDOE"
    assert bh.short_name("DC01.ACME.LOCAL") == "DC01.ACME.LOCAL"   # no '@', unchanged


def test_parse_edges_and_nodes():
    g = bh.parse_bloodhound(_collection())
    assert g.nodes["JDOE"] == "user"
    assert g.nodes["DOMAIN ADMINS"] == "group"
    assert g.nodes["DC01.ACME.LOCAL"] == "host"
    assert ("JDOE", "DOMAIN ADMINS", "MemberOf") in g.edges
    assert ("DOMAIN ADMINS", "DC01.ACME.LOCAL", "AdminTo") in g.edges
    assert ("DC01.ACME.LOCAL", "SVC", "HasSession") in g.edges


def _write_bhce_dir(td):
    for t, objs in _collection().items():
        with open(os.path.join(td, f"{t}.json"), "w", encoding="utf-8") as fh:
            json.dump({"data": objs, "meta": {"type": t, "count": len(objs), "version": 6}}, fh)


def test_load_from_directory():
    with tempfile.TemporaryDirectory() as td:
        _write_bhce_dir(td)
        col = bh.load_collection(td)
        assert set(col) == {"users", "groups", "computers"}
        assert len(col["users"]) == 2
        assert bh.parse_bloodhound(col).edges                       # edges resolved end to end


def test_load_from_zip():
    with tempfile.TemporaryDirectory() as td:
        _write_bhce_dir(td)
        zpath = os.path.join(td, "coll.zip")
        with zipfile.ZipFile(zpath, "w") as z:
            for t in ("users", "groups", "computers"):
                z.write(os.path.join(td, f"{t}.json"), f"{t}.json")
        col = bh.load_collection(zpath)
        assert set(col) == {"users", "groups", "computers"}


def test_emit_streams_nodes_and_edges():
    seen = []
    bus = EventBus()
    bus.subscribe(seen.append)
    g = bh.emit_bloodhound(bus, _collection())
    kinds = [e.kind for e in seen]
    assert kinds.count(EventKind.NODE) == len(g.nodes)
    assert EventKind.EDGE in kinds
    assert any(e.kind is EventKind.EDGE and e.data.get("label") == "AdminTo" for e in seen)


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
