"""BloodHound ingest: add real AD relationships to the graph.

Our own findings give attack paths derived from misconfigurations (see paths.py). A
BloodHound collection adds the *structural* relationships - group membership, local
admin rights, active sessions - that turn isolated findings into full graphs to Domain
Admin. This module loads a SharpHound / BloodHound-CE collection (a .zip, a directory,
or individual .json files) and streams nodes + relationship edges onto the EventBus.

v1 extracts the three highest-value edges: MemberOf, AdminTo, HasSession. The parser is
pure and tolerant (missing keys are skipped), tested against synthetic JSON matching the
collector shape. Verify against your SharpHound/BHCE version; add edge kinds as needed.
"""
from __future__ import annotations

import glob
import json
import os
import zipfile
from dataclasses import dataclass, field
from typing import Optional

from .events import Event, EventBus, EventKind

# BloodHound object type (meta.type / filename) -> our graph node type.
_NODE_TYPE = {"users": "user", "groups": "group", "computers": "host",
              "domains": "domain", "ous": "ou", "gpos": "gpo", "containers": "container"}
_KNOWN_TYPES = tuple(_NODE_TYPE)


@dataclass
class BHGraph:
    nodes: dict[str, str] = field(default_factory=dict)          # id -> node type
    edges: list[tuple[str, str, str]] = field(default_factory=list)  # (src, dst, relationship)


def short_name(name: str) -> str:
    """`JDOE@ACME.LOCAL` -> `JDOE`; leave bare names and SIDs untouched."""
    return name.split("@", 1)[0] if name and "@" in name else (name or "")


# --------------------------------------------------------------------------- #
# Loading (zip / dir / files)                                                 #
# --------------------------------------------------------------------------- #
def _objects_from_doc(doc: dict, filename: str = "") -> tuple[str, list[dict]]:
    """Return (type, objects) from one parsed BloodHound json document."""
    if isinstance(doc, dict) and isinstance(doc.get("data"), list):        # SharpHound/BHCE
        t = (doc.get("meta") or {}).get("type", "")
        objs = doc["data"]
    else:                                                                  # legacy: {"users":[...]}
        t, objs = "", []
        for key in _KNOWN_TYPES:
            if isinstance(doc.get(key), list):
                t, objs = key, doc[key]
                break
    if not t:                                                              # fall back to the filename
        base = os.path.basename(filename).lower()
        t = next((k for k in _KNOWN_TYPES if k[:-1] in base or k in base), "")
    return t, objs


def load_collection(path: str) -> dict[str, list[dict]]:
    """Load a BloodHound collection into {type: [objects]} from a .zip, dir, or .json file."""
    docs: list[tuple[str, dict]] = []
    if path.endswith(".zip") and zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if name.lower().endswith(".json"):
                    docs.append((name, json.loads(z.read(name) or b"{}")))
    elif os.path.isdir(path):
        for fp in sorted(glob.glob(os.path.join(path, "*.json"))):
            with open(fp, encoding="utf-8") as fh:
                docs.append((fp, json.load(fh)))
    else:
        with open(path, encoding="utf-8") as fh:
            docs.append((path, json.load(fh)))

    out: dict[str, list[dict]] = {}
    for filename, doc in docs:
        t, objs = _objects_from_doc(doc, filename)
        if t:
            out.setdefault(t, []).extend(objs)
    return out


# --------------------------------------------------------------------------- #
# Parsing (pure)                                                              #
# --------------------------------------------------------------------------- #
def _name_map(collection: dict[str, list[dict]]) -> dict[str, str]:
    """objectid (SID) -> display short name, across all object types."""
    m: dict[str, str] = {}
    for objs in collection.values():
        for o in objs:
            props = o.get("Properties") or {}
            sid = props.get("objectid") or o.get("ObjectIdentifier")
            if sid:
                m[sid] = short_name(props.get("name") or props.get("samaccountname") or sid)
    return m


def _results(value) -> list[dict]:
    """BloodHound nests some edge lists as {'Results': [...]}; others are bare lists."""
    if isinstance(value, dict):
        return value.get("Results") or []
    if isinstance(value, list):
        return value
    return []


def parse_bloodhound(collection: dict[str, list[dict]]) -> BHGraph:
    """Turn a loaded collection into nodes + MemberOf/AdminTo/HasSession edges."""
    g = BHGraph()
    names = _name_map(collection)

    def add_node(sid_or_name: str, ntype: str) -> str:
        label = names.get(sid_or_name, short_name(sid_or_name))
        g.nodes.setdefault(label, ntype)
        return label

    for btype, objs in collection.items():
        ntype = _NODE_TYPE.get(btype, "node")
        for o in objs:
            props = o.get("Properties") or {}
            sid = props.get("objectid") or o.get("ObjectIdentifier") or props.get("name")
            if not sid:
                continue
            src_is = add_node(sid, ntype)

            if btype == "groups":                                  # member -> group (MemberOf)
                for mem in _results(o.get("Members")):
                    mid = mem.get("ObjectIdentifier")
                    if mid:
                        g.edges.append((add_node(mid, _NODE_TYPE.get(
                            (mem.get("ObjectType") or "") .lower() + "s", "node")), src_is, "MemberOf"))
            if btype == "computers":
                for adm in _results(o.get("LocalAdmins")):         # principal -> computer (AdminTo)
                    aid = adm.get("ObjectIdentifier")
                    if aid:
                        g.edges.append((add_node(aid, _NODE_TYPE.get(
                            (adm.get("ObjectType") or "").lower() + "s", "node")), src_is, "AdminTo"))
                for ses in _results(o.get("Sessions")):            # computer -> user (HasSession)
                    uid = ses.get("ObjectIdentifier")
                    if uid:
                        g.edges.append((src_is, add_node(uid, "user"), "HasSession"))
    return g


# --------------------------------------------------------------------------- #
# Emission                                                                    #
# --------------------------------------------------------------------------- #
def _emit(bus: Optional[EventBus], kind: EventKind, **data) -> None:
    if bus is not None:
        bus.publish(Event(kind=kind, data=data, engine="bloodhound"))


def emit_bloodhound(bus: Optional[EventBus], collection: dict[str, list[dict]]) -> BHGraph:
    """Stream a parsed BloodHound collection (nodes + relationship edges) to the bus."""
    g = parse_bloodhound(collection)
    if bus is None:
        return g
    for node_id, ntype in g.nodes.items():
        _emit(bus, EventKind.NODE, id=node_id, label=node_id, type=ntype)
    for src, dst, rel in g.edges:
        _emit(bus, EventKind.EDGE, src=src, dst=dst, label=rel)
    _emit(bus, EventKind.STATUS,
          message=f"BloodHound: {len(g.nodes)} node(s), {len(g.edges)} relationship(s)")
    return g
