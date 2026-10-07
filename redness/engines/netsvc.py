r"""Exposed-service engines - the classics every network PT checks (read-only, port-gated).

Unauthenticated data stores and network services are among the most common and highest-impact
findings on a flat network. Each engine here sends ONE read-only probe and reports whether the
service is reachable and, crucially, whether it answers WITHOUT authentication:

  * **Redis** (TCP 6379)        - INFO; an answer with no auth is effectively RCE-adjacent.
  * **MongoDB** (TCP 27017)     - listDatabases; data readable with no auth.
  * **Elasticsearch** (TCP 9200)- GET /; cluster + indices readable with no auth.
  * **Memcached** (TCP 11211)   - stats; no auth by design (also a DDoS-amplification source).
  * **Printer / IPP** (TCP 631) - HTTP banner; an exposed printer leaks jobs and stored creds.

Pure parsers over captured bytes + injected probes, so everything unit-tests with no server.
All run in the default scan, port-gated by discovery. Findings use `Category.SERVICE`.
"""
from __future__ import annotations

import re
from typing import Callable, Optional

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target
from .ics_common import tcp_probe


def _svc_finding(host: str, fid: str, title: str, severity: Severity, impact: str,
                 remediation: str, evidence: str, service: str, meta: Optional[dict] = None,
                 refs: Optional[list] = None) -> Finding:
    return Finding(
        id=fid, title=title, severity=severity, category=Category.SERVICE,
        description=f"{service} is reachable at {host}.",
        impact=impact, remediation=remediation, affected=[host],
        evidence=[Evidence(source=service.lower().split()[0], detail=evidence)],
        references=refs or ["https://attack.mitre.org/techniques/T1133/"],
        meta={"service": service, **(meta or {})},
    )


def http_get(host: str, port: int, path: str = "/", timeout: float = 4.0) -> bytes:
    """One read-only HTTP/1.0 GET. Returns the raw response bytes (b'' on failure)."""
    req = (f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: redness\r\n"
           f"Accept: */*\r\nConnection: close\r\n\r\n").encode()
    return tcp_probe(host, port, req, timeout=timeout, recv=16384)


def parse_http(data: bytes) -> Optional[dict]:
    """Minimal HTTP response split into {status, server, body}."""
    if not data or not data[:5].upper().startswith(b"HTTP"):
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    text = head.decode("latin-1", "replace")
    status = 0
    m = re.match(r"HTTP/\d\.\d\s+(\d+)", text)
    if m:
        status = int(m.group(1))
    server = ""
    ms = re.search(r"(?im)^Server:\s*(.+?)\s*$", text)
    if ms:
        server = ms.group(1)
    return {"status": status, "server": server, "body": body.decode("latin-1", "replace")}


# --------------------------------------------------------------------------- #
# Redis
# --------------------------------------------------------------------------- #
def parse_redis(data: bytes) -> Optional[dict]:
    """{present, unauth, version} from an INFO reply, or None if it is not Redis."""
    if not data:
        return None
    text = data.decode("latin-1", "replace")
    if text.startswith("-NOAUTH") or "NOAUTH Authentication required" in text:
        return {"present": True, "unauth": False, "version": None}
    if "redis_version:" in text:
        m = re.search(r"redis_version:([\w.]+)", text)
        return {"present": True, "unauth": True, "version": m.group(1) if m else None}
    if text.startswith("-DENIED") or "protected mode" in text.lower():
        return {"present": True, "unauth": False, "version": None}
    return None


class RedisEngine(Engine):
    name = "redis"

    def __init__(self, runner: Optional[Callable[[str], bytes]] = None):
        self._run = runner or (lambda host: tcp_probe(host, 6379, b"INFO\r\n"))

    def is_available(self) -> bool:
        return True

    def run(self, target: Target) -> list[Finding]:
        r = parse_redis(self._run(target.host))
        if r is None:
            return []
        ver = f" {r['version']}" if r.get("version") else ""
        if r["unauth"]:
            return [_svc_finding(
                target.host, "redis-unauth", f"Redis{ver} exposed without authentication",
                Severity.CRITICAL,
                "Unauthenticated Redis allows reading and writing all data and, via config/module "
                "tricks (dir + dbfilename, MODULE LOAD), frequently remote code execution on the "
                "host.",
                "Set requirepass (or ACLs), bind to localhost/the app network only, enable "
                "protected-mode, and disable dangerous commands (CONFIG/MODULE/SLAVEOF).",
                f"INFO returned without auth{ver}", "Redis",
                meta={"version": r.get("version")},
                refs=["https://attack.mitre.org/techniques/T1210/"])]
        return [_svc_finding(
            target.host, "redis-exposed", "Redis exposed (authentication required)", Severity.INFO,
            "The Redis port is reachable; credentialed or weak-password access may still expose "
            "all data.", "Restrict Redis to its application network; use a strong password/ACLs.",
            "NOAUTH (authentication required)", "Redis")]


# --------------------------------------------------------------------------- #
# MongoDB (OP_QUERY listDatabases; byte-scan the reply for markers)
# --------------------------------------------------------------------------- #
def build_op_query(command: str) -> bytes:
    """A legacy OP_QUERY on admin.$cmd for a simple {<command>:1} BSON document."""
    import struct
    name = command.encode()
    doc_body = b"\x10" + name + b"\x00" + struct.pack("<i", 1)      # int32 element <command>=1
    doc = struct.pack("<i", len(doc_body) + 5) + doc_body + b"\x00"
    body = (struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, 1) + doc)
    header = struct.pack("<iiii", 16 + len(body), 1, 0, 2004)       # len, reqID, respTo, OP_QUERY
    return header + body


def parse_mongo(data: bytes) -> Optional[dict]:
    """{present, unauth} by scanning an OP_REPLY for markers, or None if not MongoDB."""
    if len(data) < 16:
        return None
    text = data.decode("latin-1", "replace")
    present = any(k in text for k in ("ismaster", "isWritablePrimary", "maxWireVersion",
                                      "databases", "totalSize", "topologyVersion"))
    if not present:
        return None
    if "databases" in text and "totalSize" in text:
        return {"present": True, "unauth": True}
    if any(k in text for k in ("requires authentication", "Unauthorized", "not authorized",
                               "authentication")):
        return {"present": True, "unauth": False}
    return {"present": True, "unauth": False}


class MongoEngine(Engine):
    name = "mongodb"

    def __init__(self, runner: Optional[Callable[[str], bytes]] = None):
        self._run = runner or (lambda host: tcp_probe(host, 27017,
                                                       build_op_query("listDatabases")))

    def is_available(self) -> bool:
        return True

    def run(self, target: Target) -> list[Finding]:
        r = parse_mongo(self._run(target.host))
        if r is None:
            return []
        if r["unauth"]:
            return [_svc_finding(
                target.host, "mongodb-no-auth", "MongoDB exposed without authentication",
                Severity.CRITICAL,
                "listDatabases succeeded with no credentials - every database is readable and "
                "writable by anyone on the network.",
                "Enable authentication (--auth / security.authorization), create admin + app "
                "users, and bind MongoDB to its application network only.",
                "listDatabases returned databases without auth", "MongoDB",
                refs=["https://attack.mitre.org/techniques/T1210/"])]
        return [_svc_finding(
            target.host, "mongodb-exposed", "MongoDB exposed (authentication required)",
            Severity.INFO, "The MongoDB port is reachable; weak or default credentials may still "
            "grant access.", "Restrict MongoDB to its application network; enforce strong auth.",
            "MongoDB responded (auth required)", "MongoDB")]


# --------------------------------------------------------------------------- #
# Elasticsearch (HTTP)
# --------------------------------------------------------------------------- #
def parse_elasticsearch(data: bytes) -> Optional[dict]:
    """{present, unauth, version} from GET / on 9200, or None if not Elasticsearch."""
    h = parse_http(data)
    if h is None:
        return None
    body = h["body"]
    looks_es = ('"cluster_name"' in body or '"lucene_version"' in body
                or "You Know, for Search" in body or "missing authentication credentials" in body
                or "Elasticsearch" in h["server"])
    if not looks_es:
        return None
    if h["status"] in (401, 403):
        return {"present": True, "unauth": False, "version": None}
    if h["status"] == 200 and '"cluster_name"' in body:
        m = re.search(r'"number"\s*:\s*"([\w.]+)"', body)
        return {"present": True, "unauth": True, "version": m.group(1) if m else None}
    return {"present": True, "unauth": False, "version": None}


class ElasticsearchEngine(Engine):
    name = "elasticsearch"

    def __init__(self, runner: Optional[Callable[[str], bytes]] = None):
        self._run = runner or (lambda host: http_get(host, 9200, "/"))

    def is_available(self) -> bool:
        return True

    def run(self, target: Target) -> list[Finding]:
        r = parse_elasticsearch(self._run(target.host))
        if r is None:
            return []
        ver = f" {r['version']}" if r.get("version") else ""
        if r["unauth"]:
            return [_svc_finding(
                target.host, "elasticsearch-unauth",
                f"Elasticsearch{ver} exposed without authentication", Severity.HIGH,
                "The cluster and its indices are readable (and often writable) with no "
                "credentials - a direct data breach, and a path to stored secrets.",
                "Enable security (xpack.security.enabled) with authentication and TLS; bind to the "
                "application network; put a reverse proxy with auth in front.",
                f"GET / returned cluster info without auth{ver}", "Elasticsearch",
                meta={"version": r.get("version")})]
        return [_svc_finding(
            target.host, "elasticsearch-exposed", "Elasticsearch exposed (auth required)",
            Severity.INFO, "The Elasticsearch HTTP port is reachable.",
            "Restrict to the application network; keep security enabled.",
            "Elasticsearch responded (auth required)", "Elasticsearch")]


# --------------------------------------------------------------------------- #
# Memcached
# --------------------------------------------------------------------------- #
def parse_memcached(data: bytes) -> Optional[dict]:
    """{present, version} from a stats reply, or None if not Memcached."""
    if not data or b"STAT " not in data:
        return None
    text = data.decode("latin-1", "replace")
    m = re.search(r"STAT version ([\w.]+)", text)
    return {"present": True, "version": m.group(1) if m else None}


class MemcachedEngine(Engine):
    name = "memcached"

    def __init__(self, runner: Optional[Callable[[str], bytes]] = None):
        self._run = runner or (lambda host: tcp_probe(host, 11211, b"stats\r\n"))

    def is_available(self) -> bool:
        return True

    def run(self, target: Target) -> list[Finding]:
        r = parse_memcached(self._run(target.host))
        if r is None:
            return []
        ver = f" {r['version']}" if r.get("version") else ""
        return [_svc_finding(
            target.host, "memcached-exposed", f"Memcached{ver} exposed (no authentication)",
            Severity.HIGH,
            "Memcached has no authentication: anyone reachable can read and overwrite cached data "
            "(sessions, query results, sometimes credentials), and an exposed UDP memcached is a "
            "high-amplification DDoS reflector.",
            "Bind memcached to localhost/the app network, disable UDP (-U 0), and firewall 11211.",
            f"stats returned without auth{ver}", "Memcached",
            meta={"version": r.get("version")},
            refs=["https://attack.mitre.org/techniques/T1498/002/"])]


# --------------------------------------------------------------------------- #
# Printer / IPP (HTTP banner on 631)
# --------------------------------------------------------------------------- #
_PRINTER_SIG = re.compile(r"(?i)\b(cups|ipp|printer|jetdirect|laserjet|officejet|brother|"
                          r"kyocera|lexmark|ricoh|xerox|canon|epson|sharp mfp|print server)\b")


def parse_printer(data: bytes) -> Optional[dict]:
    """{model} if the HTTP banner on 631 looks like a printer/IPP server, else None."""
    h = parse_http(data)
    if h is None:
        return None
    hay = h["server"] + " " + h["body"][:2000]
    m = _PRINTER_SIG.search(hay)
    if not m:
        return None
    model = h["server"] or m.group(0)
    tm = re.search(r"(?i)<title>\s*(.+?)\s*</title>", h["body"])
    if tm:
        model = tm.group(1)[:80]
    return {"model": model}


class PrinterEngine(Engine):
    name = "ipp"

    def __init__(self, runner: Optional[Callable[[str], bytes]] = None):
        self._run = runner or (lambda host: http_get(host, 631, "/"))

    def is_available(self) -> bool:
        return True

    def run(self, target: Target) -> list[Finding]:
        r = parse_printer(self._run(target.host))
        if r is None:
            return []
        return [_svc_finding(
            target.host, "printer-exposed", f"Network printer exposed: {r['model']}",
            Severity.MEDIUM,
            "An exposed printer/IPP service can leak queued and stored documents, address books, "
            "and configured credentials (LDAP/SMB/SMTP scan-to-folder passwords are often "
            "recoverable), and is a common pivot and spoofing point.",
            "Restrict printer management to an admin VLAN; set an admin password; disable unused "
            "protocols (IPP/raw-9100/FTP/Telnet); rotate stored scan/LDAP credentials.",
            f"HTTP banner on 631: {r['model']}", "Printer/IPP",
            meta={"model": r["model"]})]
