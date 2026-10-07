"""Exposed-service engines: Redis / MongoDB / Elasticsearch / Memcached / printer (IPP)."""
import struct

from redness.engines import (ElasticsearchEngine, MemcachedEngine, MongoEngine, PrinterEngine,
                             RedisEngine)
from redness.engines.base import Target
from redness.engines.netsvc import (build_op_query, parse_elasticsearch, parse_http,
                                    parse_memcached, parse_mongo, parse_printer, parse_redis)
from redness.findings import Category, Severity


def _tgt(host="10.0.0.20"):
    return Target(host=host)


def _http(status=200, server="", body=""):
    head = f"HTTP/1.1 {status} X\r\n"
    if server:
        head += f"Server: {server}\r\n"
    return (head + "\r\n" + body).encode()


def test_parse_http():
    h = parse_http(_http(200, "nginx", '{"ok":1}'))
    assert h["status"] == 200 and h["server"] == "nginx" and '"ok"' in h["body"]
    assert parse_http(b"not http") is None


# --- Redis ----------------------------------------------------------------- #
def test_parse_redis_unauth_and_auth():
    unauth = b"$120\r\n# Server\r\nredis_version:7.2.4\r\nos:Linux\r\n"
    r = parse_redis(unauth)
    assert r["unauth"] is True and r["version"] == "7.2.4"
    assert parse_redis(b"-NOAUTH Authentication required.\r\n")["unauth"] is False
    assert parse_redis(b"") is None


def test_redis_engine():
    fs = RedisEngine(runner=lambda h: b"$10\r\nredis_version:7.2.4\r\n").run(_tgt())
    assert [f.id for f in fs] == ["redis-unauth"]
    assert fs[0].severity is Severity.CRITICAL and fs[0].category is Category.SERVICE
    assert RedisEngine(runner=lambda h: b"-NOAUTH Authentication required.\r\n").run(_tgt())[0].id \
        == "redis-exposed"
    assert RedisEngine(runner=lambda h: b"").run(_tgt()) == []


# --- MongoDB --------------------------------------------------------------- #
def test_build_op_query_opcode():
    req = build_op_query("listDatabases")
    assert struct.unpack_from("<i", req, 12)[0] == 2004          # OP_QUERY
    assert b"admin.$cmd\x00" in req


def test_parse_mongo():
    noauth = b"\x00" * 16 + b'....databases....totalSize....'
    assert parse_mongo(noauth)["unauth"] is True
    authon = b"\x00" * 16 + b'maxWireVersion requires authentication'
    assert parse_mongo(authon) == {"present": True, "unauth": False}
    assert parse_mongo(b"\x00" * 20) is None                     # no mongo markers


def test_mongo_engine():
    fs = MongoEngine(runner=lambda h: b"\x00" * 16 + b"databases totalSize").run(_tgt())
    assert [f.id for f in fs] == ["mongodb-no-auth"] and fs[0].severity is Severity.CRITICAL
    auth = MongoEngine(runner=lambda h: b"\x00" * 16 + b"maxWireVersion authentication").run(_tgt())
    assert auth[0].id == "mongodb-exposed"
    assert MongoEngine(runner=lambda h: b"").run(_tgt()) == []


# --- Elasticsearch --------------------------------------------------------- #
def test_parse_elasticsearch():
    body = '{"name":"n","cluster_name":"es","version":{"number":"8.13.0"},"tagline":"You Know"}'
    r = parse_elasticsearch(_http(200, "", body))
    assert r["unauth"] is True and r["version"] == "8.13.0"
    e401 = _http(401, "", '{"error":{"reason":"missing authentication credentials"}}')
    assert parse_elasticsearch(e401)["unauth"] is False
    assert parse_elasticsearch(_http(200, "nginx", "<html>hi</html>")) is None


def test_elasticsearch_engine():
    body = '{"cluster_name":"es","version":{"number":"8.13.0"}}'
    fs = ElasticsearchEngine(runner=lambda h: _http(200, "", body)).run(_tgt())
    assert [f.id for f in fs] == ["elasticsearch-unauth"] and fs[0].severity is Severity.HIGH


# --- Memcached ------------------------------------------------------------- #
def test_parse_memcached_and_engine():
    stats = b"STAT pid 7\r\nSTAT version 1.6.21\r\nEND\r\n"
    assert parse_memcached(stats)["version"] == "1.6.21"
    assert parse_memcached(b"nope") is None
    fs = MemcachedEngine(runner=lambda h: stats).run(_tgt())
    assert [f.id for f in fs] == ["memcached-exposed"] and fs[0].severity is Severity.HIGH


# --- Printer / IPP --------------------------------------------------------- #
def test_parse_printer_and_engine():
    assert parse_printer(_http(200, "CUPS/2.4 IPP/2.1"))["model"] == "CUPS/2.4 IPP/2.1"
    assert parse_printer(_http(200, "", "<html><title>HP LaserJet MFP</title></html>"))["model"] \
        == "HP LaserJet MFP"
    assert parse_printer(_http(200, "nginx", "<html>website</html>")) is None
    fs = PrinterEngine(runner=lambda h: _http(200, "CUPS/2.4 IPP/2.1")).run(_tgt())
    assert [f.id for f in fs] == ["printer-exposed"] and fs[0].severity is Severity.MEDIUM


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            passed += 1
    print(f"{passed} passed")
