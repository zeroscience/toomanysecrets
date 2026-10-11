"""IoT engines: MQTT anonymous-access + CoAP resource discovery."""
import struct

from redness.engines import CoapEngine, MqttEngine
from redness.engines.base import Target
from redness.engines.coap import build_get_wellknown, parse_coap
from redness.engines.mqtt import build_connect, parse_connack
from redness.findings import SCHEMA_VERSION, Category, Severity


def _tgt(host="10.0.0.9"):
    return Target(host=host)


def test_schema_bumped_and_new_categories():
    assert SCHEMA_VERSION >= "1.3.0"
    assert Category.IOT.value == "iot" and Category.SERVICE.value == "service"


# --- MQTT ------------------------------------------------------------------ #
def test_build_connect_is_mqtt_connect():
    req = build_connect()
    assert req[0] == 0x10 and b"MQTT" in req


def test_parse_connack():
    assert parse_connack(bytes([0x20, 0x02, 0x00, 0x00]))["accepted"] is True
    na = parse_connack(bytes([0x20, 0x02, 0x00, 0x05]))
    assert na["accepted"] is False and na["meaning"] == "not authorized"
    assert parse_connack(b"\x30\x02\x00\x00") is None               # not a CONNACK


def test_mqtt_engine_anonymous_accepted():
    fs = MqttEngine(runner=lambda h: bytes([0x20, 0x02, 0x00, 0x00])).run(_tgt())
    assert [f.id for f in fs] == ["mqtt-anonymous"]
    assert fs[0].severity is Severity.HIGH and fs[0].category is Category.IOT


def test_mqtt_engine_auth_required_is_info():
    fs = MqttEngine(runner=lambda h: bytes([0x20, 0x02, 0x00, 0x05])).run(_tgt())
    assert [f.id for f in fs] == ["mqtt-exposed"] and fs[0].severity is Severity.INFO


def test_mqtt_engine_no_connack_no_findings():
    assert MqttEngine(runner=lambda h: b"").run(_tgt()) == []


# --- CoAP ------------------------------------------------------------------ #
def _coap_response(payload=b"</sensors/temp>;rt=temperature"):
    return bytes([0x60, 0x45, 0x00, 0x01, 0xFF]) + payload           # ACK, 2.05 Content


def test_build_get_wellknown():
    req = build_get_wellknown()
    assert req[0] == 0x40 and req[1] == 0x01 and b".well-known" in req and b"core" in req


def test_parse_coap():
    r = parse_coap(_coap_response())
    assert r["code"] == "2.05" and r["success"] is True
    assert "sensors/temp" in r["payload"]
    assert parse_coap(b"\x00\x00\x00\x00") is None                  # version != 1


def test_coap_engine_emits_finding_with_resources():
    fs = CoapEngine(runner=lambda h: _coap_response()).run(_tgt())
    assert [f.id for f in fs] == ["coap-exposed"]
    assert fs[0].category is Category.IOT and "sensors/temp" in fs[0].meta["resources"]


def test_coap_engine_no_response_no_findings():
    assert CoapEngine(runner=lambda h: b"").run(_tgt()) == []


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            passed += 1
    print(f"{passed} passed")
