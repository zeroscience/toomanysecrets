"""ICS/OT field-protocol engines: pure parsers + engine runs against hand-built packets."""
import struct

from redness.engines import BacnetEngine, EnipEngine, ModbusEngine
from redness.engines.bacnet import build_whois, parse_iam
from redness.engines.base import Target
from redness.engines.enip import build_list_identity, parse_list_identity
from redness.engines.ics_common import ics_findings
from redness.engines.modbus import build_read_device_id, parse_device_id
from redness.findings import SCHEMA_VERSION, Category, Severity


def _tgt(host="10.0.0.5"):
    return Target(host=host)


# --------------------------------------------------------------------------- #
# contract
# --------------------------------------------------------------------------- #
def test_schema_bumped_and_category_ics():
    assert SCHEMA_VERSION == "1.2.0"
    assert Category.ICS.value == "ics"


def test_ics_findings_shape():
    fs = ics_findings("10.0.0.5", protocol="Modbus", exposed_id="modbus-exposed",
                      exposed_title="Modbus/TCP endpoint exposed", impact="x",
                      device={"vendor": "ACME", "product": "PLC1", "revision": "1.0"},
                      inventory_id="modbus-device-identity", evidence="e")
    assert [f.id for f in fs] == ["modbus-exposed", "modbus-device-identity"]
    assert fs[0].category is Category.ICS and fs[0].severity is Severity.HIGH
    assert fs[0].meta["protocol"] == "Modbus" and fs[0].meta["purdue"] == 1
    assert fs[1].severity is Severity.INFO and fs[1].meta["device"]["vendor"] == "ACME"
    # round-trips through the findings JSON contract
    assert fs[0].to_dict()["category"] == "ics"


def test_ics_findings_exposure_only_when_no_device():
    fs = ics_findings("10.0.0.5", protocol="Modbus", exposed_id="modbus-exposed",
                      exposed_title="t", impact="x")
    assert len(fs) == 1 and fs[0].id == "modbus-exposed"


# --------------------------------------------------------------------------- #
# EtherNet/IP (CIP) List Identity
# --------------------------------------------------------------------------- #
def _enip_reply(name=b"1756-L71", vendor=1, devtype=0x0E, state=3):
    sockaddr = struct.pack(">HH", 2, 44818) + bytes([192, 168, 1, 10]) + b"\x00" * 8
    item = (struct.pack("<H", 1) + sockaddr + struct.pack("<HHH", vendor, devtype, 100)
            + bytes([20, 11]) + struct.pack("<H", 0) + struct.pack("<I", 0x12345678)
            + bytes([len(name)]) + name + bytes([state]))
    body = struct.pack("<H", 1) + struct.pack("<HH", 0x000C, len(item)) + item
    header = struct.pack("<HHII8sI", 0x0063, len(body), 0, 0, b"\x00" * 8, 0)
    return header + body


def test_parse_list_identity():
    dev = parse_list_identity(_enip_reply())
    assert dev["vendor"] == "Rockwell Automation/Allen-Bradley"
    assert dev["product"] == "1756-L71" and dev["revision"] == "20.11"
    assert dev["serial"] == "0x12345678" and dev["device_type"] == "Programmable Logic Controller"
    assert dev["state"] == "Operational"


def test_parse_list_identity_rejects_non_enip():
    assert parse_list_identity(b"\x00" * 24) is None       # wrong command
    assert parse_list_identity(b"short") is None
    # valid header, no identity item -> exposure marker
    hdr = struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"\x00" * 8, 0)
    assert parse_list_identity(hdr) == {"_enip": True}


def test_enip_engine_emits_exposure_and_inventory():
    eng = EnipEngine(runner=lambda host: _enip_reply())
    fs = eng.run(_tgt())
    assert [f.id for f in fs] == ["enip-exposed", "enip-device-identity"]
    assert fs[0].severity is Severity.HIGH and "1756-L71" in fs[1].title


def test_enip_engine_no_response_no_findings():
    assert EnipEngine(runner=lambda host: b"").run(_tgt()) == []


def test_build_list_identity_is_24_bytes_cmd_0x63():
    req = build_list_identity()
    assert len(req) == 24 and struct.unpack_from("<H", req, 0)[0] == 0x0063


# --------------------------------------------------------------------------- #
# Modbus/TCP Read Device Identification
# --------------------------------------------------------------------------- #
def _modbus_devid(objs=((0x00, b"Schneider Electric"), (0x02, b"2.70"), (0x04, b"BMXP342020"))):
    body = bytes([0x2B, 0x0E, 0x01, 0x81, 0x00, 0x00, len(objs)])
    for oid, val in objs:
        body += bytes([oid, len(val)]) + val
    return struct.pack(">HHHB", 1, 0, 1 + len(body), 1) + body


def test_parse_modbus_device_id():
    dev = parse_device_id(_modbus_devid())
    assert dev["vendor"] == "Schneider Electric" and dev["revision"] == "2.70"
    assert dev["product"] == "BMXP342020"


def test_parse_modbus_exception_is_exposure_only():
    exc = struct.pack(">HHHB", 1, 0, 2, 1) + bytes([0xAB, 0x01])   # 0x2B|0x80 exception
    assert parse_device_id(exc) == {"_modbus": True}


def test_parse_modbus_rejects_non_modbus():
    assert parse_device_id(struct.pack(">HHHB", 1, 5, 2, 1) + b"\x2b") is None  # proto != 0
    assert parse_device_id(b"\x00\x00") is None


def test_modbus_engine_emits_exposure_and_inventory():
    fs = ModbusEngine(runner=lambda host: _modbus_devid()).run(_tgt())
    assert [f.id for f in fs] == ["modbus-exposed", "modbus-device-identity"]
    assert "BMXP342020" in fs[1].title


def test_modbus_engine_exception_exposure_only():
    exc = struct.pack(">HHHB", 1, 0, 2, 1) + bytes([0xAB, 0x01])
    fs = ModbusEngine(runner=lambda host: exc).run(_tgt())
    assert [f.id for f in fs] == ["modbus-exposed"]


def test_build_read_device_id():
    req = build_read_device_id(1)
    assert req[7:] == bytes([0x2B, 0x0E, 0x01, 0x00])


# --------------------------------------------------------------------------- #
# BACnet/IP Who-Is / I-Am
# --------------------------------------------------------------------------- #
def _iam(instance=12345, vendor=9):
    apdu = (bytes([0x10, 0x00])
            + bytes([0xC4]) + struct.pack(">I", (8 << 22) | instance)   # device object id
            + bytes([0x22, 0x01, 0xE0])                                 # max APDU
            + bytes([0x91, 0x00])                                       # segmentation
            + bytes([0x21, vendor]))                                    # vendor id
    npdu = bytes([0x01, 0x00])
    bvlc = bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(npdu) + len(apdu))
    return bvlc + npdu + apdu


def test_parse_iam():
    dev = parse_iam(_iam())
    assert dev["device_instance"] == 12345 and dev["vendor_id"] == 9
    assert dev["vendor"] == "Siemens"


def test_parse_iam_rejects_non_iam():
    bad = bytearray(_iam())
    bad[6] = 0x30                               # not an unconfirmed-request APDU
    assert parse_iam(bytes(bad)) is None
    assert parse_iam(b"\x00\x00") is None


def test_bacnet_engine_emits_findings():
    fs = BacnetEngine(runner=lambda host: _iam()).run(_tgt())
    assert [f.id for f in fs] == ["bacnet-exposed", "bacnet-device-identity"]
    assert fs[0].severity is Severity.MEDIUM and fs[0].meta["purdue"] == 2


def test_build_whois():
    assert build_whois() == bytes([0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08])


# --------------------------------------------------------------------------- #
# DNP3 - Request Link Status / Link Status
# --------------------------------------------------------------------------- #
from redness.engines import Dnp3Engine, HartIpEngine  # noqa: E402
from redness.engines.dnp3 import (build_request_link_status, dnp3_crc,  # noqa: E402
                                  parse_link_frame)
from redness.engines.hartip import build_session_initiate, parse_hartip  # noqa: E402


def _link_status(outstation=1024, master=1):
    """A valid outstation Link Status reply frame (func 0x0B, DIR=0/PRM=0), with CRC."""
    header = bytes([0x05, 0x64, 0x05, 0x0B]) + struct.pack("<HH", master, outstation)
    return header + struct.pack("<H", dnp3_crc(header[2:]))


def test_dnp3_crc_is_deterministic_and_little_endian():
    frame = build_request_link_status(dest=1024, src=1)
    assert frame[:2] == b"\x05\x64" and len(frame) == 10
    # the appended CRC matches dnp3_crc over LEN..SRC (bytes 2..7)
    assert struct.unpack_from("<H", frame, 8)[0] == dnp3_crc(frame[2:8])


def test_parse_link_frame():
    f = parse_link_frame(_link_status(outstation=2051, master=3))
    assert f["func"] == 0x0B and f["func_name"] == "Link Status"
    assert f["src_addr"] == 2051 and f["dest_addr"] == 3


def test_parse_link_frame_rejects_non_dnp3():
    assert parse_link_frame(b"\x00\x00" + b"\x00" * 10) is None
    assert parse_link_frame(b"\x05\x64") is None            # too short


def test_dnp3_engine_confirmed_outstation():
    fs = Dnp3Engine(runner=lambda host: (True, _link_status(outstation=2051))).run(_tgt())
    assert [f.id for f in fs] == ["dnp3-exposed", "dnp3-outstation"]
    assert fs[0].severity is Severity.HIGH and "2051" in fs[1].title


def test_dnp3_engine_port_open_no_reply_is_exposure_only():
    fs = Dnp3Engine(runner=lambda host: (True, b"")).run(_tgt())
    assert [f.id for f in fs] == ["dnp3-exposed"]


def test_dnp3_engine_not_connected_no_findings():
    assert Dnp3Engine(runner=lambda host: (False, b"")).run(_tgt()) == []


# --------------------------------------------------------------------------- #
# HART-IP - Session Initiate
# --------------------------------------------------------------------------- #
def _hartip_response(msg_type=1, msg_id=0):
    return struct.pack(">BBBBHH", 1, msg_type, msg_id, 0, 1, 8)


def test_build_session_initiate_header():
    req = build_session_initiate()
    assert req[0] == 1 and req[1] == 0 and req[2] == 0            # version, request, session-init


def test_parse_hartip():
    hdr = parse_hartip(_hartip_response())
    assert hdr["version"] == 1 and hdr["msg_type"] == 1 and hdr["msg_id"] == 0


def test_parse_hartip_rejects_non_hartip():
    assert parse_hartip(struct.pack(">BBBBHH", 9, 1, 0, 0, 1, 8)) is None   # bad version
    assert parse_hartip(b"\x01\x01") is None                                # too short


def test_hartip_engine_confirmed():
    fs = HartIpEngine(runner=lambda host: (True, _hartip_response())).run(_tgt())
    assert [f.id for f in fs] == ["hart-ip-exposed"]
    assert "confirmed" in fs[0].evidence[0].detail.lower()


def test_hartip_engine_port_open_no_reply():
    fs = HartIpEngine(runner=lambda host: (True, b"")).run(_tgt())
    assert [f.id for f in fs] == ["hart-ip-exposed"]


def test_hartip_engine_not_connected():
    assert HartIpEngine(runner=lambda host: (False, b"")).run(_tgt()) == []


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            passed += 1
    print(f"{passed} passed")
