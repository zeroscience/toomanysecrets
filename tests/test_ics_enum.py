"""OT enumeration tier: Modbus unit-id sweep + DNP3 outstation-address scan (read-only)."""
import struct

from redness.engines import Dnp3ScanEngine, ModbusSweepEngine
from redness.engines.base import Target
from redness.engines.dnp3 import dnp3_crc
from redness.findings import Category, Severity


def _tgt(host="10.20.0.9"):
    return Target(host=host)


def _modbus_devid(name=b"RTU"):
    objs = ((0x00, b"ACME"), (0x02, b"1.0"), (0x04, name))
    body = bytes([0x2B, 0x0E, 0x01, 0x81, 0x00, 0x00, len(objs)])
    for oid, val in objs:
        body += bytes([oid, len(val)]) + val
    return struct.pack(">HHHB", 1, 0, 1 + len(body), 1) + body


def _link_status(outstation):
    header = bytes([0x05, 0x64, 0x05, 0x0B]) + struct.pack("<HH", 1, outstation)
    return header + struct.pack("<H", dnp3_crc(header[2:]))


# --- Modbus unit-id sweep -------------------------------------------------- #
def test_modbus_sweep_maps_units_behind_gateway():
    # units 3 and 7 respond with identity; others are silent
    replies = {3: _modbus_devid(b"PumpCtl"), 7: _modbus_devid(b"ValveCtl")}
    eng = ModbusSweepEngine(units=range(1, 11),
                            runner=lambda host, unit: replies.get(unit, b""))
    fs = eng.run(_tgt())
    assert [f.id for f in fs] == ["modbus-exposed", "modbus-gateway-units"]
    gw = fs[1]
    assert gw.severity is Severity.INFO and gw.category is Category.ICS
    assert [d["unit"] for d in gw.meta["units"]] == [3, 7]
    assert "PumpCtl" in gw.evidence[0].detail and "ValveCtl" in gw.evidence[0].detail


def test_modbus_sweep_no_response_no_findings():
    eng = ModbusSweepEngine(units=range(1, 5), runner=lambda host, unit: b"")
    assert eng.run(_tgt()) == []


# --- DNP3 address scan ----------------------------------------------------- #
def test_dnp3_scan_discovers_outstations():
    replies = {1024: (True, _link_status(1024)), 2051: (True, _link_status(2051))}
    eng = Dnp3ScanEngine(addrs=(0, 1024, 2051, 5),
                         runner=lambda host, addr: replies.get(addr, (True, b"")))
    fs = eng.run(_tgt())
    assert [f.id for f in fs] == ["dnp3-exposed", "dnp3-segment"]
    assert fs[1].meta["outstations"] == [1024, 2051]


def test_dnp3_scan_port_open_no_reply_is_exposure_only():
    eng = Dnp3ScanEngine(addrs=(0, 1), runner=lambda host, addr: (True, b""))
    fs = eng.run(_tgt())
    assert [f.id for f in fs] == ["dnp3-exposed"]


def test_dnp3_scan_not_connected_no_findings():
    eng = Dnp3ScanEngine(addrs=(0, 1), runner=lambda host, addr: (False, b""))
    assert eng.run(_tgt()) == []


def test_ics_engines_enum_swaps_in_sweep_variants():
    from redness.scan import ics_engines
    names_default = [e.name for e in ics_engines(enum=False)]
    enum = ics_engines(enum=True)
    assert "modbus" in names_default and "dnp3" in names_default
    # enum tier includes the sweep engines (same names, sweep classes)
    classes = {type(e).__name__ for e in enum}
    assert "ModbusSweepEngine" in classes and "Dnp3ScanEngine" in classes
    assert "ModbusEngine" not in classes and "Dnp3Engine" not in classes


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            passed += 1
    print(f"{passed} passed")
