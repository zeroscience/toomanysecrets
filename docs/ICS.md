# ICS / OT field protocols - `scan --ics`

REDNESS can enumerate industrial control systems (OT) the same way it enumerates AD: read-only
probes, normalized findings, a severity-ranked report, and nodes on the live graph. This is the
first step toward REDNESS as a general network-assessment tool, not only an AD one.

## OT-safe by construction

OT kit is fragile - an aggressive scan can disrupt a live process. So the whole pack is built to
be the least-intrusive thing that still answers "what controllers are reachable, and what are
they?":

- **Read-only.** Each engine sends ONE identity request (List Identity / Read Device Identification
  / Who-Is). It never writes a coil, register, point, or controller mode, and never does a
  write-echo liveness test.
- **Opt-in.** The pack is off by default. You turn it on with `scan --ics` - touching OT is an
  explicit scope decision, not something that happens in a routine AD scan.
- **Port-gated.** The TCP protocols (EtherNet/IP, Modbus) only run when the discovery connect-scan
  saw the port open. Nothing is blind-probed.
- **The louder tiers are deferred.** Mapping serial RTUs behind a Modbus gateway (unit-id sweep),
  DNP3 outstation-address scanning, and HART wireless-roster walks each wait behind their own
  explicit opt-in, because broad address scans are what upset old devices.

## Protocols (this release)

| Protocol | Transport | Probe | Findings |
|----------|-----------|-------|----------|
| **EtherNet/IP (CIP)** | TCP 44818 | List Identity (0x63) | `enip-exposed` (HIGH), `enip-device-identity` (INFO: vendor/product/rev/serial/state) |
| **Modbus/TCP** | TCP 502 | Read Device Identification (fn 0x2B/0x0E) | `modbus-exposed` (HIGH), `modbus-device-identity` (INFO) |
| **BACnet/IP** | UDP 47808 | Who-Is -> I-Am | `bacnet-exposed` (MEDIUM), `bacnet-device-identity` (INFO: device instance + vendor) |
| **DNP3** | TCP 20000 | Request Link Status (fn 0x09) | `dnp3-exposed` (HIGH), `dnp3-outstation` (INFO: outstation address) when it replies |
| **HART-IP** | TCP 5094 | Session Initiate | `hart-ip-exposed` (HIGH) |

For DNP3 and HART-IP the engines confirm presence and (for DNP3) discover the outstation address;
reading full device attributes - DNP3 Group 0 (vendor/firmware/model) and the HART-IP field-device
roster via HART Command 0 - rides the application/session layer and needs a real device, so it is
deferred to the gated enumeration tier + a real-device verify pass (same contract-first caution as
RBCD). For DNP3, a listening port is already the exposure; a Link Status reply upgrades it to
confirmed with the outstation address.

Every OT finding is `Category.ICS` and carries `meta["protocol"]`, `meta["purdue"]` (Purdue model
level), and `meta["device"]` (vendor/product/revision/serial) when identity was read. The headline
risk is always the same: **an unauthenticated control protocol is reachable** - these protocols
have no authentication or encryption by design, so network reachability *is* the exposure.

## Usage

```bash
# OT discovery folded into a normal scan (read-only, port-gated)
redness scan --targets examples/scope.txt --ics --out report.docx

# OT-only sweep of a cell, with the live graph
redness scan --target 10.20.0.0/24 --ics --live
```

## Validating against real/simulated devices

Parsers unit-test against captured bytes (no hardware). For real validation, free simulators cover
the first three protocols:

- **EtherNet/IP:** `cpppo` (`python -m cpppo.server.enip`), or Wireshark sample captures.
- **Modbus:** `diagslave`, `pymodbus` server, or ModbusPal.
- **BACnet:** the YABE/BACnet stack test tools, or a real controller on a lab VLAN.

## Roadmap (next in the OT pack)

- **Device attributes** - DNP3 Group 0 (vendor/firmware/model) and the HART-IP field-device roster
  (HART Command 0); gated enumeration tiers with a real-device verify pass.
- **Enumeration tiers** - Modbus unit-id sweep (serial RTUs behind a gateway) and the DNP3
  outstation-address scan, each behind its own explicit opt-in.
- **Graph (BUILT):** OT-specific node types (`plc` / `rtu` / `gateway` / `controller`) and a
  **`Process Impact`** goal node (the OT analog of Domain Admin). Each exposed controller draws a
  dashed `controller -> Process Impact` lead, and when one scan reaches both IT and OT - a Purdue
  **segmentation failure** - a solid `IT / Enterprise -> controller` edge plus an `ot-it-segmentation`
  CRITICAL finding. Derived in `redness/ot.py` (mirrors paths.py/relay.py); the auto-tour and
  replay reach the Process Impact goal just like Domain Admin. See docs/DECISIONS.md (2026-10-07).
