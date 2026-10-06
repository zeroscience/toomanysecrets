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

- **DNP3** (TCP/UDP 20000) - Request Link Status + Read Device Attributes; flag missing DNP3 Secure
  Authentication. Needs the DNP3 CRC-16.
- **HART-IP** (TCP/UDP 5094) - Command 0 identity + the field-device roster behind a gateway.
- **Graph:** OT-specific node types (`plc` / `rtu` / `gateway` / `field-device`) grouped by Purdue
  level, and an `IT host -> reachable controller -> Process Impact` attack path (the OT analog of
  path-to-Domain-Admin) when one scan reaches both IT and OT (a segmentation failure).
