# IoT protocols - MQTT + CoAP

REDNESS checks the common IoT message/transport layer as part of a normal scan (read-only,
port-gated where possible). Findings use `Category.IOT`.

| Protocol | Transport | Probe | Findings |
|----------|-----------|-------|----------|
| **MQTT** | TCP 1883 | anonymous CONNECT -> read CONNACK | `mqtt-anonymous` (HIGH, broker accepts no-cred connect) or `mqtt-exposed` (INFO, auth required) |
| **CoAP** | UDP 5683 | GET /.well-known/core | `coap-exposed` (MEDIUM) with the device's resource list |

- **MQTT** anonymous access means anyone can subscribe to every topic (`#`) - telemetry, state,
  commands, and credentials in payloads - and publish rogue messages. We only send a read-only
  CONNECT; subscribing/reading topic data is a gated follow-on. (8883/TLS is a follow-on.)
- **CoAP** plain (no DTLS) is unauthenticated; the `/.well-known/core` response both confirms the
  device and maps its resources. coaps (DTLS, UDP 5684) is the secure variant.

Both run in the default scan - MQTT is port-gated (only when TCP/1883 is open); CoAP is UDP so it
is un-gated (one read-only GET per host, like SNMP/BACnet). Parsers unit-test against captured
bytes; a real-socket smoke confirms the live path.

Next in the IoT/service direction: exposed unauthenticated services (Redis / MongoDB /
Elasticsearch / Memcached), network printers (IPP), MQTT-over-TLS, and topic sampling behind a gate.
