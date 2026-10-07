# Exposed services - Redis / MongoDB / Elasticsearch / Memcached / printers

The classic high-impact findings on a flat network: unauthenticated data stores and services.
REDNESS checks them in the default scan (read-only, one probe each, port-gated by discovery).
Findings use `Category.SERVICE`.

| Service | Port | Probe | Findings |
|---------|------|-------|----------|
| **Redis** | 6379 | INFO | `redis-unauth` (CRITICAL, no auth -> often RCE) / `redis-exposed` (INFO) |
| **MongoDB** | 27017 | listDatabases (OP_QUERY) | `mongodb-no-auth` (CRITICAL) / `mongodb-exposed` (INFO) |
| **Elasticsearch** | 9200 | GET / | `elasticsearch-unauth` (HIGH) / `elasticsearch-exposed` (INFO) |
| **Memcached** | 11211 | stats | `memcached-exposed` (HIGH, no auth by design; UDP is a DDoS amplifier) |
| **Printer / IPP** | 631 | HTTP banner | `printer-exposed` (MEDIUM: leaks jobs + stored scan/LDAP creds) |

Each engine distinguishes "reachable" from "reachable **without authentication**" where the
protocol allows - the unauth case is the critical one. All read-only (no data dumped; no keys
written). Pure parsers unit-test against captured bytes; a real-socket smoke confirms the live
path. Next: dumping/sampling (Redis keyspace, Mongo collections) behind a gated flag, and full IPP
Get-Printer-Attributes.
