"""Normalized findings model - THE CONTRACT between engines and reporting.

Engines (netexec/impacket/certipy wrappers) produce `Finding` objects.
The reporter consumes them. Neither side needs to know the other's internals;
they only agree on this schema.

Keep this stable. If you must change it, bump SCHEMA_VERSION and note it in
docs/DECISIONS.md so the other researcher's agent picks up the change.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional

SCHEMA_VERSION = "1.4.0"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
        }[self.value]


class Category(str, Enum):
    SMB = "smb"
    LDAP = "ldap"
    KERBEROS = "kerberos"
    ADCS = "adcs"
    PASSWORD = "password"
    TLS = "tls"
    CONFIG = "config"
    SECRET = "secret"      # credential material found on shares (share secret-hunting)
    ENUM = "enum"          # informational enumeration (users, shares, hosts)
    ICS = "ics"            # industrial control systems / OT field protocols (Modbus/CIP/DNP3/...)
    IOT = "iot"            # IoT / messaging protocols (MQTT, CoAP)
    SERVICE = "service"    # exposed/unauthenticated network services (Redis/Mongo/printers/...)
    WEB = "web"            # web/network template findings from nuclei (CVEs, panels, misconfig)


@dataclass
class Evidence:
    """A single piece of proof backing a finding (raw tool output, a host, a value)."""
    source: str                      # e.g. "netexec", "certipy", "impacket.GetNPUsers"
    detail: str                      # human-readable evidence line
    raw: Optional[str] = None        # verbatim tool output, optional


@dataclass
class Finding:
    id: str                          # stable slug, e.g. "smb-signing-disabled"
    title: str
    severity: Severity
    category: Category
    description: str = ""            # what it is
    impact: str = ""                # why it matters
    remediation: str = ""           # how to fix
    affected: list[str] = field(default_factory=list)   # hosts / accounts / DNs
    evidence: list[Evidence] = field(default_factory=list)
    references: list[str] = field(default_factory=list)  # URLs, CVEs, MITRE ATT&CK ids
    credentialed: bool = False       # was this found with creds or unauth?
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(
            id=d["id"],
            title=d["title"],
            severity=Severity(d["severity"]),
            category=Category(d["category"]),
            description=d.get("description", ""),
            impact=d.get("impact", ""),
            remediation=d.get("remediation", ""),
            affected=list(d.get("affected", [])),
            evidence=[Evidence(**e) for e in d.get("evidence", [])],
            references=list(d.get("references", [])),
            credentialed=bool(d.get("credentialed", False)),
            meta=dict(d.get("meta", {})),
        )


@dataclass
class Report:
    """Top-level container serialized to findings.json."""
    engagement: str = "Unnamed Engagement"
    target: str = ""                 # domain / CIDR / host
    schema_version: str = SCHEMA_VERSION
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def sorted_findings(self) -> list[Finding]:
        """Most severe first, stable by id within a severity."""
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, f.category.value, f.id),
        )

    def by_severity(self) -> dict[Severity, list[Finding]]:
        out: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            out[f.severity].append(f)
        return out

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            {
                "engagement": self.engagement,
                "target": self.target,
                "schema_version": self.schema_version,
                "meta": self.meta,
                "findings": [f.to_dict() for f in self.findings],
            },
            indent=indent,
        )

    @classmethod
    def from_json(cls, s: str) -> "Report":
        d = json.loads(s)
        return cls(
            engagement=d.get("engagement", "Unnamed Engagement"),
            target=d.get("target", ""),
            schema_version=d.get("schema_version", SCHEMA_VERSION),
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            meta=dict(d.get("meta", {})),
        )
