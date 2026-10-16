r"""Nmap engine - service/version detection (`nmap -sV`), the tech-stack detector.

REDNESS's own discovery (discovery.py) is a pure TCP connect-scan: it learns which ports are
open, not what is listening on them. This engine runs `nmap -sV` to identify the service, product,
version and CPE on each open port - the context the advisor (redness/advisor.py) needs to suggest
"run tool X against this stack". Opt-in (`scan --nmap`): nmap is a standard but ACTIVE scan.

Parsing is pure over nmap's XML (`-oX -`), so it unit-tests with no nmap and no network. The
engine emits ONE informational inventory `Finding` per host whose `meta["services"]` carries the
structured service list the advisor reads.

Reference: https://nmap.org/book/man-version-detection.html
"""
from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target


@dataclass
class Service:
    host: str
    port: int
    proto: str = "tcp"
    name: str = ""          # service name: http, ssh, microsoft-ds, ...
    product: str = ""       # Apache httpd, OpenSSH, ...
    version: str = ""       # 2.4.49
    extrainfo: str = ""
    cpes: list[str] = field(default_factory=list)

    @property
    def banner(self) -> str:
        return " ".join(x for x in (self.product, self.version, self.extrainfo) if x).strip()


def parse_nmap(xml_text: str) -> list[Service]:
    """Parse `nmap -sV -oX -` output into open-port Services. Invalid XML -> []."""
    try:
        root = ET.fromstring(xml_text or "")
    except ET.ParseError:
        return []
    out: list[Service] = []
    for host in root.findall("host"):
        addr = ""
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr") or addr
        if not addr:
            hn = host.find("hostnames/hostname")
            addr = hn.get("name") if hn is not None else ""
        for port in host.findall("ports/port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            portid = int(port.get("portid") or 0)
            proto = port.get("protocol") or "tcp"
            svc = port.find("service")
            if svc is None:
                out.append(Service(host=addr, port=portid, proto=proto))
                continue
            out.append(Service(
                host=addr, port=portid, proto=proto,
                name=svc.get("name") or "",
                product=svc.get("product") or "",
                version=svc.get("version") or "",
                extrainfo=svc.get("extrainfo") or "",
                cpes=[c.text for c in svc.findall("cpe") if c.text],
            ))
    return out


def build_findings(services: list[Service], host: str) -> list[Finding]:
    """One INFO inventory finding for `host`; its meta carries the structured service list."""
    svcs = [s for s in services if s.port]
    if not svcs:
        return []
    ev = [Evidence(source="nmap",
                   detail=f"{s.port}/{s.proto} {s.name}{(' ' + s.banner) if s.banner else ''}".strip())
          for s in svcs]
    meta_services = [{"host": s.host or host, "port": s.port, "proto": s.proto, "service": s.name,
                      "product": s.product, "version": s.version, "cpes": s.cpes} for s in svcs]
    return [Finding(
        id="nmap-services",
        title=f"Service/version inventory ({len(svcs)} service(s))",
        severity=Severity.INFO,
        category=Category.ENUM,
        description="nmap -sV service and version detection; feeds the advisor's tool suggestions.",
        impact="Identifies the exposed software and versions - the attack surface to target next.",
        remediation="Reduce the exposed service surface; patch/upgrade and firewall what is not needed.",
        affected=[host],
        evidence=ev,
        references=["https://nmap.org/book/man-version-detection.html"],
        meta={"services": meta_services, "source": "nmap"},
    )]


class NmapEngine(Engine):
    """Opt-in `nmap -sV` service/version detection. Active standard scan; the advisor's detector."""
    name = "nmap"

    def __init__(self, ports: str = "--top-ports 1000", timeout: int = 600,
                 extra: list[str] | None = None) -> None:
        self.ports = ports
        self.timeout = timeout
        self.extra = extra or []

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    def _argv(self, target: Target) -> list[str]:
        exe = shutil.which("nmap") or "nmap"
        return [exe, "-sV", "-Pn", "-T4", "-oX", "-"] + self.ports.split() + self.extra + [target.host]

    def run(self, target: Target) -> list[Finding]:
        if not self.is_available():
            return []
        try:
            proc = subprocess.run(self._argv(target), capture_output=True, text=True,
                                  timeout=self.timeout)
        except (subprocess.TimeoutExpired, OSError):
            return []
        return build_findings(parse_nmap(proc.stdout or ""), target.host)
