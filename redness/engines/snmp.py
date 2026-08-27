r"""SNMP engine - default community strings (public / private).

SNMP with a default community string is a classic finding: `public` leaks device config,
routes, ARP tables, running processes and sometimes credentials; `private` usually means
read-WRITE control of the device. SNMP is UDP/161, which a TCP connect-scan cannot see, so
this engine is not port-gated (it runs whenever its tool is present) and is skipped cleanly
when the tool is absent.

Unlike the nxc-backed engines this wraps an external `snmpwalk` (net-snmp) - REDNESS
orchestrates it rather than reimplementing SNMP/BER. Parsing is pure and the tool runner is
injectable, so parser + findings unit-test with no snmpwalk / no host. Findings reuse
CONFIG / ENUM - no schema change.

Typical snmpwalk success (sysDescr):
    SNMPv2-MIB::sysDescr.0 = STRING: Hardware: Intel64 ... Windows Server 2019 ...
"""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import Callable, Optional

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target

DEFAULT_COMMUNITIES = ("public", "private")
_SYSDESCR_OID = "1.3.6.1.2.1.1.1.0"
_VALUE = re.compile(r"=\s*(?:STRING|Hex-STRING|INTEGER):\s*(?P<v>.+?)\s*$", re.I)


def parse_snmp(raw: str) -> Optional[str]:
    """Return the sysDescr value if snmpwalk got a response, else None."""
    for line in raw.splitlines():
        if (m := _VALUE.search(line)):
            return m.group("v").strip()
    return None


def build_findings(host: str, hits: list[tuple[str, str]], credentialed: bool = False) -> list[Finding]:
    """One finding per working community; `private` (usually RW) is CRITICAL, else HIGH."""
    out: list[Finding] = []
    for community, sysdescr in hits:
        rw = community.lower() == "private"
        out.append(Finding(
            id="snmp-default-community",
            title=f"SNMP default community string '{community}'"
                  + (" (read-write)" if rw else " (read)"),
            severity=Severity.CRITICAL if rw else Severity.HIGH,
            category=Category.CONFIG,
            description=f"The host responds to SNMP with the default community string '{community}'.",
            impact=("Read-write SNMP ('private') can reconfigure the device - a full takeover of "
                    "network gear."
                    if rw else
                    "Read SNMP ('public') leaks system, network, route/ARP and process information, "
                    "and on some devices credentials - valuable reconnaissance and a foothold."),
            remediation="Change or disable default community strings; restrict SNMP to management "
                        "hosts (ACL/firewall UDP 161); prefer SNMPv3 with authentication and "
                        "encryption.",
            affected=[host],
            evidence=[Evidence(source="snmpwalk",
                               detail=f"community '{community}' -> sysDescr: {sysdescr[:200]}")],
            references=["https://attack.mitre.org/techniques/T1078/001/"],
            credentialed=credentialed,
        ))
    return out


def _default_run(host: str, community: str, *, timeout: int = 10) -> str:
    exe = shutil.which("snmpwalk")
    if not exe:
        return ""
    cmd = [exe, "-v2c", "-c", community, "-t", "2", "-r", "1", "-On", host, _SYSDESCR_OID]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return (proc.stdout or "") + "\n" + (proc.stderr or "")


class SnmpEngine(Engine):
    """Not port-gated (UDP/161); runs only when snmpwalk is installed."""

    name = "snmp"

    def __init__(self, communities=DEFAULT_COMMUNITIES,
                 runner: Optional[Callable[[str, str], str]] = None):
        self.communities = tuple(communities)
        self._run = runner or _default_run

    def is_available(self) -> bool:
        return shutil.which("snmpwalk") is not None

    def run(self, target: Target) -> list[Finding]:
        hits: list[tuple[str, str]] = []
        for community in self.communities:
            desc = parse_snmp(self._run(target.host, community))
            if desc is not None:
                hits.append((community, desc))
        return build_findings(target.host, hits, credentialed=target.credentialed)
