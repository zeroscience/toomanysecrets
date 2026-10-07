r"""Passive capture analysis - `redness capture` (orchestrates tshark / Wireshark).

REDNESS orchestrates rather than reimplements: this drives **tshark** (the Wireshark CLI) over a
live interface or an existing `.pcap` and turns what it sees into findings - cleartext credentials
on the wire and plaintext/sensitive protocols in use. It uses tshark's own taps:

  * `-z credentials` -> usernames/passwords tshark recovered (FTP/HTTP/IMAP/POP/SMTP/...).
  * `-z io,phs`      -> the protocol hierarchy, from which we flag cleartext/sensitive protocols.

Pure parsers over tshark's text output (unit-tested against captured samples); the tshark argv is
documented and best-effort (verify field/tap names on a box with Wireshark, same caution as the
nxc flags). Read-only analysis - capturing your own authorized traffic. Findings reuse
`Category.PASSWORD` (cleartext creds) and `Category.CONFIG` (cleartext protocols).
"""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import Callable, Optional

from .events import EventBus, EventKind
from .findings import Category, Evidence, Finding, Report, Severity

# Plaintext / sensitive protocols worth flagging if seen in a capture (no transport encryption).
_SENSITIVE = {
    "telnet": "Telnet (credentials + session in cleartext)",
    "ftp": "FTP (credentials + data in cleartext)",
    "tftp": "TFTP (no auth, cleartext file transfer)",
    "http": "HTTP (cleartext; check for Basic auth / cookies)",
    "pop": "POP3 (mail credentials in cleartext)",
    "imap": "IMAP (mail credentials in cleartext)",
    "smtp": "SMTP (mail; AUTH may be in cleartext)",
    "snmp": "SNMP (community strings in cleartext)",
    "rlogin": "rlogin (legacy, cleartext)",
    "rsh": "rsh (legacy, cleartext)",
    "finger": "finger (information disclosure)",
    "ntlmssp": "NTLM authentication observed (relayable / crackable)",
    "kerberos": "Kerberos observed (AS-REQ/TGS may be roastable)",
}


def creds_argv(source: str, *, live: bool = False, duration: int = 60) -> list[str]:
    """tshark argv for the credentials + protocol-hierarchy taps over a pcap or a live interface."""
    base = ["tshark", "-q", "-z", "credentials", "-z", "io,phs"]
    if live:
        return ["tshark", "-i", source, "-a", f"duration:{duration}",
                "-q", "-z", "credentials", "-z", "io,phs"]
    return base[:1] + ["-r", source] + base[1:]


def parse_credentials(output: str) -> list[dict]:
    """Rows from tshark's `-z credentials` table: [{packet, protocol, username, info}]."""
    out: list[dict] = []
    in_table = False
    for line in output.splitlines():
        s = line.strip()
        if s.lower() == "credentials":
            in_table = True
            continue
        if not in_table:
            continue
        if s.startswith("=") or s.startswith("-") or not s:
            continue
        if s.lower().startswith("packet") and "protocol" in s.lower():
            continue                                  # header row
        parts = s.split(None, 3)
        if len(parts) >= 3 and parts[0].isdigit():
            out.append({"packet": int(parts[0]), "protocol": parts[1],
                        "username": parts[2], "info": parts[3] if len(parts) > 3 else ""})
    return out


def parse_protocols(output: str) -> set[str]:
    """The set of protocol names present in a `-z io,phs` protocol-hierarchy tree."""
    protos: set[str] = set()
    in_tree = False
    for line in output.splitlines():
        if "Protocol Hierarchy Statistics" in line:
            in_tree = True
            continue
        if not in_tree:
            continue
        if line.strip().startswith("="):
            in_tree = False
            continue
        m = re.match(r"\s*([a-zA-Z0-9_.-]+)\s+frames:", line)
        if m:
            protos.add(m.group(1).lower())
    return protos


def build_findings(creds: list[dict], protocols: set[str]) -> list[Finding]:
    out: list[Finding] = []
    if creds:
        shown = "; ".join(f"{c['protocol']}:{c['username']}" for c in creds[:12])
        out.append(Finding(
            id="cleartext-credentials",
            title=f"Cleartext credentials captured on the wire ({len(creds)})",
            severity=Severity.CRITICAL, category=Category.PASSWORD,
            description="tshark recovered credentials sent in cleartext in the captured traffic.",
            impact="Credentials transmitted without encryption are trivially captured by anyone on "
                   "the path (a switch SPAN, ARP spoofing, or a shared segment) and reused.",
            remediation="Move these services to encrypted transports (FTPS/SFTP, HTTPS, IMAPS/"
                        "POP3S, SMTPS/STARTTLS, SSH); enforce TLS and disable the cleartext ports.",
            affected=sorted({c["protocol"] for c in creds}),
            evidence=[Evidence(source="tshark", detail=shown)],
            references=["https://attack.mitre.org/techniques/T1040/"],
            meta={"count": len(creds),
                  "credentials": [{"protocol": c["protocol"], "username": c["username"]}
                                  for c in creds]},
        ))
    sensitive = sorted(p for p in protocols if p in _SENSITIVE)
    if sensitive:
        out.append(Finding(
            id="cleartext-protocols",
            title=f"Plaintext / sensitive protocols observed ({len(sensitive)})",
            severity=Severity.MEDIUM, category=Category.CONFIG,
            description="The capture contains protocols that carry data or authentication without "
                        "transport encryption.",
            impact="Sessions and often credentials on these protocols can be read or hijacked by a "
                   "network attacker.",
            remediation="Replace with encrypted equivalents and disable the cleartext services.",
            affected=sensitive,
            evidence=[Evidence(source="tshark", detail="; ".join(_SENSITIVE[p] for p in sensitive))],
            references=["https://attack.mitre.org/techniques/T1040/"],
            meta={"protocols": sensitive},
        ))
    return out


def is_available() -> bool:
    return shutil.which("tshark") is not None


def _default_runner(argv: list[str], timeout: int) -> str:
    exe = shutil.which("tshark")
    if not exe:
        return ""
    try:
        p = subprocess.run([exe] + argv[1:], capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return (p.stdout or "") + "\n" + (p.stderr or "")


def run_capture(source: str, *, live: bool = False, duration: int = 60,
                engagement: str = "REDNESS capture", bus: Optional[EventBus] = None,
                runner: Optional[Callable[[list[str], int], str]] = None) -> Report:
    """Analyze a pcap (or a live interface) via tshark and return a Report."""
    argv = creds_argv(source, live=live, duration=duration)
    output = (runner or _default_runner)(argv, duration + 30 if live else 120)
    creds = parse_credentials(output)
    protocols = parse_protocols(output)
    findings = build_findings(creds, protocols)
    report = Report(engagement=engagement, target=source, findings=findings)
    if bus is not None:
        from .events import Event
        bus.publish(Event(kind=EventKind.STATUS, engine="capture",
                          data={"message": f"capture: {len(creds)} cred(s), "
                                           f"{len(sensitive_count(protocols))} sensitive proto(s)"}))
        for f in findings:
            bus.publish(Event(kind=EventKind.FINDING, data={"finding": f.to_dict()},
                              engine="capture"))
        bus.publish(Event(kind=EventKind.DONE, engine="capture", data={}))
    return report


def sensitive_count(protocols: set[str]) -> list[str]:
    return sorted(p for p in protocols if p in _SENSITIVE)
