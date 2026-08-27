r"""FTP engine - anonymous login + exposure (+ credentialed access).

Wraps `nxc ftp`. Anonymous FTP is a classic unauthenticated foothold (read, sometimes
write, of whatever the server exposes) and the banner often leaks an outdated ftpd. Passive
- connect, try an anonymous login (or the supplied creds) once, read the banner - so it runs
in the default scan like the other read-only engines.

Parsing is pure and separated from exec (same discipline as netexec.py), verified against
NetExec's ftp protocol output:
    FTP   <host> 21 <name> [*] Banner: <server version>
    FTP   <host> 21 <name> [+] anonymous: - Anonymous Login!
    FTP   <host> 21 <name> [+] jdoe:Passw0rd
(FTP has no admin/`Pwn3d!` concept.) Findings reuse CONFIG / ENUM - no schema change.
"""
from __future__ import annotations

import re
import shutil
import subprocess

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target
from .netexec import strip_log_prefix

_LINE = re.compile(r"^FTP\s+(?P<host>\S+)\s+(?P<port>\d+)\s+(?P<name>\S+)\s+(?P<body>.*?)\s*$", re.I)
_BANNER = re.compile(r"\[\*\]\s*Banner:\s*(?P<v>.+?)\s*$", re.I)
_ANON = re.compile(r"\[\+\]\s+(?P<id>\S+?):\S*\s*-\s*Anonymous Login!", re.I)
_LOGIN = re.compile(r"\[\+\]\s+(?P<user>[^:\s]+):(?P<pw>\S*)\s*$")


def _iter(raw: str):
    for line in raw.splitlines():
        m = _LINE.match(strip_log_prefix(line))
        if m:
            yield m.group("host"), m.group("body")


def parse_ftp(raw: str, credentialed: bool = False) -> list[Finding]:
    """FTP findings from nxc ftp stdout (one host per scan run)."""
    host = ""
    banner = ""
    anon = False
    login: str | None = None
    for h, body in _iter(raw):
        host = host or h
        if (m := _BANNER.search(body)):
            banner = m.group("v")
        if _ANON.search(body):
            anon = True
        elif (m := _LOGIN.search(body)):
            login = m.group("user")
    if not host:
        return []

    detail = f"FTP {host}" + (f": {banner}" if banner else "")
    out: list[Finding] = []
    if anon:
        out.append(Finding(
            id="ftp-anonymous",
            title="Anonymous FTP login allowed",
            severity=Severity.MEDIUM,
            category=Category.CONFIG,
            description="The FTP service accepts anonymous logins.",
            impact="Unauthenticated users can read (and sometimes write) whatever the server "
                   "exposes - a common source of leaked files and a foothold for payload staging.",
            remediation="Disable anonymous FTP, or restrict it to a locked-down read-only jail; "
                        "prefer SFTP/FTPS with authentication.",
            affected=[host],
            evidence=[Evidence(source="netexec", detail=f"{detail} (anonymous login)")],
            references=["https://attack.mitre.org/techniques/T1078/003/"],
            credentialed=False,
        ))
    out.append(Finding(
        id="ftp-exposed",
        title="FTP service reachable",
        severity=Severity.INFO,
        category=Category.ENUM,
        description="The host exposes a reachable FTP service."
                    + (" Banner may reveal the server version." if banner else ""),
        affected=[host],
        evidence=[Evidence(source="netexec", detail=detail)],
        credentialed=credentialed,
    ))
    if login and login.lower() != "anonymous":
        out.append(Finding(
            id="ftp-access",
            title=f"FTP access with supplied credentials: {login}",
            severity=Severity.LOW,
            category=Category.CONFIG,
            description=f"The supplied credentials authenticate to FTP on this host as '{login}'.",
            impact="Confirms a reachable authenticated FTP path for this credential.",
            remediation="Restrict FTP access and prefer authenticated SFTP/FTPS; apply least "
                        "privilege on the account.",
            affected=[host],
            evidence=[Evidence(source="netexec", detail=f"{host}: {login} authenticated")],
            credentialed=credentialed,
        ))
    return out


class FtpEngine(Engine):
    name = "ftp"

    def __init__(self, timeout: int = 120):
        self.timeout = timeout

    def _bin(self) -> str | None:
        return shutil.which("nxc") or shutil.which("netexec")

    def is_available(self) -> bool:
        return self._bin() is not None

    def _auth_args(self, target: Target) -> list[str]:
        # FTP has no PtH/Kerberos; supply creds if given, else probe anonymous.
        if target.credentialed and target.username:
            return ["-u", target.username, "-p", target.password or ""]
        return ["-u", "anonymous", "-p", ""]

    def run(self, target: Target) -> list[Finding]:
        exe = self._bin()
        if not exe:
            return []
        cmd = [exe, "ftp", target.host] + self._auth_args(target)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except (subprocess.TimeoutExpired, OSError):
            return []
        raw = (proc.stdout or "") + "\n" + (proc.stderr or "")
        findings = parse_ftp(raw, credentialed=target.credentialed)
        if findings and findings[0].evidence:
            findings[0].evidence[0].raw = raw.strip()[:4000]
        return findings
