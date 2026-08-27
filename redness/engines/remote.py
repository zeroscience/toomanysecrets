r"""Remote-access protocol engines - RDP / WinRM / MSSQL exposure + credentialed reach.

These are the lateral-movement surfaces the SMB / LDAP / AD CS / TLS engines miss:
the services an operator actually pivots through. Each wraps one nxc protocol
(`nxc rdp|winrm|mssql`), reads the connection banner and any credentialed-auth line,
and emits normalized findings.

Unlike `poison`/`spray`, these are PASSIVE enumeration - connect, read the banner, and
(only if the operator supplied creds) try those exact creds once. No guessing, no
lockout risk, nothing written to the target - so they run in `default_engines()` like
the SMB engine, not as a gated command.

Grouped in one module because all three share nxc's `PROTO host port name <body>` line
format and the same exposure/access finding shape. Parsing stays pure and separate from
subprocess exec (same discipline as netexec.py), unit-tested against captured nxc output
with no live host or nxc install needed.

Findings reuse existing categories - no `SCHEMA_VERSION` bump:
  * CONFIG - a misconfiguration (RDP NLA disabled) or a reachable-with-creds access path
  * ENUM   - plain service exposure (informational inventory)

Verified against NetExec's rdp/winrm/mssql protocol output:
    RDP     <host> 3389 <name> [*] Windows 10 ... (name:PC01) (domain:CORP.LOCAL) (nla:False)
    WINRM   <host> 5985 <name> [*] Windows ... (name:PC01) (domain:CORP.LOCAL)
    WINRM   <host> 5985 <name> [+] CORP.LOCAL\jdoe:Passw0rd (Pwn3d!)
    MSSQL   <host> 1433 <name> [+] CORP.LOCAL\sa:Passw0rd (Pwn3d!)
`mark_pwned()` renders `(Pwn3d!)`; WINRM-SSL is the TLS variant of the WINRM token.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target
from .netexec import strip_log_prefix

# Shared banner sub-fields (identical shape across the three protocols).
_NLA = re.compile(r"\(nla:(?P<v>True|False)\)", re.I)
_DOMAIN = re.compile(r"\(domain:(?P<v>[^)]+)\)", re.I)
_NAME = re.compile(r"\(name:(?P<v>[^)]+)\)", re.I)
_OS = re.compile(r"\[\*\]\s+(?P<os>.+?)\s+\((?:name|edition|nla):", re.I)
# A credentialed success line: "[+] domain\user:secret" with an optional "(Pwn3d!)".
# Requires a non-empty principal before ':' so a bare "[+] :" never counts as access.
_AUTH_OK = re.compile(r"\[\+\]\s+(?P<id>\S+\\[^:\s]+):\S*?\s*(?P<pwn>\(Pwn3d!\))?\s*$")


def _line_re(proto: str) -> re.Pattern:
    """nxc line matcher for a protocol token (WINRM also matches WINRM-SSL)."""
    return re.compile(
        rf"^{proto}(?:-\w+)?\s+(?P<host>\S+)\s+(?P<port>\d+)\s+(?P<name>\S+)\s+(?P<body>.*?)\s*$",
        re.I,
    )


def _iter(raw: str, proto: str):
    """Yield (host, port, name, body) for each nxc line of `proto`."""
    lre = _line_re(proto)
    for line in raw.splitlines():
        m = lre.match(strip_log_prefix(line))
        if m:
            yield m.group("host"), m.group("port"), m.group("name"), m.group("body")


@dataclass
class _Banner:
    host: str
    port: str = ""
    name: str = ""
    domain: str = ""
    os: str = ""
    nla: bool | None = None            # RDP only; None elsewhere
    reachable: bool = False


@dataclass
class _Access:
    identity: str                      # "CORP\\jdoe" as nxc reports it
    admin: bool = False                # (Pwn3d!)


def parse_banner(raw: str, proto: str) -> _Banner | None:
    """First reachable-host banner for `proto` (one Target = one host per scan run)."""
    b: _Banner | None = None
    for host, port, name, body in _iter(raw, proto):
        if b is None:
            b = _Banner(host=host, port=port, reachable=True)
        if name and name != host:
            b.name = name
        if (m := _NAME.search(body)):
            b.name = m.group("v")
        if (m := _DOMAIN.search(body)):
            b.domain = m.group("v")
        if (m := _OS.search(body)):
            b.os = m.group("os")
        if (m := _NLA.search(body)):
            b.nla = m.group("v").lower() == "true"
    return b


def parse_access(raw: str, proto: str) -> _Access | None:
    """A credentialed `[+] dom\\user:secret (Pwn3d!)` success for `proto`, if any."""
    best: _Access | None = None
    for _host, _port, _name, body in _iter(raw, proto):
        if (m := _AUTH_OK.search(body)):
            acc = _Access(identity=m.group("id"), admin=bool(m.group("pwn")))
            # Prefer an admin hit if several lines match.
            if best is None or (acc.admin and not best.admin):
                best = acc
    return best


# --------------------------------------------------------------------------- #
# Per-protocol finding builders (pure)                                         #
# --------------------------------------------------------------------------- #
def _os_detail(b: _Banner) -> str:
    bits = [x for x in (b.os, f"name:{b.name}" if b.name else "",
                        f"domain:{b.domain}" if b.domain else "") if x]
    return ", ".join(bits) or "reachable"


def parse_rdp(raw: str, credentialed: bool = False) -> list[Finding]:
    b = parse_banner(raw, "RDP")
    if b is None:
        return []
    out: list[Finding] = []
    if b.nla is False:
        out.append(Finding(
            id="rdp-nla-disabled",
            title="RDP without Network Level Authentication (NLA)",
            severity=Severity.MEDIUM,
            category=Category.CONFIG,
            description="The host accepts RDP connections without requiring Network Level "
                        "Authentication, so session setup happens before the user authenticates.",
            impact="Pre-authentication attack surface: enables pre-auth RDP exploits (e.g. "
                   "BlueKeep / CVE-2019-0708 class) on unpatched hosts and rogue-RDP credential "
                   "harvesting, and removes a brute-force / DoS speed bump.",
            remediation="Require NLA: 'Require user authentication for remote connections by using "
                        "Network Level Authentication' = Enabled (GPO), and keep RDP hosts patched.",
            affected=[b.host],
            evidence=[Evidence(source="netexec", detail=f"RDP {b.host}: nla:False ({_os_detail(b)})")],
            references=["https://attack.mitre.org/techniques/T1021/001/"],
            credentialed=credentialed,
        ))
    out.append(_exposed("rdp-exposed", "RDP", b, credentialed))
    acc = parse_access(raw, "RDP")
    if acc is not None:
        out.append(_access(
            "rdp-access", "RDP", b, acc,
            sev=Severity.HIGH if acc.admin else Severity.MEDIUM,
            impact=("Administrative interactive logon over RDP - full control of the host."
                    if acc.admin else
                    "Interactive RDP logon as a valid domain principal - a lateral-movement foothold."),
            ref="https://attack.mitre.org/techniques/T1021/001/",
            credentialed=credentialed,
        ))
    return out


def parse_winrm(raw: str, credentialed: bool = False) -> list[Finding]:
    b = parse_banner(raw, "WINRM")
    if b is None:
        return []
    out = [_exposed("winrm-exposed", "WinRM", b, credentialed)]
    acc = parse_access(raw, "WINRM")
    if acc is not None:
        out.append(_access(
            "winrm-access", "WinRM", b, acc,
            sev=Severity.CRITICAL if acc.admin else Severity.HIGH,
            impact=("Administrative WinRM access - remote PowerShell as an administrator is direct "
                    "remote code execution and host takeover."
                    if acc.admin else
                    "WinRM access as a valid principal - remote PowerShell command execution on the host."),
            ref="https://attack.mitre.org/techniques/T1021/006/",
            credentialed=credentialed,
        ))
    return out


def parse_mssql(raw: str, credentialed: bool = False) -> list[Finding]:
    b = parse_banner(raw, "MSSQL")
    if b is None:
        return []
    out = [_exposed("mssql-exposed", "MSSQL", b, credentialed)]
    acc = parse_access(raw, "MSSQL")
    if acc is not None:
        out.append(_access(
            "mssql-access", "MSSQL", b, acc,
            sev=Severity.CRITICAL if acc.admin else Severity.HIGH,
            impact=("Sysadmin access to MSSQL - xp_cmdshell / job execution yields remote code "
                    "execution as the SQL service account (often high-privileged)."
                    if acc.admin else
                    "Authenticated MSSQL access as a valid principal - database read/write and a "
                    "common path to code execution (xp_cmdshell, linked servers)."),
            ref="https://attack.mitre.org/techniques/T1210/",
            credentialed=credentialed,
        ))
    return out


def _exposed(fid: str, label: str, b: _Banner, credentialed: bool) -> Finding:
    return Finding(
        id=fid,
        title=f"{label} service reachable",
        severity=Severity.INFO,
        category=Category.ENUM,
        description=f"The host exposes a reachable {label} service.",
        affected=[b.host],
        evidence=[Evidence(source="netexec", detail=f"{label} {b.host}: {_os_detail(b)}")],
        credentialed=credentialed,
    )


def _access(fid: str, label: str, b: _Banner, acc: _Access, *, sev: Severity,
            impact: str, ref: str, credentialed: bool) -> Finding:
    admin = " (admin)" if acc.admin else ""
    return Finding(
        id=fid,
        title=f"{label} access with supplied credentials{admin}: {acc.identity}",
        severity=sev,
        category=Category.CONFIG,
        description=f"The supplied credentials authenticate to {label} on this host"
                    + (" with administrative privilege (Pwn3d)." if acc.admin else "."),
        impact=impact,
        remediation="Restrict which principals may reach this service (host firewall / network "
                    "segmentation), enforce least privilege on the account, and require MFA / a "
                    "privileged-access workstation for administrative remote access.",
        affected=[b.host],
        evidence=[Evidence(source="netexec",
                           detail=f"{label} {b.host}: {acc.identity}" + (" (Pwn3d!)" if acc.admin else ""))],
        references=[ref],
        credentialed=credentialed,
    )


# --------------------------------------------------------------------------- #
# Engines (thin nxc drivers; parsing above stays pure)                         #
# --------------------------------------------------------------------------- #
@dataclass
class _ProtoSpec:
    name: str                          # engine name (doctor / events)
    proto: str                         # nxc protocol token
    parse: object                      # parse_* callable


class _RemoteEngine(Engine):
    """Shared nxc driver for a single remote-access protocol."""

    spec: _ProtoSpec

    def __init__(self, timeout: int = 300):
        self.timeout = timeout
        self.name = self.spec.name

    def _bin(self) -> str | None:
        return shutil.which("nxc") or shutil.which("netexec")

    def is_available(self) -> bool:
        return self._bin() is not None

    def _auth_args(self, target: Target) -> list[str]:
        if not target.credentialed:
            return []                  # unauthenticated banner read (exposure + RDP NLA)
        args = ["-u", target.username or ""]
        if target.nthash:
            args += ["-H", target.nthash]
        else:
            args += ["-p", target.password or ""]
        if target.kerberos:
            args += ["-k"]
        if target.domain:
            args += ["-d", target.domain]
        return args

    def _invoke(self, target: Target) -> str:
        exe = self._bin()
        if not exe:
            return ""
        cmd = [exe, self.spec.proto, target.host] + self._auth_args(target)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except (subprocess.TimeoutExpired, OSError):
            return ""
        return (proc.stdout or "") + "\n" + (proc.stderr or "")

    def run(self, target: Target) -> list[Finding]:
        if not self.is_available():
            return []
        raw = self._invoke(target)
        findings = self.spec.parse(raw, credentialed=target.credentialed)
        if findings and findings[0].evidence:
            findings[0].evidence[0].raw = raw.strip()[:4000]
        return findings


class RdpEngine(_RemoteEngine):
    spec = _ProtoSpec(name="rdp", proto="rdp", parse=parse_rdp)


class WinRMEngine(_RemoteEngine):
    spec = _ProtoSpec(name="winrm", proto="winrm", parse=parse_winrm)


class MssqlEngine(_RemoteEngine):
    spec = _ProtoSpec(name="mssql", proto="mssql", parse=parse_mssql)
