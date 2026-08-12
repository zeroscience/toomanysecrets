r"""NetExec (nxc) engine — SMB.

Design: parsing is pure and separate from execution, so parsers are unit-testable
against captured `nxc` output without a live DC or nxc installed (see tests/).

`run()` shells out to nxc; the `parse_*` functions turn stdout into Findings.

NetExec stdout is line-oriented and stable enough to regex:

    SMB  10.10.0.15  445  DC01  [*] Windows Server 2019 Build 17763 x64 \
         (name:DC01) (domain:acme.local) (signing:False) (SMBv1:True)
    SMB  10.10.0.15  445  DC01  [+] acme.local\guest:                       (null/guest auth OK)
    SMB  10.10.0.15  445  DC01  [+] acme.local\admin:Pass (Pwn3d!)          (local admin)
    SMB  10.10.0.15  445  DC01  Share      Permissions   Remark
    SMB  10.10.0.15  445  DC01  IPC$       READ          Remote IPC
    SMB  10.10.0.15  445  DC01  backups    READ,WRITE    Nightly backups

Reference: https://www.netexec.wiki/
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target

# Shares present on virtually every Windows host — not findings on their own.
DEFAULT_SHARES = {"ADMIN$", "C$", "IPC$", "PRINT$", "NETLOGON", "SYSVOL", "FAX$"}

# SMB  <host>  <port>  <netbios>  <body>
_LINE = re.compile(
    r"^SMB\s+(?P<host>\S+)\s+(?P<port>\d+)\s+(?P<name>\S+)\s+(?P<body>.*?)\s*$"
)
_SIGNING = re.compile(r"\(signing:(?P<v>True|False)\)", re.I)
_SMBV1 = re.compile(r"\(SMBv1:(?P<v>True|False)\)", re.I)
_DOMAIN = re.compile(r"\(domain:(?P<v>[^)]+)\)", re.I)
_OS = re.compile(r"\[\*\]\s+(?P<os>.+?)\s+\(name:", re.I)
# A successful auth line: "[+] domain\user:pass" optionally "(Pwn3d!)"
_AUTH_OK = re.compile(r"\[\+\]\s+(?P<id>\S+?)\s*(?P<pwn>\(Pwn3d!\))?\s*$")
# Newer nxc reports anonymous access as a banner field: "(Null Auth:True)".
_NULLAUTH = re.compile(r"\(Null\s*Auth:(?P<v>True|False)\)", re.I)
# Share table row: name, optional permissions (READ / WRITE / READ,WRITE), remark
_SHARE_ROW = re.compile(
    r"^(?P<share>\S+)\s+(?P<perms>(?:READ|WRITE)(?:,(?:READ|WRITE))*)?\s*(?P<remark>.*)$"
)


@dataclass
class _Host:
    ip: str
    name: str = ""
    domain: str = ""
    os: str = ""
    signing: bool | None = None
    smbv1: bool | None = None


# nxc's --verbose / --log format prepends a log prefix before the protocol token, e.g.
#   "2026-07-22 12:49:01 | samruser.py:172 - INFO - SMB   10.0.0.1  445 ..."
# Strip it so the anchored SMB/LDAP parsers still work if verbose output ever reaches us.
_LOG_PREFIX = re.compile(
    r"^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d\s*\|\s*\S+\s*-\s*\w+\s*-\s*"
)


def strip_log_prefix(line: str) -> str:
    """Remove an optional nxc verbose/log line prefix (shared with the LDAP parser)."""
    return _LOG_PREFIX.sub("", line.strip(), count=1)


def _iter_lines(raw: str):
    """Yield (host, port, name, body) tuples from nxc SMB output."""
    for line in raw.splitlines():
        m = _LINE.match(strip_log_prefix(line))
        if m:
            yield m.group("host"), m.group("port"), m.group("name"), m.group("body")


# --------------------------------------------------------------------------- #
# Pure parsers (unit-testable)                                                 #
# --------------------------------------------------------------------------- #
def parse_hosts(raw: str) -> dict[str, _Host]:
    """Extract per-host banner facts (signing, SMBv1, OS, domain)."""
    hosts: dict[str, _Host] = {}
    for host, _port, name, body in _iter_lines(raw):
        h = hosts.setdefault(host, _Host(ip=host))
        if name and name != host:
            h.name = name
        if (m := _SIGNING.search(body)):
            h.signing = m.group("v").lower() == "true"
        if (m := _SMBV1.search(body)):
            h.smbv1 = m.group("v").lower() == "true"
        if (m := _DOMAIN.search(body)):
            h.domain = m.group("v")
        if (m := _OS.search(body)):
            h.os = m.group("os")
    return hosts


def parse_banner_findings(raw: str, credentialed: bool = False) -> list[Finding]:
    """SMB signing + SMBv1 findings, aggregated across hosts."""
    hosts = parse_hosts(raw)
    findings: list[Finding] = []

    signing_off = sorted(h.ip for h in hosts.values() if h.signing is False)
    if signing_off:
        findings.append(Finding(
            id="smb-signing-not-required",
            title="SMB signing not required",
            severity=Severity.MEDIUM,
            category=Category.SMB,
            description="One or more hosts do not require SMB signing.",
            impact="Enables SMB/NTLM relay attacks: an attacker on the network path can relay "
                   "authentication to other services and act as the victim.",
            remediation="Enforce SMB signing via GPO — 'Microsoft network server: Digitally sign "
                        "communications (always)' = Enabled — on all hosts, especially DCs.",
            affected=signing_off,
            evidence=[Evidence(source="netexec", detail=f"(signing:False) on {len(signing_off)} host(s)")],
            references=["https://attack.mitre.org/techniques/T1557/001/"],
            credentialed=credentialed,
        ))

    smbv1_on = sorted(h.ip for h in hosts.values() if h.smbv1 is True)
    if smbv1_on:
        findings.append(Finding(
            id="smbv1-enabled",
            title="SMBv1 enabled",
            severity=Severity.HIGH,
            category=Category.SMB,
            description="Hosts still speak the deprecated SMBv1 protocol.",
            impact="SMBv1 is vulnerable to critical RCE (e.g. MS17-010/EternalBlue) and enables "
                   "downgrade attacks.",
            remediation="Disable the SMBv1 feature on all hosts (Remove-WindowsFeature FS-SMB1 / "
                        "GPO), verify no legacy clients depend on it first.",
            affected=smbv1_on,
            evidence=[Evidence(source="netexec", detail=f"(SMBv1:True) on {len(smbv1_on)} host(s)")],
            references=["https://attack.mitre.org/techniques/T1210/"],
            credentialed=credentialed,
        ))
    return findings


def parse_null_session(raw: str) -> list[Finding]:
    """Detect anonymous SMB access from two nxc signals, keyed by host (deduped).

    1. An auth-success line with an empty password: ``[+] domain\\:`` / ``[+] domain\\guest:``
    2. The banner field newer nxc prints: ``(Null Auth:True)``
    Either one on a host counts once; the banner + --shares runs repeat lines, so we key
    on host to avoid the double-count seen in the field.
    """
    hosts: dict[str, str] = {}                  # host -> short detail (first signal seen)
    for host, _port, _name, body in _iter_lines(raw):
        m = _AUTH_OK.match(body)
        if m:
            ident = m.group("id")               # e.g. "acme.local\guest:" or "acme.local\:"
            user = ident.split("\\")[-1]         # empty password => ends with ':' and nothing after
            if user.endswith(":") or user in (":", "guest:") or user.lower().startswith("guest:"):
                hosts.setdefault(host, ident)
        nm = _NULLAUTH.search(body)
        if nm and nm.group("v").lower() == "true":
            hosts.setdefault(host, "Null Auth:True")

    if not hosts:
        return []
    affected = sorted(hosts)
    detail = "; ".join(f"{h} ({hosts[h]})" for h in affected)
    return [Finding(
        id="smb-null-or-guest-auth",
        title="SMB null / guest session allowed",
        severity=Severity.MEDIUM,
        category=Category.SMB,
        description="Hosts accept unauthenticated (null) or guest SMB sessions.",
        impact="Allows unauthenticated attackers to enumerate shares, users, and policies — "
               "a common first foothold.",
        remediation="Restrict anonymous access: set 'RestrictNullSessAccess', disable the Guest "
                    "account, and enforce 'Network access: Restrict anonymous access to Named "
                    "Pipes and Shares'.",
        affected=affected,
        evidence=[Evidence(source="netexec", detail=f"anonymous SMB access: {detail}")],
        references=["https://attack.mitre.org/techniques/T1135/"],
        credentialed=False,
    )]


def parse_shares(raw: str, credentialed: bool = False) -> list[Finding]:
    """Enumerate shares; flag writable non-default shares as a finding."""
    writable: list[str] = []
    readable_nondefault: list[str] = []
    listed: list[str] = []
    in_table = False

    for host, _port, _name, body in _iter_lines(raw):
        low = body.lower()
        if "enumerated shares" in low:
            in_table = True
            continue
        if body.startswith("Share") or body.startswith("-----"):
            continue
        if not in_table:
            continue
        m = _SHARE_ROW.match(body)
        if not m or not m.group("share"):
            continue
        share = m.group("share")
        perms = (m.group("perms") or "").upper()
        if share in ("Share", "-----"):
            continue
        listed.append(f"{host}\\{share} [{perms or '-'}]")
        if "WRITE" in perms and share.upper() not in DEFAULT_SHARES:
            writable.append(f"{host}\\{share}")
        elif "READ" in perms and share.upper() not in DEFAULT_SHARES:
            readable_nondefault.append(f"{host}\\{share}")

    findings: list[Finding] = []
    if writable:
        findings.append(Finding(
            id="smb-writable-share",
            title="Writable non-default SMB share",
            severity=Severity.HIGH,
            category=Category.SMB,
            description="Non-default shares are writable by the tested principal.",
            impact="Writable shares enable payload staging, malicious file drops (e.g. SCF/LNK "
                   "coercion), and can aid lateral movement or persistence.",
            remediation="Review share and NTFS permissions; remove write access for non-privileged "
                        "principals and apply least privilege.",
            affected=sorted(writable),
            evidence=[Evidence(source="netexec", detail="WRITE permission on non-default share(s)")],
            references=["https://attack.mitre.org/techniques/T1135/"],
            credentialed=credentialed,
        ))
    if listed:
        findings.append(Finding(
            id="enum-smb-shares",
            title="SMB shares enumerated",
            severity=Severity.INFO,
            category=Category.ENUM,
            description="Shares visible to the tested principal.",
            affected=sorted(listed),
            evidence=[Evidence(source="netexec", detail=f"{len(listed)} share entries")],
            credentialed=credentialed,
        ))
    return findings


def parse_all(raw: str, credentialed: bool = False) -> list[Finding]:
    """Run every SMB parser over a combined nxc output blob."""
    out: list[Finding] = []
    out.extend(parse_banner_findings(raw, credentialed))
    out.extend(parse_null_session(raw))
    out.extend(parse_shares(raw, credentialed))
    return out


# --------------------------------------------------------------------------- #
# Execution                                                                    #
# --------------------------------------------------------------------------- #
class NetExecEngine(Engine):
    name = "netexec"

    def __init__(self, timeout: int = 300):
        self.timeout = timeout

    def _bin(self) -> str | None:
        return shutil.which("nxc") or shutil.which("netexec")

    def is_available(self) -> bool:
        return self._bin() is not None

    def _auth_args(self, target: Target) -> list[str]:
        user = target.username if target.username is not None else ""
        args = ["-u", user]
        if target.nthash:
            args += ["-H", target.nthash]
        else:
            args += ["-p", target.password if target.password is not None else ""]
        if target.kerberos:
            args += ["-k"]
        if target.domain:
            args += ["-d", target.domain]
        return args

    def _invoke(self, extra: list[str], target: Target) -> str:
        exe = self._bin()
        if not exe:
            return ""
        cmd = [exe, "smb", target.host] + self._auth_args(target) + extra
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )
        except (subprocess.TimeoutExpired, OSError):
            return ""
        # nxc prints results to stdout; some builds mix into stderr — take both.
        return (proc.stdout or "") + "\n" + (proc.stderr or "")

    def run(self, target: Target) -> list[Finding]:
        if not self.is_available():
            return []
        raw_banner = self._invoke([], target)             # signing / SMBv1 / OS
        raw_shares = self._invoke(["--shares"], target)   # share enumeration
        combined = raw_banner + "\n" + raw_shares
        findings = parse_all(combined, credentialed=target.credentialed)
        # Attach raw output to the first evidence item for the report appendix.
        if findings and findings[0].evidence:
            findings[0].evidence[0].raw = combined.strip()[:4000]
        return findings
