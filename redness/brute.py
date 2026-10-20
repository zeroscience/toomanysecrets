r"""Online password guessing via hydra / medusa - `redness brute` (INTRUSIVE, gated).

Extends REDNESS's lockout-aware posture (spray.py, for SMB/LDAP via nxc) to arbitrary services -
ssh, ftp, rdp, http, telnet, mysql, ... - by driving hydra (or medusa). Online guessing is
DANGEROUS: without the target's lockout policy it can LOCK OUT ACCOUNTS (a DoS on the client) and
it is loud to a SOC. So the posture is spray-style:

  * a small password set (a spray) across users is the default and only needs consent;
  * a large per-user password list is true brute-force (lockout DoS) and is REFUSED unless the
    operator passes --force AND types FORCE (see cli.cmd_brute). The decision is count-based here
    (`lockout_risk`); the CLI owns the gating, this module owns the execution + parsing.

Parsing is pure over hydra/medusa stdout (unit-tested, no tools needed). A valid credential is a
CRITICAL `Category.PASSWORD` finding, written to loot like the other credential pipelines.

References: https://github.com/vanhauser-thc/thc-hydra , https://github.com/jmk-foofus/medusa
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional

from .findings import Category, Evidence, Finding, Report, Severity

# hydra:  [22][ssh] host: 10.0.0.5   login: root   password: toor
_HYDRA = re.compile(r"^\[(?P<port>\d+)\]\[(?P<svc>[\w-]+)\]\s+host:\s*(?P<host>\S+)\s+"
                    r"login:\s*(?P<user>.*?)\s+password:\s*(?P<pw>.*?)\s*$", re.M)
# medusa: ACCOUNT FOUND: [ssh] Host: 10.0.0.5 User: root Password: toor [SUCCESS]
_MEDUSA = re.compile(r"ACCOUNT FOUND:\s*\[(?P<svc>[\w-]+)\]\s*Host:\s*(?P<host>\S+)\s*"
                     r"User:\s*(?P<user>.*?)\s*Password:\s*(?P<pw>.*?)\s*\[SUCCESS", re.I)

# medusa module names differ from hydra service names for a few protocols.
_MEDUSA_MODULE = {"smb": "smbnt", "http-get": "http", "http": "http", "rdp": "rdp", "ssh": "ssh",
                  "ftp": "ftp", "telnet": "telnet", "mysql": "mysql", "mssql": "mssql",
                  "vnc": "vnc", "postgres": "postgres"}


@dataclass
class BruteHit:
    service: str
    host: str
    username: str
    password: str
    port: str = ""


@dataclass
class BruteResult:
    hits: list = field(default_factory=list)      # list[BruteHit]
    tool: str = ""
    service: str = ""


def parse_hydra(output: str) -> list[BruteHit]:
    return [BruteHit(service=m.group("svc"), host=m.group("host"), port=m.group("port"),
                     username=m.group("user"), password=m.group("pw"))
            for m in _HYDRA.finditer(output or "")]


def parse_medusa(output: str) -> list[BruteHit]:
    return [BruteHit(service=m.group("svc"), host=m.group("host"),
                     username=m.group("user"), password=m.group("pw"))
            for m in _MEDUSA.finditer(output or "")]


def count_passwords(password: Optional[str], pass_file: Optional[str]) -> int:
    """How many passwords this run will try per user (for the lockout gate)."""
    if password:
        return 1
    if pass_file and os.path.exists(pass_file):
        try:
            with open(pass_file, encoding="utf-8", errors="replace") as fh:
                return sum(1 for ln in fh if ln.strip())
        except OSError:
            return 0
    return 0


def lockout_risk(num_passwords: int, max_per_user: int) -> bool:
    """True when this is true brute-force (many passwords/user) rather than a safe spray."""
    return num_passwords > max_per_user


def hydra_argv(target: str, service: str, *, port: str = "", user: str = "", user_file: str = "",
               password: str = "", pass_file: str = "", tasks: int = 4,
               extra: Optional[list[str]] = None) -> list[str]:
    exe = shutil.which("hydra") or "hydra"
    argv = [exe]
    argv += (["-l", user] if user else []) + (["-L", user_file] if user_file else [])
    argv += (["-p", password] if password else []) + (["-P", pass_file] if pass_file else [])
    argv += ["-t", str(tasks), "-I"]
    if port:
        argv += ["-s", str(port)]
    argv += (extra or [])
    argv += [f"{service}://{target}"]
    return argv


def medusa_argv(target: str, service: str, *, port: str = "", user: str = "", user_file: str = "",
                password: str = "", pass_file: str = "", tasks: int = 4,
                extra: Optional[list[str]] = None) -> list[str]:
    exe = shutil.which("medusa") or "medusa"
    module = _MEDUSA_MODULE.get(service, service)
    argv = [exe, "-h", target, "-M", module, "-t", str(tasks)]
    argv += (["-u", user] if user else []) + (["-U", user_file] if user_file else [])
    argv += (["-p", password] if password else []) + (["-P", pass_file] if pass_file else [])
    if port:
        argv += ["-n", str(port)]
    argv += (extra or [])
    return argv


def build_findings(hits: list[BruteHit], tool: str) -> list[Finding]:
    out: list[Finding] = []
    for h in hits:
        who = f"{h.host}" + (f":{h.port}" if h.port else "")
        out.append(Finding(
            id="brute-credential",
            title=f"Valid credential found on {h.service} ({who})",
            severity=Severity.CRITICAL,
            category=Category.PASSWORD,
            description=f"{tool} guessed a valid credential for the {h.service} service.",
            impact="A working credential grants authenticated access to the service and whatever "
                   "it exposes; it is often reused across other systems.",
            remediation="Reset the password; enforce a strong policy, lockout thresholds and MFA; "
                        "investigate for prior misuse of this account.",
            affected=[f"{who} ({h.service})"],
            evidence=[Evidence(source=tool, detail=f"{h.username}:{h.password}")],
            references=["https://attack.mitre.org/techniques/T1110/"],
            meta={"service": h.service, "host": h.host, "port": h.port,
                  "username": h.username, "password": h.password, "tool": tool},
        ))
    return out


def is_available(tool: str = "") -> bool:
    if tool:
        return shutil.which(tool) is not None
    return bool(shutil.which("hydra") or shutil.which("medusa"))


def run_brute(target: str, service: str, *, tool: str = "hydra", port: str = "",
              user: str = "", user_file: str = "", password: str = "", pass_file: str = "",
              tasks: int = 4, extra: Optional[list[str]] = None, loot_dir: str = "loot",
              engagement: str = "REDNESS brute", timeout: int = 1800,
              runner: Optional[Callable[[list[str]], str]] = None) -> tuple[Report, BruteResult]:
    """Run hydra/medusa, parse hits, build findings + loot. `runner(argv)->stdout` is injectable."""
    build = hydra_argv if tool == "hydra" else medusa_argv
    argv = build(target, service, port=port, user=user, user_file=user_file,
                 password=password, pass_file=pass_file, tasks=tasks, extra=extra)

    if runner is None:
        def runner(a):
            if not shutil.which(a[0]) and not shutil.which(tool):
                return ""
            try:
                p = subprocess.run(a, capture_output=True, text=True, timeout=timeout)
            except (subprocess.TimeoutExpired, OSError):
                return ""
            return (p.stdout or "") + "\n" + (p.stderr or "")

    output = runner(argv)
    hits = parse_hydra(output) if tool == "hydra" else parse_medusa(output)
    report = Report(engagement=engagement, target=f"{target} ({service})",
                    findings=build_findings(hits, tool))
    if hits:
        try:
            os.makedirs(loot_dir, exist_ok=True)
            with open(os.path.join(loot_dir, "brute_hits.txt"), "a", encoding="utf-8") as fh:
                for h in hits:
                    fh.write(f"{h.host}:{h.port or ''}:{h.service}:{h.username}:{h.password}\n")
        except OSError:
            pass
    return report, BruteResult(hits=hits, tool=tool, service=service)
