"""Environment doctor - what's installed, what each engine needs, how to enable it.

Answers the #1 question ("why 0 findings?"): the external tools aren't on PATH.
REDNESS orchestrates NetExec / Certipy / Impacket + hashcat/john rather than
reimplementing them, so those must be installed (see requirements-engines.txt).
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass

from .scan import default_engines

# How to enable each engine / tool.
# NOTE: NetExec has no wheel for Python 3.12 (published versions require <3.12), so
# `pip install netexec` fails on 3.12. Use pipx, which runs it under a compatible
# Python in its own env and puts `nxc` on PATH. Certipy bundles cleanly and REDNESS
# can even run it in-process (see engines/certipy.py), so the self-contained exe works.
INSTALL_HINTS = {
    "netexec": "pipx install netexec       (no py3.12 wheel; pipx picks a compatible Python)",
    "netexec-ldap": "pipx install netexec  (LDAP: users + AS-REP/Kerberoast capture)",
    "certipy": "pip install certipy-ad     (or bundle it; REDNESS runs it in-process)",
    "gpp": "pipx install netexec          (nxc -M gpp_password; needs domain creds)",
    "delegation": "pipx install netexec   (LDAP: delegation / MAQ / gMSA enum; needs domain creds)",
    "tls": "built-in (Python stdlib) - always available",
    "rdp": "pipx install netexec       (RDP: NLA check + service exposure)",
    "winrm": "pipx install netexec     (WinRM: exposure + credentialed remote-exec reach)",
    "mssql": "pipx install netexec     (MSSQL: exposure + credentialed reach)",
    "ftp": "pipx install netexec       (FTP: anonymous login + exposure)",
    "http": "built-in (Python stdlib) - AD web surfaces (/certsrv ESC8, OWA)",
    "snmp": "sudo apt install snmp     (net-snmp `snmpwalk`; default community strings)",
    "responder": "sudo apt install responder   (Linux/Kali; for the intrusive `poison` command)",
    "nuclei": "go install .../nuclei@latest  (or apt/brew; then `nuclei -update-templates`; for scan --nuclei)",
}


@dataclass
class Check:
    name: str
    available: bool
    hint: str


def check_engines() -> list[Check]:
    out = []
    for eng in default_engines():
        out.append(Check(eng.name, eng.is_available(),
                         INSTALL_HINTS.get(eng.name, "")))
    return out


def check_crackers() -> list[Check]:
    checks = []
    for tool, hint in (("hashcat", "https://hashcat.net/hashcat/"),
                       ("john", "John the Ripper (jumbo)")):
        checks.append(Check(tool, shutil.which(tool) is not None,
                            f"install for --wordlist cracking - {hint}"))
    return checks


def check_poison() -> list[Check]:
    """Responder - the poisoner behind the opt-in `poison` command (not a scan engine)."""
    from .engines.responder import is_available as responder_available
    return [Check("responder", responder_available(), INSTALL_HINTS["responder"])]


def check_optional() -> list[Check]:
    """Opt-in engines not in the default scan (active / needs a separate tool)."""
    from .engines import NucleiEngine
    return [Check("nuclei", NucleiEngine().is_available(), INSTALL_HINTS["nuclei"])]


def report_text() -> str:
    lines = ["REDNESS environment check", "=" * 26, "", "Engines:"]
    engines = check_engines()
    for c in engines:
        mark = "OK " if c.available else "-- "
        lines.append(f"  [{mark}] {c.name:<14} {'' if c.available else '-> ' + c.hint}")
    lines += ["", "Hash cracking (optional, for scan --wordlist):"]
    for c in check_crackers():
        mark = "OK " if c.available else "-- "
        lines.append(f"  [{mark}] {c.name:<14} {'' if c.available else '-> ' + c.hint}")

    lines += ["", "NetNTLMv2 capture (optional, for the intrusive `poison` command):"]
    for c in check_poison():
        mark = "OK " if c.available else "-- "
        lines.append(f"  [{mark}] {c.name:<14} {'' if c.available else '-> ' + c.hint}")

    lines += ["", "Opt-in web scanning (optional, for the ACTIVE `scan --nuclei`):"]
    for c in check_optional():
        mark = "OK " if c.available else "-- "
        lines.append(f"  [{mark}] {c.name:<14} {'' if c.available else '-> ' + c.hint}")

    ready = sum(c.available for c in engines)
    lines += ["", f"{ready}/{len(engines)} engines ready."]
    if ready < len(engines):
        lines += ["Install the missing tools (see requirements-engines.txt) for full coverage:",
                  "  pip install -r requirements-engines.txt"]
    else:
        lines.append("All engines ready - real findings will flow.")
    return "\n".join(lines)
