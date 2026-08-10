"""Environment doctor — what's installed, what each engine needs, how to enable it.

Answers the #1 question ("why 0 findings?"): the external tools aren't on PATH.
REDNESS orchestrates NetExec / Certipy / Impacket + hashcat/john rather than
reimplementing them, so those must be installed (see requirements-engines.txt).
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass

from .scan import default_engines

# How to enable each engine / tool.
INSTALL_HINTS = {
    "netexec": "pip install netexec        (provides the `nxc` binary)",
    "netexec-ldap": "pip install netexec   (LDAP: users + AS-REP/Kerberoast capture)",
    "certipy": "pip install certipy-ad     (provides the `certipy` binary)",
    "tls": "built-in (Python stdlib) — always available",
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
                            f"install for --wordlist cracking — {hint}"))
    return checks


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

    ready = sum(c.available for c in engines)
    lines += ["", f"{ready}/{len(engines)} engines ready."]
    if ready < len(engines):
        lines += ["Install the missing tools (see requirements-engines.txt) for full coverage:",
                  "  pip install -r requirements-engines.txt"]
    else:
        lines.append("All engines ready — real findings will flow.")
    return "\n".join(lines)
