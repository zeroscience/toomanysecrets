r"""Searchsploit lookup - detected product+version -> public exploit candidates (read-only).

Exploit-DB's `searchsploit` queries a LOCAL offline database, so this is a safe, read-only lookup
(no network, nothing sent to a target). Given a service's product + version (from nmap/-sV or a
banner), it returns matching public exploits, which the advisor attaches as INFO findings with the
EDB references - a pointer to "there is known public exploit code for this", not an exploit run.

Parsing is pure over `searchsploit --json` output, so it unit-tests with no exploitdb installed.

Reference: https://www.exploit-db.com/searchsploit
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass

from ..findings import Category, Evidence, Finding, Severity


@dataclass
class Exploit:
    title: str
    edb_id: str = ""
    etype: str = ""         # remote / webapps / dos / local ...
    platform: str = ""
    path: str = ""

    @property
    def url(self) -> str:
        return f"https://www.exploit-db.com/exploits/{self.edb_id}" if self.edb_id else ""


def parse_searchsploit(output: str) -> list[Exploit]:
    """Parse `searchsploit --json` into Exploits (the RESULTS_EXPLOIT array). Invalid -> []."""
    try:
        data = json.loads(output or "")
    except (ValueError, TypeError):
        return []
    out: list[Exploit] = []
    for r in (data.get("RESULTS_EXPLOIT") or []):
        if not isinstance(r, dict):
            continue
        out.append(Exploit(
            title=(r.get("Title") or "").strip(),
            edb_id=str(r.get("EDB-ID") or r.get("Codes") or "").strip(),
            etype=(r.get("Type") or "").strip(),
            platform=(r.get("Platform") or "").strip(),
            path=(r.get("Path") or "").strip(),
        ))
    return [e for e in out if e.title]


def is_available() -> bool:
    return shutil.which("searchsploit") is not None


def search(terms: str, timeout: int = 30) -> list[Exploit]:
    """Run `searchsploit --json <terms>` and return parsed exploits ([] if unavailable/failed)."""
    exe = shutil.which("searchsploit")
    if not exe or not terms.strip():
        return []
    try:
        proc = subprocess.run([exe, "--json", "--disable-colour", terms],
                              capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return []
    return parse_searchsploit(proc.stdout or "")


def finding_for(product: str, version: str, exploits: list[Exploit], host: str) -> Finding:
    """Build an INFO finding listing public exploit candidates for a product+version on a host."""
    pv = f"{product} {version}".strip()
    refs = [e.url for e in exploits if e.url][:10]
    ev = [Evidence(source="searchsploit", detail=f"[{e.etype}] {e.title}"
                   + (f" (EDB-{e.edb_id})" if e.edb_id else "")) for e in exploits[:10]]
    return Finding(
        id=f"searchsploit:{product.lower().replace(' ', '-')}",
        title=f"Public exploit candidates for {pv}",
        severity=Severity.INFO,
        category=Category.WEB,
        description=f"Exploit-DB lists {len(exploits)} public exploit(s) matching '{pv}'. "
                    "These are candidates to review for applicability - not confirmed exploitable.",
        impact="Known public exploit code may exist for this software/version.",
        remediation="Confirm the exact version, patch/upgrade, and validate each candidate's "
                    "applicability before relying on it.",
        affected=[host],
        evidence=ev,
        references=refs,
        meta={"product": product, "version": version, "exploit_count": len(exploits),
              "source": "searchsploit"},
    )
