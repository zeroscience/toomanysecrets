r"""Advisor - "run the right tool for what we found".

REDNESS already normalizes findings and detects services (nmap -sV). The advisor turns that
context into a ranked list of offensive NEXT STEPS: for each detected service / finding it names a
tool, why it applies, and a ready-to-run command. It never runs the intrusive ones itself - it
suggests. Three tiers mirror REDNESS's passive -> opt-in -> gated posture:

  * auto    - read-only lookups REDNESS can run for you (searchsploit); enrich the report.
  * suggest - print the exact command, operator decides (nuclei, sqlmap, metasploit, aircrack).
  * gated   - online brute / spray; run only through the consent+FORCE+audit path (hydra, spray).

OT-safe: hosts carrying any ICS finding are excluded - the advisor never points an active/exploit
tool at fragile OT. Pure (no subprocess here except the opt-in searchsploit auto-lookup helper), so
the rule engine unit-tests with no tools installed.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field

from .findings import Category, Finding, Report, Severity

_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8081, 9443}
_SECURE_PORTS = {443, 8443, 9443}


@dataclass
class Suggestion:
    tool: str               # nuclei / sqlmap / hydra / metasploit / searchsploit / redness spray ...
    target: str             # host, host:port, or URL
    reason: str             # what was detected that makes this apply
    command: str            # ready-to-run command (templated; fill in wordlists/creds)
    tier: str               # "auto" | "suggest" | "gated"
    binary: str = ""        # the executable to check on PATH ("" -> always available, e.g. redness)
    priority: int = 50      # lower = show first
    available: bool = field(default=False)

    def resolve(self) -> "Suggestion":
        self.available = (not self.binary) or (shutil.which(self.binary) is not None)
        return self


_TIER_ORDER = {"auto": 0, "suggest": 1, "gated": 2}


def ot_hosts(report: Report) -> set[str]:
    """Hosts carrying any ICS finding - excluded from active/exploit suggestions."""
    out: set[str] = set()
    for f in report.findings:
        if f.category is Category.ICS:
            out.update(h.split(":", 1)[0] for h in f.affected)
    return out


def detected_services(report: Report) -> list[dict]:
    """Services to reason about: nmap -sV inventory, plus web services implied by WEB findings."""
    out: list[dict] = []
    seen: set[tuple] = set()

    def add(host, port, service="", product="", version=""):
        key = (host, int(port or 0), service)
        if host and key not in seen:
            seen.add(key)
            out.append({"host": host, "port": int(port or 0), "service": service,
                        "product": product, "version": version})

    for f in report.findings:
        for s in (f.meta or {}).get("services", []):     # nmap inventory
            add(s.get("host"), s.get("port"), s.get("service", ""),
                s.get("product", ""), s.get("version", ""))
        if f.category is Category.WEB:                    # nuclei/searchsploit web services (host:port)
            for aff in f.affected:
                host, _, port = aff.rpartition(":")
                if host and port.isdigit():
                    add(host, port, "https" if int(port) in _SECURE_PORTS else "http")
    return out


def _is_web(svc: dict) -> bool:
    return svc["service"].startswith("http") or svc["port"] in _WEB_PORTS


def _url(svc: dict) -> str:
    scheme = "https" if (svc["port"] in _SECURE_PORTS or svc["service"] in ("https", "ssl/http")) else "http"
    return f"{scheme}://{svc['host']}:{svc['port']}"


def suggest(report: Report) -> list[Suggestion]:
    """Ranked next-step tool suggestions from the report's services + findings (OT excluded)."""
    skip = ot_hosts(report)
    out: list[Suggestion] = []

    for svc in detected_services(report):
        host, port, name = svc["host"], svc["port"], svc["service"]
        if host in skip:
            continue
        hp = f"{host}:{port}"

        if _is_web(svc):
            url = _url(svc)
            out.append(Suggestion("nuclei", url, "web service exposed",
                                  f"redness scan --target {host} --nuclei", "suggest",
                                  binary="nuclei", priority=20))
            out.append(Suggestion("sqlmap", url, "web app - test request parameters for SQLi",
                                  f"sqlmap -u {url}/ --batch --crawl=2 --level=2 --risk=1",
                                  "suggest", binary="sqlmap", priority=30))
        if name == "ssh" or port == 22:
            out.append(Suggestion("hydra", hp, "SSH - online password guessing (lockout/noise risk)",
                                  f"hydra -L users.txt -P passwords.txt -t 4 ssh://{host}", "gated",
                                  binary="hydra", priority=60))
        if name in ("ftp",) or port == 21:
            out.append(Suggestion("hydra", hp, "FTP - online password guessing",
                                  f"hydra -L users.txt -P passwords.txt ftp://{host}", "gated",
                                  binary="hydra", priority=61))
        if name in ("ms-wbt-server", "rdp") or port == 3389:
            out.append(Suggestion("hydra", hp, "RDP - online password guessing (lockout risk)",
                                  f"hydra -L users.txt -P passwords.txt rdp://{host}", "gated",
                                  binary="hydra", priority=62))
        if name in ("microsoft-ds", "netbios-ssn") or port == 445:
            out.append(Suggestion("redness spray", host, "SMB - lockout-aware password spray",
                                  f"redness spray --target {host} -p 'Season2025!' "
                                  f"--auth-user USER --auth-pass PASS", "gated", priority=55))

        product, version = svc.get("product", ""), svc.get("version", "")
        if product:
            terms = f"{product} {version}".strip()
            out.append(Suggestion("searchsploit", hp, f"identify public exploits for {terms}",
                                  f"searchsploit {terms}", "auto", binary="searchsploit",
                                  priority=10))
            out.append(Suggestion("metasploit", hp, f"check for a module matching {terms}",
                                  f'msfconsole -q -x "search {product}; exit"', "suggest",
                                  binary="msfconsole", priority=40))

    for f in report.findings:                             # finding-driven suggestions
        if f.id == "wireless-weak-encryption":
            for net in f.affected:
                out.append(Suggestion("aircrack-ng", net,
                                      "WPA/WEP network - capture a handshake (active) then crack offline",
                                      "airodump-ng --bssid <BSSID> -c <CH> -w cap wlan0   # then: "
                                      "redness handshake --cap cap-01.cap --wordlist rockyou.txt",
                                      "suggest", binary="aircrack-ng", priority=70))

    # dedup (tool+target+command), resolve availability, rank (tier, then priority)
    uniq: dict[tuple, Suggestion] = {}
    for s in out:
        uniq.setdefault((s.tool, s.target, s.command), s)
    ranked = sorted((s.resolve() for s in uniq.values()),
                    key=lambda s: (_TIER_ORDER.get(s.tier, 9), s.priority, s.tool))
    return ranked


def run_autolookups(report: Report) -> list[Finding]:
    """The 'auto' tier: run read-only searchsploit for each detected product+version.

    Returns new INFO findings to add to the report (no network; local exploitdb). No-op when
    searchsploit is not installed.
    """
    from .engines import searchsploit as ss
    if not ss.is_available():
        return []
    out: list[Finding] = []
    seen: set[tuple] = set()
    skip = ot_hosts(report)
    for svc in detected_services(report):
        host, product, version = svc["host"], svc.get("product", ""), svc.get("version", "")
        if not product or host in skip:
            continue
        key = (product, version)
        if key in seen:
            continue
        seen.add(key)
        exploits = ss.search(f"{product} {version}".strip())
        if exploits:
            out.append(ss.finding_for(product, version, exploits, host))
    return out
