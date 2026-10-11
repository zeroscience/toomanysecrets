r"""Nuclei engine - template-based web/network vulnerability scanning (opt-in, ACTIVE).

Nuclei (ProjectDiscovery) runs thousands of community YAML templates - CVEs, exposed panels,
default logins, misconfigurations, technology fingerprints, takeovers - against a target and
emits one JSON object per match (`-jsonl`). This engine shells out, groups the matches by
template, and normalizes them into REDNESS `Finding`s (`Category.WEB`).

UNLIKE the rest of the default scan, nuclei is ACTIVE: it sends real crafted requests. So:

  * it is **opt-in** (`scan --nuclei`), never in `default_engines()`;
  * it is **port-gated** to web ports (80/443/8080/8443) by discovery, so it never touches
    OT/ICS field ports;
  * we always pass `-exclude-tags intrusive,dos,fuzz,brute` and rate-limit, so the default
    profile stays detection-oriented and safe-ish for production estates. Fragile OT HMIs should
    still be scoped out by the operator - nuclei is a web scanner, not an OT-safe probe.

Parsing is a pure function over captured JSONL, so it unit-tests with no nuclei installed and no
network. `info.remediation` is used when a template carries one; otherwise we synthesize a
remediation (every REDNESS finding must carry one). Templates + the nuclei binary are a separate
install (like nxc/certipy) - they are not bundled.

Reference: https://github.com/projectdiscovery/nuclei
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Optional

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target

# nuclei severity strings -> REDNESS Severity. "unknown"/missing -> INFO.
_SEV = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}

# Tags we always exclude: the intrusive / denial-of-service / fuzzing / brute-force families.
# This is the core safety rail - it keeps the default run detection-oriented.
EXCLUDE_TAGS = "intrusive,dos,fuzz,brute"


def _asset(url_or_host: str) -> str:
    """A stable `host:port` web-service id from a nuclei host/matched-at value.

    Strips the scheme and path, and - so every web service is a distinct node under its host,
    never collapsing onto the bare host - infers the port from the scheme when it is not explicit:
    'https://h:8443/x' -> 'h:8443', 'https://h' -> 'h:443', 'http://h' -> 'h:80'.
    """
    s = (url_or_host or "").strip()
    scheme = ""
    low = s.lower()
    if low.startswith("https://"):
        scheme, s = "https", s[8:]
    elif low.startswith("http://"):
        scheme, s = "http", s[7:]
    s = s.split("/", 1)[0]
    if not s:
        return ""
    if ":" not in s:                                      # no explicit port -> infer from scheme
        s += ":443" if scheme == "https" else ":80" if scheme == "http" else ""
    return s


def _as_list(v) -> list[str]:
    if not v:
        return []
    return [str(x) for x in v] if isinstance(v, (list, tuple)) else [str(v)]


def _remediation(info: dict, cves: list[str]) -> str:
    rem = (info.get("remediation") or "").strip()
    if rem:
        return rem
    if cves:
        return ("Apply the vendor patch / upgrade the affected component to a fixed release; "
                "see references.")
    return ("Validate the finding, then restrict access to or update/patch the affected "
            "component; see references.")


def parse_nuclei(output: str) -> list[Finding]:
    """Parse nuclei `-jsonl` output into Findings, grouped by template-id.

    One Finding per template; every host:port it matched on becomes an entry in `affected`, and
    each concrete match (matched-at URL) becomes an Evidence line. Invalid/blank lines are skipped.
    """
    by_tid: dict[str, Finding] = {}
    order: list[str] = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        tid = rec.get("template-id") or rec.get("templateID")
        if not tid:
            continue
        info = rec.get("info") or {}
        sev = _SEV.get(str(info.get("severity", "")).lower(), Severity.INFO)
        host_field = rec.get("host") or rec.get("matched-at") or rec.get("ip") or ""
        asset = _asset(host_field)
        matched = rec.get("matched-at") or rec.get("matcher-name") or host_field or asset
        classification = info.get("classification") or {}
        cves = _as_list(classification.get("cve-id"))

        ev_detail = f"{tid} matched at {matched}"
        extracted = _as_list(rec.get("extracted-results"))
        if extracted:
            ev_detail += " | extracted: " + ", ".join(extracted[:5])
        evidence = Evidence(source="nuclei", detail=ev_detail, raw=rec.get("curl-command"))

        if tid in by_tid:
            f = by_tid[tid]
            if asset and asset not in f.affected:
                f.affected.append(asset)
            f.evidence.append(evidence)
            continue

        order.append(tid)
        name = info.get("name") or tid
        tags = _as_list(info.get("tags"))
        cvss = classification.get("cvss-score")
        refs = _as_list(info.get("reference")) + cves
        impact = (f"{', '.join(cves)} is present on the target; see references for exploitability."
                  if cves else
                  f"nuclei flagged this {sev.value} issue; validate and assess impact in context.")
        by_tid[tid] = Finding(
            id=f"nuclei:{tid}",
            title=name,
            severity=sev,
            category=Category.WEB,
            description=(info.get("description") or "").strip(),
            impact=impact,
            remediation=_remediation(info, cves),
            affected=[asset] if asset else [],
            evidence=[evidence],
            references=refs,
            meta={"template_id": tid, "type": rec.get("type"), "tags": tags,
                  "cvss_score": cvss, "cves": cves, "source": "nuclei"},
        )
    return [by_tid[t] for t in order]


class NucleiEngine(Engine):
    """Opt-in active web/network scanner. Port-gated to web ports; never in the default scan."""
    name = "nuclei"

    def __init__(self, profile: str = "light", templates: Optional[str] = None,
                 timeout: int = 300) -> None:
        self.profile = profile if profile in ("light", "full") else "light"
        self.templates = templates
        self.timeout = timeout

    def is_available(self) -> bool:
        return shutil.which("nuclei") is not None

    def _argv(self, target: Target) -> list[str]:
        exe = shutil.which("nuclei") or "nuclei"
        argv = [exe, "-jsonl", "-silent", "-no-color", "-disable-update-check",
                "-exclude-tags", EXCLUDE_TAGS,
                "-rate-limit", "150", "-concurrency", "25", "-timeout", "8"]
        if self.profile == "light":
            # skip the info-level template noise; keep actionable severities only
            argv += ["-severity", "low,medium,high,critical"]
        if self.templates:
            argv += ["-t", self.templates]
        # probe both schemes on this host; discovery has already gated us to a live web port
        argv += ["-u", f"http://{target.host}", "-u", f"https://{target.host}"]
        return argv

    def run(self, target: Target) -> list[Finding]:
        if not self.is_available():
            return []
        try:
            proc = subprocess.run(self._argv(target), capture_output=True, text=True,
                                  timeout=self.timeout)
        except (subprocess.TimeoutExpired, OSError):
            return []
        return parse_nuclei(proc.stdout or "")
