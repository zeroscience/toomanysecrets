r"""HTTP engine - AD-relevant web surfaces only (NOT a general web scanner).

REDNESS is an AD/Windows tool, so this deliberately does not try to be nuclei/Nikto. It
probes a short list of paths that map to an Active Directory attack path and reports those:

  * /certsrv/ , /certsrv/certfnsh.asp  -> AD CS Web Enrollment  == ESC8 (NTLM relay target)
  * /owa/ , /ews/                       -> Exchange / OWA exposure
  * /                                   -> server reachable + Server banner (inventory)

Pure stdlib (urllib) so it always runs; no external tool. HTTPS uses an unverified TLS
context (AD web endpoints are routinely self-signed; the TLS engine judges the cert). The
network fetch is injectable so `build_findings` and the classifier unit-test with no server.
Findings reuse ADCS / ENUM categories - no schema change.
"""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target

# (label, path). Order matters only for readability.
PROBES: list[tuple[str, str]] = [
    ("certsrv", "/certsrv/"),
    ("certfnsh", "/certsrv/certfnsh.asp"),
    ("owa", "/owa/"),
    ("ews", "/ews/"),
    ("root", "/"),
]
# Status codes that mean "this path exists" (200 OK, or auth/redirect gates in front of it).
PRESENT = {200, 301, 302, 401, 403}


@dataclass
class Probe:
    label: str
    scheme: str                        # "http" | "https"
    status: int                        # 0 = no response
    server: str = ""                   # Server header, if any

    @property
    def present(self) -> bool:
        return self.status in PRESENT


def build_findings(host: str, probes: list[Probe], credentialed: bool = False) -> list[Finding]:
    """Turn probe results into findings (pure)."""
    out: list[Finding] = []

    adcs = [p for p in probes if p.label in ("certsrv", "certfnsh") and p.present]
    if adcs:
        url = f"{adcs[0].scheme}://{host}/certsrv/"
        out.append(Finding(
            id="adcs-web-enrollment",
            title="AD CS Web Enrollment exposed (ESC8 relay target)",
            severity=Severity.HIGH,
            category=Category.ADCS,
            description="The AD CS HTTP Web Enrollment interface (/certsrv) is reachable.",
            impact="Web Enrollment accepts NTLM authentication, making it an ESC8 relay target: "
                   "an attacker who coerces a privileged machine (e.g. a DC via PetitPotam) can "
                   "relay that authentication here to obtain a certificate and impersonate it - "
                   "a path to domain compromise.",
            remediation="Disable HTTP Web Enrollment if unused; otherwise require HTTPS with "
                        "Extended Protection for Authentication (EPA) and enable SMB/LDAP signing "
                        "to break the relay chain.",
            affected=[host],
            evidence=[Evidence(source="http", detail=f"{url} -> HTTP {adcs[0].status}")],
            references=["https://attack.mitre.org/techniques/T1649/"],
            credentialed=credentialed,
        ))

    web = [p for p in probes if p.label in ("owa", "ews") and p.present]
    if web:
        labels = sorted({p.label.upper() for p in web})
        out.append(Finding(
            id="exchange-owa-exposed",
            title=f"Exchange web surface exposed ({', '.join(labels)})",
            severity=Severity.LOW,
            category=Category.ENUM,
            description="An Exchange web endpoint (OWA / EWS) is reachable.",
            impact="Exchange web surfaces enable user enumeration and password spraying against "
                   "domain accounts, and are a frequent target for known Exchange CVEs.",
            remediation="Restrict external exposure, enforce MFA, and keep Exchange patched.",
            affected=[host],
            evidence=[Evidence(source="http", detail=", ".join(
                f"/{p.label}/ -> {p.scheme} HTTP {p.status}" for p in web))],
            credentialed=credentialed,
        ))

    root = next((p for p in probes if p.label == "root" and p.status), None)
    if root:
        out.append(Finding(
            id="http-exposed",
            title="HTTP service reachable",
            severity=Severity.INFO,
            category=Category.ENUM,
            description="The host exposes a reachable web server.",
            affected=[host],
            evidence=[Evidence(source="http",
                               detail=f"{root.scheme}://{host}/ -> HTTP {root.status}"
                                      + (f" (Server: {root.server})" if root.server else ""))],
            credentialed=credentialed,
        ))
    return out


def _default_fetch(url: str, timeout: float = 5.0) -> tuple[int, str]:
    """GET `url`, return (status, Server header). 0 on connection failure."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "REDNESS"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.headers.get("Server", "")
    except urllib.error.HTTPError as e:            # 401/403/404 still tell us the path state
        return e.code, e.headers.get("Server", "") if e.headers else ""
    except (urllib.error.URLError, OSError, ValueError):
        return 0, ""


class HttpEngine(Engine):
    name = "http"

    def __init__(self, timeout: float = 5.0, fetch=None):
        self.timeout = timeout
        self._fetch = fetch or _default_fetch

    def is_available(self) -> bool:
        return True                                # pure stdlib

    def run(self, target: Target) -> list[Finding]:
        probes: list[Probe] = []
        for scheme, port in (("https", 443), ("http", 80)):
            base = f"{scheme}://{target.host}"
            root_status, _ = self._fetch(f"{base}/", self.timeout)
            if root_status == 0:
                continue                           # scheme not listening; skip its probes
            for label, path in PROBES:
                status, server = self._fetch(base + path, self.timeout)
                probes.append(Probe(label=label, scheme=scheme, status=status, server=server))
        return build_findings(target.host, probes, credentialed=target.credentialed)
