"""Certipy engine — AD CS (certificate services) misconfigurations, ESC1–ESC16.

Certipy's `find` command emits structured JSON with a per-object
`"[!] Vulnerabilities"` map ({"ESC1": "<why>"}). We parse that into normalized
Findings, which is far more robust than scraping the text report.

Parsing is pure (parse_certipy_json) and separate from execution (CertipyEngine.run),
so it unit-tests against captured JSON with no certipy / DC / CA — see tests/.

Reference: https://github.com/ly4k/Certipy
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target

# Per-ESC severity + remediation. Default (unknown ESC) is HIGH with generic advice.
# Sources: Certipy docs + SpecterOps "Certified Pre-Owned".
_ESC: dict[int, tuple[Severity, str]] = {
    1: (Severity.CRITICAL,
        "Remove ENROLLEE_SUPPLIES_SUBJECT (msPKI-Certificate-Name-Flag) from the template, "
        "or restrict enrollment to trusted principals and require manager approval."),
    2: (Severity.CRITICAL,
        "Restrict the 'Any Purpose' / SubCA EKU template; limit enrollment and enable manager approval."),
    3: (Severity.HIGH,
        "Restrict Certificate Request Agent (Enrollment Agent) templates and enrollment-agent rights."),
    4: (Severity.HIGH,
        "Fix template ACLs: remove write/owner rights for non-privileged principals over the template object."),
    5: (Severity.HIGH,
        "Fix ACLs on the PKI objects / containers (CA object, templates container) in AD."),
    6: (Severity.CRITICAL,
        "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA (certutil -setreg policy\\EditFlags) and restart CertSvc."),
    7: (Severity.HIGH,
        "Restrict CA security (ManageCA / ManageCertificates) rights to trusted administrators only."),
    8: (Severity.HIGH,
        "Disable NTLM on AD CS web endpoints or enable EPA/HTTPS-only; consider RPC/DCOM hardening to block relay."),
    9: (Severity.HIGH,
        "Set strong certificate mapping (StrongCertificateBindingEnforcement) and remove no-security-extension flags."),
    10: (Severity.HIGH,
         "Enforce strong certificate mapping; patch/mitigate weak UPN/SAN mapping (KB5014754)."),
    11: (Severity.HIGH,
         "Enforce IF_ENFORCEENCRYPTICERTREQUEST on the CA to require RPC encryption (block relay to ICPR)."),
    13: (Severity.HIGH,
         "Review templates whose issuance policy links to a privileged group via OID group-link."),
    15: (Severity.HIGH,
         "Restrict enrollment on schema-v1 templates that allow application-policy injection (CVE-2024-49019)."),
    16: (Severity.HIGH,
         "Enable the security extension (szOID_NTDS_CA_SECURITY_EXT) on the CA."),
}

_VULN_KEY = re.compile(r"vulnerab", re.I)     # matches "[!] Vulnerabilities"
_ESC_NUM = re.compile(r"ESC\s*0*([0-9]+)", re.I)


def _sev_and_fix(esc_num: int) -> tuple[Severity, str]:
    return _ESC.get(esc_num, (
        Severity.HIGH,
        "Review the flagged AD CS misconfiguration and apply least-privilege enrollment "
        "and CA hardening per Certipy guidance.",
    ))


def _name_of(obj: dict[str, Any]) -> str:
    for k in ("Template Name", "CA Name", "Name", "DNS Name"):
        if obj.get(k):
            return str(obj[k])
    return "unknown"


def _iter_objects(data: dict[str, Any]):
    """Yield (kind, obj) for every template and CA in a certipy JSON blob."""
    for section, kind in (("Certificate Templates", "template"),
                          ("Certificate Authorities", "ca")):
        block = data.get(section) or {}
        # certipy keys entries by stringified index ("0","1",...)
        items = block.values() if isinstance(block, dict) else block
        for obj in items:
            if isinstance(obj, dict):
                yield kind, obj


def parse_certipy_json(data: "dict | str", credentialed: bool = False) -> list[Finding]:
    """Turn a certipy `find -json` blob (dict or JSON string) into Findings."""
    if isinstance(data, str):
        data = json.loads(data)

    findings: list[Finding] = []
    cas_seen: list[str] = []
    templates_seen: list[str] = []

    for kind, obj in _iter_objects(data):
        name = _name_of(obj)
        (templates_seen if kind == "template" else cas_seen).append(name)

        vulns: dict[str, str] = {}
        for k, v in obj.items():
            if _VULN_KEY.search(k) and isinstance(v, dict):
                vulns.update(v)

        for esc_key, why in vulns.items():
            m = _ESC_NUM.search(esc_key)
            if not m:
                continue
            n = int(m.group(1))
            sev, fix = _sev_and_fix(n)
            findings.append(Finding(
                id=f"adcs-esc{n}",
                title=f"AD CS ESC{n} — vulnerable certificate {kind}",
                severity=sev,
                category=Category.ADCS,
                description=f"Certipy flagged {kind} '{name}' as ESC{n} vulnerable.",
                impact=str(why) or "Abuse can lead to certificate-based authentication as a "
                                   "higher-privileged principal, up to domain compromise.",
                remediation=fix,
                affected=[name],
                evidence=[Evidence(source="certipy", detail=f"ESC{n}: {why}")],
                references=["https://github.com/ly4k/Certipy",
                            "https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                credentialed=credentialed,
                meta={"esc": n, "object": kind},
            ))

    # Informational: what was discovered.
    if cas_seen or templates_seen:
        findings.append(Finding(
            id="enum-adcs",
            title="AD CS enumerated",
            severity=Severity.INFO,
            category=Category.ENUM,
            description="Certificate Authorities and templates discovered via Certipy.",
            affected=[f"CA: {c}" for c in cas_seen] + [f"Template: {t}" for t in templates_seen],
            evidence=[Evidence(source="certipy",
                               detail=f"{len(cas_seen)} CA(s), {len(templates_seen)} template(s)")],
            credentialed=credentialed,
        ))
    return findings


class CertipyEngine(Engine):
    name = "certipy"

    def __init__(self, timeout: int = 300):
        self.timeout = timeout

    def _bin(self) -> str | None:
        return shutil.which("certipy") or shutil.which("certipy-ad")

    @staticmethod
    def _module_available() -> bool:
        """True if the certipy package is importable (bundled into the exe or pip-installed)."""
        try:
            import certipy.entry  # noqa: F401
            return True
        except Exception:
            return False

    def is_available(self) -> bool:
        # Prefer a CLI binary on PATH, but a bundled/importable module works too — that's
        # what lets the self-contained exe run certipy without certipy.exe on PATH.
        return self._bin() is not None or self._module_available()

    def _certipy_args(self, target: Target, prefix: str) -> list[str]:
        args = ["find", "-dc-ip", target.host, "-vulnerable", "-json", "-output", prefix]
        if target.username:
            args += ["-u", f"{target.username}@{target.domain}" if target.domain else target.username]
        if target.nthash:
            args += ["-hashes", f":{target.nthash}"]
        elif target.password is not None:
            args += ["-p", target.password]
        return args

    def _run_cli(self, args: list[str]) -> bool:
        exe = self._bin()
        if not exe:
            return False
        try:
            subprocess.run([exe] + args, capture_output=True, text=True, timeout=self.timeout)
            return True
        except (subprocess.TimeoutExpired, OSError):
            self.emit_status("certipy CLI failed/timed out")
            return False

    def _run_inproc(self, args: list[str]) -> bool:
        """Invoke certipy in-process via its console entrypoint (certipy.entry:main).

        This is the path a frozen/self-contained exe takes: the certipy binary isn't on
        PATH, but the module is bundled. We patch sys.argv and call main(); it parses argv
        exactly like the CLI and writes the same -output JSON we then parse.
        """
        try:
            import certipy.entry
        except Exception as e:
            self.emit_status(f"certipy module unavailable: {e}")
            return False
        old_argv = sys.argv
        sys.argv = ["certipy"] + args
        try:
            certipy.entry.main()
        except SystemExit:
            pass                              # argparse/normal exit
        except Exception as e:
            self.emit_status(f"certipy in-process error: {e}")
            return False
        finally:
            sys.argv = old_argv
        return True

    def run(self, target: Target) -> list[Finding]:
        if not self.is_available():
            return []
        via = "CLI" if self._bin() else "in-process"
        self.emit_status(f"certipy find against {target.host} ({via})")
        self.emit_probe(target=target.host, test="adcs-find")

        with tempfile.TemporaryDirectory() as td:
            prefix = os.path.join(td, "redness")
            args = self._certipy_args(target, prefix)
            ok = self._run_cli(args) if self._bin() else self._run_inproc(args)
            if not ok:
                return []
            matches = glob.glob(os.path.join(td, "*.json"))
            if not matches:
                return []
            with open(matches[0], encoding="utf-8") as fh:
                data = json.load(fh)

        findings = parse_certipy_json(data, credentialed=target.credentialed)
        self._stream_graph(target, findings)
        for f in findings:
            self.emit_finding(f)
        self.emit_done()
        return findings

    def _stream_graph(self, target: Target, findings: list[Finding]) -> None:
        """Emit graph nodes/edges so a live 3D view can render the AD CS surface."""
        dc = target.domain or target.host
        self.emit_node(id=dc, label=dc, type="domain")
        for f in findings:
            for name in f.affected:
                self.emit_node(id=name, label=name, type=f.meta.get("object", "adcs"))
                self.emit_edge(src=dc, dst=name, label=f.meta.get("esc") and f"ESC{f.meta['esc']}" or "")
