"""NetExec engine wrapper (STUB — Person A to flesh out).

Strategy: shell out to `nxc` with `--jsonl` / greppable output where available,
parse into Finding objects. This stub shows the intended shape and the parsing
seam; wire real subprocess calls + parsers here.

Reference: https://www.netexec.wiki/
"""
from __future__ import annotations

import shutil

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target


class NetExecEngine(Engine):
    name = "netexec"

    def is_available(self) -> bool:
        return shutil.which("nxc") is not None or shutil.which("netexec") is not None

    def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        # TODO(Person A): replace stubs with real subprocess calls + parsers.
        #   nxc smb <host> -u '' -p ''            -> null session / shares / signing
        #   nxc ldap <host> -u U -p P --users     -> user enumeration, pwd-not-required
        #   nxc smb <host> ... --shares           -> readable/writable shares
        # For each parsed condition, append a normalized Finding below.

        findings.extend(self._check_smb_signing(target))
        return findings

    def _check_smb_signing(self, target: Target) -> list[Finding]:
        """Placeholder: real impl parses `nxc smb <host>` banner 'signing:False'."""
        # This stub returns nothing until wired to live output.
        return []

    # Helper kept here so parsers have a single place to mint findings.
    @staticmethod
    def _smb_signing_disabled(host: str, raw: str) -> Finding:
        return Finding(
            id="smb-signing-not-required",
            title="SMB signing not required",
            severity=Severity.MEDIUM,
            category=Category.SMB,
            description="The host does not require SMB signing.",
            impact="Enables SMB relay (NTLM relay) attacks, allowing an attacker on the "
                   "network path to authenticate as the victim to other services.",
            remediation="Enforce SMB signing via GPO: 'Microsoft network server: Digitally "
                        "sign communications (always)' = Enabled on all hosts, especially DCs.",
            affected=[host],
            evidence=[Evidence(source="netexec", detail="signing:False", raw=raw)],
            references=["https://attack.mitre.org/techniques/T1557/001/"],
            credentialed=False,
        )
