r"""Delegation abuse enumeration - unconstrained / constrained / RBCD + MAQ, gMSA, shadow creds.

All of these are LDAP-attribute reads against the DC, so this mirrors engines/ldap.py: one
engine, several `nxc ldap <dc> <auth> ...` invocations, each fed to a pure `parse_*`. This
module is step 1 - the pure parsers + `build_findings` only (the subprocess `DelegationEngine`
+ registration come in step 2), so it unit-tests against captured nxc output with no nxc/DC.

Severity philosophy (docs/DECISIONS, delegation): informational baseline, CRITICAL reserved for
the genuinely urgent cases, to avoid alert fatigue.
- unconstrained delegation: HIGH on a NON-DC principal (the attack primitive - coerce a DA and
  capture its TGT); INFO on a DC (expected/benign - DCs legitimately have it).
- constrained: HIGH; CRITICAL only with protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION -
  impersonate ANY user to the target SPNs).
- RBCD: HIGH.
- machine-account-quota: INFO (MAQ > 0). The "CRITICAL when combined with AD CS" escalation is a
  cross-finding correlation and belongs to paths.py/report (Gjoko), not this single engine.
- gMSA readable / shadow-credentials: HIGH. No credential is recovered into meta["credentials"]
  here - this is enumeration, not credential recovery.

Findings use Category.LDAP (reuse; no schema bump). nxc flag/module names could not be
introspected offline - verify `--trusted-for-delegation` / `--find-delegation` / `-M maq` /
`-M gmsa` against real nxc and drop captured samples into tests/ if a format differs.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target

# userAccountControl bits (delegation-relevant)
UAC_SERVER_TRUST = 0x2000            # SERVER_TRUST_ACCOUNT -> domain controller
UAC_TRUSTED_FOR_DELEGATION = 0x80000  # unconstrained delegation
UAC_TRUSTED_TO_AUTH = 0x1000000       # constrained w/ protocol transition (S4U2Self)


@dataclass
class DelegAccount:
    account: str
    is_dc: bool = False


@dataclass
class DelegEntry:
    account: str
    kind: str                        # "constrained" | "constrained-proto" | "rbcd"
    to: list = field(default_factory=list)   # target SPNs / principals


# --------------------------------------------------------------------------- #
# Pure parsers (tolerate nxc's "LDAP <host> <port> <name>" line prefix)        #
# --------------------------------------------------------------------------- #
_ACCT = r"[^\s:]+"


def _strip_prefix(line: str) -> str:
    """Drop an optional `LDAP  <host>  <port>  <name>` nxc prefix, keep the message body."""
    m = re.match(r"^\s*LDAP\s+\S+\s+\d+\s+\S+\s+(?P<body>.*)$", line)
    return m.group("body") if m else line.strip()


def parse_unconstrained(raw: str, *, dc_names: "set[str] | None" = None) -> list[DelegAccount]:
    """Accounts with unconstrained delegation from `nxc ldap --trusted-for-delegation`.

    A DC is recognised by a SERVER_TRUST_ACCOUNT UAC flag when present, or by matching a known
    DC name (`dc_names`, lowercased sAMAccountName without a trailing $). Order-preserving dedupe.
    """
    dc_names = {n.lower().rstrip("$") for n in (dc_names or set())}
    out: list[DelegAccount] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        body = _strip_prefix(line)
        m = re.match(rf"(?P<acct>{_ACCT})(?:\s+(?P<uac>0x[0-9a-fA-F]+|\d+))?\s*$", body)
        if not m:
            continue
        acct = m.group("acct")
        if not acct or ":" in acct or acct in seen:
            continue
        seen.add(acct)
        is_dc = acct.lower().rstrip("$") in dc_names
        if m.group("uac") is not None:
            uac = int(m.group("uac"), 0)
            if uac & UAC_SERVER_TRUST:
                is_dc = True
        out.append(DelegAccount(account=acct, is_dc=is_dc))
    return out


def parse_find_delegation(raw: str) -> list[DelegEntry]:
    """Constrained + RBCD entries from `nxc ldap --find-delegation`.

    Rows look like `<account>  <type>  <rights-to>` where type is one of
    Constrained / Constrained w/ Protocol Transition / Resource-Based Constrained.
    """
    out: list[DelegEntry] = []
    for line in raw.splitlines():
        body = _strip_prefix(line)
        low = body.lower()
        if "resource-based" in low or "rbcd" in low:
            kind = "rbcd"
        elif "protocol transition" in low or "with protocol" in low:
            kind = "constrained-proto"
        elif "constrained" in low:
            kind = "constrained"
        else:
            continue
        acct = body.split()[0] if body.split() else ""
        if not acct:
            continue
        to = re.findall(r"[A-Za-z0-9_.$/-]+/[A-Za-z0-9_.$-]+", body)   # SPN-ish tokens
        out.append(DelegEntry(account=acct, kind=kind, to=to))
    return out


def parse_maq(raw: str) -> "int | None":
    """The ms-DS-MachineAccountQuota value (None if not found)."""
    m = re.search(r"(?i)MachineAccountQuota[^0-9-]*(-?\d+)", raw)
    return int(m.group(1)) if m else None


def parse_gmsa(raw: str) -> list[str]:
    """gMSA account names with a readable managed password (`nxc ldap -M gmsa`)."""
    out, seen = [], set()
    for line in raw.splitlines():
        body = _strip_prefix(line)
        m = re.search(r"(?i)Account:\s*(?P<acct>[^\s]+).*?(?:NTLM|Password|managedpassword):", body)
        if not m:
            m = re.search(r"(?i)(?P<acct>[^\s]+\$)\s+.*read", body)
        if m:
            acct = m.group("acct").rstrip(":")
            if acct not in seen:
                seen.add(acct)
                out.append(acct)
    return out


def parse_shadow_creds(raw: str) -> list[str]:
    """Accounts with a populated msDS-KeyCredentialLink (shadow-credential present)."""
    out, seen = [], set()
    for line in raw.splitlines():
        body = _strip_prefix(line)
        if re.search(r"(?i)KeyCredentialLink|shadow.?cred", body):
            m = re.match(rf"(?P<acct>{_ACCT})", body)
            if m and m.group("acct") not in seen:
                seen.add(m.group("acct"))
                out.append(m.group("acct"))
    return out


# --------------------------------------------------------------------------- #
# Findings                                                                     #
# --------------------------------------------------------------------------- #
_MITRE_DELEG = "https://attack.mitre.org/techniques/T1558/003/"
_MITRE_RBCD = "https://attack.mitre.org/techniques/T1134/"


def build_findings(
    *,
    unconstrained: "list[DelegAccount] | None" = None,
    delegation: "list[DelegEntry] | None" = None,
    maq: "int | None" = None,
    gmsa: "list[str] | None" = None,
    shadow: "list[str] | None" = None,
    adcs_present: bool = False,
) -> list[Finding]:
    """Turn parsed delegation state into Findings (Category.LDAP; no meta['credentials']).

    `adcs_present` (computed by run_scan from CertipyEngine's findings this run) escalates the
    machine-account-quota finding from INFO to CRITICAL: MAQ + an AD CS ESC path is a real
    escalation, but MAQ alone is not.
    """
    findings: list[Finding] = []

    # unconstrained: HIGH on non-DC (the primitive); INFO on a DC (expected).
    non_dc = [a.account for a in (unconstrained or []) if not a.is_dc]
    dcs = [a.account for a in (unconstrained or []) if a.is_dc]
    if non_dc:
        findings.append(Finding(
            id="delegation-unconstrained", title="Unconstrained delegation on non-DC account(s)",
            severity=Severity.HIGH, category=Category.LDAP,
            description="Non-DC principals are trusted for unconstrained delegation; they cache "
                        "the TGT of any user that authenticates to them.",
            impact="Coercing a privileged user (e.g. a Domain Admin, or a DC via the printer bug) "
                   "to authenticate lets the holder capture that TGT and impersonate them - a "
                   "direct path to Domain Admin.",
            remediation="Remove TRUSTED_FOR_DELEGATION; use constrained delegation or the RBCD "
                        "model; mark sensitive accounts 'Account is sensitive and cannot be "
                        "delegated' and add them to Protected Users.",
            affected=non_dc,
            evidence=[Evidence(source="netexec-ldap", detail=f"{len(non_dc)} non-DC account(s)")],
            references=[_MITRE_DELEG], credentialed=True,
            meta={"delegation": "unconstrained"},
        ))
    if dcs:
        findings.append(Finding(
            id="delegation-unconstrained-dc", title="Unconstrained delegation on domain controller(s)",
            severity=Severity.INFO, category=Category.LDAP,
            description="Domain controllers are trusted for unconstrained delegation by design "
                        "(expected); listed for context, not as a misconfiguration.",
            impact="Expected for DCs; relevant only as context for coercion/relay attack paths.",
            remediation="No action for legitimate DCs; ensure no non-DC shares this trust.",
            affected=dcs,
            evidence=[Evidence(source="netexec-ldap", detail=f"{len(dcs)} DC(s)")],
            references=[_MITRE_DELEG], credentialed=True,
            meta={"delegation": "unconstrained", "expected": True},
        ))

    # constrained + RBCD
    for e in (delegation or []):
        if e.kind == "rbcd":
            findings.append(Finding(
                id="delegation-rbcd", title=f"Resource-based constrained delegation: {e.account}",
                severity=Severity.HIGH, category=Category.LDAP,
                description=f"'{e.account}' has msDS-AllowedToActOnBehalfOfOtherIdentity configured "
                            f"(RBCD).",
                impact="A principal that can write this attribute can impersonate any user to the "
                       "account's services (S4U); combined with a controllable machine account it "
                       "is a common escalation.",
                remediation="Review and restrict who can write msDS-AllowedToActOnBehalfOf on the "
                            "account; remove stale RBCD entries.",
                affected=[e.account],
                evidence=[Evidence(source="netexec-ldap",
                                   detail=f"RBCD -> {', '.join(e.to) or 'configured'}")],
                references=[_MITRE_RBCD], credentialed=True,
                meta={"delegation": "rbcd", "to": e.to},
            ))
        else:
            proto = e.kind == "constrained-proto"
            findings.append(Finding(
                id="delegation-constrained",
                title=f"Constrained delegation{' (protocol transition)' if proto else ''}: {e.account}",
                severity=Severity.CRITICAL if proto else Severity.HIGH, category=Category.LDAP,
                description=f"'{e.account}' has msDS-AllowedToDelegateTo set"
                            + (" with protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION)."
                               if proto else " (S4U2Proxy to the listed SPNs)."),
                impact=("With protocol transition the account can impersonate ANY user (incl. "
                        "privileged) to the target services." if proto else
                        "The account can impersonate users that authenticate to it, onward to the "
                        "target services."),
                remediation="Minimise delegation targets; remove protocol transition where not "
                            "required; prefer RBCD scoped to specific principals.",
                affected=[e.account],
                evidence=[Evidence(source="netexec-ldap",
                                   detail=f"delegate-to: {', '.join(e.to) or 'set'}")],
                references=[_MITRE_DELEG], credentialed=True,
                meta={"delegation": e.kind, "to": e.to},
            ))

    # machine account quota - INFO baseline; CRITICAL only in combination with an AD CS ESC path.
    if maq is not None and maq > 0:
        combo = bool(adcs_present)
        findings.append(Finding(
            id="machine-account-quota",
            title=f"Machine account quota is {maq}" + (" (+ AD CS ESC path)" if combo else ""),
            severity=Severity.CRITICAL if combo else Severity.INFO, category=Category.LDAP,
            description=f"ms-DS-MachineAccountQuota is {maq}: any authenticated user can create up "
                        f"to {maq} machine account(s).",
            impact=("An AD CS ESC path was also found this scan: an attacker can create a machine "
                    "account and abuse the vulnerable template to escalate to Domain Admin."
                    if combo else
                    "Attacker-created machine accounts enable RBCD and shadow-credential attacks; "
                    "urgent only in combination with a writable target or an ADCS ESC path."),
            remediation="Set ms-DS-MachineAccountQuota to 0 and delegate machine-account creation "
                        "to a controlled group.",
            affected=["domain"],
            evidence=[Evidence(source="netexec-ldap", detail=f"MachineAccountQuota={maq}")],
            references=[_MITRE_RBCD], credentialed=True,
            meta={"maq": maq, "adcs_combo": combo},
        ))

    if gmsa:
        findings.append(Finding(
            id="gmsa-readable", title="Readable gMSA managed password(s)",
            severity=Severity.HIGH, category=Category.LDAP,
            description="The managed password of one or more gMSA accounts is readable by the "
                        "tested principal (msDS-ManagedPassword).",
            impact="A readable gMSA password yields the service account's credential; if the gMSA "
                   "is privileged this is a direct escalation.",
            remediation="Restrict msDS-GroupMSAMembership (PrincipalsAllowedToRetrieveManagedPassword) "
                        "to the minimum required hosts.",
            affected=list(gmsa),
            evidence=[Evidence(source="netexec-ldap", detail=f"{len(gmsa)} readable gMSA(s)")],
            references=[_MITRE_DELEG], credentialed=True,
            meta={"gmsa": list(gmsa)},
        ))

    if shadow:
        findings.append(Finding(
            id="shadow-credentials", title="Populated msDS-KeyCredentialLink (shadow credentials)",
            severity=Severity.HIGH, category=Category.LDAP,
            description="Accounts carry a populated msDS-KeyCredentialLink (an alternate "
                        "authentication key / shadow credential).",
            impact="A writable KeyCredentialLink lets an attacker add their own key and "
                   "authenticate as the account (PKINIT). Write-ability is an ACL question "
                   "(BloodHound) - this flags that the attribute is in use.",
            remediation="Review msDS-KeyCredentialLink entries and who can write them; remove "
                        "unexpected keys.",
            affected=list(shadow),
            evidence=[Evidence(source="netexec-ldap", detail=f"{len(shadow)} account(s)")],
            references=[_MITRE_RBCD], credentialed=True,
            meta={"shadow_credentials": list(shadow)},
        ))

    return findings


# --------------------------------------------------------------------------- #
# Execution (impure) - orchestrate several `nxc ldap` reads                     #
# --------------------------------------------------------------------------- #
def _dc_names_from_host(host: str) -> "set[str]":
    """Best-effort DC name hint from the scanned host: a hostname's short name
    (`dc01.acme.local` -> {"dc01"}); empty for an IP. The reliable DC signal is the UAC
    SERVER_TRUST bit in the output when nxc includes it (see parse_unconstrained)."""
    if host and not re.match(r"^[0-9.]+$", host):
        return {host.split(".")[0].lower()}
    return set()


class DelegationEngine(Engine):
    """Delegation-family LDAP enumeration via several `nxc ldap` reads against the DC.

    In default_engines() but no-ops without domain creds (delegation attributes need an authed
    LDAP read) or without nxc. `run` takes an optional `adcs_present` that run_scan supplies
    (via the `wants_adcs_context` flag) from CertipyEngine's findings this scan, so the MAQ
    finding can escalate without duplicating ADCS detection here. `runner` is injectable.
    """
    name = "delegation"
    wants_adcs_context = True

    def __init__(self, timeout: int = 300, runner=subprocess.run):
        self.timeout = timeout
        self.runner = runner

    def _bin(self) -> "str | None":
        return shutil.which("nxc") or shutil.which("netexec")

    def is_available(self) -> bool:
        return self._bin() is not None

    def _auth_args(self, t: Target) -> list[str]:
        args = ["-u", t.username or ""]
        if t.nthash:
            args += ["-H", t.nthash]
        else:
            args += ["-p", t.password if t.password is not None else ""]
        if t.kerberos:
            args += ["-k"]
        if t.domain:
            args += ["-d", t.domain]
        return args

    def _invoke(self, extra: list[str], t: Target) -> str:
        exe = self._bin()
        if not exe:
            return ""
        cmd = [exe, "ldap", t.host] + self._auth_args(t) + extra
        try:
            p = self.runner(cmd, capture_output=True, text=True, timeout=self.timeout)
        except (subprocess.TimeoutExpired, OSError):
            return ""
        return (getattr(p, "stdout", "") or "") + "\n" + (getattr(p, "stderr", "") or "")

    def run(self, target: Target, adcs_present: bool = False) -> list[Finding]:
        if not self.is_available() or not target.credentialed:   # delegation reads need auth
            return []
        dc = _dc_names_from_host(target.host)
        return build_findings(
            unconstrained=parse_unconstrained(
                self._invoke(["--trusted-for-delegation"], target), dc_names=dc),
            delegation=parse_find_delegation(self._invoke(["--find-delegation"], target)),
            maq=parse_maq(self._invoke(["-M", "maq"], target)),
            gmsa=parse_gmsa(self._invoke(["-M", "gmsa"], target)),
            shadow=None,     # parse_shadow_creds is ready; its nxc invocation is deferred
            adcs_present=adcs_present,
        )
