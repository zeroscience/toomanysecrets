r"""Password spraying - pure parsers, safety math, and findings.

Try one password against many accounts to find valid domain credentials, staying UNDER the
account-lockout threshold. Spraying is active and dangerous (it can lock accounts = a DoS, and
is loud to a SOC), so - like `poison` - it is a gated CLI command that NEVER runs in `scan`;
this module holds only the pure pieces (no `Engine` subclass, not registered as a default
engine), mirroring engines/responder.py vs poison.py. The gated `run_spray` orchestrator and
`cmd_spray` come in step 2.

Two-phase nxc orchestration (docs/SPRAY.md): read the lockout policy (`--pass-pol`) + user list
first, compute a safe attempt budget, then spray `nxc smb <dc> -u users -p <pw>
--continue-on-success`. Recovered creds are stored (account:password, like `credential-cracked`
/`gpp`) and ride in `meta["credentials"]` for the attack-path graph (paths.py). Reuses
`Category.PASSWORD` (no schema change).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..findings import Category, Evidence, Finding, Severity


@dataclass
class PassPolicy:
    threshold: int = 0            # account lockout threshold; 0 = no lockout
    observation_window: int = 0   # minutes; the "reset lockout counter" interval
    lockout_duration: int = 0     # minutes
    min_length: int = 0


@dataclass
class SprayHit:
    username: str                 # as nxc reports it, e.g. "ACME\\jdoe"
    password: str
    admin: bool = False           # nxc "(Pwn3d!)" -> local admin on the target


# --- pure parsers (tolerate nxc's "SMB <host> <port> <name>" line prefix) --- #
_POL_THRESHOLD = re.compile(r"(?i)Account Lockout Threshold:\s*(?P<v>\S+)")
_POL_WINDOW = re.compile(r"(?i)Reset Account Lockout Counter:\s*(?P<n>\d+)\s*minute")
_POL_DURATION = re.compile(r"(?i)(?:Locked Account Duration|Account Lockout Duration):\s*(?P<n>\d+)\s*minute")
_POL_MINLEN = re.compile(r"(?i)Minimum password length:\s*(?P<n>\d+)")
# a spray success: "[+] DOMAIN\user:password" with an optional " (Pwn3d!)" admin flag
_HIT = re.compile(r"(?i)\[\+\]\s+(?P<acct>\S+?):(?P<pw>.+?)(?:\s+\((?P<flag>[^)]*)\))?\s*$")


def parse_pass_pol(raw: str) -> PassPolicy:
    """Parse `nxc smb --pass-pol` output into a PassPolicy (threshold 'None' -> 0)."""
    pol = PassPolicy()
    if (m := _POL_THRESHOLD.search(raw)):
        v = m.group("v")
        pol.threshold = 0 if v.lower() in ("none", "0") else int(re.sub(r"\D", "", v) or "0")
    if (m := _POL_WINDOW.search(raw)):
        pol.observation_window = int(m.group("n"))
    if (m := _POL_DURATION.search(raw)):
        pol.lockout_duration = int(m.group("n"))
    if (m := _POL_MINLEN.search(raw)):
        pol.min_length = int(m.group("n"))
    return pol


def parse_spray_hits(raw: str) -> list[SprayHit]:
    """Recovered creds from `nxc` spray stdout: only `[+]` successes; `[-]` failures ignored."""
    hits: list[SprayHit] = []
    for line in raw.splitlines():
        if (m := _HIT.search(line)):
            flag = m.group("flag") or ""
            hits.append(SprayHit(username=m.group("acct"), password=m.group("pw"),
                                 admin="pwn3d" in flag.lower()))
    return hits


# --- lockout-safety math (what the gated orchestrator refuses on) --- #
NO_LOCKOUT = -1                    # sentinel: threshold == 0, no lockout configured


def safe_budget(policy: PassPolicy, margin: int = 1) -> int:
    """Max password attempts per user per observation window before risking lockout.

    NO_LOCKOUT when the domain sets no threshold. Otherwise threshold minus a safety margin
    (never below 0). threshold==1 -> 0, i.e. even one attempt is unsafe.
    """
    if policy.threshold <= 0:
        return NO_LOCKOUT
    return max(0, policy.threshold - margin)


def is_spray_safe(policy: PassPolicy, passwords: int = 1, margin: int = 1) -> bool:
    """True if spraying `passwords` password(s) this window stays within the safe budget."""
    budget = safe_budget(policy, margin)
    return budget == NO_LOCKOUT or passwords <= budget


def spray_argv(host: str, user_file: str, password: str) -> list[str]:
    """nxc args for the spray itself (-u/-p are the spray CANDIDATES, not tester creds)."""
    return ["smb", host, "-u", user_file, "-p", password, "--continue-on-success"]


# --- findings --- #
_SPRAY_REFS = ["https://attack.mitre.org/techniques/T1110/003/"]


def build_findings(hits: list[SprayHit], policy: "PassPolicy | None" = None,
                   *, host: str = "") -> list[Finding]:
    """One `spray-hit` per recovered credential (CRITICAL if Pwn3d admin, else HIGH), plus a
    `password-policy-no-lockout` MEDIUM when the domain sets no lockout threshold.

    Stores the recovered account:password (like `credential-cracked`) and rides each hit in
    `meta["credentials"]` for the attack-path graph. Account keeps its DOMAIN\\ prefix (spray
    targets are domain accounts).
    """
    findings: list[Finding] = []
    for h in hits:
        account = h.username
        uname = account.split("\\")[-1]
        crit = h.admin
        findings.append(Finding(
            id="spray-hit",
            title=f"Password spray hit{' (admin)' if crit else ''}: {account}",
            severity=Severity.CRITICAL if crit else Severity.HIGH,
            category=Category.PASSWORD,
            description=f"A sprayed password validated for '{account}'"
                        + (" with administrative access (Pwn3d)" if crit else "") + ".",
            impact="A valid domain credential is a foothold for authenticated access and further "
                   "compromise" + ("; administrative access enables host takeover." if crit else "."),
            remediation="Reset the account password; enforce a strong password policy and MFA; "
                        "verify account lockout is configured.",
            affected=[account],
            evidence=[Evidence(source="netexec",
                               detail=f"{account}:{h.password}" + (" (Pwn3d!)" if crit else ""))],
            references=_SPRAY_REFS,
            credentialed=False,
            meta={"credentials": [{
                "account": account, "username": uname, "kind": "password",
                "password": h.password, "source": "spray",
            }]},
        ))
    if policy is not None and policy.threshold == 0:
        findings.append(Finding(
            id="password-policy-no-lockout",
            title="No account lockout threshold (spraying/brute-force friendly)",
            severity=Severity.MEDIUM,
            category=Category.PASSWORD,
            description="The domain password policy sets no account lockout threshold, so accounts "
                        "can be sprayed or brute-forced online without ever locking out.",
            impact="Unlimited online password guessing against every domain account.",
            remediation="Configure an account lockout threshold (e.g. 5-10 attempts) with an "
                        "appropriate observation window and lockout duration.",
            affected=[host or "domain"],
            evidence=[Evidence(source="netexec", detail="Account Lockout Threshold: None")],
            references=["https://attack.mitre.org/techniques/T1110/"],
            credentialed=True,
        ))
    return findings
