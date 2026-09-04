"""NTLM relay-path derivation: connect coercion + missing signing + ESC8 into relay chains.

Individually we already report "SMB signing not required", "AD CS Web Enrollment exposed
(ESC8)", and (after `coerce`) coercible DCs. The *relay map* is the thing almost no
orchestrator draws: it correlates them into the concrete chains an operator would actually
run -

    coerce a DC (PetitPotam/PrinterBug)  ->  relay its NTLM to /certsrv (ESC8)  ->  DC cert  ->  Domain Admin
    coerced / poisoned NTLM              ->  relay to SMB on a signing-disabled host  ->  code execution

Pure derivation from findings a scan already produced (no new tool), streamed to the live
graph as a central "NTLM Relay" node with coercion fan-in and relay fan-out. Mirrors paths.py:
`derive_*` / `build_*` are pure and unit-tested; emission is separate. Runs after
emit_attack_paths so the Domain Admin goal node already exists.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .events import Event, EventBus, EventKind
from .findings import Category, Evidence, Finding, Severity
from .paths import GOAL

RELAY = "NTLM Relay"                        # synthetic attacker-position node


@dataclass(frozen=True)
class RelayChain:
    victim: str                            # coerced source ("" = any coercible DC, not yet run)
    target: str                            # relay destination (CA host / signing-off host)
    kind: str                              # "adcs-esc8" | "smb"
    to_da: bool                            # does the chain reach Domain Admin


# --------------------------------------------------------------------------- #
# Pure derivation (unit-testable)                                             #
# --------------------------------------------------------------------------- #
def coercible_victims(report) -> list[str]:
    """Hosts confirmed coercible this engagement (findings from the `coerce` command)."""
    out: set[str] = set()
    for f in report.findings:
        if f.id.startswith("coercion-"):
            out.update(f.affected)
    return sorted(out)


def esc8_targets(report) -> list[str]:
    """CA/web-enrollment hosts exposing AD CS HTTP enrollment (ESC8 relay targets)."""
    out: list[str] = []
    for f in report.findings:
        if f.id == "adcs-web-enrollment":
            out.extend(f.affected)
    return sorted(set(out))


def smb_unsigned_hosts(report) -> list[str]:
    """Hosts that do not require SMB signing (relay-to-SMB targets)."""
    out: list[str] = []
    for f in report.findings:
        if f.id == "smb-signing-not-required":
            out.extend(f.affected)
    return sorted(set(out))


_POISON_IDS = {"llmnr-nbtns-poisonable", "wpad-lookup-observed"}
POISON_NODE = "LLMNR/NBT-NS poison"


def poisoning_present(report) -> bool:
    """True if the segment has spoofable name resolution (from `listen`) - an alternate way to
    obtain the NTLM authentication a relay needs, besides coercion."""
    return any(f.id in _POISON_IDS for f in report.findings)


def derive_relay_chains(report) -> list[RelayChain]:
    """The relay chains implied by a scan's findings (ESC8 first - it reaches DA)."""
    victims = coercible_victims(report) or [""]     # "" = generic "a coercible DC"
    chains: list[RelayChain] = []
    for ca in esc8_targets(report):
        for v in victims:
            chains.append(RelayChain(v, ca, "adcs-esc8", True))
    for host in smb_unsigned_hosts(report):
        for v in victims:
            chains.append(RelayChain(v, host, "smb", False))
    return chains


def build_relay_findings(report) -> list[Finding]:
    """One finding per relay avenue present (ESC8 -> CRITICAL, SMB -> HIGH). Category.CONFIG."""
    findings: list[Finding] = []
    victims = coercible_victims(report)
    who = ", ".join(victims) if victims else "a coercible DC (e.g. via PetitPotam/PrinterBug)"
    poison = poisoning_present(report)
    # The auth to relay has two sources: coercion, or poisoning spoofable name resolution.
    src_note = (" The authentication to relay can also be captured by poisoning the segment's "
                "LLMNR/NBT-NS name resolution (`redness poison`, seen via `redness listen`), not "
                "only by coercion." if poison else "")
    poison_ref = ["https://attack.mitre.org/techniques/T1557/001/"] if poison else []

    esc8 = esc8_targets(report)
    if esc8:
        findings.append(Finding(
            id="ntlm-relay-to-adcs",
            title="NTLM relay to AD CS Web Enrollment (ESC8) -> Domain Admin",
            severity=Severity.CRITICAL,
            category=Category.CONFIG,
            description="AD CS HTTP Web Enrollment is reachable and accepts NTLM, so coerced "
                        "authentication can be relayed to it to enroll a certificate as the "
                        "victim machine.",
            impact=f"Coercing {who} and relaying to {', '.join(esc8)} yields a certificate for a "
                   "Domain Controller account; that cert authenticates for DCSync - full domain "
                   "compromise. This chains coercion + ESC8 that are each present in this scan."
                   + src_note,
            remediation="Enable EPA (Extended Protection for Authentication) + require HTTPS on the "
                        "CA web endpoints, disable HTTP enrollment if unused, and enforce SMB/LDAP "
                        "signing to break relay. Patch the coercion vectors (KB5005413, disable "
                        "Spooler on DCs).",
            affected=esc8,
            evidence=[Evidence(source="relay", detail=f"ESC8 at {', '.join(esc8)}; victim: {who}")],
            references=["https://attack.mitre.org/techniques/T1187/",
                        "https://attack.mitre.org/techniques/T1649/"] + poison_ref,
            credentialed=False,
            meta={"relay": "adcs-esc8", "targets": esc8, "poison_source": poison},
        ))

    smb = smb_unsigned_hosts(report)
    if smb:
        findings.append(Finding(
            id="ntlm-relay-to-smb",
            title="NTLM relay to SMB on signing-disabled host(s)",
            severity=Severity.HIGH,
            category=Category.CONFIG,
            description="One or more hosts do not require SMB signing, so coerced or poisoned NTLM "
                        "authentication can be relayed to them.",
            impact=f"Relaying {who}'s (or any captured) authentication to these hosts enables "
                   "authenticated actions and, with a privileged victim, code execution / "
                   "secrets dump on the target." + src_note,
            remediation="Enforce SMB signing (Digitally sign communications = always) via GPO on "
                        "all hosts, especially DCs; combine with the coercion patches.",
            affected=smb,
            evidence=[Evidence(source="relay", detail=f"{len(smb)} signing-disabled host(s)")],
            references=["https://attack.mitre.org/techniques/T1557/001/"],
            credentialed=False,
            meta={"relay": "smb", "targets": smb, "poison_source": poison},
        ))
    return findings


# --------------------------------------------------------------------------- #
# Emission to the live graph                                                  #
# --------------------------------------------------------------------------- #
def _emit(bus: Optional[EventBus], kind: EventKind, **data) -> None:
    if bus is not None:
        bus.publish(Event(kind=kind, data=data, engine="relay"))


def emit_relay_paths(bus: Optional[EventBus], report, domain: str = "domain") -> list[RelayChain]:
    """Derive relay chains, add the findings to the report, and stream the map to the bus.

    Draws a central `NTLM Relay` node with coercion fan-in (victims, or the domain as a stand-in
    for 'a coercible DC') and relay fan-out (ESC8 CAs -> Domain Admin goal, signing-off hosts).
    """
    chains = derive_relay_chains(report)
    findings = build_relay_findings(report)
    report.findings.extend(findings)                    # so the report + summary include them
    if not chains or bus is None:
        return chains

    _emit(bus, EventKind.NODE, id=RELAY, label=RELAY, type="relay")
    victims = coercible_victims(report)
    if victims:
        for v in victims:                               # proven coercible -> relay
            _emit(bus, EventKind.NODE, id=v, label=v, type="host")
            _emit(bus, EventKind.EDGE, src=v, dst=RELAY, label="coerce", attack=True,
                  technique="T1187")
    else:                                               # generic: the domain feeds a coercible DC
        _emit(bus, EventKind.EDGE, src=domain, dst=RELAY, label="coerce a DC", attack=True,
              potential=True, technique="T1187")

    if poisoning_present(report):                       # the OTHER source of relay-able auth
        _emit(bus, EventKind.NODE, id=POISON_NODE, label=POISON_NODE, type="owned")
        _emit(bus, EventKind.EDGE, src=POISON_NODE, dst=RELAY, label="poison LLMNR/NBT-NS",
              attack=True, technique="T1557.001")

    for ca in esc8_targets(report):
        _emit(bus, EventKind.NODE, id=ca, label=ca, type="template")
        _emit(bus, EventKind.EDGE, src=RELAY, dst=ca, label="relay: ADCS ESC8", attack=True,
              technique="T1649")
        _emit(bus, EventKind.NODE, id=GOAL, label=GOAL, type="goal")
        _emit(bus, EventKind.EDGE, src=ca, dst=GOAL, label="DC cert -> DCSync", attack=True,
              technique="T1649")
    for host in smb_unsigned_hosts(report):
        _emit(bus, EventKind.EDGE, src=RELAY, dst=host, label="relay: SMB (no signing)",
              attack=True, technique="T1557.001")

    _emit(bus, EventKind.STATUS,
          message=f"relay map: {len(chains)} chain(s), {len(esc8_targets(report))} to Domain Admin")
    return chains
