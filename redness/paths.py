"""Attack-path derivation: turn findings into the relationships that matter.

The scan graph today shows *what exists* (hosts, users, shares, CAs). This module adds
*how you get to Domain Admin*: it derives attack-path edges from the findings a scan
already produced and streams them to the live graph as distinct "attack" edges, marking
compromised accounts as owned and pointing domain-takeover primitives at a Domain Admin
goal node.

v1 derives edges from our own findings (no extra tool). A later pass can ingest a real
BloodHound collection (nxc ldap --bloodhound) for AdminTo / MemberOf / HasSession edges.
Pure logic (derive_*), separate from emission, so it unit-tests with a synthetic Report.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .events import Event, EventBus, EventKind
from .findings import Category, Report

GOAL = "Domain Admin"                      # synthetic goal node for escalation paths
_ROAST_IDS = {"krb-asrep-roastable", "krb-kerberoastable"}
# AD CS ESCs that are direct low-priv -> Domain Admin primitives.
_DA_ESC = {1, 2, 3, 6, 8}


@dataclass(frozen=True)
class AttackEdge:
    src: str
    dst: str
    label: str
    technique: str = ""                    # MITRE ATT&CK id, for the report later
    potential: bool = False                # a lead not yet proven (e.g. roastable, uncracked)


# --------------------------------------------------------------------------- #
# Pure derivation (unit-testable)                                             #
# --------------------------------------------------------------------------- #
def compromised_accounts(report: Report) -> set[str]:
    """Accounts we own: every credential-cracked finding."""
    out: set[str] = set()
    for f in report.findings:
        if f.id == "credential-cracked":
            acct = f.meta.get("account") or (f.affected[0] if f.affected else None)
            if acct:
                out.add(acct)
    return out


def roastable_accounts(report: Report) -> set[str]:
    """Accounts with a capturable AS-REP / Kerberoast hash (crackable offline)."""
    out: set[str] = set()
    for f in report.findings:
        if f.id in _ROAST_IDS:
            out.update(f.affected)
    return out


def adcs_da_targets(report: Report) -> list[tuple[str, int]]:
    """(template-or-CA, esc-number) for AD CS findings that escalate to Domain Admin."""
    out: list[tuple[str, int]] = []
    for f in report.findings:
        esc = f.meta.get("esc")
        if f.category is Category.ADCS and esc in _DA_ESC:
            for target in f.affected:
                out.append((target, int(esc)))
    return out


def derive_attack_edges(report: Report, domain: str = "domain") -> list[AttackEdge]:
    """Derive the attack-path edges implied by a scan's findings."""
    edges: list[AttackEdge] = []
    owned = compromised_accounts(report)
    roast = roastable_accounts(report)

    for account in sorted(owned):                       # proven: cracked credential
        edges.append(AttackEdge(account, domain, "valid credential", "T1078"))
    for account in sorted(roast - owned):               # lead: roastable, not yet cracked
        edges.append(AttackEdge(account, domain, "roastable (crack offline)", "T1558",
                                potential=True))
    for target, esc in adcs_da_targets(report):         # domain-takeover primitive
        edges.append(AttackEdge(target, GOAL, f"AD CS ESC{esc}", "T1649"))
    return edges


# --------------------------------------------------------------------------- #
# Emission to the live graph                                                  #
# --------------------------------------------------------------------------- #
def _emit(bus: Optional[EventBus], kind: EventKind, **data) -> None:
    if bus is not None:
        bus.publish(Event(kind=kind, data=data, engine="paths"))


def emit_attack_paths(bus: Optional[EventBus], report: Report,
                      domain: str = "domain") -> list[AttackEdge]:
    """Derive attack edges and stream them (owned/goal nodes + attack edges) to the bus."""
    edges = derive_attack_edges(report, domain)
    if not edges or bus is None:
        return edges

    for account in compromised_accounts(report):        # recolor owned accounts
        _emit(bus, EventKind.NODE, id=account, label=account, type="owned")
    if any(e.dst == GOAL for e in edges):
        _emit(bus, EventKind.NODE, id=GOAL, label=GOAL, type="goal")
    for e in edges:
        _emit(bus, EventKind.EDGE, src=e.src, dst=e.dst, label=e.label,
              attack=True, potential=e.potential, technique=e.technique)

    owned_n = len(compromised_accounts(report))
    _emit(bus, EventKind.STATUS, message=f"attack paths: {len(edges)} edge(s), {owned_n} owned")
    return edges
