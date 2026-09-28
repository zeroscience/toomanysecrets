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
from typing import TYPE_CHECKING, Iterable, Optional

from .events import Event, EventBus, EventKind
from .findings import Category, Report

if TYPE_CHECKING:                          # type-only; no runtime coupling to bloodhound.py
    from .bloodhound import BHGraph

GOAL = "Domain Admin"                      # synthetic goal node for escalation paths
_ROAST_IDS = {"krb-asrep-roastable", "krb-kerberoastable"}
# AD CS ESCs that are direct low-priv -> Domain Admin primitives.
_DA_ESC = {1, 2, 3, 6, 8}
# BloodHound groups whose membership == Domain Admin (matched on short name, case-insensitive).
_DA_GROUPS = {"domain admins", "enterprise admins", "administrators"}
# best-effort MITRE technique per BloodHound edge kind (report mapping; approximate).
_BH_TECHNIQUE = {"AdminTo": "T1078", "HasSession": "T1550", "MemberOf": ""}


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


def _bfs(adj: dict[str, set[str]], starts: Iterable[str]) -> set[str]:
    """Nodes reachable from `starts` over adjacency `adj` (starts included)."""
    seen = set(starts)
    stack = list(seen)
    while stack:
        for nxt in adj.get(stack.pop(), ()):  # noqa: PLW2901
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def bloodhound_paths(bh: "BHGraph", owned: set[str], *,
                     da_targets: Optional[set[str]] = None,
                     domain: str = "domain") -> list[AttackEdge]:
    """Reachability over ingested BloodHound edges: light the path an OWNED principal has to
    Domain Admin (MemberOf / AdminTo / HasSession) as attack edges toward the goal node.

    `bh` is a parsed BloodHound graph (redness.bloodhound.parse_bloodhound); `owned` the proven
    -compromised principals (e.g. paths.compromised_accounts()). BH edges already point in
    control-flow direction (own src -> reach dst), so a forward BFS from `owned` is reachability
    and a reverse BFS from the DA targets is "can reach DA"; only edges on an owned->DA path are
    emitted. `potential=True` - the relationships are real but each hop is still a technique to
    execute. Pure: the CALLER supplies `bh` + `owned` (no ingestion here; the Report carries no
    BloodHound data - see docs/DECISIONS.md), so this is not wired into derive_attack_edges().

    `da_targets` defaults to name-matched DA groups (_DA_GROUPS). Treating a Domain Controller or
    a BloodHound `highvalue` node as a target (e.g. the "AdminTo DC -> DA" case) needs richer
    ingestion and is deferred - pass `da_targets` explicitly to override meanwhile.

    NB: hop edges reuse the BloodHound relationship as the label, so re-emitting them with
    attack=True upgrades the existing structural link in place rather than duplicating it.
    """
    if not bh.edges or not owned:
        return []
    fwd: dict[str, set[str]] = {}
    rev: dict[str, set[str]] = {}
    for src, dst, _rel in bh.edges:
        fwd.setdefault(src, set()).add(dst)
        rev.setdefault(dst, set()).add(src)

    targets = da_targets if da_targets is not None else {
        n for n in bh.nodes if n.split("@", 1)[0].lower() in _DA_GROUPS}
    if not targets:
        return []

    on_path = _bfs(fwd, owned) & _bfs(rev, targets)     # reachable-from-owned AND can-reach-DA
    if not on_path:
        return []

    edges: list[AttackEdge] = []
    seen: set[tuple[str, str, str]] = set()
    for src, dst, rel in bh.edges:
        if src in on_path and dst in on_path and (src, dst, rel) not in seen:
            seen.add((src, dst, rel))
            edges.append(AttackEdge(src, dst, rel, _BH_TECHNIQUE.get(rel, ""), potential=True))
    for target in sorted(targets & on_path):            # terminal hop -> the goal node
        edges.append(AttackEdge(target, GOAL, "escalates to Domain Admin", "", potential=True))
    return edges


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
