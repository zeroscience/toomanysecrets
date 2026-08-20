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

from dataclasses import dataclass
from typing import Callable, Optional

from .engines import CertipyEngine, LdapEngine, NetExecEngine, TLSEngine
from .engines.base import Engine, Target
from .events import Event, EventBus, EventKind
from .findings import Report
from .scan import _emit_finding_graph


@dataclass(frozen=True)
class Action:
    id: str
    label: str
    node_types: tuple[str, ...]          # which graph node types this applies to
    engine: Callable[[], Engine]
    offensive: bool = False              # Phase 3 gating flag (all False for now)


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
