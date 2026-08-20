"""Engine base class. Person A's domain.

An Engine wraps an external tool (netexec, impacket, certipy), runs it against a
target, and returns normalized `Finding` objects. The reporter never sees the raw
tool - only the findings.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Optional

from ..events import Event, EventKind, EventBus
from ..findings import Finding


@dataclass
class Target:
    host: str                      # DC IP/hostname or CIDR
    domain: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    nthash: Optional[str] = None   # for pass-the-hash
    kerberos: bool = False

    @property
    def credentialed(self) -> bool:
        return bool(self.username and (self.password or self.nthash or self.kerberos))


class Engine(abc.ABC):
    name: str = "engine"

    # Optional live-event sink. Left None means "don't stream" - engines still
    # return their findings normally, so nothing breaks when no bus is attached.
    bus: Optional[EventBus] = None

    @abc.abstractmethod
    def is_available(self) -> bool:
        """True if the underlying tool is installed and callable."""

    @abc.abstractmethod
    def run(self, target: Target) -> list[Finding]:
        """Execute against target, return normalized findings."""

    # -- streaming helpers (no-ops unless a bus is attached) ----------------- #
    def emit(self, kind: EventKind, **data) -> None:
        if self.bus is not None:
            self.bus.publish(Event(kind=kind, data=data, engine=self.name))

    def emit_status(self, message: str) -> None:
        self.emit(EventKind.STATUS, message=message)

    def emit_finding(self, finding: Finding) -> None:
        self.emit(EventKind.FINDING, finding=finding.to_dict())

    def emit_node(self, id: str, label: str, type: str, **meta) -> None:
        self.emit(EventKind.NODE, id=id, label=label, type=type, meta=meta)

    def emit_edge(self, src: str, dst: str, label: str = "") -> None:
        self.emit(EventKind.EDGE, src=src, dst=dst, label=label)

    def emit_probe(self, target: str, test: str) -> None:
        self.emit(EventKind.PROBE, target=target, test=test)

    def emit_done(self) -> None:
        self.emit(EventKind.DONE, engine=self.name)
