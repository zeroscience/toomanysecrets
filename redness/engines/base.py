"""Engine base class. Person A's domain.

An Engine wraps an external tool (netexec, impacket, certipy), runs it against a
target, and returns normalized `Finding` objects. The reporter never sees the raw
tool — only the findings.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Optional

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

    @abc.abstractmethod
    def is_available(self) -> bool:
        """True if the underlying tool is installed and callable."""

    @abc.abstractmethod
    def run(self, target: Target) -> list[Finding]:
        """Execute against target, return normalized findings."""
