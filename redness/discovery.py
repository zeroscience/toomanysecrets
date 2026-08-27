"""Lightweight TCP service discovery - decide which engines to run per host.

The "hail-mary" default scan should run *everything passive*, but firing every engine at
every host wastes time (an `nxc mssql` against a box with no 1433 open) and is noisy. So
before running engines against a host we do a quick TCP connect-scan (stdlib sockets, no
nmap dependency) of the ports our engines care about, and dispatch only the engines whose
service is actually open. "According to the enumeration and logic."

This is discovery, not exploitation: a plain TCP connect (SYN + accept), nothing sent to
the service. It stays comfortably inside the passive-scan envelope. `--no-discovery` turns
it off and runs every available engine (the old behaviour).

Pure and injectable: `open_ports` takes a `checker` callable so the dispatch logic
unit-tests with no real sockets. UDP-only services (SNMP/161) are NOT port-gated here - a
TCP connect-scan cannot see them, so their engines are left un-gated (always run).
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, Optional

# Which TCP port(s) each engine's service listens on. An engine listed here runs against a
# host only if one of its ports is open; an engine NOT listed is never port-gated (always
# runs) - so a new/UDP engine keeps working until it is added here. Keyed by `Engine.name`.
ENGINE_PORTS: dict[str, tuple[int, ...]] = {
    "netexec": (445,),                 # SMB
    "netexec-ldap": (389, 636),        # LDAP / LDAPS (users + AS-REP/Kerberoast capture)
    "certipy": (389, 636),             # AD CS enumeration over LDAP
    "gpp": (445,),                     # GPP cpassword over SYSVOL (SMB)
    "rdp": (3389,),
    "winrm": (5985, 5986),
    "mssql": (1433,),
    "ftp": (21,),
    "http": (80, 443),                 # AD web surfaces (/certsrv = ESC8, OWA)
    "tls": (443, 636, 3269, 5986),     # the TLS endpoints the TLS engine probes
    # NOTE: "snmp" is intentionally absent - UDP/161 is invisible to a TCP connect-scan,
    # so the SNMP engine is left un-gated (runs whenever snmpwalk is installed).
}

# Ports we connect-scan by default: the union of ENGINE_PORTS plus a few context ports we
# surface even if no engine consumes them yet (so discovery is informative in the report).
_CONTEXT_PORTS: dict[int, str] = {
    21: "ftp", 80: "http", 88: "kerberos", 135: "msrpc", 139: "netbios-ssn",
    443: "https", 445: "smb", 389: "ldap", 464: "kpasswd", 636: "ldaps",
    1433: "mssql", 3268: "gc-ldap", 3269: "gc-ldaps", 3389: "rdp",
    5985: "winrm", 5986: "winrm-ssl",
}

PORT_NAMES = dict(_CONTEXT_PORTS)


def default_ports() -> list[int]:
    """The full set we connect-scan (engine ports + context ports), sorted."""
    ports = set(_CONTEXT_PORTS)
    for pset in ENGINE_PORTS.values():
        ports.update(pset)
    return sorted(ports)


def check_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """True if a TCP connection to host:port completes within `timeout`."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ValueError, OverflowError):
        return False


def open_ports(
    host: str,
    ports: Optional[Iterable[int]] = None,
    *,
    timeout: float = 0.5,
    workers: int = 32,
    checker: Callable[[str, int, float], bool] = check_port,
) -> set[int]:
    """Return the subset of `ports` open on `host` (concurrent TCP connect-scan).

    `checker` is injectable so the dispatch logic can be tested without real sockets.
    """
    plist = list(ports if ports is not None else default_ports())
    if not plist:
        return set()
    found: set[int] = set()
    with ThreadPoolExecutor(max_workers=min(workers, len(plist))) as ex:
        results = ex.map(lambda p: checker(host, p, timeout), plist)
        for port, ok in zip(plist, results):
            if ok:
                found.add(port)
    return found


def should_run(engine_name: str, open_set: set[int]) -> bool:
    """Whether a port-gated engine should run given the host's open ports.

    Engines not in ENGINE_PORTS are never gated (return True) - unknown or UDP-only engines
    keep running so discovery never silently drops coverage it does not understand.
    """
    ports = ENGINE_PORTS.get(engine_name)
    if not ports:
        return True
    return any(p in open_set for p in ports)


def describe(open_set: set[int]) -> str:
    """Human-readable 'port(name)' list for a STATUS line."""
    if not open_set:
        return "none"
    return ", ".join(f"{p}({PORT_NAMES.get(p, '?')})" for p in sorted(open_set))
