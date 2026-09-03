"""Simulated enumeration that drives the EventBus so the live graph animates.

No DC/tools needed: this replays a realistic AD sweep (hosts, users, shares, ADCS,
attack paths) as a timed stream of events, exactly the shape real engines emit. Lets you
see the 3D graph build and light up before any GUI phase is committed.
"""
from __future__ import annotations

import random
import time

from ..events import Event, EventBus, EventKind
from ..findings import Category, Finding, Severity


def _emit(bus: EventBus, kind: EventKind, engine: str = "demo", **data) -> None:
    bus.publish(Event(kind=kind, data=data, engine=engine))


def _finding(bus: EventBus, **kw) -> None:
    f = Finding(**kw)
    _emit(bus, EventKind.FINDING, finding=f.to_dict())


def simulate_action(bus: EventBus, params: dict) -> None:
    """Simulate what a right-click enum discovers, so the demo shows a NEW node pop up (+ flash).

    What legitimately makes a new node appear within the already-scanned scope? A real SMB
    enumeration of a host reveals: readable **shares** on that host, and - via active
    **sessions** - a logged-on **user** and the **workstation** that user is logged into (a
    host we hadn't touched yet, still inside the engagement scope). That is the honest source
    of a "new" node, and what we simulate here.
    """
    action = (params.get("action") or "").strip()
    target = (params.get("target") or "").strip()
    if not target:
        return
    _emit(bus, EventKind.STATUS, message=f"{action}: probing {target}")
    time.sleep(0.6)

    if action == "enum-smb":
        for share in ("backups$", "IT-scripts"):        # readable shares on the host
            sid = f"\\\\{target}\\{share}"
            _emit(bus, EventKind.NODE, id=sid, label=share, type="share")
            _emit(bus, EventKind.EDGE, src=target, dst=sid, label="share")
            time.sleep(0.45)
        _finding(bus, id="smb-writable-share", title="Writable non-default SMB share",
                 severity=Severity.HIGH, category=Category.SMB,
                 affected=[f"\\\\{target}\\backups$"], credentialed=True)
        time.sleep(0.4)
        # an active session -> a logged-on user + the workstation they came from (new in-scope host)
        user = random.choice(["svc-sql", "helpdesk", "adm.blake", "backup-op"])
        _emit(bus, EventKind.NODE, id=user, label=user, type="user")
        _emit(bus, EventKind.EDGE, src=target, dst=user, label="session")
        time.sleep(0.45)
        ws = f"10.10.0.{random.randint(40, 99)}"
        _emit(bus, EventKind.NODE, id=ws, label=f"WS ({ws})", type="host")
        _emit(bus, EventKind.EDGE, src=user, dst=ws, label="logged-on")
        _emit(bus, EventKind.STATUS,
              message=f"enum-smb: 2 shares, session {user} -> new host {ws} (in scope)")
    else:
        # other enum actions reveal one related detail node so the flash is still demoed
        label = action.replace("enum-", "").upper() or "detail"
        rid = f"{target} :: {label}"
        _emit(bus, EventKind.NODE, id=rid, label=label, type="host")
        _emit(bus, EventKind.EDGE, src=target, dst=rid, label=action.replace("enum-", ""))
        _emit(bus, EventKind.STATUS, message=f"{action}: enumerated {target}")


def run(bus: EventBus, step: float = 0.45) -> None:
    """Drive one full simulated enumeration onto `bus`. Blocks ~10-12s."""
    def pause():
        time.sleep(step)

    domain = "acme.local"
    _emit(bus, EventKind.STATUS, message="Starting assessment of acme.local")
    _emit(bus, EventKind.NODE, id=domain, label=domain, type="domain")
    pause()

    # --- SMB sweep --------------------------------------------------------- #
    hosts = [("DC01", "10.10.0.15"), ("FS01", "10.10.0.22"), ("WS01", "10.10.0.30")]
    _emit(bus, EventKind.STATUS, message="netexec: SMB sweep")
    for name, ip in hosts:
        _emit(bus, EventKind.NODE, id=ip, label=f"{name} ({ip})", type="host")
        _emit(bus, EventKind.EDGE, src=domain, dst=ip, label="host")
        _emit(bus, EventKind.PROBE, target=ip, test="smb")
        pause()

    _finding(bus, id="smb-signing-not-required", title="SMB signing not required",
             severity=Severity.MEDIUM, category=Category.SMB,
             affected=["10.10.0.15", "10.10.0.30"], credentialed=False)
    _emit(bus, EventKind.STATUS, message="[MEDIUM] SMB signing not required (2 hosts)")
    pause()
    _finding(bus, id="smbv1-enabled", title="SMBv1 enabled",
             severity=Severity.HIGH, category=Category.SMB, affected=["10.10.0.15"])
    _emit(bus, EventKind.STATUS, message="[HIGH] SMBv1 enabled on DC01")
    pause()

    # --- LDAP users -------------------------------------------------------- #
    _emit(bus, EventKind.STATUS, message="ldap: enumerating users")
    users = ["Administrator", "jdoe", "svc-backup"]
    for u in users:
        _emit(bus, EventKind.NODE, id=u, label=u, type="user")
        _emit(bus, EventKind.EDGE, src=domain, dst=u, label="user")
        _emit(bus, EventKind.PROBE, target=u, test="kerberos")
        pause()
    _finding(bus, id="krb-asrep-roastable", title="AS-REP roastable accounts",
             severity=Severity.HIGH, category=Category.KERBEROS,
             affected=["svc-backup", "jdoe"], credentialed=False)
    _emit(bus, EventKind.STATUS, message="[HIGH] AS-REP roastable: svc-backup, jdoe")
    pause()

    # --- Shares ------------------------------------------------------------ #
    _emit(bus, EventKind.NODE, id="10.10.0.22\\backups", label="backups (RW)", type="share")
    _emit(bus, EventKind.EDGE, src="10.10.0.22", dst="10.10.0.22\\backups", label="share")
    _emit(bus, EventKind.PROBE, target="10.10.0.22\\backups", test="shares")
    pause()
    _finding(bus, id="smb-writable-share", title="Writable non-default SMB share",
             severity=Severity.HIGH, category=Category.SMB,
             affected=["10.10.0.22\\backups"], credentialed=True)
    _emit(bus, EventKind.STATUS, message="[HIGH] Writable share FS01\\backups")
    pause()

    # --- ADCS -------------------------------------------------------------- #
    _emit(bus, EventKind.STATUS, message="certipy: AD CS enumeration")
    _emit(bus, EventKind.NODE, id="ACME-CA", label="ACME-CA", type="ca")
    _emit(bus, EventKind.EDGE, src=domain, dst="ACME-CA", label="ca")
    _emit(bus, EventKind.NODE, id="UserAuth", label="UserAuth (template)", type="template")
    _emit(bus, EventKind.EDGE, src="ACME-CA", dst="UserAuth", label="template")
    _emit(bus, EventKind.PROBE, target="UserAuth", test="adcs-esc")
    pause()
    _finding(bus, id="adcs-esc1", title="AD CS ESC1: enrollee-supplied SAN",
             severity=Severity.CRITICAL, category=Category.ADCS,
             affected=["UserAuth"], credentialed=True, meta={"esc": 1},
             impact="Any user can obtain a cert impersonating Domain Admin.")
    _emit(bus, EventKind.STATUS, message="[CRITICAL] AD CS ESC1 on UserAuth: domain compromise")
    pause()

    # svc-backup's roasted hash cracks with a weak password, so we now own it.
    _finding(bus, id="credential-cracked", title="Password recovered for svc-backup",
             severity=Severity.CRITICAL, category=Category.KERBEROS,
             affected=["svc-backup"], credentialed=True,
             meta={"account": "svc-backup", "password": "Summer2024!"})
    _emit(bus, EventKind.STATUS, message="[CRITICAL] Cracked svc-backup:Summer2024!")
    pause()

    # Derive and light up the attack paths implied by those findings.
    from ..findings import Report
    from ..paths import emit_attack_paths
    report = Report(engagement="demo", target=domain)
    report.findings = [
        Finding(id="krb-asrep-roastable", title="AS-REP roastable", severity=Severity.HIGH,
                category=Category.KERBEROS, affected=["svc-backup", "jdoe"]),
        Finding(id="credential-cracked", title="cracked", severity=Severity.CRITICAL,
                category=Category.KERBEROS, affected=["svc-backup"],
                meta={"account": "svc-backup"}),
        Finding(id="adcs-esc1", title="ESC1", severity=Severity.CRITICAL,
                category=Category.ADCS, affected=["UserAuth"], meta={"esc": 1}),
    ]
    emit_attack_paths(bus, report, domain)
    pause()

    _emit(bus, EventKind.DONE, engine="demo")
    _emit(bus, EventKind.STATUS, message="Assessment complete: 6 findings, attack paths mapped")
