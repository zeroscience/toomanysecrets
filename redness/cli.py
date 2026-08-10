"""REDNESS CLI entrypoint.

  python -m redness.cli demo --out report.docx     # end-to-end with sample data
  python -m redness.cli report findings.json --out report.docx
  python -m redness.cli doctor                       # what engines/tools are installed
  python -m redness.cli live                          # live 3D GUI
  python -m redness.cli scan --target 10.0.0.10 -u user -p pass --out report.docx
  python -m redness.cli scan --targets scope.txt --live
"""
from __future__ import annotations

import argparse
import sys

from .findings import Category, Evidence, Finding, Report, Severity
from .report import docx_report


def _print_summary(report: Report) -> None:
    counts = {s: len(v) for s, v in report.by_severity().items()}
    total = len(report.findings)
    print(f"\n[=] {total} finding(s) across {report.target or 'targets'}")
    for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        if counts[s]:
            print(f"    {s.value.upper():>8}: {counts[s]}")
    for f in report.sorted_findings():
        if f.category != Category.ENUM:
            print(f"    [{f.severity.value.upper()}] {f.title} -> {', '.join(f.affected) or '-'}")


def _sample_report() -> Report:
    """Realistic sample findings so the report pipeline runs without a live DC."""
    r = Report(engagement="ACME Internal AD Review", target="acme.local / 10.10.0.0/24")
    r.findings = [
        Finding(
            id="adcs-esc1",
            title="ADCS ESC1 — enrollee-supplied SAN on client-auth template",
            severity=Severity.CRITICAL,
            category=Category.ADCS,
            description="A certificate template permits low-privileged users to enroll and "
                        "supply an arbitrary Subject Alternative Name for a client-auth EKU.",
            impact="Any domain user can request a certificate impersonating Domain Admin and "
                   "authenticate as them — full domain compromise.",
            remediation="Remove ENROLLEE_SUPPLIES_SUBJECT from the template, restrict enrollment "
                        "permissions, and enable manager approval. Review with Certipy 'find'.",
            affected=["CA01.acme.local\\ACME-CA — Template: UserAuth"],
            evidence=[Evidence(source="certipy", detail="ESC1 vulnerable; EnrolleeSuppliesSubject=True")],
            references=["https://github.com/ly4k/Certipy"],
            credentialed=True,
        ),
        Finding(
            id="krb-asrep",
            title="AS-REP roastable accounts (Kerberos pre-auth disabled)",
            severity=Severity.HIGH,
            category=Category.KERBEROS,
            description="Accounts without Kerberos pre-authentication allow offline cracking of "
                        "their password hashes without any credentials.",
            impact="An unauthenticated attacker can retrieve and crack password hashes offline.",
            remediation="Enable 'Do not require Kerberos preauthentication' = off for all accounts; "
                        "enforce strong passwords.",
            affected=["svc-backup", "jdoe"],
            evidence=[Evidence(source="impacket.GetNPUsers", detail="2 AS-REP hashes retrieved")],
            references=["https://attack.mitre.org/techniques/T1558/004/"],
            credentialed=False,
        ),
        Finding(
            id="smb-signing-not-required",
            title="SMB signing not required",
            severity=Severity.MEDIUM,
            category=Category.SMB,
            description="Multiple hosts do not require SMB signing.",
            impact="Enables NTLM relay attacks across the network path.",
            remediation="Enforce SMB signing via GPO on all hosts, especially domain controllers.",
            affected=["10.10.0.15", "10.10.0.22", "10.10.0.30"],
            evidence=[Evidence(source="netexec", detail="signing:False on 3 hosts")],
            references=["https://attack.mitre.org/techniques/T1557/001/"],
            credentialed=False,
        ),
        Finding(
            id="tls-weak",
            title="Weak TLS configuration on LDAPS",
            severity=Severity.LOW,
            category=Category.TLS,
            description="LDAPS endpoint negotiates TLS 1.0 and offers CBC cipher suites.",
            impact="Deprecated protocols/ciphers are susceptible to known downgrade attacks.",
            remediation="Disable TLS 1.0/1.1, restrict to TLS 1.2+ with AEAD cipher suites.",
            affected=["DC01.acme.local:636"],
            evidence=[Evidence(source="tls-scan", detail="TLSv1.0 accepted; TLS_RSA_WITH_AES_128_CBC_SHA")],
            credentialed=False,
        ),
        Finding(
            id="enum-users",
            title="Domain users enumerated",
            severity=Severity.INFO,
            category=Category.ENUM,
            description="Full domain user list obtained via null LDAP bind.",
            affected=["Administrator", "jdoe", "svc-backup", "krbtgt", "guest"],
            evidence=[Evidence(source="netexec", detail="5 users via ldap --users")],
            credentialed=False,
        ),
    ]
    return r


def cmd_demo(args) -> int:
    report = _sample_report()
    docx_report.build(report, args.out)
    print(f"[+] Wrote sample report -> {args.out}")
    return 0


def cmd_report(args) -> int:
    with open(args.findings, encoding="utf-8") as fh:
        report = Report.from_json(fh.read())
    docx_report.build(report, args.out)
    print(f"[+] Wrote report -> {args.out}")
    return 0


def cmd_live(args) -> int:
    import threading
    import time
    import webbrowser

    from .events import default_bus
    from .live import LiveServer
    from .live import demo as live_demo
    from .scan import run_scan

    # Scan handler invoked when the GUI's "Start scan" button POSTs targets.
    def on_scan(params: dict) -> None:
        targets = [t.strip() for t in (params.get("targets") or []) if t and t.strip()]
        if not targets:
            return
        run_scan(
            targets,
            username=params.get("username") or None,
            password=params.get("password") or None,
            domain=params.get("domain") or None,
            bus=default_bus,
            engagement="REDNESS live scan",
        )

    server = LiveServer(default_bus, host=args.host, port=args.port, on_scan=on_scan)
    url = server.start()
    print(f"[+] Live graph at {url}")
    print("[*] Use the browser's 'New scan' panel to run against targets.")
    if not args.no_open:
        webbrowser.open(url)

    if args.demo:                     # opt-in simulated stream (no targets needed)
        def drive():
            time.sleep(1.5)
            while True:
                live_demo.run(default_bus)
                if not args.loop:
                    break
                time.sleep(2.0)
        threading.Thread(target=drive, daemon=True).start()
        print("[*] Streaming simulated enumeration (--demo).")

    print("[*] Ctrl+C to stop.")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] Stopping.")
        server.stop()
    return 0


def cmd_doctor(args) -> int:
    from .doctor import report_text
    print(report_text())
    return 0


def cmd_scan(args) -> int:
    import time
    import webbrowser

    from .events import default_bus
    from .scan import run_scan
    from .scope import merge_targets

    try:
        targets = merge_targets(args.target, args.targets)
    except OSError as e:
        print(f"[!] could not read scope file: {e}")
        return 2
    if not targets:
        print("[!] no targets — pass --target HOST and/or --targets scope.txt")
        return 2
    print(f"[*] {len(targets)} target(s): {', '.join(targets)}")

    bus = default_bus if args.live else None
    server = None
    if args.live:
        from .live import LiveServer
        server = LiveServer(bus, host=args.host, port=args.port)
        url = server.start()
        print(f"[+] Live graph at {url}")
        if not args.no_open:
            webbrowser.open(url)
        time.sleep(1.2)                       # let the browser connect before streaming

    report = run_scan(
        targets,
        username=args.username, password=args.password, nthash=args.hash,
        domain=args.domain, kerberos=args.kerberos, bus=bus,
        engagement=args.engagement,
    )

    # Hash loot + optional cracking (AS-REP / Kerberoast).
    from .crack import run_cracking
    crackres = run_cracking(report, loot_dir=args.loot_dir, wordlist=args.wordlist)
    if crackres.creds:
        print(f"[+] Captured {len(crackres.creds)} hash(es) -> {', '.join(crackres.loot_files)}")
        if args.wordlist:
            if not crackres.tool:
                print("[!] --wordlist set but no hashcat/john on PATH (hashes saved to loot).")
            elif crackres.cracked:
                print(f"[+] Cracked {len(crackres.cracked)} credential(s) via {crackres.tool}:")
                for c in crackres.cracked:
                    print(f"    {c.account}:{c.password}")
            else:
                print(f"[*] {crackres.tool} ran but cracked nothing with this wordlist.")

    _print_summary(report)

    if args.out:
        docx_report.build(report, args.out)
        print(f"[+] Report -> {args.out}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(report.to_json())
        print(f"[+] Findings JSON -> {args.json}")

    if server:
        print("[*] Live graph running. Ctrl+C to stop.")
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[*] Stopping.")
            server.stop()
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="redness", description="AD assessment orchestrator + reporter")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="render a sample .docx (no target needed)")
    d.add_argument("--out", default="report.docx")
    d.set_defaults(func=cmd_demo)

    rp = sub.add_parser("report", help="render a .docx from a findings.json")
    rp.add_argument("findings")
    rp.add_argument("--out", default="report.docx")
    rp.set_defaults(func=cmd_report)

    sub.add_parser("doctor", help="check which engines/tools are installed").set_defaults(func=cmd_doctor)

    lv = sub.add_parser("live", help="serve the live 3D graph (simulated enumeration)")
    lv.add_argument("--host", default="127.0.0.1")
    lv.add_argument("--port", type=int, default=8765)
    lv.add_argument("--no-open", action="store_true", help="don't auto-open a browser")
    lv.add_argument("--demo", action="store_true", help="stream simulated data (no targets needed)")
    lv.add_argument("--loop", action="store_true", help="with --demo: replay continuously")
    lv.set_defaults(func=cmd_live)

    sc = sub.add_parser("scan", help="run engines against targets -> report (+ optional live graph)")
    sc.add_argument("--target", help="single target: IP, hostname, or CIDR")
    sc.add_argument("--targets", help="scope file: one IP/hostname/CIDR per line (# comments ok)")
    sc.add_argument("-u", "--username")
    sc.add_argument("-p", "--password")
    sc.add_argument("-H", "--hash", help="NT hash for pass-the-hash (LM:NT or :NT)")
    sc.add_argument("-d", "--domain")
    sc.add_argument("-k", "--kerberos", action="store_true", help="use Kerberos auth")
    sc.add_argument("--engagement", default="REDNESS assessment")
    sc.add_argument("--wordlist", help="crack captured AS-REP/Kerberoast hashes (needs hashcat/john)")
    sc.add_argument("--loot-dir", default="loot", help="where to write captured hashes / cracked creds")
    sc.add_argument("--out", help="write a .docx report to this path")
    sc.add_argument("--json", help="write findings JSON to this path")
    sc.add_argument("--live", action="store_true", help="stream to the live 3D graph")
    sc.add_argument("--host", default="127.0.0.1", help="live graph bind host")
    sc.add_argument("--port", type=int, default=8765, help="live graph port")
    sc.add_argument("--no-open", action="store_true", help="don't auto-open the browser")
    sc.set_defaults(func=cmd_scan)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
