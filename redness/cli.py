"""REDNESS CLI entrypoint.

  python -m redness.cli demo --out report.docx     # end-to-end with sample data
  python -m redness.cli report findings.json --out report.docx
  python -m redness.cli doctor                       # what engines/tools are installed
  python -m redness.cli live                          # live 3D GUI
  python -m redness.cli scan --target 10.0.0.10 -u user -p pass --out report.docx
  python -m redness.cli scan --targets examples/scope.txt --live
"""
from __future__ import annotations

import argparse
import sys

from . import trigger
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


def _report_crack(crackres, *, wordlist) -> None:
    """Print captured-hash + cracking results for scan/poison (shared, kept in sync)."""
    if not crackres.creds:
        return
    print(f"[+] Captured {len(crackres.creds)} hash(es) -> {', '.join(crackres.loot_files)}")
    if crackres.cracked:
        src = "built-in wordlist" if crackres.used_builtin else (wordlist or "wordlist")
        print(f"[+] Cracked {len(crackres.cracked)} credential(s) via {crackres.tool} ({src}):")
        for c in crackres.cracked:
            print(f"    {c.account}:{c.password}")
    elif crackres.tool or crackres.used_builtin:
        which = "built-in wordlist" if crackres.used_builtin else "this wordlist"
        print(f"[*] {crackres.tool or 'cracker'} ran but cracked nothing with {which}.")
    elif wordlist:
        print("[!] --wordlist set but no hashcat/john on PATH (hashes saved to loot).")


def _sample_report() -> Report:
    """Realistic sample findings so the report pipeline runs without a live DC."""
    r = Report(engagement="ACME Internal AD Review", target="acme.local / 10.10.0.0/24")
    r.findings = [
        Finding(
            id="adcs-esc1",
            title="ADCS ESC1 - enrollee-supplied SAN on client-auth template",
            severity=Severity.CRITICAL,
            category=Category.ADCS,
            description="A certificate template permits low-privileged users to enroll and "
                        "supply an arbitrary Subject Alternative Name for a client-auth EKU.",
            impact="Any domain user can request a certificate impersonating Domain Admin and "
                   "authenticate as them - full domain compromise.",
            remediation="Remove ENROLLEE_SUPPLIES_SUBJECT from the template, restrict enrollment "
                        "permissions, and enable manager approval. Review with Certipy 'find'.",
            affected=["CA01.acme.local\\ACME-CA - Template: UserAuth"],
            evidence=[Evidence(source="certipy", detail="ESC1 vulnerable; EnrolleeSuppliesSubject=True")],
            references=["https://github.com/ly4k/Certipy"],
            credentialed=True,
            meta={"esc": 1},
        ),
        Finding(
            id="credential-cracked",
            title="Password recovered for svc-backup",
            severity=Severity.CRITICAL,
            category=Category.KERBEROS,
            description="The AS-REP hash for 'svc-backup' was cracked offline.",
            impact="A recovered password is a valid domain credential enabling authenticated "
                   "access and further compromise.",
            remediation="Reset the account password immediately; enforce a strong password policy.",
            affected=["svc-backup"],
            evidence=[Evidence(source="crack/hashcat", detail="svc-backup:Summer2024!")],
            credentialed=True,
            meta={"account": "svc-backup", "password": "Summer2024!", "hash_type": "krb5asrep"},
        ),
        Finding(
            id="krb-asrep-roastable",
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


def cmd_diff(args) -> int:
    from .diff import diff_reports

    with open(args.baseline, encoding="utf-8") as fh:
        baseline = Report.from_json(fh.read())
    with open(args.current, encoding="utf-8") as fh:
        current = Report.from_json(fh.read())
    result = diff_reports(baseline, current)
    print(result.to_text())
    if args.json:
        import json
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result.to_dict(), fh, indent=2)
        print(f"\n[+] Wrote diff JSON -> {args.json}")
    # Non-zero exit on a regression so retests can gate CI / scripts.
    return 2 if result.regressed() else 0


def cmd_live(args) -> int:
    import threading
    import time
    import webbrowser

    from .events import default_bus
    from .live import demo as live_demo

    server = _live_server(default_bus, args.host, args.port,
                          enable_offensive=getattr(args, "enable_offensive", False),
                          demo=args.demo)
    url = server.start()
    print(f"[+] Live graph at {url}")
    print("[*] Use the 'New scan' panel, or right-click a node for enum actions.")
    _print_offensive_banner(server)
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


def _live_scan_handler(bus):
    """Scan handler for the GUI's 'Start scan' button (shared by live/gui)."""
    from .scan import run_scan

    def on_scan(params: dict) -> None:
        targets = [t.strip() for t in (params.get("targets") or []) if t and t.strip()]
        if not targets:
            return
        run_scan(targets, username=params.get("username") or None,
                 password=params.get("password") or None,
                 domain=params.get("domain") or None,
                 bus=bus, engagement="REDNESS live scan")
    return on_scan


def _live_action_handler(bus):
    """Right-click action handler (POST /action) - runs one engine against one target."""
    from .actions import run_action

    def on_action(params: dict) -> None:
        action = params.get("action")
        target = (params.get("target") or "").strip()
        if not action or not target:
            return
        run_action(action, target, username=params.get("username") or None,
                   password=params.get("password") or None,
                   domain=params.get("domain") or None, bus=bus)
    return on_action


def _live_offensive_handlers(bus):
    """Arm/execute handlers for the gated offensive /action channel (only wired when enabled).

    `on_arm` issues a single-use arm_token (raises ArmError -> the bridge maps to 4xx). `on_execute`
    runs the armed action against a Target built from the posted creds; `target` is the principal
    (a user node) while `host` is the box to connect to (the DC), defaulting to domain/target.
    """
    from .actions import arm, execute_armed_action
    from .engines.base import Target

    def on_arm(params: dict) -> dict:
        return arm((params.get("action") or "").strip(), (params.get("target") or "").strip())

    def on_execute(params: dict) -> None:
        action = (params.get("action") or "").strip()
        target = (params.get("target") or "").strip()
        if not action or not target:
            return
        tgt = Target(host=(params.get("host") or params.get("domain") or target),
                     username=params.get("username") or None,
                     password=params.get("password") or None,
                     nthash=params.get("hash") or None,
                     domain=params.get("domain") or None)
        execute_armed_action(action, target, tgt, arm_token=params.get("arm_token") or "",
                             confirm=params.get("confirm") or "", bus=bus)
    return on_arm, on_execute


def _live_server(bus, host, port, enable_offensive=False, demo=False):
    """LiveServer wired with the scan + action handlers and the action catalog.

    In `demo` mode a right-click action is served by the simulator (so it discovers new nodes
    with no tools installed) instead of the real engine runner.
    """
    from .actions import catalog
    from .live import LiveServer
    if demo:
        from .live import demo as live_demo
        on_action = lambda p: live_demo.simulate_action(bus, p)   # noqa: E731
    else:
        on_action = _live_action_handler(bus)
    on_arm, on_execute = _live_offensive_handlers(bus) if enable_offensive else (None, None)
    return LiveServer(bus, host=host, port=port,
                      on_scan=_live_scan_handler(bus),
                      on_action=on_action,
                      action_catalog=catalog(),
                      on_arm=on_arm, on_execute=on_execute,
                      enable_offensive=enable_offensive)


def _print_offensive_banner(server) -> None:
    """Print the console-only offensive token (never embedded in the page) if enabled."""
    if getattr(server, "offensive_enabled", False):
        print("\n[!] OFFENSIVE CHANNEL ENABLED - kerberoast / secretsdump / dcsync are unlocked.",
              file=sys.stderr)
        print("[!] Every arm/execute is audited to loot/.", file=sys.stderr)
        print(f"[!] Offensive token (paste into the GUI to unlock these actions): {server.offensive_token}\n",
              file=sys.stderr)


def cmd_gui(args) -> int:
    """Native desktop window (pywebview) around the live GUI; falls back to a browser."""
    import time

    from .events import default_bus

    server = _live_server(default_bus, args.host, args.port,
                          enable_offensive=getattr(args, "enable_offensive", False))
    url = server.start()
    print(f"[+] REDNESS GUI at {url}")
    _print_offensive_banner(server)
    try:
        import webview                                    # pywebview
        webview.create_window("REDNESS · Zero Science Lab", url, width=1360, height=900)
        webview.start()                                   # blocks until the window closes
    except ImportError:
        import webbrowser
        print("[!] pywebview not installed - opening in your browser instead.")
        print('    For a native window:  pip install ".[gui]"   (or: pip install pywebview)')
        webbrowser.open(url)
        print("[*] Ctrl+C to stop.")
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
    server.stop()
    return 0


def cmd_scan(args) -> int:
    import time
    import webbrowser

    from .events import default_bus
    from .scan import default_engines, run_scan
    from .scope import merge_targets

    try:
        targets = merge_targets(args.target, args.targets)
    except OSError as e:
        print(f"[!] could not read scope file: {e}")
        return 2
    if not targets:
        print("[!] no targets - pass --target HOST and/or --targets examples/scope.txt")
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

    engines = default_engines()
    if args.hunt_secrets or args.hunt_content:   # opt-in: spider shares for secrets (needs nxc)
        from .engines.sharehunt import SecretHuntEngine
        engines.append(SecretHuntEngine(content=args.hunt_content, loot_dir=args.loot_dir))

    report = run_scan(
        targets,
        username=args.username, password=args.password, nthash=args.hash,
        domain=args.domain, kerberos=args.kerberos, bus=bus,
        engagement=args.engagement, engines=engines,
        discover=not args.no_discovery, listen_secs=args.listen,
    )

    # Hash loot + optional cracking (AS-REP / Kerberoast). --no-crack hard-disables all
    # cracking (forces no wordlist AND no built-in fallback); otherwise the built-in list
    # auto-cracks when no --wordlist is given and a cracker is on PATH.
    from .crack import run_cracking
    wl = None if args.no_crack else args.wordlist
    crackres = run_cracking(report, loot_dir=args.loot_dir, wordlist=wl, builtin=not args.no_crack)
    _report_crack(crackres, wordlist=wl)

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


_SPRAY_BANNER = (
    "\n=====================================================================\n"
    " REDNESS spray - password spraying (INTRUSIVE)\n"
    " Spraying CAN LOCK OUT ACCOUNTS (a denial of service against the\n"
    " client) and is loud to a SOC. Lockout-aware, but know the account\n"
    " lockout policy before you run it.\n"
    "=====================================================================\n"
)


def cmd_spray(args) -> int:
    import shutil
    import time
    import webbrowser

    from .spray import run_spray

    # safeguard: the danger banner ALWAYS prints (to stderr), even in scripted --yes/--force mode.
    print(_SPRAY_BANNER, file=sys.stderr)

    if not (shutil.which("nxc") or shutil.which("netexec")):
        print("[!] nxc (NetExec) is not installed / not on PATH.", file=sys.stderr)
        print("    Install on the Kali/Linux operator box:  pipx install netexec", file=sys.stderr)
        return 2

    credentialed = bool(args.auth_user and (args.auth_pass or args.auth_hash or args.kerberos))
    if not credentialed:
        # The single most dangerous path: the lockout policy cannot be read.
        print("[!!] ---------------------------------------------------------------", file=sys.stderr)
        print("[!!] UNCREDENTIALED SPRAY: the domain account-lockout policy is UNKNOWN.", file=sys.stderr)
        print("[!!] This CAN LOCK OUT EVERY ACCOUNT it touches (a DoS on the client).", file=sys.stderr)
        print("[!!] Requires --user-file AND --force, AND a typed FORCE confirmation.", file=sys.stderr)
        print("[!!] ---------------------------------------------------------------", file=sys.stderr)
        if not args.user_file:
            print("[*] Aborted: --user-file is required for an uncredentialed spray.", file=sys.stderr)
            return 2
        if not args.force:
            print("[*] Aborted: --force is required for an uncredentialed spray.", file=sys.stderr)
            return 2

    where = f"--user-file {args.user_file}" if args.user_file else "auto-enumerated users"
    print(f"[*] Target {args.target}; spraying 1 password across {where}.")

    # Normal consent prompt (skipped only by --yes).
    if not args.yes:
        try:
            if input(f"    Type YES to spray {args.target} with 1 password: ").strip() != "YES":
                print("[*] Aborted.")
                return 1
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Aborted.")
            return 1

    # safeguard: forcing past a safety refusal needs a SECOND, distinct FORCE confirmation that
    # --yes never skips - so --force + --yes together can never silently bypass both checks.
    def _force_prompt(reason: str) -> bool:
        label = {"unknown-policy": "the account-lockout policy is UNKNOWN",
                 "lockout-risk": "the lockout threshold is too low to spray safely"}.get(reason, reason)
        print(f"\n[!!] SAFETY OVERRIDE: {label}.", file=sys.stderr)
        print("[!!] Proceeding MAY LOCK OUT ACCOUNTS (a DoS against the client).", file=sys.stderr)
        try:
            return input("    Type FORCE to override and risk account lockout: ").strip() == "FORCE"
        except (EOFError, KeyboardInterrupt):
            return False

    bus = None
    server = None
    if args.live:
        from .events import default_bus
        from .live import LiveServer
        bus = default_bus
        server = LiveServer(bus, host=args.host, port=args.port)
        url = server.start()
        print(f"[+] Live graph at {url}")
        if not args.no_open:
            webbrowser.open(url)
        time.sleep(1.2)

    report, res = run_spray(
        args.target, args.password,
        username=args.auth_user, auth_password=args.auth_pass, nthash=args.auth_hash,
        domain=args.domain, kerberos=args.kerberos, user_file=args.user_file,
        margin=args.margin, force=args.force, confirm_force=_force_prompt,
        bus=bus, engagement=args.engagement, loot_dir=args.loot_dir,
    )

    if res.refused:
        reasons = {
            "unknown-policy": "lockout policy unknown (uncredentialed) and not force-confirmed",
            "lockout-risk": "lockout threshold too low and not force-confirmed",
            "no-users": "no user list to spray (need --user-file)",
        }
        print(f"[*] Spray refused: {reasons.get(res.reason, res.reason)}.", file=sys.stderr)
    elif res.hits:
        print(f"[+] {len(res.hits)} valid credential(s) from {res.tested} account(s):")
        for h in res.hits:
            print(f"    {h.username}:{h.password}" + ("  (Pwn3d!)" if h.admin else ""))
    else:
        print(f"[*] No valid credentials from {res.tested} account(s) with this password.")

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


_POISON_BANNER = (
    "\n=====================================================================\n"
    " REDNESS poison - LLMNR/NBT-NS/mDNS poisoning (NetNTLMv2 capture)\n"
    " INTRUSIVE: affects OTHER hosts on the local segment.\n"
    "=====================================================================\n"
)


def cmd_poison(args) -> int:
    import time
    import webbrowser

    from .engines.responder import is_available
    from .poison import run_poison

    print(_POISON_BANNER)
    if args.analyze:
        print(f"[*] Analyze mode: passively observing '{args.iface}' - no poisoning.")
    else:
        print(f"[!] This ACTIVELY POISONS name resolution on '{args.iface}' and coerces")
        print("    authentication from other hosts on this segment.")

    if not is_available():
        print("[!] Responder is not installed / not on PATH.")
        print("    Install it on the Kali/Linux operator box:  sudo apt install responder")
        print("    (or from https://github.com/lgandx/Responder)")
        return 2

    if not args.yes:
        verb = "observe" if args.analyze else "poison"
        resp = input(f"    Type YES to {verb} {args.iface} for {args.duration}s: ").strip()
        if resp != "YES":
            print("[*] Aborted.")
            return 1

    bus = None
    server = None
    if args.live:
        from .events import default_bus
        from .live import LiveServer
        bus = default_bus
        server = LiveServer(bus, host=args.host, port=args.port)
        url = server.start()
        print(f"[+] Live graph at {url}")
        if not args.no_open:
            webbrowser.open(url)
        time.sleep(1.2)                       # let the browser connect before streaming

    print(f"[*] Running Responder on {args.iface} for {args.duration}s (Ctrl+C to stop early)...")
    wl = None if args.no_crack else args.wordlist
    report, crackres = run_poison(
        args.iface, duration=args.duration, analyze=args.analyze, bus=bus,
        engagement=args.engagement, loot_dir=args.loot_dir, wordlist=wl,
        builtin=not args.no_crack,
    )

    _report_crack(crackres, wordlist=wl)
    if not crackres.creds:
        print("[*] No NetNTLMv2 hashes captured in this window.")

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


_COERCE_BANNER = (
    "\n=====================================================================\n"
    " REDNESS coerce - active RPC forced authentication (PetitPotam/\n"
    " PrinterBug/DFSCoerce). INTRUSIVE: actively coerces a TARGET machine\n"
    " (often a DC) into authenticating to your listener; the target WILL\n"
    " log the authentication/RPC event.\n"
    "=====================================================================\n"
)


def cmd_coerce(args) -> int:
    import shutil
    import time
    import webbrowser

    from .coerce import run_coerce

    # safeguard (like spray): the danger banner ALWAYS prints (to stderr), even scripted.
    print(_COERCE_BANNER, file=sys.stderr)

    if not (shutil.which("nxc") or shutil.which("netexec")):
        print("[!] nxc (NetExec) is not installed / not on PATH.", file=sys.stderr)
        print("    Install on the Kali/Linux operator box:  pipx install netexec", file=sys.stderr)
        return 2

    # Warning-only pre-flight: we cannot reliably verify a listener on another machine.
    print(f"[!] A listener MUST already be running at {args.listener} to CAPTURE the coerced")
    print("    authentication - run `redness poison` there first. This command only TRIGGERS it.")

    credentialed = bool(args.username and (args.password or args.hash or args.kerberos))
    if not credentialed:
        print("[!!] ---------------------------------------------------------------", file=sys.stderr)
        print("[!!] UNCREDENTIALED COERCION: relies on an unpatched target; less", file=sys.stderr)
        print("[!!] reliable and the patch state is unknown. Requires --force AND a", file=sys.stderr)
        print("[!!] typed FORCE confirmation.", file=sys.stderr)
        print("[!!] ---------------------------------------------------------------", file=sys.stderr)
        if not args.force:
            print("[*] Aborted: --force is required for an uncredentialed coercion.", file=sys.stderr)
            return 2

    print(f"[*] Target {args.target}; coercing via {args.method} -> {args.listener}.")

    # Normal consent prompt (skipped only by --yes).
    if not args.yes:
        try:
            if input(f"    Type YES to coerce {args.target} to authenticate to {args.listener}: "
                     ).strip() != "YES":
                print("[*] Aborted.")
                return 1
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Aborted.")
            return 1

    # safeguard: forcing past the uncredentialed refusal needs a SECOND, distinct FORCE
    # confirmation that --yes never skips - so --force + --yes can never bypass both checks.
    def _force_prompt(reason: str) -> bool:
        label = {"uncredentialed": "coercion will run UNAUTHENTICATED against a possibly-patched "
                                   "target"}.get(reason, reason)
        print(f"\n[!!] SAFETY OVERRIDE: {label}.", file=sys.stderr)
        try:
            return input("    Type FORCE to override and run the coercion: ").strip() == "FORCE"
        except (EOFError, KeyboardInterrupt):
            return False

    bus = None
    server = None
    if args.live:
        from .events import default_bus
        from .live import LiveServer
        bus = default_bus
        server = LiveServer(bus, host=args.host, port=args.port)
        url = server.start()
        print(f"[+] Live graph at {url}")
        if not args.no_open:
            webbrowser.open(url)
        time.sleep(1.2)

    report, res = run_coerce(
        args.target, args.listener, method=args.method,
        username=args.username, password=args.password, nthash=args.hash,
        domain=args.domain, kerberos=args.kerberos,
        target_not_dc_ok=args.target_not_dc_ok, force=args.force, confirm_force=_force_prompt,
        bus=bus, engagement=args.engagement, loot_dir=args.loot_dir,
    )

    if res.refused:
        reasons = {
            "uncredentialed": "uncredentialed and not force-confirmed",
            "not-a-dc": f"{args.target} does not look like a Domain Controller (no LDAP) - "
                        "pass --target-not-dc-ok to allow",
        }
        print(f"[*] Coercion refused: {reasons.get(res.reason, res.reason)}.", file=sys.stderr)
    else:
        coerced = [r.method for r in res.results if r.coerced]
        if coerced:
            print(f"[+] {args.target} coerced via: {', '.join(coerced)}"
                  + (" (Domain Controller)" if res.is_dc else ""))
            print(f"[*] Check the `redness poison` listener at {args.listener} for the captured hash.")
        else:
            print(f"[*] {args.target} did not authenticate to the listener via any method tried.")

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


_TRIGGER_BANNER = (
    "\n=====================================================================\n"
    " REDNESS trigger - forced-authentication UNC link (NetNTLMv2 capture)\n"
    " The artifact coerces a victim's credentials when opened.\n"
    "=====================================================================\n"
)


def cmd_listen(args) -> int:
    """Passive link-local discovery: listen for mDNS/LLMNR/NBT-NS/SSDP announcements."""
    import time
    import webbrowser

    from .mcast import listen

    print("[*] REDNESS link-local discovery (passive listen).")
    if args.active:
        print("[*] --active: will also send a single SSDP M-SEARCH to solicit UPnP replies.")

    bus = None
    server = None
    if args.live:
        from .events import default_bus
        from .live import LiveServer
        bus = default_bus
        server = LiveServer(bus, host=args.host, port=args.port)
        url = server.start()
        print(f"[+] Live graph at {url}")
        if not args.no_open:
            webbrowser.open(url)
        time.sleep(1.0)

    report, _announces = listen(args.duration, active=args.active, bus=bus)
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


def cmd_trigger(args) -> int:
    # Generator output goes to stdout so it can be redirected cleanly
    # (`redness trigger --host X > lure.html`); the banner + operator hints go to stderr.
    print(_TRIGGER_BANNER, file=sys.stderr)

    content = trigger.generate(args.format, args.host, share=args.share, filename=args.filename)
    unc = trigger.unc_path(args.host, args.share, args.filename)
    _ext = trigger.FORMATS[args.format][1]

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"[+] Wrote {args.format} trigger -> {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(content)
        print(f"[*] {args.format} trigger written to stdout "
              f"(suggested filename: lure{_ext})", file=sys.stderr)

    print(f"[*] Embedded UNC path: {unc}", file=sys.stderr)
    print("[*] Run `redness poison` on the capture host to catch the NetNTLMv2 auth; "
          "check the victim's SMB signing via `redness scan`.", file=sys.stderr)
    return 0


def cmd_bloodhound(args) -> int:
    import time
    import webbrowser

    from .bloodhound import emit_bloodhound, load_collection
    from .events import default_bus

    try:
        collection = load_collection(args.path)
    except (OSError, ValueError) as e:
        print(f"[!] could not load BloodHound collection: {e}")
        return 2
    total = sum(len(v) for v in collection.values())
    summary = ", ".join(f"{k}={len(v)}" for k, v in collection.items()) or "none"
    print(f"[*] Loaded {total} object(s): {summary}")

    bus = server = None
    if args.live:
        from .live import LiveServer
        bus = default_bus
        server = LiveServer(bus, host=args.host, port=args.port)
        url = server.start()
        print(f"[+] Live graph at {url}")
        if not args.no_open:
            webbrowser.open(url)
        time.sleep(1.2)

    g = emit_bloodhound(bus, collection)
    print(f"[+] {len(g.nodes)} node(s), {len(g.edges)} relationship(s)")

    if server:
        print("[*] Live graph running. Ctrl+C to stop.")
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
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

    df = sub.add_parser("diff", help="retest diff: compare a baseline findings.json to a current one")
    df.add_argument("baseline", help="prior scan findings.json")
    df.add_argument("current", help="current scan findings.json")
    df.add_argument("--json", help="write the classified diff to this path")
    df.set_defaults(func=cmd_diff)

    sub.add_parser("doctor", help="check which engines/tools are installed").set_defaults(func=cmd_doctor)

    g = sub.add_parser("gui", help="native desktop window (pywebview; falls back to browser)")
    g.add_argument("--host", default="127.0.0.1")
    g.add_argument("--port", type=int, default=8765)
    g.add_argument("--enable-offensive", action="store_true",
                   help="unlock the gated offensive right-click actions (kerberoast/secretsdump/"
                        "dcsync); prints a separate console token you paste into the GUI. Loopback only")
    g.set_defaults(func=cmd_gui)

    lv = sub.add_parser("live", help="serve the live 3D graph (simulated enumeration)")
    lv.add_argument("--host", default="127.0.0.1")
    lv.add_argument("--port", type=int, default=8765)
    lv.add_argument("--enable-offensive", action="store_true",
                    help="unlock the gated offensive right-click actions (loopback only; "
                         "prints a separate console token to paste into the GUI)")
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
    sc.add_argument("--no-crack", action="store_true",
                    help="skip cracking entirely (just write loot); overrides --wordlist and the built-in list")
    sc.add_argument("--hunt-secrets", action="store_true",
                    help="spider readable SMB shares for secrets (Snaffler-style; needs nxc; opt-in)")
    sc.add_argument("--hunt-content", action="store_true",
                    help="also download candidates and scan file contents (Phase 2; more intrusive; implies --hunt-secrets)")
    sc.add_argument("--no-discovery", action="store_true",
                    help="run every available engine on every host (skip the TCP service "
                         "connect-scan that otherwise dispatches only relevant engines)")
    sc.add_argument("--listen", type=int, default=0, metavar="SECONDS",
                    help="also run a passive link-local sweep for N seconds; its poisonable "
                         "LLMNR/NBT-NS findings feed the relay map (poison -> relay -> target)")
    sc.add_argument("--loot-dir", default="loot", help="where to write captured hashes / cracked creds")
    sc.add_argument("--out", help="write a .docx report to this path")
    sc.add_argument("--json", help="write findings JSON to this path")
    sc.add_argument("--live", action="store_true", help="stream to the live 3D graph")
    sc.add_argument("--host", default="127.0.0.1", help="live graph bind host")
    sc.add_argument("--port", type=int, default=8765, help="live graph port")
    sc.add_argument("--no-open", action="store_true", help="don't auto-open the browser")
    sc.set_defaults(func=cmd_scan)

    po = sub.add_parser("poison",
                        help="LLMNR/NBT-NS poisoning to capture NetNTLMv2 (intrusive; opt-in)")
    po.add_argument("--iface", required=True, help="interface to listen/poison on (e.g. eth0)")
    po.add_argument("--duration", type=int, default=600, help="seconds to run (default 600)")
    po.add_argument("--analyze", action="store_true",
                    help="passive observe only (responder -A); no poisoning")
    po.add_argument("--yes", action="store_true", help="skip the confirmation prompt (scripted use)")
    po.add_argument("--engagement", default="REDNESS NetNTLMv2 capture")
    po.add_argument("--wordlist", help="crack captured NetNTLMv2 hashes (needs hashcat/john)")
    po.add_argument("--no-crack", action="store_true",
                    help="skip cracking entirely (just write loot); overrides --wordlist and the built-in list")
    po.add_argument("--loot-dir", default="loot", help="where to write captured hashes / cracked creds")
    po.add_argument("--out", help="write a .docx report to this path")
    po.add_argument("--json", help="write findings JSON to this path")
    po.add_argument("--live", action="store_true", help="stream to the live 3D graph")
    po.add_argument("--host", default="127.0.0.1", help="live graph bind host")
    po.add_argument("--port", type=int, default=8765, help="live graph port")
    po.add_argument("--no-open", action="store_true", help="don't auto-open the browser")
    po.set_defaults(func=cmd_poison)

    sp = sub.add_parser("spray",
                        help="lockout-aware password spraying (intrusive; opt-in, gated)")
    sp.add_argument("--target", required=True, help="domain controller / host to spray against")
    sp.add_argument("-p", "--password", required=True, help="the single password to spray")
    sp.add_argument("--user-file", help="file of usernames to spray (required if uncredentialed; "
                    "else auto-enumerated via nxc ldap --users)")
    sp.add_argument("--auth-user", help="tester username to read pass-pol + enumerate users")
    sp.add_argument("--auth-pass", help="tester password (for recon)")
    sp.add_argument("--auth-hash", help="tester NT hash for pass-the-hash recon")
    sp.add_argument("-d", "--domain", help="domain")
    sp.add_argument("-k", "--kerberos", action="store_true", help="use Kerberos auth for recon")
    sp.add_argument("--margin", type=int, default=1, help="lockout safety margin (default 1)")
    sp.add_argument("--force", action="store_true",
                    help="override a safety refusal (ALSO needs a typed FORCE confirmation)")
    sp.add_argument("--yes", action="store_true",
                    help="skip the initial YES prompt (scripted use; does NOT skip FORCE)")
    sp.add_argument("--engagement", default="REDNESS password spray")
    sp.add_argument("--loot-dir", default="loot", help="where to write user list / recovered creds")
    sp.add_argument("--out", help="write a .docx report to this path")
    sp.add_argument("--json", help="write findings JSON to this path")
    sp.add_argument("--live", action="store_true", help="stream to the live 3D graph")
    sp.add_argument("--host", default="127.0.0.1", help="live graph bind host")
    sp.add_argument("--port", type=int, default=8765, help="live graph port")
    sp.add_argument("--no-open", action="store_true", help="don't auto-open the browser")
    sp.set_defaults(func=cmd_spray)

    co = sub.add_parser("coerce",
                        help="active RPC forced-auth coercion (PetitPotam/PrinterBug/DFSCoerce; "
                             "intrusive; opt-in, gated)")
    co.add_argument("--target", required=True, help="host to coerce (must look like a DC unless "
                    "--target-not-dc-ok)")
    co.add_argument("--listener", required=True, help="attacker IP the coerced auth is directed "
                    "to (run `redness poison` there to capture it)")
    co.add_argument("--method", choices=["all", "petitpotam", "printerbug", "dfscoerce", "shadowcoerce"],
                    default="all", help="coercion method (default: all - PetitPotam/PrinterBug/DFSCoerce)")
    co.add_argument("-u", "--username", help="tester username (authenticated coercion)")
    co.add_argument("-p", "--password", help="tester password")
    co.add_argument("-H", "--hash", help="tester NT hash for pass-the-hash")
    co.add_argument("-d", "--domain", help="domain")
    co.add_argument("-k", "--kerberos", action="store_true", help="use Kerberos auth")
    co.add_argument("--target-not-dc-ok", action="store_true",
                    help="allow coercing a target that does not look like a DC (findings HIGH, not CRITICAL)")
    co.add_argument("--force", action="store_true",
                    help="allow uncredentialed coercion (ALSO needs a typed FORCE confirmation)")
    co.add_argument("--yes", action="store_true",
                    help="skip the initial YES prompt (scripted use; does NOT skip FORCE)")
    co.add_argument("--engagement", default="REDNESS coercion")
    co.add_argument("--loot-dir", default="loot", help="where to write the coercion audit log")
    co.add_argument("--out", help="write a .docx report to this path")
    co.add_argument("--json", help="write findings JSON to this path")
    co.add_argument("--live", action="store_true", help="stream to the live 3D graph")
    co.add_argument("--host", default="127.0.0.1", help="live graph bind host")
    co.add_argument("--port", type=int, default=8765, help="live graph port")
    co.add_argument("--no-open", action="store_true", help="don't auto-open the browser")
    co.set_defaults(func=cmd_coerce)

    li = sub.add_parser("listen",
                        help="passive link-local discovery (mDNS/LLMNR/NBT-NS/SSDP) on the segment")
    li.add_argument("--duration", type=int, default=60, help="seconds to listen (default 60)")
    li.add_argument("--active", action="store_true",
                    help="also send one SSDP M-SEARCH to solicit UPnP replies (still low-noise)")
    li.add_argument("--engagement", default="REDNESS link-local discovery")
    li.add_argument("--out", help="write a .docx report to this path")
    li.add_argument("--json", help="write findings JSON to this path")
    li.add_argument("--live", action="store_true", help="stream to the live 3D graph")
    li.add_argument("--host", default="127.0.0.1", help="live graph bind host")
    li.add_argument("--port", type=int, default=8765, help="live graph port")
    li.add_argument("--no-open", action="store_true", help="don't auto-open the browser")
    li.set_defaults(func=cmd_listen)

    tr = sub.add_parser("trigger",
                        help="generate a forced-authentication UNC trigger link (NetNTLMv2 capture; opt-in)")
    tr.add_argument("--host", required=True, help="our capture host/IP (where the listener runs)")
    tr.add_argument("--format", choices=sorted(trigger.FORMATS), default="html",
                    help="artifact format (default: html)")
    tr.add_argument("--share", default="share", help="UNC share name (default: share)")
    tr.add_argument("--filename", default="x.jpg", help="UNC file name (cosmetic; default: x.jpg)")
    tr.add_argument("--out", help="write artifact to this path (default: print to stdout)")
    tr.set_defaults(func=cmd_trigger)

    bh = sub.add_parser("bloodhound",
                        help="ingest a SharpHound/BloodHound collection into the graph")
    bh.add_argument("path", help="BloodHound .zip, a directory of .json, or a single .json")
    bh.add_argument("--live", action="store_true", help="stream to the live 3D graph")
    bh.add_argument("--host", default="127.0.0.1", help="live graph bind host")
    bh.add_argument("--port", type=int, default=8765, help="live graph port")
    bh.add_argument("--no-open", action="store_true", help="don't auto-open the browser")
    bh.set_defaults(func=cmd_bloodhound)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
