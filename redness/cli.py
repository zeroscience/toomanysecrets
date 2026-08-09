"""REDNESS CLI entrypoint.

  python -m redness.cli demo --out report.docx     # end-to-end with sample data
  python -m redness.cli report findings.json --out report.docx
"""
from __future__ import annotations

import argparse
import sys

from .findings import Category, Evidence, Finding, Report, Severity
from .report import docx_report


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

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
