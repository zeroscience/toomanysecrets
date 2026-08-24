r"""GPP cpassword engine - recover Group Policy Preferences passwords from SYSVOL.

GPP stored account/service/task passwords as `cpassword="..."` in XMLs under SYSVOL. The
value is AES-256 encrypted with a key Microsoft *published* (MS-GPPREF), so it is trivially
decryptable by any authenticated user - it is decryption, not cracking. SYSVOL is world-
readable to the domain and GPP often set one local-admin password fleet-wide, so a recovered
cpassword is a classic fast path to lateral movement / Domain Admin.

Approach (docs/GPP.md): orchestrate `nxc smb <dc> -M gpp_password`, which walks SYSVOL and
decrypts the cpasswords, and parse its stdout - no AES dependency on our side. This is step 1
of the build order: the pure `parse_gpp_output` + `build_findings` only (the subprocess
`GppEngine.run` + registration come in step 2), so it unit-tests against captured nxc output
with no nxc/DC.

Recovered credentials are *stored* (account:password) like `credential-cracked` - a discrete
usable credential, not a raw file blob - and ride in `meta["credentials"]` for the attack-path
graph (paths.py). Reuses `Category.SECRET` (no schema change).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..findings import Category, Evidence, Finding, Severity


@dataclass
class GppCred:
    username: str
    password: str
    source: str = ""       # GPP xml basename, e.g. "Groups.xml"
    gpo: str = ""          # policy GUID, e.g. "{31B2F340-...}"
    where: str = ""        # full SYSVOL path


# nxc `gpp_password` prints one block per GPP file: a "Found credentials in <path>" line,
# then "Password: <pw>", then "Username(s): <name|list>". Match by token (tolerates nxc's
# "SMB <host> <port> <name>" line prefix + version drift), like engines/netexec.py.
_FOUND = re.compile(r"(?i)Found credentials in\s+(?P<path>.+?)\s*$")
_PASS = re.compile(r"(?i)\bPassword:\s*(?P<pw>.+?)\s*$")
_USERS = re.compile(r"(?i)\buser\s?names?:\s*(?P<users>.+?)\s*$")
_GUID = re.compile(r"\{[0-9A-Fa-f-]{36}\}")


def _parse_users(s: str) -> list[str]:
    """A username list ('['a', 'b']' repr) or a single bare username."""
    toks = re.findall(r"""['"]([^'"]*)['"]""", s)      # python-list repr
    if toks:
        return [t for t in toks if t]
    s = s.strip()
    return [s] if s else []


def parse_gpp_output(stdout: str) -> list[GppCred]:
    """Parse `nxc smb -M gpp_password` stdout into recovered credentials.

    One GppCred per (username, password); empty-password blocks (a removed cpassword) are
    skipped. A file can apply one password to several usernames -> several creds.
    """
    creds: list[GppCred] = []

    def flush(block: "dict | None") -> None:
        if not block:
            return
        pw = (block.get("password") or "").strip()
        if not pw:                                     # removed/blank cpassword
            return
        path = block.get("path", "")
        source = path.replace("\\", "/").rstrip("/").split("/")[-1] if path else ""
        gpo = m.group(0) if (m := _GUID.search(path)) else ""
        for u in block.get("users") or []:
            if u.strip():
                creds.append(GppCred(username=u.strip(), password=pw,
                                     source=source, gpo=gpo, where=path))

    cur: "dict | None" = None
    for line in stdout.splitlines():
        if (m := _FOUND.search(line)):
            flush(cur)
            cur = {"path": m.group("path"), "password": "", "users": []}
            continue
        if cur is None:
            continue
        if (m := _PASS.search(line)):
            cur["password"] = m.group("pw")
        elif (m := _USERS.search(line)):
            cur["users"] = _parse_users(m.group("users"))
    flush(cur)
    return creds


_REFS = ["https://attack.mitre.org/techniques/T1552/006/",
         "https://support.microsoft.com/kb/2962486"]      # MS14-025


def build_findings(creds: list[GppCred], *, host: str = "") -> list[Finding]:
    """One CRITICAL `gpp-cpassword` finding per recovered credential.

    Stores the recovered account:password (a discrete usable credential, like
    `credential-cracked`) and rides it in `meta["credentials"]` for the attack-path graph.
    GPP passwords are frequently LOCAL accounts applied fleet-wide, so the username is used
    as-is (no fabricated DOMAIN\\ prefix).
    """
    findings: list[Finding] = []
    for c in creds:
        account = c.username
        where = f" ({c.where})" if c.where else ""
        findings.append(Finding(
            id="gpp-cpassword",
            title=f"GPP cpassword recovered: {account}",
            severity=Severity.CRITICAL,
            category=Category.SECRET,
            description=f"A Group Policy Preferences password for '{account}' was recovered "
                        f"(decrypted) from SYSVOL"
                        + (f" on {host}" if host else "")
                        + (f" ({c.source})" if c.source else "") + ".",
            impact="GPP cpassword is AES-encrypted with a Microsoft-published key, so any "
                   "authenticated user can decrypt it. GPP often set the same local-admin "
                   "password fleet-wide - a direct path to lateral movement / Domain Admin.",
            remediation="Remove the GPP-stored password and delete the preference from the GPO; "
                        "rotate the exposed account; deploy LAPS; ensure MS14-025 is applied.",
            affected=[account],
            evidence=[Evidence(source="netexec", detail=f"{account}:{c.password}{where}")],
            references=_REFS,
            credentialed=True,
            meta={"credentials": [{
                "account": account,
                "username": c.username,
                "kind": "password",
                "password": c.password,
                "source": f"gpp-{c.source}" if c.source else "gpp",
            }]},
        ))
    return findings
