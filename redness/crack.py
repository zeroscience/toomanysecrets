"""Offline cracking of captured hashes — the adscan-style "detect a hash, crack it" loop.

Scope: the crackable material REDNESS obtains — AS-REP (`krb5asrep`) and Kerberoast
(`krb5tgs`) hashes captured during enumeration (see engines/ldap.py), plus NetNTLMv2
(`netntlmv2`) hashes from the opt-in poisoner (see poison.py). The *capture* of NetNTLMv2
(active LLMNR/NBT-NS poisoning) lives in poison.py, not here; this module only cracks
whatever hashes arrive via finding.meta["hashes"].

Two independent capabilities:
  1. write_loot()  — always available: dump hashes to hashcat-ready files so they can be
     cracked elsewhere. This is the baseline "hash detected" deliverable.
  2. crack()       — if hashcat or john is on PATH and a wordlist is given, run it and map
     recovered passwords back to accounts.

Cracking recovered credentials from an authorized engagement is standard practice; only
run this against systems you are authorized to test.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from .findings import Category, Evidence, Finding, Report, Severity
from .wordlists import write_basic_wordlist

# hashcat -m mode per hash type; john --format per hash type.
HASHCAT_MODE = {"krb5asrep": "18200", "krb5tgs": "13100", "netntlmv2": "5600"}
JOHN_FORMAT = {"krb5asrep": "krb5asrep", "krb5tgs": "krb5tgs", "netntlmv2": "netntlmv2"}
# Which finding category a cracked credential belongs to, by source hash type. Keeps the
# `credential-cracked` finding labeled correctly (Kerberos roasting vs NetNTLMv2 poisoning).
HASH_CATEGORY = {
    "krb5asrep": Category.KERBEROS,
    "krb5tgs": Category.KERBEROS,
    "netntlmv2": Category.SMB,
}


@dataclass
class Cred:
    account: str
    hash_type: str
    value: str
    password: Optional[str] = None


@dataclass
class CrackResult:
    creds: list[Cred] = field(default_factory=list)
    loot_files: list[str] = field(default_factory=list)
    tool: Optional[str] = None
    used_builtin: bool = False        # cracked with the built-in wordlist (no --wordlist given)

    @property
    def cracked(self) -> list[Cred]:
        return [c for c in self.creds if c.password is not None]


# --------------------------------------------------------------------------- #
# Pure helpers                                                                 #
# --------------------------------------------------------------------------- #
def collect_hashes(report: Report) -> list[Cred]:
    """Gather every hash a scan stashed in finding.meta['hashes']."""
    creds: list[Cred] = []
    seen: set[str] = set()
    for f in report.findings:
        for h in f.meta.get("hashes", []):
            val = h.get("hash", "")
            if val and val not in seen:
                seen.add(val)
                creds.append(Cred(account=h.get("account", "?"),
                                  hash_type=h.get("type", "unknown"), value=val))
    return creds


def write_loot(creds: list[Cred], loot_dir: str) -> list[str]:
    """Write hashes to <loot_dir>/<type>.txt (one per line). Returns file paths."""
    os.makedirs(loot_dir, exist_ok=True)
    by_type: dict[str, list[str]] = {}
    for c in creds:
        by_type.setdefault(c.hash_type, []).append(c.value)
    paths = []
    for htype, values in by_type.items():
        p = os.path.join(loot_dir, f"{htype}.txt")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("\n".join(values) + "\n")
        paths.append(p)
    return paths


def available_tool() -> Optional[str]:
    if shutil.which("hashcat"):
        return "hashcat"
    if shutil.which("john"):
        return "john"
    return None


def parse_hashcat_show(output: str, creds: list[Cred]) -> None:
    """Map `hash:password` lines from `hashcat --show` back onto creds by hash prefix.

    Password may contain ':', so match by the known hash value as a prefix rather than
    splitting on ':'.
    """
    lines = output.splitlines()
    for c in creds:
        for line in lines:
            if line.startswith(c.value + ":"):
                c.password = line[len(c.value) + 1:]
                break


def parse_john_show(output: str, creds: list[Cred]) -> None:
    """Map `login:password:...` lines from `john --show` back onto creds by account."""
    by_acct = {c.account.lower(): c for c in creds}
    for line in output.splitlines():
        if ":" not in line or line.lower().startswith(("0 password", "no password")):
            continue
        parts = line.split(":")
        login = parts[0].split("@")[0].lower()
        if login in by_acct and len(parts) >= 2:
            by_acct[login].password = parts[1]


# --------------------------------------------------------------------------- #
# Cracking (needs hashcat/john)                                                #
# --------------------------------------------------------------------------- #
def crack(creds: list[Cred], wordlist: str, *, tool: Optional[str] = None,
          workdir: Optional[str] = None, timeout: int = 1800,
          runner=subprocess.run) -> str:
    """Attempt to crack `creds` in place (sets .password). Returns the tool used or ''.

    `runner` is injectable for testing. Groups by hash type; runs one tool invocation
    per type; maps results back onto creds.
    """
    tool = tool or available_tool()
    if not tool or not creds or not os.path.isfile(wordlist):
        return ""
    workdir = workdir or "."
    os.makedirs(workdir, exist_ok=True)

    by_type: dict[str, list[Cred]] = {}
    for c in creds:
        by_type.setdefault(c.hash_type, []).append(c)

    for htype, group in by_type.items():
        hashfile = os.path.join(workdir, f"_crack_{htype}.txt")
        with open(hashfile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(c.value for c in group) + "\n")

        if tool == "hashcat":
            mode = HASHCAT_MODE.get(htype)
            if not mode:
                continue
            runner(["hashcat", "-m", mode, "-a", "0", hashfile, wordlist,
                    "--quiet", "--potfile-disable=0"],
                   capture_output=True, text=True, timeout=timeout)
            show = runner(["hashcat", "-m", mode, hashfile, "--show"],
                          capture_output=True, text=True, timeout=timeout)
            parse_hashcat_show(getattr(show, "stdout", "") or "", group)
        elif tool == "john":
            fmt = JOHN_FORMAT.get(htype)
            if not fmt:
                continue
            runner(["john", f"--format={fmt}", f"--wordlist={wordlist}", hashfile],
                   capture_output=True, text=True, timeout=timeout)
            show = runner(["john", "--show", f"--format={fmt}", hashfile],
                          capture_output=True, text=True, timeout=timeout)
            parse_john_show(getattr(show, "stdout", "") or "", group)
    return tool


def annotate(report: Report, cracked: list[Cred], tool: str = "") -> None:
    """Append a CRITICAL finding per recovered credential."""
    for c in cracked:
        if c.password is None:
            continue
        report.findings.append(Finding(
            id="credential-cracked",
            title=f"Password recovered for {c.account}",
            severity=Severity.CRITICAL,
            category=HASH_CATEGORY.get(c.hash_type, Category.KERBEROS),
            description=f"The {c.hash_type} hash for '{c.account}' was cracked offline.",
            impact="A recovered password is a valid domain credential enabling authenticated "
                   "access and further compromise.",
            remediation="Reset the account password immediately; enforce a strong password "
                        "policy and consider gMSA for service accounts.",
            affected=[c.account],
            evidence=[Evidence(source=f"crack/{tool or 'offline'}",
                               detail=f"{c.account}:{c.password}")],
            credentialed=True,
            meta={"account": c.account, "password": c.password, "hash_type": c.hash_type},
        ))


def run_cracking(report: Report, *, loot_dir: str = "loot",
                 wordlist: Optional[str] = None, builtin: bool = True) -> CrackResult:
    """End-to-end: collect hashes -> write loot -> (optionally) crack -> annotate report.

    Cracking uses `wordlist` if given. Otherwise, when `builtin` is True and a cracker
    (hashcat/john) is on PATH, it falls back to the small built-in weak-password list
    (redness.wordlists.BASIC_WORDLIST) so egregiously weak creds are caught automatically.
    Pass builtin=False (the `--no-crack` flag) to skip cracking entirely; loot is always
    written regardless.
    """
    creds = collect_hashes(report)
    result = CrackResult(creds=creds)
    if not creds:
        return result
    result.loot_files = write_loot(creds, loot_dir)

    effective = wordlist
    if effective is None and builtin and available_tool() is not None:
        effective = write_basic_wordlist(loot_dir)
        result.used_builtin = True

    if effective:
        result.tool = crack(creds, effective, workdir=loot_dir) or None
        annotate(report, result.cracked, tool=result.tool or "")
    return result
