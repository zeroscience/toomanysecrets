r"""Share secret-hunting engine - Snaffler-style, over nxc's spider_plus inventory.

REDNESS does not spider SMB itself: `nxc smb <host> -M spider_plus` walks every readable
share and writes a JSON inventory (`~/.nxc/modules/nxc_spider_plus/<host>.json`). Our value
is a **pure classifier** over that inventory that flags secrets (keys, KeePass DBs, GPP
cpassword, web.config/.env, unattend.xml, password files, ...) as `Category.SECRET` findings.

This is step 1 of docs/SHAREHUNT.md - the pure parser + classifier + findings builder only.
The subprocess wrapper (`SecretHuntEngine.run`, `scan --hunt-secrets`) and Phase-2 content
inspection come later, so this unit-tests against a captured spider_plus JSON with no nxc/DC.

Redaction: findings carry secrets in `meta["secrets"]`; the `match` field is always masked/
truncated (Phase 1 is filename-only, so it is empty) - never a full secret value.
"""
from __future__ import annotations

import glob
import json as _json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Callable, Optional

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target


# --------------------------------------------------------------------------- #
# Inventory model + spider_plus JSON parsing (pure)                            #
# --------------------------------------------------------------------------- #
@dataclass
class FileRec:
    share: str
    path: str          # share-relative, forward-slash normalized
    size: int = 0


_SIZE_UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}
_SIZE_RE = re.compile(r"^\s*([\d.]+)\s*([KMGT]?B)?\s*$", re.I)


def _parse_size(v) -> int:
    """spider_plus reports size as an int or a human string ('1.16 KB'); best-effort -> bytes."""
    if isinstance(v, bool):
        return 0
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, str) and (m := _SIZE_RE.match(v)):
        try:
            return int(float(m.group(1)) * _SIZE_UNITS.get((m.group(2) or "B").upper(), 1))
        except ValueError:
            return 0
    return 0


def parse_spider_json(data) -> list[FileRec]:
    """Flatten spider_plus JSON `{share: {relpath: {size,...}}}` into FileRec list.

    Accepts a dict or a JSON string. Tolerant of missing/oddly-typed metadata.
    """
    if isinstance(data, (str, bytes)):
        data = _json.loads(data)
    recs: list[FileRec] = []
    for share, files in (data or {}).items():
        if not isinstance(files, dict):
            continue
        for path, meta in files.items():
            size = _parse_size(meta.get("size")) if isinstance(meta, dict) else 0
            norm = str(path).replace("\\", "/").lstrip("/")
            recs.append(FileRec(share=str(share), path=norm, size=size))
    return recs


# --------------------------------------------------------------------------- #
# Snaffler-style classifier (pure, Phase 1: filename / extension / path)       #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Rule:
    rule: str              # stable rule id, e.g. "private-key"
    kind: str              # human secret type, e.g. "private key"
    severity: Severity


# matcher: (basename_lower, ext_lower, path_lower) -> bool
Matcher = Callable[[str, str, str], bool]


def _ext(*exts: str) -> Matcher:
    exts = tuple(e.lower() for e in exts)
    return lambda name, ext, lp: ext in exts


def _name(*names: str) -> Matcher:
    names = tuple(n.lower() for n in names)
    return lambda name, ext, lp: name in names


def _name_re(pattern: str) -> Matcher:
    rx = re.compile(pattern, re.I)
    return lambda name, ext, lp: bool(rx.search(name))


# Ordered CRITICAL -> MEDIUM; first match wins.
_RULES: list[tuple[Rule, Matcher]] = [
    # ---- CRITICAL ----
    (Rule("private-key", "private key", Severity.CRITICAL),
     lambda n, e, lp: e in (".pem", ".ppk", ".key")
     or n in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")),
    (Rule("keepass-db", "KeePass database", Severity.CRITICAL), _ext(".kdbx", ".kdb")),
    (Rule("pkcs12", "PKCS#12 keystore", Severity.CRITICAL), _ext(".pfx", ".p12")),
    (Rule("gpp-cpassword", "GPP cpassword file", Severity.CRITICAL),
     _name("groups.xml", "services.xml", "scheduledtasks.xml", "printers.xml", "datasources.xml")),
    (Rule("git-credentials", "git credentials", Severity.CRITICAL), _name(".git-credentials")),
    # ---- HIGH ----
    (Rule("config-credential", "config file (likely credentials)", Severity.HIGH),
     lambda n, e, lp: e == ".env"
     or n in ("web.config", "app.config", "appsettings.json", "application.properties",
              "settings.py", "wp-config.php", ".pgpass", ".my.cnf", ".npmrc")),
    (Rule("unattend", "unattend answer file", Severity.HIGH),
     _name("unattend.xml", "autounattend.xml", "sysprep.xml", "sysprep.inf")),
    # ---- MEDIUM ----
    (Rule("password-file", "password file (by name)", Severity.MEDIUM),
     _name_re(r"passw(or)?ds?\.(txt|csv|xlsx?|docx?)$")),
    (Rule("config-backup", "config backup", Severity.MEDIUM),
     lambda n, e, lp: e in (".bak", ".old", ".backup")
     and any(t in n for t in (".config", ".xml", ".ini", ".env", ".json", ".properties"))),
    (Rule("script", "script (review for creds)", Severity.MEDIUM),
     _ext(".ps1", ".bat", ".cmd", ".vbs")),
]


def classify_file(share: str, path: str, size: int = 0) -> Optional[Rule]:
    """Return the first matching Snaffler-style Rule for a file, or None if uninteresting."""
    name = path.replace("\\", "/").rstrip("/").split("/")[-1].lower()
    ext = os.path.splitext(name)[1]
    lp = path.lower()
    for rule, match in _RULES:
        if match(name, ext, lp):
            return rule
    return None


# --------------------------------------------------------------------------- #
# Findings (pure)                                                              #
# --------------------------------------------------------------------------- #
def _unc(host: str, share: str, path: str) -> str:
    return f"\\\\{host}\\{share}\\" + path.replace("/", "\\")


_REFS = ["https://attack.mitre.org/techniques/T1552/001/",   # Credentials In Files
         "https://attack.mitre.org/techniques/T1039/"]        # Data from Network Shared Drive


def build_findings(inventory: list[FileRec], *, host: str) -> list[Finding]:
    """Classify an inventory into `Category.SECRET` findings (one per secret) + one INFO.

    `meta["secrets"]` mirrors `meta["hashes"]`; `match` is always masked (empty in Phase 1 -
    filename-only, no content is read).
    """
    findings: list[Finding] = []
    shares: set[str] = set()
    interesting = 0

    for rec in inventory:
        shares.add(rec.share)
        rule = classify_file(rec.share, rec.path, rec.size)
        if rule is None:
            continue
        interesting += 1
        unc = _unc(host, rec.share, rec.path)
        secret = {
            "host": host,
            "share": rec.share,
            "path": rec.path,
            "unc": unc,
            "rule": rule.rule,
            "kind": rule.kind,
            "size": rec.size,
            "match": "",          # Phase 1: filename-only -> no content, nothing to redact
        }
        findings.append(Finding(
            id="share-secret",
            title=f"Share secret: {rule.kind}",
            severity=rule.severity,
            category=Category.SECRET,
            description=f"A {rule.kind} was found on a readable SMB share at {unc}.",
            impact="Files on readable shares frequently contain plaintext credentials, keys, or "
                   "connection strings - a common and fast path to privilege escalation / Domain Admin.",
            remediation="Remove credential material from shares; restrict share and NTFS permissions "
                        "to least privilege; rotate any exposed secret; store secrets in a vault.",
            affected=[unc],
            evidence=[Evidence(source="sharehunt", detail=f"{rule.rule}: {unc} ({rec.size} bytes)")],
            references=_REFS,
            credentialed=True,          # spidering shares uses the tested principal's creds
            meta={"secrets": [secret]},
        ))

    findings.append(Finding(
        id="enum-share-spider",
        title="Shares spidered for secrets",
        severity=Severity.INFO,
        category=Category.ENUM,
        description=f"Spidered {len(shares)} readable share(s), {len(inventory)} file(s); "
                    f"{interesting} flagged as potential secret(s).",
        affected=[],                    # aggregate context; per-secret findings own the nodes
        evidence=[Evidence(source="sharehunt",
                           detail=f"{len(inventory)} files across {len(shares)} share(s): "
                                  f"{', '.join(sorted(shares)) or 'none'}")],
        credentialed=True,
    ))
    return findings


# --------------------------------------------------------------------------- #
# Execution (impure) - orchestrate nxc's spider_plus module                    #
# --------------------------------------------------------------------------- #
class SecretHuntEngine(Engine):
    """Spider readable SMB shares via nxc `-M spider_plus`, classify the inventory.

    Opt-in (not in default_engines(); wired to `scan --hunt-secrets`). Phase 1 is
    filename/path classification only (DOWNLOAD_FLAG=False) - no file content is read.
    The only impure method is `_spider`; `run` delegates to the pure parser/classifier,
    so it unit-tests by overriding `_spider` (no nxc/DC needed).
    """
    name = "sharehunt"

    def __init__(self, timeout: int = 600, runner=subprocess.run):
        self.timeout = timeout
        self.runner = runner            # injectable for tests

    def _bin(self) -> Optional[str]:
        return shutil.which("nxc") or shutil.which("netexec")

    def is_available(self) -> bool:
        return self._bin() is not None

    def _auth_args(self, target: Target) -> list[str]:
        user = target.username if target.username is not None else ""
        args = ["-u", user]
        if target.nthash:
            args += ["-H", target.nthash]
        else:
            args += ["-p", target.password if target.password is not None else ""]
        if target.kerberos:
            args += ["-k"]
        if target.domain:
            args += ["-d", target.domain]
        return args

    def _spider(self, target: Target) -> Optional[str]:
        """Run `nxc smb -M spider_plus`; return the JSON inventory text, or None.

        Impure seam (subprocess + locate/read the JSON file); overridden in tests.
        """
        exe = self._bin()
        if not exe:
            return None
        outdir = tempfile.mkdtemp(prefix="redness_spider_")
        try:
            cmd = ([exe, "smb", target.host] + self._auth_args(target)
                   + ["-M", "spider_plus", "-o", "DOWNLOAD_FLAG=False", f"OUTPUT_FOLDER={outdir}"])
            try:
                self.runner(cmd, capture_output=True, text=True, timeout=self.timeout)
            except (subprocess.TimeoutExpired, OSError):
                return None
            # spider_plus names the file by target; tolerate scheme differences + a build
            # that ignores OUTPUT_FOLDER (default ~/.nxc location).
            candidates = [os.path.join(outdir, f"{target.host}.json")]
            candidates += sorted(glob.glob(os.path.join(outdir, "*.json")),
                                 key=os.path.getmtime, reverse=True)
            candidates.append(os.path.expanduser(
                f"~/.nxc/modules/nxc_spider_plus/{target.host}.json"))
            for path in candidates:
                if path and os.path.isfile(path):
                    try:
                        return open(path, encoding="utf-8").read()
                    except OSError:
                        continue
            return None
        finally:
            shutil.rmtree(outdir, ignore_errors=True)

    def run(self, target: Target) -> list[Finding]:
        if not self.is_available():
            return []
        raw = self._spider(target)
        if not raw:
            return []
        findings = build_findings(parse_spider_json(raw), host=target.host)
        # Attach the raw inventory to the first finding for the report appendix (like netexec).
        if findings and findings[0].evidence:
            findings[0].evidence[0].raw = raw.strip()[:4000]
        return findings
