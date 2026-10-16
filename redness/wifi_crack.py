r"""Offline WPA/WEP handshake cracking via aircrack-ng - `redness handshake`.

Given a captured handshake (`.cap` / `.pcap` / `.hccapx`) and a wordlist, run aircrack-ng offline
and recover the passphrase. This is the OFFLINE, read-only half of the wireless workflow: capturing
the handshake (airodump-ng) and any deauth to force it (aireplay-ng) are the ACTIVE steps and stay
out of REDNESS - the advisor suggests them, the operator runs them, then feeds the `.cap` here.

Parsing is pure over aircrack-ng stdout (unit-tested, no aircrack needed); a recovered key becomes
a CRITICAL `Category.PASSWORD` finding and is written to loot, mirroring the hash-crack pipeline.

Reference: https://www.aircrack-ng.org/
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

from .findings import Category, Evidence, Finding, Report, Severity

# aircrack-ng prints:  "KEY FOUND! [ Passphrase123 ]"   (WPA)
#                      "KEY FOUND! [ AB:CD:EF:12:34 ]"   (WEP, colon-separated hex)
_KEY = re.compile(r"KEY FOUND!\s*\[\s*(?P<key>.+?)\s*\]")
# aircrack echoes the target network near the top: "Opening cap...", "1  AA:BB..  CorpWiFi"


@dataclass
class CrackResult:
    cracked: bool = False
    key: str = ""
    ssid: str = ""
    bssid: str = ""


def parse_aircrack(output: str, *, ssid: str = "", bssid: str = "") -> CrackResult:
    """Parse aircrack-ng stdout for a recovered key. Returns CrackResult(cracked=False) if none."""
    m = _KEY.search(output or "")
    if not m:
        return CrackResult(cracked=False, ssid=ssid, bssid=bssid)
    if not ssid:
        ms = re.search(r"(?im)^\s*\d+\s+([0-9A-Fa-f:]{17})\s+(.+?)\s*$", output or "")
        if ms:
            bssid = bssid or ms.group(1)
            ssid = ms.group(2).strip()
    return CrackResult(cracked=True, key=m.group("key").strip(), ssid=ssid, bssid=bssid)


def build_finding(res: CrackResult, capfile: str) -> Optional[Finding]:
    """A recovered passphrase -> CRITICAL finding. None when nothing was cracked."""
    if not res.cracked:
        return None
    who = res.ssid or res.bssid or os.path.basename(capfile)
    return Finding(
        id="wifi-passphrase-cracked",
        title=f"Wi-Fi passphrase recovered for {who}",
        severity=Severity.CRITICAL,
        category=Category.PASSWORD,
        description="A WPA/WEP handshake was cracked offline with aircrack-ng.",
        impact="The recovered pre-shared key grants full access to the wireless network and any "
               "flat segment it reaches.",
        remediation="Rotate the PSK to a long random passphrase; prefer WPA2/WPA3-Enterprise "
                    "(802.1X) so there is no shared key to crack.",
        affected=[who],
        evidence=[Evidence(source="aircrack-ng",
                           detail=f"{who}: {res.key}" + (f" [{res.bssid}]" if res.bssid else ""))],
        references=["https://attack.mitre.org/techniques/T1557/"],
        meta={"ssid": res.ssid, "bssid": res.bssid, "key": res.key, "source": "aircrack-ng"},
    )


def is_available() -> bool:
    return shutil.which("aircrack-ng") is not None


def crack(capfile: str, wordlist: str, *, bssid: str = "", timeout: int = 1800,
          runner=None) -> CrackResult:
    """Run `aircrack-ng -w <wordlist> [-b bssid] <capfile>` and parse the result.

    `runner` (capfile, wordlist, bssid) -> stdout is injectable for tests; defaults to subprocess.
    """
    if runner is None:
        def runner(cap, wl, bs):
            exe = shutil.which("aircrack-ng")
            if not exe:
                return ""
            argv = [exe, "-w", wl]
            if bs:
                argv += ["-b", bs]
            argv += [cap]
            try:
                p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            except (subprocess.TimeoutExpired, OSError):
                return ""
            return (p.stdout or "") + "\n" + (p.stderr or "")
    return parse_aircrack(runner(capfile, wordlist, bssid), bssid=bssid)


def run_handshake(capfile: str, wordlist: str, *, bssid: str = "", engagement: str = "REDNESS wifi",
                  loot_dir: str = "loot", runner=None) -> tuple[Report, CrackResult]:
    """Crack a handshake and return (Report, CrackResult). Writes a recovered key to loot."""
    res = crack(capfile, wordlist, bssid=bssid, runner=runner)
    findings: list[Finding] = []
    f = build_finding(res, capfile)
    if f:
        findings.append(f)
        try:
            os.makedirs(loot_dir, exist_ok=True)
            with open(os.path.join(loot_dir, "wifi_keys.txt"), "a", encoding="utf-8") as fh:
                fh.write(f"{res.ssid or res.bssid or capfile}:{res.key}\n")
        except OSError:
            pass
    return Report(engagement=engagement, target=(res.ssid or res.bssid or capfile),
                  findings=findings), res
