r"""Wireless detection - `redness wifi` (orchestrates the OS wireless tooling).

Surveys the Wi-Fi networks in range and flags the risky ones: open (unencrypted) networks and
legacy weak encryption (WEP / WPA1 / TKIP). It drives the native tool - `netsh wlan show networks`
on Windows, `nmcli dev wifi` on Linux - and normalizes the output into findings. Read-only: it
lists what the adapter already sees, it does not transmit, deauth, or crack.

Pure parsers over captured `netsh` / `nmcli` output (unit-tested); the tool argv is best-effort
(verify on a box with a wireless adapter). Findings reuse `Category.CONFIG`.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from typing import Callable, Optional

from .findings import Category, Evidence, Finding, Report, Severity

_WEAK = re.compile(r"(?i)\b(wep|wpa1|wpa-personal|tkip)\b")
_OPEN = re.compile(r"(?i)\b(open|none)\b")


def parse_netsh(output: str) -> list[dict]:
    """Parse `netsh wlan show networks mode=bssid` into [{ssid, auth, encryption, bssid, signal}]."""
    nets: list[dict] = []
    cur: Optional[dict] = None
    for line in output.splitlines():
        s = line.strip()
        m = re.match(r"SSID\s+\d+\s*:\s*(.*)$", s)
        if m:
            cur = {"ssid": m.group(1).strip() or "(hidden)", "auth": "", "encryption": "",
                   "bssid": "", "signal": ""}
            nets.append(cur)
            continue
        if cur is None:
            continue
        if (m := re.match(r"Authentication\s*:\s*(.*)$", s)):
            cur["auth"] = m.group(1).strip()
        elif (m := re.match(r"Encryption\s*:\s*(.*)$", s)):
            cur["encryption"] = m.group(1).strip()
        elif (m := re.match(r"BSSID\s+\d+\s*:\s*(.*)$", s)) and not cur["bssid"]:
            cur["bssid"] = m.group(1).strip()
        elif (m := re.match(r"Signal\s*:\s*(.*)$", s)) and not cur["signal"]:
            cur["signal"] = m.group(1).strip()
    return nets


def parse_nmcli(output: str) -> list[dict]:
    """Parse `nmcli -t -f SSID,BSSID,SECURITY,SIGNAL dev wifi` (terminal mode, ':'-escaped)."""
    nets: list[dict] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = [f.replace("\\:", ":") for f in re.split(r"(?<!\\):", line)]
        if len(fields) < 3:
            continue
        ssid, bssid, security = fields[0], fields[1], fields[2]
        signal = fields[3] if len(fields) > 3 else ""
        sec = "" if security in ("", "--") else security          # nmcli '--' = open
        nets.append({"ssid": ssid or "(hidden)", "bssid": bssid,
                     "auth": sec or "Open", "encryption": sec, "signal": signal})
    return nets


def _is_open(net: dict) -> bool:
    sec = f"{net.get('auth', '')} {net.get('encryption', '')}".strip().lower()
    if not sec or sec in ("--", "open none", "open"):
        return True
    if "wpa2" in sec or "wpa3" in sec or _WEAK.search(sec):
        return False                                  # secured (or weak, but not open)
    return bool(_OPEN.search(sec))


def build_findings(networks: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    opens = [n for n in networks if _is_open(n)]
    weak = [n for n in networks
            if not _is_open(n) and _WEAK.search(f"{n.get('auth','')} {n.get('encryption','')}")]
    if opens:
        names = ", ".join(sorted({n["ssid"] for n in opens}))
        out.append(Finding(
            id="wireless-open",
            title=f"Open (unencrypted) Wi-Fi network(s) in range: {len(opens)}",
            severity=Severity.MEDIUM, category=Category.CONFIG,
            description=f"Open wireless networks were detected in range: {names}.",
            impact="Traffic on an open network is unencrypted and interceptable; an open SSID is "
                   "also a rogue-AP/eviltwin and client-association risk for staff devices.",
            remediation="Use WPA2/WPA3-Enterprise; remove or isolate open/guest SSIDs; monitor for "
                        "rogue APs; enforce client Wi-Fi policy (no auto-join to open networks).",
            affected=sorted({n["ssid"] for n in opens}),
            evidence=[Evidence(source="wireless",
                               detail="; ".join(f"{n['ssid']} [{n.get('bssid','')}]"
                                                for n in opens[:12]))],
            references=["https://attack.mitre.org/techniques/T1557/"],
            meta={"networks": opens},
        ))
    if weak:
        names = ", ".join(sorted({n["ssid"] for n in weak}))
        out.append(Finding(
            id="wireless-weak-encryption",
            title=f"Wi-Fi network(s) with weak encryption (WEP/WPA1/TKIP): {len(weak)}",
            severity=Severity.HIGH, category=Category.CONFIG,
            description=f"Wireless networks using legacy, breakable encryption were detected: "
                        f"{names}.",
            impact="WEP is trivially broken and WPA1/TKIP is weak; an attacker in range can recover "
                   "the key and decrypt or join the network.",
            remediation="Migrate to WPA2/WPA3 (AES/CCMP); retire WEP/WPA1/TKIP entirely.",
            affected=sorted({n["ssid"] for n in weak}),
            evidence=[Evidence(source="wireless",
                               detail="; ".join(f"{n['ssid']}: {n.get('auth','')}"
                                                for n in weak[:12]))],
            references=["https://attack.mitre.org/techniques/T1557/"],
            meta={"networks": weak},
        ))
    if networks:
        out.append(Finding(
            id="wireless-inventory",
            title=f"Wi-Fi networks in range: {len(networks)}",
            severity=Severity.INFO, category=Category.CONFIG,
            description="Inventory of the wireless networks the adapter can see.",
            impact="Situational awareness of the RF environment and nearby SSIDs/BSSIDs.",
            remediation="Review for unexpected or rogue SSIDs near the engagement site.",
            affected=sorted({n["ssid"] for n in networks}),
            evidence=[Evidence(source="wireless",
                               detail="; ".join(f"{n['ssid']} ({n.get('auth','')})"
                                                for n in networks[:20]))],
            meta={"count": len(networks)},
        ))
    return out


def _default_runner() -> str:
    if sys.platform.startswith("win"):
        exe = shutil.which("netsh")
        argv = [exe, "wlan", "show", "networks", "mode=bssid"] if exe else None
    else:
        exe = shutil.which("nmcli")
        argv = [exe, "-t", "-f", "SSID,BSSID,SECURITY,SIGNAL", "dev", "wifi"] if exe else None
    if not argv:
        return ""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return (p.stdout or "") + "\n" + (p.stderr or "")


def is_available() -> bool:
    return bool(shutil.which("netsh") if sys.platform.startswith("win") else shutil.which("nmcli"))


def run_wireless(*, engagement: str = "REDNESS wireless",
                 runner: Optional[Callable[[], str]] = None,
                 parser: Optional[Callable[[str], list[dict]]] = None) -> Report:
    """Scan Wi-Fi via the OS tool and return a Report. `parser` defaults by platform."""
    output = (runner or _default_runner)()
    if parser is None:
        parser = parse_netsh if sys.platform.startswith("win") else parse_nmcli
    networks = parser(output)
    return Report(engagement=engagement, target="wireless",
                  findings=build_findings(networks))
