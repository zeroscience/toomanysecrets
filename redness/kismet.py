r"""Kismet ingest - `redness kismet <file>` (passive wireless capture -> findings).

Kismet is a passive 802.11 sensor: it only listens, so ingesting its capture fits REDNESS's
read-only ethos (like the BloodHound ingest). This parses a Kismet log - the modern SQLite
`.kismet` database or a legacy `.netxml` - into the networks/clients it saw and normalizes them
into findings, reusing the same open / weak-encryption / inventory findings as `redness wifi`,
plus a client PREFERRED-NETWORK-LIST finding (devices probing for named SSIDs are karma/evil-twin
bait).

Pure parsers (unit-tested against a sample .netxml and a constructed SQLite), no Kismet needed.
Kismet device JSON keys vary across versions, so extraction is deliberately tolerant.

Reference: https://www.kismetwireless.net/
"""
from __future__ import annotations

import json
import sqlite3
import xml.etree.ElementTree as ET
from typing import Optional

from .findings import Category, Evidence, Finding, Report, Severity
from .wireless import build_findings as _wifi_findings


def _net(ssid: str, bssid: str = "", crypt: str = "", channel: str = "") -> dict:
    sec = crypt or "Open"
    return {"ssid": ssid or "(hidden)", "bssid": bssid, "auth": sec, "encryption": sec,
            "signal": "", "channel": channel}


def parse_netxml(xml_text: str) -> tuple[list[dict], list[dict]]:
    """Legacy Kismet .netxml -> (networks, clients). Invalid XML -> ([], [])."""
    try:
        root = ET.fromstring(xml_text or "")
    except ET.ParseError:
        return [], []
    nets, clients = [], []
    for wn in root.findall("wireless-network"):
        ssid_el = wn.find("SSID")
        ssid = (ssid_el.findtext("ssid") if ssid_el is not None else "") or ""
        crypt = (ssid_el.findtext("encryption") if ssid_el is not None else "") or ""
        bssid = wn.findtext("BSSID") or ""
        channel = wn.findtext("channel") or ""
        if ssid or bssid:
            nets.append(_net(ssid.strip(), bssid.strip(), crypt.strip(), channel.strip()))
        for wc in wn.findall("wireless-client"):
            mac = wc.findtext("client-mac") or ""
            if mac:
                clients.append({"mac": mac.strip(), "probed": []})
    return nets, clients


def _deep(d, *keys, default=""):
    """Tolerant nested lookup: _deep(obj, 'a', 'b') -> obj['a']['b'] or default."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur


def _device_to_record(dev: dict) -> tuple[Optional[dict], Optional[dict]]:
    """One Kismet device JSON -> (network | None, client | None)."""
    dtype = _deep(dev, "kismet.device.base.type") or ""
    mac = _deep(dev, "kismet.device.base.macaddr") or ""
    dot11 = _deep(dev, "dot11.device", default={}) or {}
    if "AP" in dtype:
        adv = _deep(dot11, "dot11.device.last_beaconed_ssid_record", default={}) or {}
        ssid = (_deep(adv, "dot11.advertisedssid.ssid")
                or _deep(dev, "kismet.device.base.commonname") or "")
        crypt = (_deep(adv, "dot11.advertisedssid.crypt_string")
                 or _deep(dev, "kismet.device.base.crypt") or "")
        channel = str(_deep(dev, "kismet.device.base.channel") or "")
        return _net(ssid, mac, crypt, channel), None
    if "Client" in dtype:
        probed_map = _deep(dot11, "dot11.device.probed_ssid_map", default=[]) or []
        probed = []
        for p in probed_map if isinstance(probed_map, list) else []:
            s = _deep(p, "dot11.probedssid.ssid")
            if s:
                probed.append(s)
        return None, {"mac": mac, "probed": probed}
    return None, None


def parse_kismetdb(path: str) -> tuple[list[dict], list[dict]]:
    """Modern Kismet SQLite `.kismet` -> (networks, clients). Tolerant of schema drift."""
    nets, clients = [], []
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error:
        try:
            con = sqlite3.connect(path)
        except sqlite3.Error:
            return [], []
    try:
        cur = con.execute("SELECT device FROM devices")
        for (blob,) in cur:
            if isinstance(blob, (bytes, bytearray)):
                try:
                    blob = blob.decode("utf-8", "replace")
                except Exception:
                    continue
            try:
                dev = json.loads(blob)
            except (ValueError, TypeError):
                continue
            net, client = _device_to_record(dev)
            if net:
                nets.append(net)
            elif client:
                clients.append(client)
    except sqlite3.Error:
        pass
    finally:
        con.close()
    return nets, clients


def load(path: str) -> tuple[list[dict], list[dict]]:
    """Detect .kismet (SQLite) vs .netxml by content and parse accordingly."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError:
        return [], []
    if head.startswith(b"SQLite format 3"):
        return parse_kismetdb(path)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return parse_netxml(fh.read())
    except OSError:
        return [], []


def build_wireless_findings(networks: list[dict], clients: list[dict]) -> list[Finding]:
    """Reuse the wifi open/weak/inventory findings, plus a client preferred-network-list finding."""
    out = _wifi_findings(networks)
    probing = [c for c in clients if c.get("probed")]
    if probing:
        ssids = sorted({s for c in probing for s in c["probed"]})
        out.append(Finding(
            id="wireless-client-pnl",
            title=f"Wi-Fi clients leaking preferred networks: {len(probing)} device(s)",
            severity=Severity.MEDIUM,
            category=Category.CONFIG,
            description="Client devices were seen actively probing for named SSIDs, revealing their "
                        "preferred-network list (PNL).",
            impact="A probed SSID can be impersonated (karma / evil-twin) to lure the device into "
                   "associating, enabling credential capture or machine-in-the-middle.",
            remediation="Disable auto-join to non-hidden/open networks; remove stale saved networks; "
                        "prefer 802.1X profiles; educate users on open-Wi-Fi auto-connect.",
            affected=ssids,
            evidence=[Evidence(source="kismet",
                               detail="; ".join(f"{c['mac']} -> {', '.join(c['probed'][:5])}"
                                                for c in probing[:12]))],
            references=["https://attack.mitre.org/techniques/T1557/"],
            meta={"clients": len(probing), "probed_ssids": ssids},
        ))
    return out


def ingest(path: str, *, engagement: str = "REDNESS wireless (kismet)") -> Report:
    networks, clients = load(path)
    return Report(engagement=engagement, target="wireless",
                  findings=build_wireless_findings(networks, clients))
