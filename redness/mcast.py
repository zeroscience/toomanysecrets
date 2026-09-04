r"""Passive link-local discovery - the broadcast/multicast "chatter" a WiFi/LAN segment leaks.

REDNESS's scan does ACTIVE discovery (TCP connect-scan + AD protocols). This adds the passive
layer: sit on a segment and harvest what devices announce of their own accord over multicast /
broadcast. On a WiFi / office LAN this is noisy and it maps straight to attack surface:

  * mDNS   (5353, 224.0.0.251)          -> hostnames, printers (_ipp), AirPlay/Chromecast, NAS/IoT
  * LLMNR  (5355, 224.0.0.252)          -> names being resolved  == POISONABLE (feeds `poison`)
  * NBT-NS (137 broadcast)              -> NetBIOS name queries  == POISONABLE
  * SSDP   (1900, 239.255.255.250)      -> UPnP device type + Server banner (routers, media, IoT)
  * WPAD   (a `wpad` query on any of the above) -> WPAD spoofing -> credential theft

Parsing is pure (bytes -> records) and separated from the socket loop, so it unit-tests against
captured packet bytes with no network (same discipline as the engines). Findings reuse ENUM
(inventory) / CONFIG (poisonable name resolution, WPAD) - no schema change. The listener itself
sends nothing by default (fully passive); `--active` adds a single SSDP M-SEARCH solicitation.

Authorized, in-scope segments only (it observes other hosts' traffic).
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Optional

from .events import Event, EventBus, EventKind
from .findings import Category, Evidence, Finding, Report, Severity

# Multicast endpoints.
MDNS = ("224.0.0.251", 5353)
LLMNR = ("224.0.0.252", 5355)
SSDP = ("239.255.255.250", 1900)
NBTNS_PORT = 137


@dataclass
class Announce:
    proto: str                 # "mdns" | "llmnr" | "nbtns" | "ssdp"
    src: str                   # source IP the datagram came from
    name: str = ""             # hostname / queried name / device friendly name
    ip: str = ""               # advertised A-record IP, if any
    kind: str = ""             # service/device type, or "query"
    detail: str = ""           # extra (Server banner, LOCATION, ...)


# --------------------------------------------------------------------------- #
# DNS wire-format parsing (shared by mDNS + LLMNR; both are DNS on multicast)   #
# --------------------------------------------------------------------------- #
def _read_name(data: bytes, off: int) -> tuple[str, int]:
    """Decode a DNS name at `off`, following compression pointers. Returns (name, next_off)."""
    labels: list[str] = []
    jumped = False
    next_off = off
    steps = 0
    while True:
        if off >= len(data) or steps > 128:
            break
        steps += 1
        length = data[off]
        if length == 0:
            off += 1
            if not jumped:
                next_off = off
            break
        if (length & 0xC0) == 0xC0:                 # compression pointer
            if off + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                next_off = off + 2
            off = pointer
            jumped = True
            continue
        off += 1
        labels.append(data[off:off + length].decode("latin-1", "replace"))
        off += length
    return ".".join(labels), next_off


def parse_dns(data: bytes) -> dict:
    """Minimal DNS message parse -> {'questions': [(name,qtype)], 'answers': [(name,type,rdata)]}.

    rdata is decoded for A (dotted IP), AAAA (IPv6), PTR/CNAME/SRV (target name); otherwise b''.
    """
    out = {"questions": [], "answers": []}
    if len(data) < 12:
        return out
    qd, an = struct.unpack("!HH", data[4:8])
    _ns, _ar = struct.unpack("!HH", data[8:12])
    off = 12
    for _ in range(qd):
        name, off = _read_name(data, off)
        if off + 4 > len(data):
            return out
        qtype = struct.unpack("!H", data[off:off + 2])[0]
        off += 4
        out["questions"].append((name, qtype))
    for _ in range(an):
        name, off = _read_name(data, off)
        if off + 10 > len(data):
            break
        rtype = struct.unpack("!H", data[off:off + 2])[0]
        rdlen = struct.unpack("!H", data[off + 8:off + 10])[0]   # skip class(2) + ttl(4)
        off += 10
        rdata = data[off:off + rdlen]
        decoded: object = b""
        if rtype == 1 and rdlen == 4:               # A
            decoded = socket.inet_ntoa(rdata)
        elif rtype == 28 and rdlen == 16:           # AAAA
            try:
                decoded = socket.inet_ntop(socket.AF_INET6, rdata)
            except OSError:
                decoded = ""
        elif rtype in (12, 5):                       # PTR / CNAME
            decoded, _ = _read_name(data, off)
        elif rtype == 33:                            # SRV: prio(2) weight(2) port(2) target
            decoded, _ = _read_name(data, off + 6) if rdlen > 6 else ("", off)
        out["answers"].append((name, rtype, decoded))
        off += rdlen
    return out


# --------------------------------------------------------------------------- #
# Per-protocol parsers -> Announce records                                     #
# --------------------------------------------------------------------------- #
def parse_mdns(data: bytes, src: str) -> list[Announce]:
    msg = parse_dns(data)
    out: list[Announce] = []
    for name, rtype, rdata in msg["answers"]:
        if rtype in (1, 28) and rdata:              # A/AAAA: host -> ip
            out.append(Announce("mdns", src, name=name.rstrip("."), ip=str(rdata), kind="host"))
        elif rtype == 12 and rdata:                 # PTR: a service type / instance
            out.append(Announce("mdns", src, name=str(rdata).rstrip("."),
                                kind=name.rstrip(".")))
    for qname, _qtype in msg["questions"]:          # probes also reveal a device's own name
        if qname:
            out.append(Announce("mdns", src, name=qname.rstrip("."), kind="query"))
    return out


def parse_llmnr(data: bytes, src: str) -> list[Announce]:
    msg = parse_dns(data)
    out: list[Announce] = []
    for qname, _qtype in msg["questions"]:
        if qname:
            out.append(Announce("llmnr", src, name=qname.rstrip("."), kind="query"))
    for name, rtype, rdata in msg["answers"]:
        if rtype == 1 and rdata:
            out.append(Announce("llmnr", src, name=name.rstrip("."), ip=str(rdata), kind="host"))
    return out


def decode_netbios_name(encoded: str) -> str:
    """Reverse RFC1001 first-level encoding: pairs of nibbles offset by 'A'. Trailing pad/suffix
    trimmed. E.g. 'EGFCEFEECACACACACACACACACACACACA' -> 'FRED'."""
    if len(encoded) < 2:
        return ""
    out = bytearray()
    for i in range(0, len(encoded) - 1, 2):
        hi = ord(encoded[i]) - 0x41
        lo = ord(encoded[i + 1]) - 0x41
        if hi < 0 or hi > 15 or lo < 0 or lo > 15:
            break
        out.append((hi << 4) | lo)
    if len(out) >= 16:
        out = out[:15]                # the 16th byte is the NetBIOS service suffix, not the name
    return out.decode("latin-1", "replace").rstrip(" \x00")


def parse_nbtns(data: bytes, src: str) -> list[Announce]:
    """NBT-NS name query: DNS-ish header + a first-level-encoded NetBIOS name in the question."""
    if len(data) < 13 or data[12] != 0x20:          # question name length byte is 0x20 (32)
        # still try: find the encoded 32-byte name after the 12-byte header + length byte
        pass
    if len(data) < 12 + 1 + 32:
        return []
    encoded = data[13:13 + 32].decode("latin-1", "replace")
    name = decode_netbios_name(encoded)
    if not name:
        return []
    return [Announce("nbtns", src, name=name, kind="query")]


_SSDP_FIELDS = ("server", "st", "nt", "location", "usn")


def parse_ssdp(text: str, src: str) -> list[Announce]:
    """SSDP is HTTP-over-UDP (NOTIFY / M-SEARCH response). Pull Server/type/LOCATION headers."""
    fields = {}
    for line in text.split("\r\n"):
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip().lower()
            if k in _SSDP_FIELDS:
                fields[k] = v.strip()
    dtype = fields.get("st") or fields.get("nt") or ""
    if not (dtype or fields.get("server") or fields.get("location")):
        return []
    return [Announce("ssdp", src, name=fields.get("usn", "") or src, kind=dtype,
                     detail=fields.get("server", "") or fields.get("location", ""))]


# --------------------------------------------------------------------------- #
# Aggregation + findings (pure)                                                #
# --------------------------------------------------------------------------- #
def _is_wpad(name: str) -> bool:
    return name.split(".")[0].lower() == "wpad"


def build_findings(announces: list[Announce]) -> list[Finding]:
    hosts: dict[str, str] = {}                      # name/ip -> a short descriptor
    ssdp: dict[str, str] = {}
    poisonable: dict[str, set] = {"llmnr": set(), "nbtns": set()}
    wpad_seen: set[str] = set()

    for a in announces:
        if a.proto in ("llmnr", "nbtns") and a.kind == "query" and a.name:
            poisonable[a.proto].add(a.name)
            if _is_wpad(a.name):
                wpad_seen.add(a.src)
        if a.proto == "mdns" and a.kind == "query" and _is_wpad(a.name):
            wpad_seen.add(a.src)
        if a.ip:
            hosts[a.ip] = a.name or a.ip
        elif a.proto == "mdns" and a.kind == "host" and a.name:
            hosts[a.name] = a.name
        if a.proto == "ssdp":
            ssdp[a.detail or a.src] = a.kind or "UPnP device"

    findings: list[Finding] = []

    if wpad_seen:
        findings.append(Finding(
            id="wpad-lookup-observed",
            title="WPAD name resolution observed on the segment",
            severity=Severity.HIGH,
            category=Category.CONFIG,
            description="One or more hosts are looking up 'wpad' via LLMNR/NBT-NS/mDNS to find a "
                        "proxy auto-config server.",
            impact="An attacker on the segment can answer the WPAD query, serve a malicious "
                   "proxy.pac, and coerce the victim's browser/OS to authenticate to them - a "
                   "classic path to NetNTLM capture and relay.",
            remediation="Create an authoritative internal WPAD DNS record (or disable WPAD), and "
                        "disable LLMNR + NBT-NS via GPO so the name can't be spoofed.",
            affected=sorted(wpad_seen),
            evidence=[Evidence(source="mcast", detail=f"wpad lookups from {', '.join(sorted(wpad_seen))}")],
            references=["https://attack.mitre.org/techniques/T1557/001/"],
            credentialed=False,
        ))

    llmnr_n, nbt_n = poisonable["llmnr"], poisonable["nbtns"]
    if llmnr_n or nbt_n:
        protos = [p for p, s in (("LLMNR", llmnr_n), ("NBT-NS", nbt_n)) if s]
        names = sorted(llmnr_n | nbt_n)
        findings.append(Finding(
            id="llmnr-nbtns-poisonable",
            title=f"Spoofable name resolution active ({' + '.join(protos)})",
            severity=Severity.MEDIUM,
            category=Category.CONFIG,
            description=f"{' and '.join(protos)} name-resolution queries are broadcast on the "
                        "segment (falling back from DNS).",
            impact="An attacker on the segment can answer these with `redness poison` (Responder) "
                   "to capture NetNTLMv2 authentication and relay it - no credentials needed.",
            remediation="Disable LLMNR (GPO: Turn off multicast name resolution) and NBT-NS "
                        "(DHCP option 001 / adapter setting) across the estate.",
            affected=names[:50],
            evidence=[Evidence(source="mcast",
                               detail=f"{len(names)} distinct name(s); e.g. {', '.join(names[:8])}")],
            references=["https://attack.mitre.org/techniques/T1557/001/"],
            credentialed=False,
        ))

    if ssdp:
        findings.append(Finding(
            id="ssdp-upnp-devices",
            title="UPnP / SSDP devices announced on the segment",
            severity=Severity.INFO,
            category=Category.ENUM,
            description="Devices advertise themselves over SSDP/UPnP (routers, media players, "
                        "printers, IoT).",
            affected=sorted(ssdp.values())[:50],
            evidence=[Evidence(source="mcast", detail=f"{len(ssdp)} UPnP device(s)")],
            credentialed=False,
        ))

    if hosts:
        findings.append(Finding(
            id="mcast-inventory",
            title="Hosts / devices discovered passively (link-local)",
            severity=Severity.INFO,
            category=Category.ENUM,
            description="Hosts and devices seen from their own multicast/broadcast announcements, "
                        "with no active scanning.",
            affected=sorted(hosts.values())[:100],
            evidence=[Evidence(source="mcast", detail=f"{len(hosts)} host/device(s) announced")],
            credentialed=False,
        ))
    return findings


def _emit(bus: Optional[EventBus], kind: EventKind, **data) -> None:
    if bus is not None:
        bus.publish(Event(kind=kind, data=data, engine="mcast"))


def emit_graph(bus: Optional[EventBus], announces: list[Announce], root: str = "segment") -> None:
    """Draw discovered hosts/devices as nodes hanging off a segment node."""
    if bus is None or not announces:
        return
    _emit(bus, EventKind.NODE, id=root, label="link-local segment", type="domain")
    seen: set[str] = set()
    for a in announces:
        nid = a.ip or a.name
        if not nid or nid in seen:
            continue
        seen.add(nid)
        _emit(bus, EventKind.NODE, id=nid, label=a.name or a.ip, type="host")
        label = "poisonable" if (a.proto in ("llmnr", "nbtns") and a.kind == "query") else a.proto
        _emit(bus, EventKind.EDGE, src=root, dst=nid, label=label)


# --------------------------------------------------------------------------- #
# Impure listener (sockets). Thin; the value is the pure parsers above.        #
# --------------------------------------------------------------------------- #
def _bind_multicast(group: str, port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", port))
    mreq = struct.pack("=4sl", socket.inet_aton(group), socket.INADDR_ANY)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    s.setblocking(False)
    return s


def _bind_broadcast(port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", port))
    s.setblocking(False)
    return s


def listen(duration: int = 60, *, active: bool = False, bus: Optional[EventBus] = None,
           engagement: str = "REDNESS link-local discovery") -> tuple[Report, list[Announce]]:
    """Listen on the segment for `duration` seconds, aggregate announcements into a Report.

    Passive by default (sends nothing). `active=True` fires one SSDP M-SEARCH to solicit UPnP
    replies. Sockets that fail to bind (privileges / port in use) are skipped with a status.
    """
    import select
    import time

    report = Report(engagement=engagement, target="link-local segment")
    socks: dict[int, str] = {}                      # fileno -> proto
    handlers = {"mdns": parse_mdns, "llmnr": parse_llmnr, "nbtns": parse_nbtns}
    live = []
    for proto, group, port in (("mdns", *MDNS), ("llmnr", *LLMNR)):
        try:
            s = _bind_multicast(group, port)
            socks[s.fileno()] = proto
            live.append(s)
        except OSError as e:
            _emit(bus, EventKind.STATUS, message=f"mcast: {proto} unavailable ({e})")
    for proto, port in (("nbtns", NBTNS_PORT), ("ssdp", SSDP[1])):
        try:
            s = _bind_multicast(SSDP[0], port) if proto == "ssdp" else _bind_broadcast(port)
            socks[s.fileno()] = proto
            live.append(s)
        except OSError as e:
            _emit(bus, EventKind.STATUS, message=f"mcast: {proto} unavailable ({e})")

    by_fileno = {s.fileno(): s for s in live}
    if active:
        _ssdp_msearch(live, bus)
    _emit(bus, EventKind.STATUS,
          message=f"mcast: listening {duration}s on {', '.join(sorted(socks.values()))}")

    announces: list[Announce] = []
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline and live:
        timeout = max(0.0, deadline - time.monotonic())
        try:
            ready, _, _ = select.select(live, [], [], min(timeout, 2.0))
        except (OSError, ValueError):
            break
        for s in ready:
            try:
                data, addr = s.recvfrom(65535)
            except OSError:
                continue
            proto = socks.get(s.fileno(), "")
            src = addr[0]
            recs = (parse_ssdp(data.decode("latin-1", "replace"), src) if proto == "ssdp"
                    else handlers[proto](data, src))
            for r in recs:
                announces.append(r)
    for s in live:
        try:
            s.close()
        except OSError:
            pass

    report.findings = build_findings(announces)
    emit_graph(bus, announces)
    for f in report.findings:
        _emit(bus, EventKind.FINDING, finding=f.to_dict())
    _emit(bus, EventKind.STATUS,
          message=f"mcast: {len(announces)} announcement(s), {len(report.findings)} finding(s)")
    _emit(bus, EventKind.DONE, engine="mcast")
    return report, announces


def _ssdp_msearch(socks, bus) -> None:
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    for s in socks:
        try:
            s.sendto(msg, SSDP)
        except OSError:
            pass
    _emit(bus, EventKind.STATUS, message="mcast: sent SSDP M-SEARCH (--active)")
