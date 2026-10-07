r"""SSH audit engine - banner + weak crypto negotiation (read-only, TCP 22).

Reads the SSH identification banner and the server's SSH_MSG_KEXINIT (the algorithm offer) and
flags weak key-exchange, ciphers, MACs and host-key types - CBC-mode ciphers, SHA-1 kex/MACs,
arcfour/3des/blowfish, ssh-rsa (SHA-1 sig) / ssh-dss. Read-only: it never authenticates, it only
reads the banner and the unauthenticated KEXINIT the server sends to every client.

Pure parsers (banner regex + the KEXINIT name-list layout) + an injected probe, so it unit-tests
against captured bytes with no server. Port-gated to TCP/22 in the default scan. Findings reuse
`Category.CONFIG`.
"""
from __future__ import annotations

import re
import socket
import struct
from typing import Callable, Optional

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target

_NAMELISTS = ("kex", "host_key", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c",
              "comp_c2s", "comp_s2c", "lang_c2s", "lang_s2c")

# Weak-algorithm matchers (case-insensitive substrings / patterns).
_WEAK_KEX = re.compile(r"(?i)(sha1$|group1-|group-exchange-sha1|group14-sha1|rsa1024)")
_WEAK_ENC = re.compile(r"(?i)(-cbc$|3des|arcfour|blowfish|cast128|^des$|none)")
_WEAK_MAC = re.compile(r"(?i)(md5|sha1|-96$|umac-64)")
_WEAK_HOSTKEY = re.compile(r"(?i)^(ssh-rsa|ssh-dss)$")


def parse_banner(data: bytes) -> Optional[str]:
    """The SSH identification string (first 'SSH-...' line), or None."""
    text = data.decode("latin-1", "replace")
    m = re.search(r"(SSH-\d+\.\d+-[^\r\n]+)", text)
    return m.group(1).strip() if m else None


def parse_kexinit(data: bytes) -> Optional[dict]:
    """Parse an SSH_MSG_KEXINIT packet into its algorithm name-lists, or None."""
    if len(data) < 22:
        return None
    # the KEXINIT payload starts at offset 5 (after packet_length(4) + padding_length(1));
    # its first byte is the message type SSH_MSG_KEXINIT = 0x14.
    if data[5:6] == b"\x14":
        payload = data[5:]
    else:
        idx = data.find(b"\x14")                    # fall back: banner may precede the packet
        if idx < 5:
            return None
        payload = data[idx:]
    off = 1 + 16                                   # msg type (1) + cookie (16)
    out: dict[str, list[str]] = {}
    for name in _NAMELISTS:
        if off + 4 > len(payload):
            return None
        (ln,) = struct.unpack_from(">I", payload, off)
        off += 4
        val = payload[off:off + ln].decode("latin-1", "replace")
        off += ln
        out[name] = [a for a in val.split(",") if a]
    return out


def weak_algorithms(kex: dict) -> dict:
    """Return {kex, ciphers, macs, host_key} lists of the WEAK algorithms the server offers."""
    ciphers = sorted(set(kex.get("enc_c2s", []) + kex.get("enc_s2c", [])))
    macs = sorted(set(kex.get("mac_c2s", []) + kex.get("mac_s2c", [])))
    return {
        "kex": [a for a in kex.get("kex", []) if _WEAK_KEX.search(a)],
        "ciphers": [a for a in ciphers if _WEAK_ENC.search(a)],
        "macs": [a for a in macs if _WEAK_MAC.search(a)],
        "host_key": [a for a in kex.get("host_key", []) if _WEAK_HOSTKEY.search(a)],
    }


def _default_probe(host: str, timeout: float = 5.0) -> tuple[bytes, bytes]:
    """Read the banner, send our ident, read the server KEXINIT. Returns (banner, kexinit)."""
    try:
        with socket.create_connection((host, 22), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(512)
            s.sendall(b"SSH-2.0-REDNESS\r\n")
            kex = b""
            try:
                kex = s.recv(4096)
            except OSError:
                pass
            return banner, kex
    except OSError:
        return b"", b""


class SshEngine(Engine):
    """SSH banner + weak-crypto audit. Port-gated to TCP/22; read-only (no authentication)."""

    name = "ssh"

    def __init__(self, probe: Optional[Callable[[str], tuple[bytes, bytes]]] = None):
        self._probe = probe or (lambda host: _default_probe(host))

    def is_available(self) -> bool:
        return True

    def run(self, target: Target) -> list[Finding]:
        banner_raw, kex_raw = self._probe(target.host)
        banner = parse_banner(banner_raw)
        if banner is None:
            return []
        out: list[Finding] = [Finding(
            id="ssh-server", title=f"SSH server: {banner}", severity=Severity.INFO,
            category=Category.CONFIG, description=f"SSH is reachable at {target.host}.",
            impact="Service/version fingerprint for the host.",
            remediation="Keep OpenSSH current; restrict SSH to management networks.",
            affected=[target.host],
            evidence=[Evidence(source="ssh", detail=banner)],
            meta={"service": "ssh", "banner": banner})]
        kex = parse_kexinit(kex_raw)
        if kex:
            weak = weak_algorithms(kex)
            flat = [f"{k}: {', '.join(v)}" for k, v in weak.items() if v]
            if flat:
                out.append(Finding(
                    id="ssh-weak-crypto",
                    title="SSH offers weak cryptographic algorithms",
                    severity=Severity.MEDIUM, category=Category.CONFIG,
                    description=f"The SSH server at {target.host} offers legacy/weak algorithms in "
                                f"its key exchange.",
                    impact="Weak ciphers (CBC), SHA-1 kex/MACs, or ssh-rsa/ssh-dss host keys enable "
                           "downgrade, integrity and (for broken primitives) decryption attacks.",
                    remediation="Restrict KexAlgorithms/Ciphers/MACs/HostKeyAlgorithms to modern "
                                "sets (curve25519, aes-gcm/ctr, hmac-sha2, ssh-ed25519/rsa-sha2); "
                                "disable CBC, arcfour, 3des, SHA-1 and ssh-dss.",
                    affected=[target.host],
                    evidence=[Evidence(source="ssh", detail="; ".join(flat))],
                    references=["https://attack.mitre.org/techniques/T1040/"],
                    meta={"service": "ssh", "weak": weak},
                ))
        return out
