"""TLS engine - weak protocols, ciphers, and certificate issues on AD TLS services.

Pure-Python (stdlib `ssl`), so it needs no external tool and runs anywhere - the
one engine that produces findings on a box with neither nxc nor certipy installed.

Scans AD-relevant TLS ports (LDAPS 636, Global-Catalog-SSL 3269, ADCS web 443) and flags:
  - legacy protocols (TLS 1.0 / 1.1) still negotiable
  - weak cipher suites (RC4 / 3DES / DES / NULL / EXPORT / CBC / < 128-bit)
  - expired or soon-to-expire certificates; self-signed certificates
  - weak cert signature (SHA-1/MD5) and small keys (< 2048-bit)  [only if `cryptography` present]

The analysis is pure and separated from the socket I/O so it unit-tests without a server.
"""
from __future__ import annotations

import socket
import ssl
import tempfile
import time
from typing import Optional

from ..findings import Category, Evidence, Finding, Severity
from .base import Engine, Target

# AD services that speak TLS. (port, label)
DEFAULT_TLS_PORTS: list[tuple[int, str]] = [
    (636, "LDAPS"),
    (3269, "LDAP Global Catalog (SSL)"),
    (443, "ADCS web enrollment / HTTPS"),
]

_LEGACY = {"TLSv1", "TLSv1.1"}
_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON")


# --------------------------------------------------------------------------- #
# Pure analysis (unit-testable)                                               #
# --------------------------------------------------------------------------- #
def eval_protocols(host: str, port: int, supported: dict[str, bool]) -> list[Finding]:
    where = f"{host}:{port}"
    legacy = sorted(v for v in _LEGACY if supported.get(v))
    if not legacy:
        return []
    return [Finding(
        id="tls-legacy-protocol",
        title="Legacy TLS protocol enabled",
        severity=Severity.MEDIUM,
        category=Category.TLS,
        description=f"{where} negotiates deprecated protocol(s): {', '.join(legacy)}.",
        impact="TLS 1.0/1.1 are deprecated and vulnerable to downgrade and known attacks "
               "(BEAST/POODLE-class); many compliance regimes forbid them.",
        remediation="Disable TLS 1.0 and 1.1; require TLS 1.2+ (AEAD suites) on this service.",
        affected=[where],
        evidence=[Evidence(source="tls", detail=f"negotiated {', '.join(legacy)}")],
        references=["https://datatracker.ietf.org/doc/rfc8996/"],
        credentialed=False,
    )]


def eval_cipher(host: str, port: int, cipher: Optional[tuple]) -> list[Finding]:
    if not cipher:
        return []
    name, _ver, bits = (cipher + (None, None, None))[:3]
    where = f"{host}:{port}"
    reasons = []
    up = (name or "").upper()
    for tok in _WEAK_CIPHER_TOKENS:
        if tok in up:
            reasons.append(tok)
    if "CBC" in up:
        reasons.append("CBC")
    if isinstance(bits, int) and bits < 128:
        reasons.append(f"{bits}-bit")
    if not reasons:
        return []
    return [Finding(
        id="tls-weak-cipher",
        title="Weak TLS cipher negotiated",
        severity=Severity.MEDIUM,
        category=Category.TLS,
        description=f"{where} negotiated a weak cipher: {name} ({', '.join(reasons)}).",
        impact="Weak ciphers (RC4/3DES/CBC/export/<128-bit) are susceptible to known "
               "cryptographic attacks and traffic decryption.",
        remediation="Restrict to modern AEAD suites (e.g. AES-GCM, CHACHA20-POLY1305) on TLS 1.2+.",
        affected=[where],
        evidence=[Evidence(source="tls", detail=f"cipher {name} ({bits}-bit)")],
        credentialed=False,
    )]


def eval_certificate(
    host: str, port: int, *,
    not_after_epoch: Optional[float] = None,
    self_signed: Optional[bool] = None,
    sig_alg: Optional[str] = None,
    key_bits: Optional[int] = None,
    now: Optional[float] = None,
) -> list[Finding]:
    where = f"{host}:{port}"
    now = now if now is not None else time.time()
    out: list[Finding] = []

    if not_after_epoch is not None:
        if not_after_epoch < now:
            out.append(Finding(
                id="tls-cert-expired", title="TLS certificate expired",
                severity=Severity.HIGH, category=Category.TLS,
                description=f"The certificate presented on {where} has expired.",
                impact="Expired certificates break trust and enable MITM if clients ignore errors.",
                remediation="Reissue and deploy a valid certificate; automate renewal.",
                affected=[where], credentialed=False,
                evidence=[Evidence(source="tls", detail="notAfter in the past")],
            ))
        elif not_after_epoch < now + 30 * 86400:
            out.append(Finding(
                id="tls-cert-expiring", title="TLS certificate expiring soon",
                severity=Severity.LOW, category=Category.TLS,
                description=f"The certificate on {where} expires within 30 days.",
                impact="Imminent expiry risks an outage and rushed, error-prone renewal.",
                remediation="Renew ahead of expiry; automate renewal.",
                affected=[where], credentialed=False,
                evidence=[Evidence(source="tls", detail="notAfter < 30 days")],
            ))

    if self_signed:
        out.append(Finding(
            id="tls-cert-self-signed", title="Self-signed TLS certificate",
            severity=Severity.LOW, category=Category.TLS,
            description=f"{where} presents a self-signed certificate.",
            impact="Self-signed certs aren't anchored to a trusted CA; users are trained to "
                   "click through warnings, weakening MITM detection.",
            remediation="Issue the certificate from the enterprise/PKI CA and distribute trust.",
            affected=[where], credentialed=False,
            evidence=[Evidence(source="tls", detail="subject == issuer")],
        ))

    if sig_alg and any(w in sig_alg.lower() for w in ("sha1", "md5")):
        out.append(Finding(
            id="tls-weak-cert-sig", title="Weak certificate signature algorithm",
            severity=Severity.MEDIUM, category=Category.TLS,
            description=f"The certificate on {where} is signed with {sig_alg}.",
            impact="SHA-1/MD5 signatures are collision-prone and deprecated for certificates.",
            remediation="Reissue the certificate with a SHA-256+ signature.",
            affected=[where], credentialed=False,
            evidence=[Evidence(source="tls", detail=sig_alg)],
        ))

    if isinstance(key_bits, int) and key_bits and key_bits < 2048:
        out.append(Finding(
            id="tls-weak-cert-key", title="Weak certificate key size",
            severity=Severity.MEDIUM, category=Category.TLS,
            description=f"The certificate on {where} uses a {key_bits}-bit key.",
            impact="Keys below 2048-bit RSA are considered insufficient.",
            remediation="Reissue with a 2048-bit+ RSA (or 256-bit+ EC) key.",
            affected=[where], credentialed=False,
            evidence=[Evidence(source="tls", detail=f"{key_bits}-bit key")],
        ))
    return out


# --------------------------------------------------------------------------- #
# Socket I/O                                                                   #
# --------------------------------------------------------------------------- #
_PROTOCOLS = {
    "TLSv1": getattr(ssl.TLSVersion, "TLSv1", None),
    "TLSv1.1": getattr(ssl.TLSVersion, "TLSv1_1", None),
    "TLSv1.2": getattr(ssl.TLSVersion, "TLSv1_2", None),
    "TLSv1.3": getattr(ssl.TLSVersion, "TLSv1_3", None),
}


class TLSEngine(Engine):
    name = "tls"

    def __init__(self, ports: Optional[list[tuple[int, str]]] = None, timeout: float = 5.0):
        self.ports = ports or DEFAULT_TLS_PORTS
        self.timeout = timeout

    def is_available(self) -> bool:
        return True                      # pure stdlib

    def _port_open(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                return True
        except OSError:
            return False

    def _supports(self, host: str, port: int, ver) -> bool:
        if ver is None:
            return False
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ver
            ctx.maximum_version = ver
        except (ValueError, OSError):
            return False                 # this build won't even offer that version
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    return True
        except (ssl.SSLError, OSError):
            return False

    def _cipher(self, host: str, port: int) -> Optional[tuple]:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    return ss.cipher()
        except (ssl.SSLError, OSError):
            return None

    def _cert(self, host: str, port: int) -> tuple[Optional[float], Optional[bool], Optional[str], Optional[int]]:
        """Return (not_after_epoch, self_signed, sig_alg, key_bits) best-effort."""
        try:
            pem = ssl.get_server_certificate((host, port), timeout=self.timeout)
        except (ssl.SSLError, OSError, TypeError):
            # older Pythons: get_server_certificate has no timeout kwarg
            try:
                pem = ssl.get_server_certificate((host, port))
            except (ssl.SSLError, OSError):
                return None, None, None, None

        not_after = self_signed = sig_alg = key_bits = None
        # stdlib parse: notAfter + subject/issuer (self-signed) via the private decoder.
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
                fh.write(pem)
                path = fh.name
            d = ssl._ssl._test_decode_cert(path)          # type: ignore[attr-defined]
            if d.get("notAfter"):
                not_after = ssl.cert_time_to_seconds(d["notAfter"])
            if d.get("subject") and d.get("issuer"):
                self_signed = d["subject"] == d["issuer"]
        except Exception:
            pass
        finally:
            try:
                import os
                os.unlink(path)
            except Exception:
                pass

        # richer parse only if cryptography is available (optional dependency).
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa
            cert = x509.load_pem_x509_certificate(pem.encode())
            sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
            pk = cert.public_key()
            if isinstance(pk, rsa.RSAPublicKey):
                key_bits = pk.key_size
        except Exception:
            pass
        return not_after, self_signed, sig_alg, key_bits

    def run(self, target: Target) -> list[Finding]:
        host = target.host
        findings: list[Finding] = []
        for port, label in self.ports:
            if not self._port_open(host, port):
                continue
            self.emit_probe(target=f"{host}:{port}", test="tls")
            supported = {name: self._supports(host, port, ver) for name, ver in _PROTOCOLS.items()}
            findings += eval_protocols(host, port, supported)
            findings += eval_cipher(host, port, self._cipher(host, port))
            na, ss_flag, sig, kb = self._cert(host, port)
            findings += eval_certificate(
                host, port, not_after_epoch=na, self_signed=ss_flag, sig_alg=sig, key_bits=kb,
            )
            findings.append(Finding(
                id="enum-tls-service", title=f"TLS service ({label})",
                severity=Severity.INFO, category=Category.ENUM,
                description=f"TLS service reachable on {host}:{port} ({label}).",
                affected=[f"{host}:{port}"], credentialed=False,
                evidence=[Evidence(source="tls", detail=f"protocols: "
                          f"{', '.join(k for k, v in supported.items() if v) or 'none negotiated'}")],
            ))
        return findings
