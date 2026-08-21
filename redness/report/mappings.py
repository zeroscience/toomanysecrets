"""Finding -> framework mappings for the report (MITRE ATT&CK for now).

Kept as plain data so it is easy to review and extend. Compliance frameworks
(CIS / ISO 27001 / NIS2) can be added here later as their own dicts.
"""
from __future__ import annotations

from typing import Optional

# finding id -> (technique id, technique name). AD CS ESC1..17 all map to T1649
# and are handled by the adcs-esc prefix in mitre_for().
MITRE: dict[str, tuple[str, str]] = {
    "smb-signing-not-required": ("T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay"),
    "smbv1-enabled": ("T1210", "Exploitation of Remote Services"),
    "smb-null-or-guest-auth": ("T1135", "Network Share Discovery"),
    "smb-writable-share": ("T1135", "Network Share Discovery"),
    "krb-asrep-roastable": ("T1558.004", "AS-REP Roasting"),
    "krb-kerberoastable": ("T1558.003", "Kerberoasting"),
    "credential-cracked": ("T1110.002", "Brute Force: Password Cracking"),
    "netntlm-captured": ("T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay"),
    "llmnr-nbtns-poisoning-possible": ("T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay"),
}
_ADCS = ("T1649", "Steal or Forge Authentication Certificates")


def mitre_for(finding_id: str) -> Optional[tuple[str, str]]:
    """Return (technique id, name) for a finding id, or None if unmapped."""
    if finding_id in MITRE:
        return MITRE[finding_id]
    if finding_id.startswith("adcs-esc"):
        return _ADCS
    return None


# Indicative control mappings. Reviewed against CIS Controls v8, ISO/IEC 27001:2022
# Annex A, and NIS2 Article 21(2) measures. These are pointers for the report, not a
# certified assessment - always confirm against your framework version.
COMPLIANCE: dict[str, dict[str, str]] = {
    "smb-signing-not-required": {"CIS": "4.1 Secure Configuration", "ISO": "A.8.20 Network security",
                                 "NIS2": "Art.21(2)(i) access control"},
    "smbv1-enabled": {"CIS": "4.1 Secure Configuration", "ISO": "A.8.9 Configuration management",
                      "NIS2": "Art.21(2)(g) cyber hygiene"},
    "smb-null-or-guest-auth": {"CIS": "6.1 Access Granting", "ISO": "A.8.3 Information access restriction",
                               "NIS2": "Art.21(2)(i) access control"},
    "smb-writable-share": {"CIS": "3.3 Data Access Control", "ISO": "A.8.3 Information access restriction",
                           "NIS2": "Art.21(2)(i) access control"},
    "krb-asrep-roastable": {"CIS": "4.7 Manage Default Accounts", "ISO": "A.8.5 Secure authentication",
                            "NIS2": "Art.21(2)(i) access control"},
    "krb-kerberoastable": {"CIS": "5.2 Use Unique Passwords", "ISO": "A.8.5 Secure authentication",
                           "NIS2": "Art.21(2)(i) access control"},
    "credential-cracked": {"CIS": "5.2 Use Unique Passwords", "ISO": "A.8.5 Secure authentication",
                           "NIS2": "Art.21(2)(i) access control"},
    "netntlm-captured": {"CIS": "4.1 Secure Configuration", "ISO": "A.8.20 Network security",
                         "NIS2": "Art.21(2)(i) access control"},
    "llmnr-nbtns-poisoning-possible": {"CIS": "4.1 Secure Configuration", "ISO": "A.8.20 Network security",
                                       "NIS2": "Art.21(2)(i) access control"},
}
_C_TLS = {"CIS": "3.10 Encrypt Data in Transit", "ISO": "A.8.24 Use of cryptography",
          "NIS2": "Art.21(2)(h) cryptography"}
_C_ADCS = {"CIS": "6.8 Role-Based Access Control", "ISO": "A.5.15 Access control",
           "NIS2": "Art.21(2)(i) access control"}

FRAMEWORKS = ("CIS", "ISO", "NIS2")


def compliance_for(finding_id: str) -> Optional[dict[str, str]]:
    """Return {CIS, ISO, NIS2} control pointers for a finding id, or None if unmapped."""
    if finding_id in COMPLIANCE:
        return COMPLIANCE[finding_id]
    if finding_id.startswith("adcs-esc"):
        return _C_ADCS
    if finding_id.startswith("tls-"):
        return _C_TLS
    return None
