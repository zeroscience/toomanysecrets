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
