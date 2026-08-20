"""Built-in weak-password wordlist for opportunistic offline cracking.

`crack.run_cracking()` falls back to this when no `--wordlist` is given and a cracker
(hashcat/john) is on PATH, so a scan/poison auto-cracks *egregiously* weak credentials
without the operator supplying rockyou. It is intentionally small and high-signal
(a few hundred candidates, sub-second): for serious cracking, pass `--wordlist rockyou.txt`.

Provenance: every entry below is **hand-curated from well-known weak / default / seasonal
password patterns** - generic security knowledge. It is NOT derived from, and does not copy,
any leaked dump (e.g. rockyou) or third-party compiled list, so there is no unclear-provenance
or licensing concern. Keep it that way: only add patterns that are common knowledge.
"""
from __future__ import annotations

import os

# Literal core - classic weak, default, keyboard-walk, and corporate/service patterns.
_CORE: tuple[str, ...] = (
    # classic weak / most-common
    "password", "Password", "Password1", "Password1!", "Password12", "Password123",
    "Password123!", "passw0rd", "Passw0rd", "Passw0rd!", "P@ssw0rd", "P@ssw0rd!",
    "P@ssword", "P@ssword1", "P@ssword123", "password1", "password123", "Pa$$w0rd",
    # welcome / changeme / letmein
    "welcome", "Welcome", "Welcome1", "Welcome1!", "Welcome123", "Welcome123!",
    "Welcome@123", "welcome1", "changeme", "Changeme1", "Changeme123", "ChangeMe123!",
    "letmein", "Letmein1", "Letmein123", "letmein1",
    # admin / default accounts
    "admin", "Admin", "Admin1", "Admin123", "Admin123!", "admin123", "administrator",
    "Administrator1", "root", "toor", "guest", "Guest1", "default", "Default1",
    "oracle", "postgres", "sa", "cisco", "Cisco123",
    # keyboard walks
    "qwerty", "Qwerty1", "Qwerty123", "Qwerty123!", "qwerty123", "qwertyuiop",
    "1qaz2wsx", "1qaz@WSX", "1q2w3e4r", "1q2w3e4r5t", "zaq12wsx", "asdfghjkl",
    "qazwsx", "qweasd", "q1w2e3r4",
    # numeric
    "123456", "1234567", "12345678", "123456789", "1234567890", "12345",
    "111111", "000000", "654321", "121212", "112233", "123123", "159753",
    # pop / sports / names
    "iloveyou", "monkey", "dragon", "football", "baseball", "basketball",
    "superman", "batman", "master", "shadow", "trustno1", "sunshine",
    "princess", "flower", "hello", "hello123", "freedom", "whatever", "ninja",
    "abc123", "Abc123", "Abc123!", "abcd1234", "Abcd1234", "Abcd1234!",
    # corporate / service-account flavored
    "Company1", "Company123", "Company123!", "Corp123", "Corp123!",
    "Secret1", "Secret123", "Secure1", "Secure123", "Test123", "Test123!",
    "Temp123", "Temp123!", "Backup1", "Backup123", "Service1", "Service123",
    "Windows1", "Windows123", "Domain1", "Domain123", "Server123", "Login123",
    "Money123", "Access123", "System123",
)

# Programmatic seasonal / year patterns - the single most common corporate-reset shape.
_SEASONS: tuple[str, ...] = ("Spring", "Summer", "Autumn", "Fall", "Winter")
_YEARS: tuple[str, ...] = tuple(str(y) for y in range(2019, 2027))
_SUFFIXES: tuple[str, ...] = ("", "!", "1", "1!", "123", "@")
_SEASONAL: tuple[str, ...] = tuple(
    f"{season}{year}{suffix}"
    for season in _SEASONS
    for year in _YEARS
    for suffix in _SUFFIXES
)


def _dedupe(*groups: tuple[str, ...]) -> tuple[str, ...]:
    """Concatenate groups, dropping empties and duplicates, preserving first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for group in groups:
        for item in group:
            if item and item not in seen:
                seen.add(item)
                out.append(item)
    return tuple(out)


# The public constant: a deduped, order-stable tuple of weak-password candidates.
BASIC_WORDLIST: tuple[str, ...] = _dedupe(_CORE, _SEASONAL)


def write_basic_wordlist(dest_dir: str) -> str:
    """Write BASIC_WORDLIST (one candidate per line) to <dest_dir>/_basic_wordlist.txt.

    Returns the path. `crack.crack()` needs an on-disk wordlist file, so run_cracking
    materializes the built-in list here before invoking hashcat/john.
    """
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, "_basic_wordlist.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(BASIC_WORDLIST) + "\n")
    return path
