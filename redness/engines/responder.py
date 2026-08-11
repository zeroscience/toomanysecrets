"""Responder log parser — extract captured NetNTLMv2 hashes.

Pure text parsing over Responder's session log (or any log/console capture that
contains its `NTLMv2-SSP Hash : user::DOMAIN:...` lines). No subprocess, no
network, no root — the poisoner/subprocess wrapper and the `poison` CLI command
live elsewhere (see docs/NETNTLM.md, build order steps 3+).

Design mirrors engines/netexec.py: a pure parser separated from execution, so it
unit-tests against a captured log sample with no Responder / LAN / privileges.
This is step 1 of docs/NETNTLM.md — parser only.
"""
from __future__ import annotations

import re
import shutil

# Responder writes one line per capture; the protocol tag varies (SMB/HTTP/LDAP/
# MSSQL/...) and session-log lines may carry a leading timestamp, e.g.:
#   [SMB]  NTLMv2-SSP Hash     : jdoe::ACME:1122334455667788:<NTproof>:<blob>
# We match the NTLMv2 hash line specifically (NTLMv1 is deliberately ignored —
# we only want the crackable `-m 5600` form) and take the whitespace-free token.
_HASH_LINE = re.compile(r"NTLMv2-SSP\s+Hash\s*:\s*(?P<hash>\S+)", re.I)


def parse_responder_log(text: str) -> list[tuple[str, str]]:
    """Extract captured NetNTLMv2 hashes from Responder log text.

    Returns a list of ``(account, netntlmv2_hash)`` tuples, de-duplicated and in
    first-seen order. ``account`` is ``DOMAIN\\user`` (or just ``user`` when
    Responder logged no domain); ``netntlmv2_hash`` is the full hashcat/john
    ``-m 5600`` string: ``user::DOMAIN:serverchallenge:NTproof:blob``.
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        m = _HASH_LINE.search(line)
        if not m:
            continue
        h = m.group("hash").strip()
        # A NetNTLMv2 hash is `user::DOMAIN:chal:NTproof:blob` — require the `::`
        # separator so stray/partial lines don't slip through.
        if "::" not in h or h in seen:
            continue
        seen.add(h)
        user, _, rest = h.partition("::")
        domain = rest.split(":", 1)[0]
        account = f"{domain}\\{user}" if domain else user
        out.append((account, h))
    return out


# --------------------------------------------------------------------------- #
# Thin Responder wrapper (subprocess construction only — kept pure/testable)  #
# --------------------------------------------------------------------------- #
def responder_binary() -> str | None:
    """Path to the `responder` executable, or None if not installed."""
    return shutil.which("responder") or shutil.which("Responder.py")


def is_available() -> bool:
    """True if Responder is installed (Linux/Kali only — never on the Windows box)."""
    return responder_binary() is not None


def responder_argv(iface: str, *, analyze: bool = False, binary: str | None = None) -> list[str]:
    """Build the Responder command line (no subprocess launched here).

    `-I <iface>` selects the listening interface; `-A` is analyze mode — Responder
    *observes* LLMNR/NBT-NS/mDNS traffic without answering it (passive, non-intrusive).
    Without `-A`, Responder actively poisons name resolution on the segment.
    """
    exe = binary or responder_binary() or "responder"
    argv = [exe, "-I", iface]
    if analyze:
        argv.append("-A")
    return argv
