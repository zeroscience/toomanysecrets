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
