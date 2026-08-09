"""Scope parsing — shared by the CLI (`--targets`) and, later, the GUI file picker.

A scope file is one target per line: an IP, hostname, or CIDR. Blank lines are
ignored; `#` starts a comment (whole-line or inline). Order is preserved and
duplicates are removed.
"""
from __future__ import annotations


def parse_scope(text: str) -> list[str]:
    """Parse scope text into an ordered, de-duplicated list of targets."""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:                       # strip inline comment
            line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return list(dict.fromkeys(out))           # dedupe, keep first-seen order


def load_scope(path: str) -> list[str]:
    """Read and parse a scope file."""
    with open(path, encoding="utf-8") as fh:
        return parse_scope(fh.read())


def merge_targets(single: str | None, scope_path: str | None) -> list[str]:
    """Combine a single --target with a --targets file, deduped, order-preserving."""
    targets: list[str] = []
    if single:
        targets.append(single.strip())
    if scope_path:
        targets.extend(load_scope(scope_path))
    return list(dict.fromkeys(t for t in targets if t))
