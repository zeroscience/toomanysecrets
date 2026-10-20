r"""User config - where the external tool binaries live (`Options` in the GUI).

REDNESS orchestrates external tools (nxc, certipy, john, hashcat, nmap, nuclei, ...) and finds them
on PATH. On a packaged .exe - or any box where the tools are not on PATH - the operator can instead
point REDNESS at each binary via the GUI's **Options** panel (or by editing the config file). The
configured directories are prepended to PATH at startup, so every `shutil.which(...)` lookup across
the engines transparently finds them; `resolve()` also honors an exact per-tool path.

Config file: `$REDNESS_CONFIG`, else `~/.redness/config.json`. Shape:
  {"tool_paths": {"nxc": "C:\\tools\\nxc.exe", "nmap": "/usr/bin/nmap", ...}}

Pure + stdlib; unit-tested with a temp config via $REDNESS_CONFIG.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Optional

# The external binaries REDNESS shells out to, in the order the Options panel lists them.
# (name used with shutil.which, friendly label).
KNOWN_TOOLS: list[tuple[str, str]] = [
    ("nxc", "NetExec (nxc)"),
    ("netexec", "NetExec (netexec alias)"),
    ("certipy", "Certipy (AD CS)"),
    ("python", "Python (for impacket / script tools)"),
    ("john", "John the Ripper"),
    ("hashcat", "hashcat"),
    ("responder", "Responder (poison)"),
    ("tshark", "tshark (Wireshark CLI)"),
    ("nmap", "nmap (-sV detection)"),
    ("nuclei", "nuclei (web templates)"),
    ("searchsploit", "searchsploit (Exploit-DB)"),
    ("aircrack-ng", "aircrack-ng (wifi crack)"),
    ("hydra", "hydra (brute)"),
    ("medusa", "medusa (brute)"),
    ("snmpwalk", "snmpwalk (SNMP)"),
]


def config_path() -> Path:
    env = os.environ.get("REDNESS_CONFIG")
    return Path(env) if env else Path.home() / ".redness" / "config.json"


def load() -> dict:
    """Load the config dict; always returns at least {'tool_paths': {}}."""
    try:
        with open(config_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data.setdefault("tool_paths", {})
            if not isinstance(data["tool_paths"], dict):
                data["tool_paths"] = {}
            return data
    except (OSError, ValueError):
        pass
    return {"tool_paths": {}}


def save(cfg: dict) -> bool:
    """Write the config to disk; True on success."""
    p = config_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)
        return True
    except OSError:
        return False


def apply(cfg: Optional[dict] = None) -> list[str]:
    """Prepend each configured binary's directory to PATH so `shutil.which` finds it.

    Returns the directories that were added (front of PATH, de-duplicated)."""
    cfg = cfg or load()
    added: list[str] = []
    for path in (cfg.get("tool_paths") or {}).values():
        if path and os.path.isfile(path):
            d = os.path.dirname(os.path.abspath(path))
            if d and d not in added:
                added.append(d)
    if added:
        parts = os.environ.get("PATH", "").split(os.pathsep)
        front = [d for d in added if d not in parts]
        if front:
            os.environ["PATH"] = os.pathsep.join(front + parts)
    return added


def resolve(name: str, cfg: Optional[dict] = None) -> Optional[str]:
    """The exact configured path for `name` if it exists, else `shutil.which(name)`."""
    cfg = cfg or load()
    p = (cfg.get("tool_paths") or {}).get(name)
    if p and os.path.isfile(p):
        return p
    return shutil.which(name)


def status(cfg: Optional[dict] = None) -> list[dict]:
    """Per-tool {name, label, configured, resolved, available} for the Options panel / doctor."""
    cfg = cfg or load()
    tp = cfg.get("tool_paths") or {}
    out = []
    for name, label in KNOWN_TOOLS:
        resolved = resolve(name, cfg)
        out.append({"name": name, "label": label, "configured": tp.get(name, "") or "",
                    "resolved": resolved or "", "available": bool(resolved)})
    return out


def update_tool_paths(new_paths: dict) -> dict:
    """Merge {name: path} into the saved config (blank values clear), persist, re-apply PATH."""
    cfg = load()
    tp = cfg.get("tool_paths") or {}
    for name, path in (new_paths or {}).items():
        path = (path or "").strip()
        if path:
            tp[name] = path
        else:
            tp.pop(name, None)
    cfg["tool_paths"] = tp
    save(cfg)
    apply(cfg)
    return cfg
