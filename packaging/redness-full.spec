# PyInstaller spec — SELF-CONTAINED redness.exe with the engines bundled in.
#
# This produces a large (~100MB+) exe that embeds NetExec/Impacket/Certipy so the
# tool works with NOTHING pre-installed on the target box. The default packaging/
# redness.spec stays lean and expects nxc/certipy on PATH; use THIS spec for a
# batteries-included build.
#
#   pip install -r requirements.txt -r requirements-engines.txt pyinstaller
#   pyinstaller --clean --noconfirm packaging/redness-full.spec
#
# STATUS: scaffold. NetExec loads protocol/module code dynamically, so PyInstaller's
# static analysis will miss pieces — expect to iterate on hiddenimports after the
# first build (run `dist/redness.exe scan ...` and add any ModuleNotFoundError here).
# Validate on a machine that has requirements-engines.txt installed.
import os
from PyInstaller.utils.hooks import collect_all, copy_metadata

_REPO = os.path.abspath(os.path.join(SPECPATH, ".."))

datas, binaries, hiddenimports = [], [], []

# Pull in each engine package wholesale (code, data files, dynamic submodules).
for pkg in ("nxc", "impacket", "certipy", "ldap3", "dsinternals", "docx"):
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception:
        pass  # package not installed -> skip (build a lean exe instead)

# Some tools read their own package metadata (entry points / version) at runtime.
for dist in ("netexec", "impacket", "certipy-ad"):
    try:
        datas += copy_metadata(dist)
    except Exception:
        pass

hiddenimports += ["lxml._elementpath"]

# Bundle the live GUI web assets (same as the lean spec).
_WEB_SRC = os.path.join(_REPO, "redness", "live", "web")
datas += [
    (os.path.join(dp, fn), os.path.relpath(dp, _REPO))
    for dp, _dn, files in os.walk(_WEB_SRC) for fn in files
]

block_cipher = None

a = Analysis(
    [os.path.join(SPECPATH, "entry.py")],
    pathex=[_REPO],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="redness-full",
    debug=False, bootloader_ignore_signals=False, strip=False, upx=True,
    upx_exclude=[], runtime_tmpdir=None, console=True,
    disable_windowed_traceback=False, target_arch=None,
    codesign_identity=None, entitlements_file=None,
)
