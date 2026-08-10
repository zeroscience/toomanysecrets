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
# STATUS (validated 2026-08-10 on Windows/py3.12):
#   * The BUILD works: this spec produces dist/redness-full.exe (~29MB) with impacket
#     (library) + certipy + ldap3 bundled, once impacket's examples/ are excluded
#     (Defender locks those hacktool scripts -> [Errno 22] during read; see below).
#   * Two things still block a *working* self-contained exe:
#     1. RUNTIME INVOCATION: the engines shell out to `certipy`/`nxc` binaries via
#        shutil.which, which a frozen exe won't find on PATH even though the modules
#        are bundled. To actually use bundled engines, add an in-process invocation
#        path (e.g. call `certipy.entry:main` with a patched sys.argv) — TODO.
#     2. WINDOWS DEFENDER quarantines core impacket files (impacket/krb5/constants.py)
#        and all examples, so both `pip install` and this build fail until the project/
#        venv folder is added to Defender exclusions (a user action — we can't change AV).
#   * NetExec has no PyPI release for Python 3.12: install via pipx/git, not pip.
# NetExec also loads protocol modules dynamically; expect hiddenimport iteration once
# it's installed and this build actually includes it.
import os
from PyInstaller.utils.hooks import collect_all, copy_metadata

_REPO = os.path.abspath(os.path.join(SPECPATH, ".."))

datas, binaries, hiddenimports = [], [], []

def _drop_impacket_examples(datas_, hidden_):
    # impacket's examples/ are CLI hacktool scripts (ntlmrelayx, GetNPUsers, ...): not
    # needed as a library, and Windows Defender locks/quarantines them, which breaks
    # both pip install and the PyInstaller read. Exclude them.
    hidden_ = [m for m in hidden_ if not m.startswith("impacket.examples")]
    datas_ = [(s, d) for (s, d) in datas_
              if "examples" not in os.path.normpath(s).replace("\\", "/").split("/")]
    return datas_, hidden_


# Pull in each engine package wholesale (code, data files, dynamic submodules).
for pkg in ("nxc", "impacket", "certipy", "ldap3", "dsinternals", "docx"):
    try:
        d, b, h = collect_all(pkg)
        if pkg == "impacket":
            d, h = _drop_impacket_examples(d, h)
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
    excludes=["impacket.examples"],
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
