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
# STATUS (validated 2026-08-10 on Windows/py3.12, after a Defender folder exclusion):
#   * WORKS for certipy: dist/redness-full.exe (~29MB) bundles impacket + certipy + ldap3
#     (impacket examples excluded — Defender locks those). CertipyEngine now runs certipy
#     IN-PROCESS via certipy.entry:main when no `certipy` binary is on PATH, so the frozen
#     exe actually executes it — verified: `redness-full.exe doctor` shows certipy [OK] and
#     a scan prints certipy's banner + attempts the real LDAP connection from inside the exe.
#   * PREREQ: Windows Defender quarantines core impacket files (impacket/krb5/constants.py)
#     + all examples; add the project/venv folder to Defender exclusions before installing
#     requirements-engines.txt (a user action — we don't modify AV/security settings).
#   * netexec: no PyPI release for py3.12 (install via pipx/git). Once installed, give
#     LdapEngine/NetExecEngine the same in-process treatment (nxc entrypoint) and add any
#     hidden imports its dynamic module loading needs.
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
