# PyInstaller spec — single-file redness.exe
#
#   pip install pyinstaller
#   pyinstaller packaging/redness.spec        (run from repo root)
#
# python-docx bundles a default template (docx/templates/default.docx) and other
# package data; collect_all pulls those in so the frozen exe can render reports.
import os
from PyInstaller.utils.hooks import collect_all

# Repo root (SPECPATH is the dir holding this spec, i.e. packaging/).
_REPO = os.path.abspath(os.path.join(SPECPATH, ".."))

_docx_datas, _docx_bins, _docx_hidden = collect_all("docx")

# Bundle the live 3D graph web assets (index.html + vendored 3d-force-graph) so the
# frozen exe can serve `redness live`. Dest mirrors the package layout, which is what
# bridge._web_dir() looks for under sys._MEIPASS.
_WEB_SRC = os.path.join(_REPO, "redness", "live", "web")
_web_datas = [
    (os.path.join(dirpath, fn), os.path.relpath(dirpath, _REPO))
    for dirpath, _dirs, files in os.walk(_WEB_SRC)
    for fn in files
]

block_cipher = None

a = Analysis(
    # Entry lives OUTSIDE the package and imports it absolutely, so the frozen exe
    # doesn't hit "attempted relative import with no known parent package".
    [os.path.join(SPECPATH, "entry.py")],
    pathex=[_REPO],            # so `import redness...` resolves during analysis
    binaries=_docx_bins,
    datas=_docx_datas + _web_datas,
    hiddenimports=_docx_hidden + ["lxml._elementpath"],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="redness",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,          # CLI tool; set False only when the GUI lands
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
