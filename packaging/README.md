# Packaging - single-file `redness.exe`

```powershell
# from repo root
.\packaging\build.ps1
# -> dist\redness.exe  (runs `demo` as a smoke test)
```

Or manually:

```powershell
pip install pyinstaller
pyinstaller --clean --noconfirm packaging/redness.spec
```

## Requirements / gotchas

- **Python >= 3.10.1** (3.11 / 3.12 recommended). Python **3.10.0** has a bug in the
  standard-library `dis` module that makes PyInstaller's analysis crash with
  `IndexError: tuple index out of range` in `_get_const_info`. Fixed in 3.10.1 -
  upgrade if you hit it (`python --version` to check).
- `python-docx` bundles a default template (`docx/templates/default.docx`). The spec
  uses `collect_all("docx")` to pull that data into the frozen exe; without it the
  reporter raises `PackageNotFoundError` at runtime.
- `upx=True` in the spec compresses the binary **only if UPX is on PATH**; it is
  skipped (not an error) otherwise. Install UPX to shrink the exe.
- The exe is built `console=True` (CLI). Flip to `False` in `redness.spec` when the
  GUI lands.

## Output
`dist\redness.exe` is self-contained - copy it to a Windows jump box, no Python needed:

```
redness.exe demo --out report.docx
redness.exe report findings.json --out report.docx
```
