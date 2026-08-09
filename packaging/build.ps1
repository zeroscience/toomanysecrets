# Build single-file redness.exe. Run from repo root:  .\packaging\build.ps1
$ErrorActionPreference = "Stop"

Write-Host "[*] Installing build deps..." -ForegroundColor Cyan
python -m pip install --quiet -r requirements.txt pyinstaller

Write-Host "[*] Cleaning previous build..." -ForegroundColor Cyan
Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue

Write-Host "[*] Building redness.exe..." -ForegroundColor Cyan
pyinstaller --clean --noconfirm packaging/redness.spec

$exe = "dist/redness.exe"
if (Test-Path $exe) {
    Write-Host "[+] Built $exe" -ForegroundColor Green
    Write-Host "[*] Smoke test:" -ForegroundColor Cyan
    & $exe demo --out dist/smoke.docx
} else {
    Write-Error "Build failed: $exe not found"
}
