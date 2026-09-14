# One-shot setup for Windows.  Usage:  .\scripts\install.ps1
# git clone ...; cd toomanysecrets; .\scripts\install.ps1; .\.venv\Scripts\redness.exe doctor
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "[*] Creating virtualenv (.venv)" -ForegroundColor Cyan
py -3 -m venv .venv
$py = ".\.venv\Scripts\python.exe"

Write-Host "[*] Installing REDNESS + engine extras (certipy, impacket)" -ForegroundColor Cyan
& $py -m pip install --upgrade pip | Out-Null
& $py -m pip install ".[engines]"

# NetExec has no py3.12 wheel -> install via pipx (its own compatible Python).
if (Get-Command nxc -ErrorAction SilentlyContinue) {
    Write-Host "[+] NetExec already on PATH - SMB/LDAP engines ready." -ForegroundColor Green
} elseif (Get-Command pipx -ErrorAction SilentlyContinue) {
    Write-Host "[*] Installing NetExec via pipx" -ForegroundColor Cyan
    try { pipx install netexec } catch { Write-Host "[!] pipx install netexec failed - install manually." -ForegroundColor Yellow }
} else {
    Write-Host "[!] NetExec + pipx missing. For SMB/LDAP + hash capture:" -ForegroundColor Yellow
    Write-Host "      py -m pip install --user pipx; pipx install netexec"
}

Write-Host "`n[*] Environment check:" -ForegroundColor Cyan
& ".\.venv\Scripts\redness.exe" doctor

Write-Host "`n[+] Done. Run with:  .\.venv\Scripts\redness.exe scan --targets examples/scope.txt --live" -ForegroundColor Green
Write-Host "    (Windows note: nxc is painful here - your Kali VM with nxc installed is the easier operator box.)"
