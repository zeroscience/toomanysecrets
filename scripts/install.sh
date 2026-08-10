#!/usr/bin/env bash
# One-shot setup for Linux / Kali.  Usage:  ./scripts/install.sh
# git clone ... && cd toomanysecrets && ./scripts/install.sh && redness doctor
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
echo "[*] Creating virtualenv (.venv) with $($PY --version 2>&1)"
"$PY" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[*] Installing REDNESS + engine extras (certipy, impacket)"
python -m pip install --upgrade pip >/dev/null
python -m pip install ".[engines]"

# NetExec has no py3.12 wheel -> install via pipx (its own compatible Python).
if command -v nxc >/dev/null 2>&1 || command -v netexec >/dev/null 2>&1; then
    echo "[+] NetExec already on PATH — SMB/LDAP engines ready."
elif command -v pipx >/dev/null 2>&1; then
    echo "[*] Installing NetExec via pipx"
    pipx install netexec || echo "[!] pipx install netexec failed — install it manually."
else
    echo "[!] NetExec not found and pipx missing. For SMB/LDAP + hash capture:"
    echo "      sudo apt install pipx && pipx install netexec"
fi

echo
echo "[*] Environment check:"
redness doctor || python -m redness.cli doctor
echo
echo "[+] Done. Activate with:  source .venv/bin/activate"
echo "    Then:  redness scan --targets scope.txt --live"
