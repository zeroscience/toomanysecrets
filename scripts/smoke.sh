#!/usr/bin/env bash
# REDNESS real-DC smoke run (Kali/Linux). Exercises doctor -> scan -> (passive) poison
# against a lab Domain Controller and confirms findings actually flow.
#
# Usage:
#   DC=10.10.0.10 DOMAIN=acme.local USER=jdoe PASS='Password1' \
#   IFACE=eth0 WORDLIST=/usr/share/wordlists/rockyou.txt ./scripts/smoke.sh
#
# Only DC is strictly required. Creds unlock LDAP/Kerberoast/ADCS; without them you
# still get unauthenticated SMB/TLS/AS-REP findings. Run ONLY against a DC you are
# authorized to test.
set -uo pipefail
cd "$(dirname "$0")/.."

DC="${DC:?set DC=<dc ip/host>}"
DOMAIN="${DOMAIN:-}"; USER="${USER:-}"; PASS="${PASS:-}"
IFACE="${IFACE:-}"; WORDLIST="${WORDLIST:-}"
OUT="${OUT:-smoke-report.docx}"; JSON="${JSON:-smoke-findings.json}"

RED="redness"; command -v "$RED" >/dev/null 2>&1 || RED="python -m redness.cli"
say() { printf '\n\033[1;31m== %s ==\033[0m\n' "$*"; }

say "1/4  environment (redness doctor)"
$RED doctor

say "2/4  scan $DC  (creds: ${USER:-<none>})"
AUTH=(); [ -n "$USER" ] && AUTH+=(-u "$USER"); [ -n "$PASS" ] && AUTH+=(-p "$PASS")
[ -n "$DOMAIN" ] && AUTH+=(-d "$DOMAIN")
WL=(); [ -n "$WORDLIST" ] && WL+=(--wordlist "$WORDLIST")
$RED scan --target "$DC" "${AUTH[@]}" "${WL[@]}" --out "$OUT" --json "$JSON"

say "3/4  findings summary (from $JSON)"
if [ -f "$JSON" ]; then
  python - "$JSON" <<'PY'
import json, sys, collections
d = json.load(open(sys.argv[1]))
fs = d.get("findings", [])
by = collections.Counter(f["severity"] for f in fs)
print(f"  total findings: {len(fs)}")
for sev in ("critical","high","medium","low","info"):
    if by.get(sev): print(f"    {sev.upper():>8}: {by[sev]}")
cats = sorted({f["category"] for f in fs})
print("  categories seen:", ", ".join(cats) or "(none)")
hashes = sum(len(f.get("meta",{}).get("hashes",[])) for f in fs)
cracked = [f for f in fs if f["id"]=="credential-cracked"]
print(f"  hashes captured: {hashes}   cracked creds: {len(cracked)}")
print("  report .docx:", "written" if True else "")
PY
else
  echo "  [!] no $JSON produced — check the scan output above"
fi

say "4/4  poison PASSIVE analyze (30s, non-intrusive) — needs Responder + root"
if [ -z "$IFACE" ]; then
  echo "  [skip] set IFACE=eth0 to exercise the poison path (analyze mode only here)."
else
  echo "  running: $RED poison --iface $IFACE --analyze --duration 30 --yes"
  echo "  (analyze = observe only; NO poisoning. Active poison is a manual, in-scope step.)"
  $RED poison --iface "$IFACE" --analyze --duration 30 --yes || \
    echo "  [!] poison analyze needs Responder installed and root (sudo)."
fi

say "done"
echo "Review: $OUT (report), $JSON (findings), and re-run any step with --live to watch the graph."
