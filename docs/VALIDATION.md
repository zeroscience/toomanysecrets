# REDNESS — first real-DC validation checklist

> Everything in REDNESS is unit-tested **offline** (pure parsers vs captured tool output).
> This is the step that proves it **in the field** against a live Domain Controller —
> where real tool output, versions, and network behavior surface gaps the offline tests
> can't. Do this on a **lab DC you own / are authorized to test**, from the Kali operator box.

## 0. Stand up a lab (pick one)
- **[GOAD — Game of Active Directory](https://github.com/Orange-Cyberdefense/GOAD)** — a
  ready-made vulnerable AD forest (ESC templates, roastable accounts, no SMB signing…).
  Best coverage for exercising every engine. Heavier to deploy.
- **A throwaway Windows Server DC VM** — `Install-ADDSForest`, add a couple users, mark one
  `Do not require Kerberos preauth` (AS-REP), give one an SPN (Kerberoast), stand up AD CS
  with a vulnerable template if you want ADCS findings. Lighter, quicker.

## 1. Install on Kali
```bash
git clone https://github.com/zeroscience/toomanysecrets.git
cd toomanysecrets
./scripts/install.sh
source .venv/bin/activate
redness doctor          # nxc + certipy + tls should be OK; responder for poison
```
`nxc` is native on Kali, so the SMB/LDAP engines light up here (the Windows pain point
doesn't apply). Install `responder` (`sudo apt install responder`) and a cracker
(`hashcat`) if you want the full loop.

## 2. One-shot smoke run
```bash
DC=10.10.0.10 DOMAIN=acme.local USER=jdoe PASS='Password1' \
IFACE=eth0 WORDLIST=/usr/share/wordlists/rockyou.txt \
./scripts/smoke.sh
```
It runs `doctor` → `scan` (writes report + findings JSON) → prints a severity/category
summary → a **passive** `poison --analyze` (no poisoning). Add `--live` to any step to watch
the 3D graph.

## 3. What to verify per engine (the real test)
Run credentialed **and** uncredentialed (drop `-u/-p`) to see both surfaces.

| Engine | Command flag path | Expect on a vulnerable lab | ✅ / notes |
|--------|-------------------|-----------------------------|-----------|
| SMB (nxc) | `scan --target DC` | `smb-signing-not-required`, maybe `smbv1-enabled`, `smb-null-or-guest-auth`, shares | |
| LDAP/Kerberos (nxc) | `scan ... -u -p -d` | `enum-domain-users`, `krb-asrep-roastable`, `krb-kerberoastable` (+ hashes in loot/) | |
| ADCS (certipy) | `scan ... -u -p -d` | `adcs-escN` for each vulnerable template | |
| TLS (stdlib) | `scan --target DC` | `tls-*` on 636/3269/443 if weak proto/cipher/cert | |
| Cracking | add `--wordlist rockyou.txt` | `credential-cracked` (CRITICAL) for weak passwords | |
| Poison (Responder) | `poison --iface eth0` (in lab!) | `netntlm-captured`, `llmnr-nbtns-poisoning-possible` | |

**Poison note:** run `--analyze` first (observe only). Active poison affects **other hosts**
on the segment — only in the isolated lab, `--iface` pinned, time-boxed, after the YES prompt.

## 4. Cross-check the outputs
- **Report** (`--out report.docx`): opens cleanly; exec-summary counts match; each finding has
  impact + remediation; enumeration appendix present.
- **Findings JSON** (`--json`): re-render with `redness report smoke-findings.json --out r.docx`
  (round-trips the schema).
- **Live graph** (`--live`): domain → hosts/users/shares/CA/templates spawn; nodes recolor by
  severity; cracked creds show up (currently via report, not yet streamed to the graph).
- **Loot** (`loot/`): `krb5asrep.txt` / `krb5tgs.txt` / `netntlmv2.txt` are valid hashcat input
  (`hashcat -m 18200/13100/5600 loot/<file> rockyou.txt`).

## 5. Record results
Note tool versions (`nxc --version`, `certipy version`, Responder), the lab, and anything
that **didn't** parse as expected — those are the follow-up issues. File them (or drop them in
`docs/DECISIONS.md`) so the parser fixes are captured. Real DC output is the source of truth;
if a parser misses a line format, add a captured sample to the matching `tests/` file.

## Likely first-run gaps to watch for
- **nxc output format drift** — the SMB/LDAP parsers key off nxc's line format; a newer nxc may
  differ. Capture the raw line and adjust the regex + add a test.
- **certipy version** — parsing keys off `find -json`'s `[!] Vulnerabilities`; verify the
  installed certipy still emits that shape.
- **Responder log line** — confirm the real `NTLMv2-SSP Hash :` line matches the parser.
