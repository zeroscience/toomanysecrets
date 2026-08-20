# Share secret-hunting engine - design note

> Status: **design; not built.** Snaffler-style share secret-hunting (docs/ROADMAP.md
> Tier 1 #3). Owner: **anjaiv** (engines area). Read `CLAUDE.md`, `docs/DECISIONS.md`,
> and `docs/ROADMAP.md` first, then this.
>
> ⚠️ **This introduces a schema change** (`Category.SECRET` + `SCHEMA_VERSION` bump +
> `scan.py:_node_type`). `findings.py` is the contract between engines (anjaiv) and
> reporting/graph (Gjoko) - **the schema change and the `meta["secrets"]` shape need
> Gjoko's review before merge**, and must stay compatible with the attack-path graph
> (`redness/paths.py`, PR #33, not yet in main).

## What it is (and why it's separate)
Everything REDNESS finds today comes from *asking a service* (SMB banner, LDAP, AD CS).
Share secret-hunting instead **spiders readable SMB shares for secrets** - passwords, keys,
connection strings, `web.config`, `unattend.xml`, `*.kdbx`, GPP `cpassword`, scripts - and
surfaces each as a **graph node + finding**. Almost no orchestrator does this well; it is
often the fastest path to DA and it reads *great* in a report.

It is **opt-in** (slower/noisier than banner checks, and content inspection pulls file data
off client shares), so it is **not** in `default_engines()` and runs only behind a flag.

## Approach: orchestrate, don't reimplement (same as every other engine)
Do **not** wrap Snaffler itself (.NET/Windows - heavy, not Kali-native) and do **not** write
our own SMB spider (docs/ROADMAP.md: "reimplementing any protocol tool = not doing"). Split:
- **nxc walks the shares** - `nxc smb <host> -u U -p P -M spider_plus` recursively enumerates
  every readable share and writes a JSON inventory
  (`~/.nxc/modules/nxc_spider_plus/<host>.json`: `{share: {path: {size, ctime, mtime}}}`).
  Kali-native, already a dependency, ships with nxc - **no new `doctor` entry**.
- **We add the value: a pure Snaffler-style classifier** over that inventory. The classifier
  is the differentiator and is unit-testable against a captured JSON, exactly like the
  Certipy JSON parser - pure functions separated from the subprocess.

Two phases:
- **Phase 1 - filename / path / extension rules** (`scan --hunt-secrets`). Low-touch: reads
  only the listing nxc already produced (no file content), so it is close to as intrusive as
  `nxc --shares`.
- **Phase 2 - content inspection** (`scan --hunt-content`, gated). Downloads small high-signal
  candidates (spider_plus `DOWNLOAD_FLAG` + `PATTERN`) and regexes their content. More
  intrusive (pulls file data); downloads land in git-ignored `loot/` only.

## The schema change (needs Gjoko's review)
`redness/findings.py` gains a category, and `redness/scan.py` a node type:
1. **`Category.SECRET = "secret"`** - secrets are not inherently SMB-specific, and the
   attack-path graph needs a distinct node type to render credential findings. Bump
   **`SCHEMA_VERSION` `1.0.0` → `1.1.0`** (additive; a consumer that predates it must tolerate
   an unknown category). Log it in `docs/DECISIONS.md`.
2. **`scan.py:_node_type`** - map `secret` → a new `"secret"` node type (today: adcs→template,
   kerberos→user, smb+`\`→share, enum→user, else host). The GUI must color/shape the new node
   type (Gjoko / `web/`); until then a `secret` node renders with the default styling.

Because both files are the engine↔reporting contract, **coordinate before merging**, same as
the crack.py contract in docs/NETNTLM.md.

## The contract with `paths.py` - `meta["secrets"]`
Findings carry secrets in **`meta["secrets"]`**, mirroring `meta["hashes"]` from `ldap.py`.
Each entry:
```
{ "host":  "10.10.0.15",
  "share": "backups",
  "path":  "db/web.config",            # share-relative
  "unc":   "\\\\10.10.0.15\\backups\\db\\web.config",
  "rule":  "config-credential",        # which classifier rule fired
  "kind":  "connection-string",        # secret type
  "size":  2048,
  "match": "Password=****" }           # ALWAYS masked/truncated - never the full secret
```
**Redaction (firm):** never store a full secret value in `meta`, the `.docx`, or
`findings.json`. `match` is truncated + masked; raw downloaded files stay in git-ignored
`loot/` only. This is a *report* tool - leaking secrets into the deliverable is a footgun.

**OPEN QUESTION for Gjoko (not yet answered):** should a *recovered credential* (a real
`user:password` / key / hash extracted from a secret) get a distinct sub-field so `paths.py`
can build attack-path edges from it, separate from a generic file-match? Two candidate shapes
(pick one with Gjoko):
- per-secret sub-object: `entry["credential"] = {"username": ..., "kind": "password|key|hash",
  "secret_masked": ...}`, or
- a separate top-level `meta["credentials"]` list (parallel to `meta["hashes"]`, which
  crack.py already consumes).
Until decided, Phase 1 emits only file-match secrets (no `credential` field); the shape is
forward-compatible either way.

## Findings to emit
One `Category.SECRET` finding **per secret** (so each becomes its own graph node, recolored by
its own severity), plus one aggregate INFO. **Single finding id + `meta["kind"]`** - the id is
always `share-secret`; the *kind* distinguishes types (no per-type id explosion).

| id | severity | when (examples) |
|----|----------|-----------------|
| `share-secret` | CRITICAL | private keys (`id_rsa`/`*.pem`/`*.ppk`), `*.kdbx`, `*.pfx`/`*.p12`, GPP `cpassword`, `.git-credentials`, connection string with password |
| `share-secret` | HIGH | `web.config`/`.env`/`application.properties`, `unattend.xml`/`sysprep.xml`, password-manager exports |
| `share-secret` | MEDIUM | `passwords.*`, scripts (`.ps1`/`.bat`/`.vbs`), `*.bak`/`*.old` of configs - needs review |
| `enum-share-spider` | INFO | aggregate: N shares spidered, M files, interesting paths |

`affected = [unc]` per secret. Every finding carries **remediation** (remove credentials from
shares; tighten share + NTFS ACLs to least privilege; rotate any exposed secret; store secrets
in a vault) and **references** (MITRE **T1552.001** Credentials In Files, **T1552.006** GPP,
**T1039** Data from Network Shared Drive). Note the **GPP `cpassword` overlap** with the Tier-2
GPP item: secret-hunting *flags* the file; the future GPP engine *decrypts* it - keep ids
distinct.

## Safety / gating
- **Opt-in flags**, never in `default_engines()`: `--hunt-secrets` (Phase 1, filename only) and
  `--hunt-content` (Phase 2, downloads + content regex - the intrusive one).
- **Redaction** as above; downloaded files → git-ignored `loot/`.
- Only spiders shares the tested principal can already read (nxc uses the supplied creds); no
  privilege escalation, no writes.

## Dependencies
- **nxc** with the bundled **`spider_plus`** module (Kali-native; already covered by
  `redness doctor`'s netexec check - no new dependency).

## Build order (suggested)
1. **Pure classifier** - `parse_spider_json(json) -> inventory`, `classify_file(share, path,
   size) -> Rule|None`, `build_findings(inventory) -> list[Finding]` (with `meta["secrets"]`,
   redacted). Tests against a captured `spider_plus` JSON sample. **No nxc/DC/network.**
2. **`Category.SECRET` schema change** - `findings.py` (enum + `SCHEMA_VERSION` 1.1.0) and
   `scan.py:_node_type`; DECISIONS.md entry. **Gjoko review gate.**
3. **`SecretHuntEngine.run(target)`** - shell out to `nxc smb -M spider_plus`, locate + read
   the JSON, feed the pure classifier; `scan --hunt-secrets` wiring (opt-in).
4. **Phase 2 content inspection** - `--hunt-content`: download candidates, `classify_content`
   regexes, redacted `match` evidence, loot handling.
5. **Docs** - DECISIONS entry, ROADMAP tick, CLAUDE.md note; resolve the `credential` sub-field
   question with Gjoko.

## Legal / ethics
Reading a client's file shares exposes real secrets. Authorized, in-scope engagements only;
handle recovered material per the engagement's data-handling rules (redacted in the report,
raw only in git-ignored `loot/`).
