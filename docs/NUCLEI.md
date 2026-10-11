# Nuclei engine (`scan --nuclei`)

Template-based web/network vulnerability scanning via [nuclei](https://github.com/projectdiscovery/nuclei).
Nuclei runs thousands of community YAML templates - CVEs, exposed panels, default logins,
misconfigurations, technology fingerprints, takeovers - and emits one JSON object per match.
REDNESS shells out, groups the matches by template, and normalizes them into `Finding`s
(`Category.WEB`).

## Why it is different from the rest of the scan
Every other default engine is passive or a single read-only probe. **Nuclei is ACTIVE**: it
sends real crafted requests. So it is treated with more care:

- **Opt-in.** Never in `default_engines()`; you enable it with `scan --nuclei`.
- **Port-gated to the web.** Discovery only runs it when a web port (80/443/8080/8443) is open,
  so it never touches OT/ICS field ports.
- **Safe-by-default profile.** We always pass `-exclude-tags intrusive,dos,fuzz,brute` and
  rate-limit (`-rate-limit 150 -concurrency 25`), keeping the run detection-oriented.
- **Still a web scanner, not an OT-safe probe.** A fragile OT HMI that happens to serve HTTP is
  still a web target. Scope those out yourself - REDNESS will not send OT-safe traffic here.

## Usage
```bash
redness scan --target 10.0.0.0/24 --nuclei --out report.docx --csv findings.csv
redness scan --targets scope.txt --nuclei --nuclei-profile full        # include info-level
redness scan --target app.lab --nuclei --nuclei-templates ~/mytemplates # custom template set
```
- `--nuclei-profile light` (default): actionable severities only (`low,medium,high,critical`).
- `--nuclei-profile full`: all severities including `info` (tech-detect, fingerprints).
- `--nuclei-templates PATH`: a specific templates dir/file (`-t`); otherwise nuclei's own store.

Nuclei is a separate install (like nxc/certipy) - it is **not** bundled, and neither is its
template store:
```bash
# install the binary (go / apt / brew / release), then fetch templates:
nuclei -update-templates
redness doctor            # shows whether nuclei is on PATH
```

## How a match becomes a finding
One `Finding` per `template-id`; every host:port it matched becomes an entry in `affected`, and
each concrete match (its `matched-at` URL) becomes an `Evidence` line.

| finding field | from nuclei |
|---------------|-------------|
| `id` | `nuclei:<template-id>` |
| `title` | `info.name` |
| `severity` | `info.severity` (unknown -> info) |
| `category` | `Category.WEB` |
| `description` | `info.description` |
| `affected` | each match's scheme-stripped `host:port` |
| `evidence` | `matched-at` + any `extracted-results`; `curl-command` kept as raw |
| `references` | `info.reference` + CVE ids from `info.classification` |
| `remediation` | `info.remediation` if present, else synthesized (CVE -> "patch/upgrade"; else "restrict/patch; see references") |
| `meta` | `template_id`, `type`, `tags`, `cvss_score`, `cves` |

Every REDNESS finding must carry a remediation; nuclei templates do not always provide one, so
the fallback above guarantees it.

## Graph
nuclei findings get the `web` node type (colour `#c77dff`) and land in the **IoT / SERVICES**
territory on the world map; like other findings they recolour by severity.

Pure parser in `redness/engines/nuclei.py` (`parse_nuclei`), tested in `tests/test_nuclei.py`
against captured JSONL - no nuclei and no network needed.
