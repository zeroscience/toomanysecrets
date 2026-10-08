# Output formats

Every command that produces findings (`demo`, `report`, `scan`, `capture`, `wifi`, `listen`,
`poison`, `spray`, `coerce`) exposes the same output surface. Pass any combination - each writes
its own file, and the console summary always prints.

| flag        | format | what you get |
|-------------|--------|--------------|
| `--out X.docx` | Word   | the full narrative report (exec summary + per-finding detail) |
| `--html X.html`| HTML   | self-contained page: the 3D graph + findings, works offline (`scan`/`report`/`demo`) |
| `--json X.json`| JSON   | the raw `findings.json` (the contract; feeds `diff` for retests) |
| `--csv X.csv`  | CSV    | the spreadsheet view - one row per **(finding x affected asset)** |

## Console verbosity

- default: severity counts + one line per finding (`[SEV] title -> affected`).
- `-q` / `--quiet`: severity counts only.
- `-v` / `--verbose`: adds the evidence and the remediation under each finding.

## The CSV (by IP / by finding)

`--csv` flattens the report so a finding touching three hosts becomes three rows. That one shape
serves both pivots:

- **by IP** - sort / filter on the `asset` column (and `asset_kind = ip` to keep only hosts).
- **by finding** - sort on `severity` (or `rank`, numeric 4..0) then `id`.

Columns (stable, additive): `severity, rank, category, id, title, asset, asset_kind,
credentialed, impact, remediation, description, evidence, references`.

`asset_kind` is a best-effort tag so a spreadsheet filter can separate assets: `ip`, `host`
(DNS name), `account` (bare user/service/machine name), `share` (UNC path), `object` (a DN or
other backslash id), or `-` for a finding with no affected asset. The file is written UTF-8 with
a BOM so Excel detects the encoding; open it directly or import as UTF-8.

```bash
redness scan --targets scope.txt -u U -p P -d dom --csv findings.csv --out report.docx
redness report findings.json --csv findings.csv --out ""   # re-export an old scan to CSV only
redness demo --csv sample.csv                                # see the shape with sample data
```

Pure stdlib (`csv`); see `redness/report/csv_report.py` and `tests/test_csv_report.py`.
