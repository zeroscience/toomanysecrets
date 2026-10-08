"""CSV export of findings - the spreadsheet view operators actually pivot on.

One row per (finding x affected asset): a finding touching three hosts becomes three rows.
That single shape serves both pivots the user asked for - sort/filter by the `asset` column
to read it "by IP", or by `id`/`severity` to read it "by finding". Assets that are not an
IP/host (an account, a template DN, a share path) land in the same column; `asset_kind` tags
which, so a spreadsheet filter can keep just the hosts.

Pure + stdlib (csv): `rows()` builds the table, `build()` writes it. No tool or network.
"""
from __future__ import annotations

import csv
import io
import ipaddress
from typing import Optional

from ..findings import Finding, Report

# Stable column order. Keep additive (append new columns) so existing importers don't break.
COLUMNS = [
    "severity", "rank", "category", "id", "title",
    "asset", "asset_kind", "credentialed",
    "impact", "remediation", "description", "evidence", "references",
]


def _asset_kind(asset: str) -> str:
    """Best-effort classification of an affected id, for a spreadsheet filter."""
    host = asset.split(":", 1)[0].split("\\", 1)[0].strip()
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        pass
    if "\\" in asset:
        return "share" if asset.count("\\") >= 3 or asset.startswith("\\\\") else "object"
    if "." in host and " " not in host:
        return "host"          # looks like a DNS name
    return "account"           # bare name: user / service / machine account


def _evidence(f: Finding) -> str:
    return " | ".join(f"{e.source}: {e.detail}" for e in f.evidence)


def rows(report: Report) -> list[dict]:
    """Flatten a report to CSV rows: one per (finding x affected asset)."""
    out: list[dict] = []
    for f in report.sorted_findings():
        assets = f.affected or ["-"]
        for asset in assets:
            out.append({
                "severity": f.severity.value,
                "rank": f.severity.rank,
                "category": f.category.value,
                "id": f.id,
                "title": f.title,
                "asset": asset,
                "asset_kind": _asset_kind(asset) if asset != "-" else "-",
                "credentialed": "yes" if f.credentialed else "no",
                "impact": f.impact,
                "remediation": f.remediation,
                "description": f.description,
                "evidence": _evidence(f),
                "references": " ".join(f.references),
            })
    return out


def render(report: Report) -> str:
    """Return the CSV text (CRLF line endings, a header row, all findings flattened)."""
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=COLUMNS, extrasaction="ignore")
    w.writeheader()
    for r in rows(report):
        w.writerow(r)
    return buf.getvalue()


def build(report: Report, path: str) -> int:
    """Write the CSV to `path`; return the number of data rows written."""
    data = rows(report)
    # newline="" per the csv module contract (it writes its own line terminators).
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(data)
    return len(data)
