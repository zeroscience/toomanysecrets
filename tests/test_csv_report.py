"""CSV export tests - flattening (one row per affected asset), asset classification, escaping.

Run:  python -m pytest tests/test_csv_report.py -q
"""
import csv
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.findings import Category, Evidence, Finding, Report, Severity  # noqa: E402
from redness.report import csv_report  # noqa: E402


def _report():
    return Report(engagement="Eng", target="acme/10.0.0.0/24", findings=[
        Finding(id="smb-signing", title="SMB signing not required", severity=Severity.MEDIUM,
                category=Category.SMB, impact="relay", remediation="enforce signing",
                affected=["10.0.0.5", "10.0.0.6"],
                evidence=[Evidence(source="netexec", detail="signing:False")],
                references=["https://attack.mitre.org/techniques/T1557/001/"]),
        Finding(id="redis-unauth", title="Redis no auth", severity=Severity.CRITICAL,
                category=Category.SERVICE, affected=["\\\\FS01\\backups"], credentialed=True),
        Finding(id="no-assets", title="Thing with no asset", severity=Severity.LOW,
                category=Category.CONFIG, affected=[]),
    ])


def test_one_row_per_affected_asset():
    rows = csv_report.rows(_report())
    # 2 (smb) + 1 (redis) + 1 (no-asset placeholder) = 4
    assert len(rows) == 4
    smb = [r for r in rows if r["id"] == "smb-signing"]
    assert [r["asset"] for r in smb] == ["10.0.0.5", "10.0.0.6"]


def test_severity_order_then_stable():
    # critical first (redis), then medium (smb x2), then low (no-assets)
    ids = [r["id"] for r in csv_report.rows(_report())]
    assert ids[0] == "redis-unauth"
    assert ids[-1] == "no-assets"


def test_asset_kind_classification():
    rows = csv_report.rows(_report())
    kinds = {r["asset"]: r["asset_kind"] for r in rows}
    assert kinds["10.0.0.5"] == "ip"
    assert kinds["\\\\FS01\\backups"] == "share"      # UNC path
    assert kinds["-"] == "-"                          # placeholder for no-asset finding


def test_render_is_valid_csv_with_header_and_bomless_text():
    text = csv_report.render(_report())
    reader = list(csv.DictReader(io.StringIO(text)))
    assert reader[0]["title"] == "Redis no auth"
    assert reader[0]["credentialed"] == "yes"
    # commas / quotes in fields stay inside one logical row
    assert len(reader) == 4
    assert set(csv_report.COLUMNS).issubset(reader[0].keys())


def test_build_writes_file_with_excel_bom(tmp_path):
    p = tmp_path / "out.csv"
    n = csv_report.build(_report(), str(p))
    assert n == 4
    raw = p.read_bytes()
    assert raw[:3] == b"\xef\xbb\xbf"                 # UTF-8 BOM so Excel detects encoding
    # round-trips through a reader that strips the BOM
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    assert len(rows) == 4


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
            except TypeError:                          # needs tmp_path fixture
                import tempfile, pathlib
                fn(pathlib.Path(tempfile.mkdtemp()))
            print(f"  ok  {name}")
    print("done")
