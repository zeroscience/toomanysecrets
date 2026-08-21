"""Share secret-hunting classifier tests - pure, no nxc/DC/network.

Fixture mimics an nxc `spider_plus` JSON inventory (size as int AND human string, to
exercise the tolerant parser). Run:
    python tests/test_sharehunt.py    (or)   python -m pytest -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.engines import sharehunt as sh  # noqa: E402
from redness.findings import Category, Severity  # noqa: E402

# {share: {relpath: {size, ...}}} - spider_plus shape.
SAMPLE = {
    "backups": {
        "db/web.config": {"size": "2.00 KB", "mtime_epoch": "1"},
        "keys/id_rsa": {"size": 1675},
        "old/app.config.bak": {"size": 900},
        "readme.txt": {"size": 100},
    },
    "IT": {
        "scripts/deploy.ps1": {"size": 500},
        "passwords.xlsx": {"size": 8000},
        "Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Groups.xml": {"size": 700},
        "images/logo.png": {"size": 4000},
    },
}

HOST = "10.10.0.15"


def test_parse_flattens_and_sizes():
    recs = sh.parse_spider_json(SAMPLE)
    assert len(recs) == 8
    by_path = {r.path: r for r in recs}
    assert by_path["keys/id_rsa"].share == "backups" and by_path["keys/id_rsa"].size == 1675
    assert by_path["db/web.config"].size == 2048          # "2.00 KB" -> bytes


def test_parse_accepts_json_string_and_bad_meta():
    import json
    recs = sh.parse_spider_json(json.dumps(SAMPLE))
    assert len(recs) == 8
    # non-dict share value is skipped, missing size -> 0
    weird = sh.parse_spider_json({"s": {"a/b.txt": {}}, "junk": []})
    assert len(weird) == 1 and weird[0].size == 0


def test_classify_severity_tiers():
    def sev(path):
        r = sh.classify_file("s", path)
        return r.severity if r else None
    assert sev("keys/id_rsa") is Severity.CRITICAL
    assert sev("secret.kdbx") is Severity.CRITICAL
    assert sev("cert.pfx") is Severity.CRITICAL
    assert sev("Policies/x/Groups.xml") is Severity.CRITICAL
    assert sev("db/web.config") is Severity.HIGH
    assert sev("host/unattend.xml") is Severity.HIGH
    assert sev("passwords.xlsx") is Severity.MEDIUM
    assert sev("old/app.config.bak") is Severity.MEDIUM
    assert sev("scripts/deploy.ps1") is Severity.MEDIUM


def test_classify_ignores_benign_and_is_case_insensitive():
    assert sh.classify_file("s", "readme.txt") is None
    assert sh.classify_file("s", "images/logo.png") is None
    assert sh.classify_file("s", "KEYS/ID_RSA").rule == "private-key"      # case-insensitive
    assert sh.classify_file("s", "DB/Web.Config").rule == "config-credential"


def test_build_findings_shape_and_counts():
    inv = sh.parse_spider_json(SAMPLE)
    findings = sh.build_findings(inv, host=HOST)
    secrets = [f for f in findings if f.id == "share-secret"]
    aggregate = [f for f in findings if f.id == "enum-share-spider"]

    assert len(secrets) == 6                       # 6 interesting of 8 files
    assert len(aggregate) == 1
    assert all(f.category is Category.SECRET for f in secrets)

    # aggregate INFO carries the counts, owns no graph node
    agg = aggregate[0]
    assert agg.severity is Severity.INFO and agg.affected == []
    assert "8 file(s)" in agg.description and "2 readable share(s)" in agg.description


def test_meta_secrets_contract_and_unc():
    findings = sh.build_findings(sh.parse_spider_json(SAMPLE), host=HOST)
    idrsa = next(f for f in findings if f.affected and f.affected[0].endswith("id_rsa"))
    assert idrsa.affected == [r"\\10.10.0.15\backups\keys\id_rsa"]
    entry = idrsa.meta["secrets"][0]
    assert set(entry) == {"host", "share", "path", "unc", "rule", "kind", "size", "match"}
    assert entry["rule"] == "private-key" and entry["kind"] == "private key"
    assert entry["unc"] == r"\\10.10.0.15\backups\keys\id_rsa"


def test_redaction_no_content_leaks_in_phase1():
    findings = sh.build_findings(sh.parse_spider_json(SAMPLE), host=HOST)
    for f in findings:
        for entry in f.meta.get("secrets", []):
            assert entry["match"] == ""            # Phase 1 never reads/stores content


def test_empty_inventory_only_aggregate():
    findings = sh.build_findings([], host=HOST)
    assert [f.id for f in findings] == ["enum-share-spider"]


# --- SecretHuntEngine.run wiring (override the impure _spider seam; no nxc/DC) --- #
def _fake_engine(raw):
    class _F(sh.SecretHuntEngine):
        def is_available(self):
            return True

        def _spider(self, target):
            return raw
    return _F()


def test_run_wiring_produces_findings():
    import json
    from redness.engines.base import Target
    findings = _fake_engine(json.dumps(SAMPLE)).run(Target(host=HOST))
    assert len([f for f in findings if f.id == "share-secret"]) == 6
    assert any(f.id == "enum-share-spider" for f in findings)
    # host threaded into the UNCs
    assert any(r"\\10.10.0.15\backups\keys\id_rsa" in f.affected for f in findings)
    # raw inventory attached to the first finding for the report appendix
    assert findings[0].evidence and findings[0].evidence[0].raw


def test_run_empty_when_spider_returns_none():
    from redness.engines.base import Target
    assert _fake_engine(None).run(Target(host=HOST)) == []


def test_run_short_circuits_when_unavailable():
    from redness.engines.base import Target

    class _Unavail(sh.SecretHuntEngine):
        def is_available(self):
            return False

        def _spider(self, target):
            raise AssertionError("must not spider when the tool is unavailable")

    assert _Unavail().run(Target(host=HOST)) == []


# --- Phase 2: content classifier + content findings (pure) --- #
_CPASS = "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH"
CONTENT_SAMPLE = (
    'conn = "Server=sql01;Database=app;User ID=sa;Password=S3cr3tP@ss;"\n'
    "password = hunter2\n"
    f'<Groups><User cpassword="{_CPASS}" /></Groups>\n'
    "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
    'api_key = "abcd1234efgh5678ijkl9012"\n'
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234\n-----END RSA PRIVATE KEY-----\n"
)
# every real secret value that must NEVER appear in a match snippet
_SECRETS = ["S3cr3tP@ss", "hunter2", _CPASS, "AKIAIOSFODNN7EXAMPLE",
            "abcd1234efgh5678ijkl9012", "MIIEpAIBAAKCAQEA1234"]


def test_classify_content_detects_all_kinds():
    rules = {m.rule for m in sh.classify_content(CONTENT_SAMPLE)}
    assert {"content-private-key", "content-gpp-cpassword", "content-connection-string",
            "content-password", "content-aws-key", "content-api-key"} <= rules


def test_content_match_redaction_invariant():
    joined = " ".join(m.match for m in sh.classify_content(CONTENT_SAMPLE))
    assert "<redacted" in joined
    for s in _SECRETS:
        assert s not in joined, f"secret leaked into match: {s}"


def test_build_content_findings_one_per_file():
    files = [("IT", "app/web.config", CONTENT_SAMPLE), ("IT", "readme.txt", "nothing here")]
    findings = sh.build_content_findings(files, host=HOST)
    assert len(findings) == 1                         # only the file with matches
    f = findings[0]
    assert f.id == "share-secret" and f.category is Category.SECRET
    assert f.severity is Severity.CRITICAL            # private key / cpassword present
    assert f.affected == [r"\\10.10.0.15\IT\app\web.config"]
    entry = f.meta["secrets"][0]
    assert entry["rule"] == "content"
    for s in _SECRETS:
        assert s not in entry["match"]                # redacted end-to-end into the finding


def test_run_content_wiring_filename_plus_content():
    import json
    from redness.engines.base import Target

    class _F(sh.SecretHuntEngine):
        def is_available(self):
            return True

        def _spider_content(self, target):
            return json.dumps(SAMPLE), [("IT", "web.config", CONTENT_SAMPLE)]

    findings = _F(content=True).run(Target(host=HOST))
    assert [f.id for f in findings].count("share-secret") >= 7   # 6 filename + >=1 content
    assert any(f.meta.get("secrets", [{}])[0].get("rule") == "content" for f in findings)


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
