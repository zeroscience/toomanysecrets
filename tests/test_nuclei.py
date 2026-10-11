"""Nuclei engine tests - pure JSONL parsing, grouping, severity/category, remediation fallback.

Captured `nuclei -jsonl` lines (trimmed). No nuclei, no network.

Run:  python -m pytest tests/test_nuclei.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.findings import Category, Severity  # noqa: E402
from redness.engines.nuclei import NucleiEngine, parse_nuclei, _asset  # noqa: E402
from redness.engines.base import Target  # noqa: E402

# Two matches for the SAME template on two hosts (should group), a CVE with a remediation,
# an exposure with no remediation (fallback), and a blank + junk line (skipped).
SAMPLE = r"""
{"template-id":"log4j-rce","info":{"name":"Apache Log4j RCE","severity":"critical","tags":["cve","rce"],"description":"Log4Shell","reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],"classification":{"cve-id":["CVE-2021-44228"],"cvss-score":10.0},"remediation":"Upgrade log4j to 2.17.1+."},"type":"http","host":"https://10.0.0.5:8443","matched-at":"https://10.0.0.5:8443/api","ip":"10.0.0.5","curl-command":"curl -X GET ..."}
{"template-id":"log4j-rce","info":{"name":"Apache Log4j RCE","severity":"critical"},"type":"http","host":"http://10.0.0.9","matched-at":"http://10.0.0.9/login"}
{"template-id":"git-config","info":{"name":"Exposed .git/config","severity":"medium","tags":["exposure","config"],"description":"Version control metadata exposed."},"type":"http","host":"http://10.0.0.5","matched-at":"http://10.0.0.5/.git/config","extracted-results":["[core]"]}

not json at all
{"no-template-id":true}
"""


def test_groups_by_template_and_collects_affected():
    fs = parse_nuclei(SAMPLE)
    assert len(fs) == 2                                   # log4j (grouped) + git-config
    log4j = next(f for f in fs if f.id == "nuclei:log4j-rce")
    assert sorted(log4j.affected) == ["10.0.0.5:8443", "10.0.0.9"]
    assert len(log4j.evidence) == 2                       # one per match


def test_severity_and_category_and_id():
    fs = parse_nuclei(SAMPLE)
    log4j = next(f for f in fs if f.id == "nuclei:log4j-rce")
    assert log4j.severity is Severity.CRITICAL
    assert log4j.category is Category.WEB
    assert "CVE-2021-44228" in log4j.references
    assert log4j.meta["cves"] == ["CVE-2021-44228"]


def test_remediation_used_when_present_else_fallback():
    fs = parse_nuclei(SAMPLE)
    log4j = next(f for f in fs if f.id == "nuclei:log4j-rce")
    git = next(f for f in fs if f.id == "nuclei:git-config")
    assert log4j.remediation == "Upgrade log4j to 2.17.1+."     # template-provided
    assert git.remediation and "see references" in git.remediation  # synthesized fallback
    assert git.severity is Severity.MEDIUM


def test_extracted_results_land_in_evidence():
    git = next(f for f in parse_nuclei(SAMPLE) if f.id == "nuclei:git-config")
    assert any("extracted:" in e.detail for e in git.evidence)


def test_junk_and_blank_lines_skipped():
    assert parse_nuclei("\n\nnot json\n{bad}\n") == []
    assert parse_nuclei("") == []


def test_asset_strips_scheme_and_path():
    assert _asset("https://h:8443/x/y") == "h:8443"
    assert _asset("http://10.0.0.1") == "10.0.0.1"
    assert _asset("10.0.0.1:80") == "10.0.0.1:80"


def test_unknown_severity_defaults_info():
    f = parse_nuclei('{"template-id":"x","info":{"name":"X","severity":"unknown"},"host":"http://h"}')
    assert f and f[0].severity is Severity.INFO


def test_engine_argv_is_safe_and_gated():
    eng = NucleiEngine(profile="light", templates="/t/custom")
    argv = eng._argv(Target(host="10.0.0.5"))
    assert "-jsonl" in argv and "-silent" in argv
    # the core safety rail: intrusive/dos/fuzz/brute always excluded
    i = argv.index("-exclude-tags")
    assert argv[i + 1] == "intrusive,dos,fuzz,brute"
    # light profile limits to actionable severities
    assert "-severity" in argv and "low,medium,high,critical" in argv
    assert "-t" in argv and "/t/custom" in argv
    assert "-u" in argv and "http://10.0.0.5" in argv and "https://10.0.0.5" in argv


def test_engine_full_profile_has_no_severity_filter():
    argv = NucleiEngine(profile="full")._argv(Target(host="h"))
    assert "-severity" not in argv


def test_engine_run_returns_empty_without_tool(monkeypatch):
    monkeypatch.setattr("redness.engines.nuclei.shutil.which", lambda _n: None)
    assert NucleiEngine().is_available() is False
    assert NucleiEngine().run(Target(host="h")) == []


if __name__ == "__main__":
    import types
    mp = types.SimpleNamespace(setattr=lambda t, n, v: None)
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
            except TypeError:
                fn(mp)
            print(f"  ok  {name}")
    print("done")
