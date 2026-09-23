"""Retest diff classification: new / fixed / unchanged / severity-changed."""
from redness.diff import DiffResult, diff_reports, finding_key
from redness.findings import Category, Finding, Report, Severity


def _f(id, sev=Severity.HIGH, affected=None, cat=Category.SMB, title="t"):
    return Finding(id=id, title=title, severity=sev, category=cat,
                   affected=list(affected or []))


def _rep(findings, engagement="acme retest"):
    return Report(engagement=engagement, target="acme.local", findings=findings)


def test_finding_key_is_id_plus_sorted_affected():
    assert finding_key(_f("x", affected=["b", "a"])) == ("x", ("a", "b"))
    assert finding_key(_f("x", affected=[])) == ("x", ())


def test_new_fixed_unchanged_partition():
    base = _rep([_f("smb-signing", affected=["dc01"]),
                 _f("tls-weak", affected=["web01"])])
    cur = _rep([_f("smb-signing", affected=["dc01"]),           # unchanged
                _f("adcs-esc1", affected=["UserAuth"])])        # new (tls-weak fixed)
    d = diff_reports(base, cur)
    assert {f.id for f in d.new} == {"adcs-esc1"}
    assert {f.id for f in d.fixed} == {"tls-weak"}
    assert {f.id for f in d.unchanged} == {"smb-signing"}
    assert d.changed == []
    assert d.counts() == {"new": 1, "fixed": 1, "unchanged": 1, "changed": 0}


def test_same_id_different_host_is_new_not_unchanged():
    base = _rep([_f("smb-signing", affected=["dc01"])])
    cur = _rep([_f("smb-signing", affected=["dc02"])])          # different asset = different issue
    d = diff_reports(base, cur)
    assert [f.affected for f in d.new] == [["dc02"]]
    assert [f.affected for f in d.fixed] == [["dc01"]]
    assert d.unchanged == []


def test_severity_change_is_changed_with_old_severity():
    base = _rep([_f("mssql-exposed", sev=Severity.MEDIUM, affected=["sql01"])])
    cur = _rep([_f("mssql-exposed", sev=Severity.CRITICAL, affected=["sql01"])])
    d = diff_reports(base, cur)
    assert d.unchanged == [] and d.new == []
    assert len(d.changed) == 1
    cur_f, old_sev = d.changed[0]
    assert cur_f.severity is Severity.CRITICAL and old_sev is Severity.MEDIUM


def test_regressed_true_on_new_and_on_severity_increase():
    base = _rep([_f("a", sev=Severity.LOW, affected=["h"])])
    up = diff_reports(base, _rep([_f("a", sev=Severity.HIGH, affected=["h"])]))
    assert up.regressed() is True                               # severity increase
    add = diff_reports(base, _rep([_f("a", sev=Severity.LOW, affected=["h"]),
                                   _f("b", affected=["h"])]))
    assert add.regressed() is True                              # a brand-new finding


def test_not_regressed_when_only_fixed_or_downgraded():
    base = _rep([_f("a", sev=Severity.CRITICAL, affected=["h"]),
                 _f("b", sev=Severity.HIGH, affected=["h"])])
    cur = _rep([_f("a", sev=Severity.LOW, affected=["h"])])     # b fixed, a downgraded
    d = diff_reports(base, cur)
    assert d.regressed() is False


def test_to_dict_shape_records_old_severity():
    base = _rep([_f("a", sev=Severity.MEDIUM, affected=["h"])])
    cur = _rep([_f("a", sev=Severity.HIGH, affected=["h"])])
    dd = diff_reports(base, cur).to_dict()
    assert dd["counts"]["changed"] == 1
    assert dd["changed"][0]["old_severity"] == "medium"
    assert dd["changed"][0]["severity"] == "high"
    assert dd["baseline"] == "acme retest" and dd["current"] == "acme retest"


def test_to_text_has_headers_and_verdict():
    base = _rep([_f("tls-weak", affected=["web01"])])
    cur = _rep([_f("adcs-esc1", sev=Severity.CRITICAL, affected=["UserAuth"])])
    txt = diff_reports(base, cur).to_text()
    assert "Retest diff:" in txt
    assert "--- NEW ---" in txt and "--- FIXED ---" in txt
    assert "REGRESSED" in txt                                   # a new finding regressed it
    assert "adcs-esc1" in txt and "tls-weak" in txt


def test_empty_reports_diff_cleanly():
    d = diff_reports(_rep([]), _rep([]))
    assert d.counts() == {"new": 0, "fixed": 0, "unchanged": 0, "changed": 0}
    assert d.regressed() is False
    assert isinstance(d, DiffResult)


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            passed += 1
    print(f"{passed} passed")
