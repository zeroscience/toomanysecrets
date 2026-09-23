"""HTML report + graph model: capture/derive a graph and render one self-contained file."""
import os
import tempfile

from redness.events import Event, EventKind
from redness.findings import Category, Evidence, Finding, Report, Severity
from redness.graphmodel import GraphCollector, graph_for, graph_from_report
from redness.report import html_report
from redness.scan import run_scan


def _rep():
    return Report(engagement="acme pentest", target="10.0.0.1, 10.0.0.2", findings=[
        Finding(id="smb-signing-not-required", title="SMB signing not required",
                severity=Severity.HIGH, category=Category.SMB, affected=["10.0.0.1"],
                impact="relay", remediation="enforce signing",
                evidence=[Evidence(source="netexec", detail="signing:False")],
                references=["https://attack.mitre.org/techniques/T1557/001/"]),
        Finding(id="adcs-esc1", title="AD CS ESC1", severity=Severity.CRITICAL,
                category=Category.ADCS, affected=["UserAuth"], meta={"esc": 1}),
    ])


# --- GraphCollector -------------------------------------------------------- #
def test_collector_dedupes_and_backfills_endpoints():
    gc = GraphCollector()
    gc.on_event(Event(kind=EventKind.NODE, data={"id": "dc01", "label": "dc01", "type": "host"}))
    gc.on_event(Event(kind=EventKind.NODE, data={"id": "dc01", "type": "host"}))     # dup id
    gc.on_event(Event(kind=EventKind.EDGE, data={"src": "dc01", "dst": "DA", "label": "x",
                                                 "attack": True}))
    g = gc.data()
    assert len([n for n in g["nodes"] if n["id"] == "dc01"]) == 1     # deduped
    assert any(n["id"] == "DA" for n in g["nodes"])                   # backfilled endpoint
    link = g["links"][0]
    assert link["source"] == "dc01" and link["target"] == "DA" and link["attack"] is True


def test_collector_ignores_malformed_events():
    gc = GraphCollector()
    gc.on_event(Event(kind=EventKind.NODE, data={"label": "no id"}))
    gc.on_event(Event(kind=EventKind.EDGE, data={"src": "a"}))        # missing dst
    gc.on_event(Event(kind=EventKind.STATUS, data={"message": "hi"}))
    assert gc.data() == {"nodes": [], "links": []}


# --- graph_from_report (fallback) ------------------------------------------ #
def test_graph_from_report_builds_domain_hosts_and_does_not_mutate():
    rep = _rep()
    before = len(rep.findings)
    g = graph_from_report(rep)
    ids = {n["id"] for n in g["nodes"]}
    assert "10.0.0.1" in ids and "10.0.0.2" in ids                    # host nodes
    assert len(rep.findings) == before                                # relay derivation used a copy
    assert g["links"]                                                 # domain->host edges at least


def test_graph_for_prefers_captured_graph():
    rep = _rep()
    rep.meta["graph"] = {"nodes": [{"id": "captured", "type": "domain"}], "links": []}
    assert graph_for(rep)["nodes"][0]["id"] == "captured"


def test_run_scan_persists_graph_in_meta():
    # a scan with no live bus still captures the graph into report.meta
    class _Eng:
        name = "smb"
        def is_available(self): return True
        def run(self, tgt): return [Finding(id="smb-signing-not-required", title="s",
                                            severity=Severity.HIGH, category=Category.SMB,
                                            affected=[tgt.host])]
    rep = run_scan(["10.0.0.9"], engines=[_Eng()], discover=False)
    assert "graph" in rep.meta and rep.meta["graph"]["nodes"]
    assert any(n["id"] == "10.0.0.9" for n in rep.meta["graph"]["nodes"])


# --- render ---------------------------------------------------------------- #
def test_render_is_self_contained_with_findings_and_graph():
    html = html_report.render(_rep())
    assert html.lstrip().startswith("<!doctype html>")
    assert "acme pentest" in html
    assert "AD CS ESC1" in html and "SMB signing not required" in html
    assert "enforce signing" in html                                 # remediation rendered
    assert "ForceGraph3D" in html                                    # vendored lib inlined
    assert 'var DATA = {"nodes"' in html or 'var DATA = {\n' in html # graph JSON injected inline
    assert "/*__GRAPH__*/" not in html and "<!--__CARDS__-->" not in html  # tokens replaced


def test_render_escapes_finding_text():
    rep = Report(engagement="x", target="t", findings=[
        Finding(id="xss", title="<script>alert(1)</script>", severity=Severity.LOW,
                category=Category.CONFIG, affected=["<b>host</b>"])])
    html = html_report.render(rep)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_build_writes_file():
    d = tempfile.mkdtemp()
    out = os.path.join(d, "r.html")
    html_report.build(_rep(), out)
    assert os.path.getsize(out) > 100_000            # vendored lib inlined -> large self-contained file
    with open(out, encoding="utf-8") as fh:
        assert "REDNESS ASSESSMENT REPORT" in fh.read()


def test_render_empty_report():
    html = html_report.render(Report(engagement="empty", target="none"))
    assert "No findings recorded." in html


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            passed += 1
    print(f"{passed} passed")
