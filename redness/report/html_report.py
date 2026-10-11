"""Self-contained HTML report - the findings + the live 3D graph in one offline file.

Mirrors the `.docx` content (severity summary + every finding with remediation) AND embeds the
same 3D attack-graph the live GUI shows, by baking in the captured node/edge set
(`redness.graphmodel.graph_for`) and inlining the vendored 3d-force-graph bundle. The result is a
single `.html` a client can open with no server, no network, and no Word - and still spin the
graph, see attack paths light up, and read the findings.

Colours and link styling are kept in sync with `redness/live/web/index.html` so the report graph
looks like the live one.
"""
from __future__ import annotations

import html
import json
import os

from ..findings import Report, Severity
from ..graphmodel import graph_for

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEV_COLOR = {"critical": "#ff4d4d", "high": "#ff7a45", "medium": "#f2c94c",
              "low": "#6fcf97", "info": "#8a93a2"}
_LOGO = os.path.join(os.path.dirname(__file__), "..", "live", "web", "logo.png")
_VENDOR = os.path.join(os.path.dirname(__file__), "..", "live", "web", "vendor",
                       "3d-force-graph.min.js")


def _esc(s: str) -> str:
    return html.escape(str(s or ""))


def _logo_img() -> str:
    """The REDNESS logo as a self-contained data-URI <img>, or '' if it can't be read."""
    try:
        import base64
        with open(_LOGO, "rb") as fh:
            b64 = base64.b64encode(fh.read()).decode("ascii")
        return f'<img class="logo" src="data:image/png;base64,{b64}" alt="REDNESS">'
    except OSError:
        return ""


def _sev_by_node(report: Report) -> dict[str, str]:
    """Worst severity affecting each asset id (matches the live graph's node recolouring)."""
    worst: dict[str, Severity] = {}
    for f in report.findings:
        for a in f.affected:
            if a not in worst or f.severity.rank > worst[a].rank:
                worst[a] = f.severity
    return {k: v.value for k, v in worst.items()}


def _graph_json(report: Report) -> str:
    g = graph_for(report)
    sev = _sev_by_node(report)
    for n in g.get("nodes", []):
        if n.get("id") in sev:
            n["sev"] = sev[n["id"]]
    return json.dumps(g)


def _finding_card(f) -> str:
    sev = f.severity.value
    parts = [f'<div class="card sev-border-{sev}">']
    parts.append('<div class="chead">'
                 f'<span class="badge b-{sev}">{sev.upper()}</span>'
                 f'<span class="ftitle">{_esc(f.title)}</span>'
                 f'<span class="fid">{_esc(f.id)}</span>'
                 f'<span class="fcat">{_esc(f.category.value)}</span>'
                 '</div>')
    if f.affected:
        chips = "".join(f'<span class="chip">{_esc(a)}</span>' for a in f.affected)
        parts.append(f'<div class="affected">{chips}</div>')
    if f.description:
        parts.append(f'<p class="desc">{_esc(f.description)}</p>')
    if f.impact:
        parts.append(f'<p><span class="lbl">Impact</span> {_esc(f.impact)}</p>')
    if f.remediation:
        parts.append(f'<p><span class="lbl">Remediation</span> {_esc(f.remediation)}</p>')
    if f.evidence:
        ev = "".join(f'<li><span class="src">{_esc(e.source)}</span> {_esc(e.detail)}</li>'
                     for e in f.evidence)
        parts.append(f'<ul class="evidence">{ev}</ul>')
    if f.references:
        refs = " | ".join(f'<a href="{_esc(r)}" rel="noopener">{_esc(r)}</a>' for r in f.references)
        parts.append(f'<p class="refs">{refs}</p>')
    parts.append("</div>")
    return "".join(parts)


def render(report: Report) -> str:
    """Return the full self-contained HTML document as a string."""
    counts = {s.value: 0 for s in Severity}
    for f in report.findings:
        counts[f.severity.value] += 1
    total = len(report.findings)

    summary = "".join(
        f'<div class="stat s-{s.value}"><div class="n">{counts[s.value]}</div>'
        f'<div class="k">{s.value.upper()}</div></div>'
        for s in _SEV_ORDER)

    cards = []
    for s in _SEV_ORDER:
        group = [f for f in report.sorted_findings() if f.severity is s]
        if not group:
            continue
        cards.append(f'<h2 class="sevh sev-{s.value}">{s.value.upper()} '
                     f'<span class="cnt">{len(group)}</span></h2>')
        cards += [_finding_card(f) for f in group]
    if not report.findings:
        cards.append('<p class="empty">No findings recorded.</p>')

    try:
        with open(_VENDOR, encoding="utf-8") as fh:
            vendor = fh.read()
    except OSError:
        vendor = ""

    tmpl = _TEMPLATE
    tmpl = tmpl.replace("<!--__LOGO__-->", _logo_img())
    tmpl = tmpl.replace("__ENGAGEMENT__", _esc(report.engagement))
    tmpl = tmpl.replace("__TARGET__", _esc(report.target))
    tmpl = tmpl.replace("__TOTAL__", str(total))
    tmpl = tmpl.replace("<!--__SUMMARY__-->", summary)
    tmpl = tmpl.replace("<!--__CARDS__-->", "".join(cards))
    tmpl = tmpl.replace("/*__GRAPH__*/", _graph_json(report))
    tmpl = tmpl.replace("/*__VENDOR__*/", vendor)
    return tmpl


def build(report: Report, out_path: str) -> str:
    """Render the report to a single self-contained .html file. Returns the path."""
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(render(report))
    return out_path


# The page. Tokens (__X__, <!--__X__-->, /*__X__*/) are string-replaced above so the large
# vendored JS (full of braces) is never fed to a formatter.
_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>REDNESS report - __ENGAGEMENT__</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  html,body { margin:0; background:#0b0d12; color:#e6e6e6;
    font:14px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  a { color:#ff7a45; text-decoration:none; } a:hover { text-decoration:underline; }
  header { padding:22px 28px 14px; border-bottom:1px solid #1c2230; display:flex;
    align-items:center; gap:16px; }
  header img.logo { height:46px; width:auto; flex:none; }
  header h1 { margin:0; font-size:17px; letter-spacing:.14em; color:#ff5252; }
  header .sub { color:#8a93a2; font-size:12.5px; margin-top:4px; }
  /* Atmosphere: a sparse starfield over a centre-lit vignette, behind the transparent WebGL
     canvas - depth + "ops console" mood without any post-processing pass. */
  #graphwrap { position:relative; height:62vh; min-height:360px; border-bottom:1px solid #1c2230;
    background:
      radial-gradient(1.5px 1.5px at 12% 22%, rgba(255,255,255,.55), transparent),
      radial-gradient(1px 1px at 28% 68%, rgba(180,200,255,.45), transparent),
      radial-gradient(1px 1px at 46% 12%, rgba(255,255,255,.40), transparent),
      radial-gradient(1.5px 1.5px at 63% 44%, rgba(255,235,220,.45), transparent),
      radial-gradient(1px 1px at 78% 78%, rgba(255,255,255,.40), transparent),
      radial-gradient(1px 1px at 88% 30%, rgba(200,215,255,.40), transparent),
      radial-gradient(1px 1px at 35% 88%, rgba(255,255,255,.30), transparent),
      radial-gradient(1.5px 1.5px at 72% 16%, rgba(255,255,255,.35), transparent),
      radial-gradient(1px 1px at 8% 54%, rgba(255,255,255,.30), transparent),
      radial-gradient(1px 1px at 55% 60%, rgba(255,255,255,.25), transparent),
      radial-gradient(ellipse 120% 120% at 50% 42%, #171b24 0%, #0c0e15 48%, #05060a 100%); }
  #graph { width:100%; height:100%; }
  #rtour { position:absolute; top:14px; left:50%; transform:translateX(-50%) translateY(-8px);
    z-index:5; background:rgba(20,8,10,.86); border:1px solid #7a1f1f; border-radius:20px;
    padding:7px 15px; font-size:11.5px; letter-spacing:.08em; color:#ffd7d0; cursor:pointer;
    opacity:0; transition:opacity .5s ease, transform .5s ease; box-shadow:0 4px 24px rgba(255,45,45,.25); }
  #rtour.show { opacity:1; transform:translateX(-50%) translateY(0); }
  #rmapbtn { position:absolute; top:12px; right:12px; z-index:6; cursor:pointer;
    background:#151a22; color:#c9d1d9; border:1px solid #232a36; border-radius:5px;
    padding:5px 11px; font:11px ui-monospace,monospace; letter-spacing:.06em; }
  #rmapbtn:hover { border-color:#ff5252; color:#fff; }
  #rmapbtn.on { background:#ff5252; color:#0b0d12; border-color:#ff5252; font-weight:700; }
  #rmaplabels { position:absolute; inset:0; pointer-events:none; z-index:5; }
  .rmaplabel { position:absolute; transform:translate(-50%,-50%); white-space:nowrap;
    font:11px ui-monospace,monospace; letter-spacing:.22em; color:#cdd6e4;
    text-shadow:0 0 8px #000,0 0 3px #000; opacity:.82; }
  #rtour .pip { display:inline-block; width:8px; height:8px; border-radius:50%; background:#ff3b3b;
    margin-right:9px; vertical-align:middle; animation:rpip 1s ease-in-out infinite; }
  #rtour .skip { color:#8a6b6b; }
  @keyframes rpip { 0%,100%{opacity:1; box-shadow:0 0 0 0 rgba(255,59,59,.6);}
    50%{opacity:.5; box-shadow:0 0 0 6px rgba(255,59,59,0);} }
  #glegend { position:absolute; left:14px; bottom:12px; font-size:11px; color:#8a93a2;
    background:rgba(11,13,18,.7); border:1px solid #1c2230; border-radius:6px; padding:8px 10px;
    max-width:60%; }
  #glegend b { color:#c9d1d9; letter-spacing:.06em; }
  .dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin:0 4px 0 10px;
    vertical-align:middle; }
  main { max-width:980px; margin:0 auto; padding:22px 20px 60px; }
  .stats { display:flex; gap:10px; flex-wrap:wrap; margin:6px 0 26px; }
  .stat { flex:1 1 90px; background:#121722; border:1px solid #1c2230; border-radius:8px;
    padding:12px 10px; text-align:center; }
  .stat .n { font-size:24px; font-weight:800; } .stat .k { font-size:10.5px; letter-spacing:.1em;
    color:#8a93a2; margin-top:2px; }
  .s-critical .n{color:#ff4d4d;} .s-high .n{color:#ff7a45;} .s-medium .n{color:#f2c94c;}
  .s-low .n{color:#6fcf97;} .s-info .n{color:#8a93a2;}
  h2.sevh { font-size:12.5px; letter-spacing:.12em; margin:26px 0 10px; padding-bottom:6px;
    border-bottom:1px solid #1c2230; }
  h2.sevh .cnt { color:#6b7280; font-weight:400; margin-left:6px; }
  .sev-critical{color:#ff4d4d;} .sev-high{color:#ff7a45;} .sev-medium{color:#f2c94c;}
  .sev-low{color:#6fcf97;} .sev-info{color:#8a93a2;}
  .card { background:#121722; border:1px solid #1c2230; border-left-width:3px; border-radius:8px;
    padding:13px 15px; margin:0 0 12px; }
  .sev-border-critical{border-left-color:#ff4d4d;} .sev-border-high{border-left-color:#ff7a45;}
  .sev-border-medium{border-left-color:#f2c94c;} .sev-border-low{border-left-color:#6fcf97;}
  .sev-border-info{border-left-color:#8a93a2;}
  .chead { display:flex; align-items:center; gap:9px; flex-wrap:wrap; }
  .badge { font-size:10px; font-weight:800; letter-spacing:.06em; padding:2px 7px; border-radius:4px;
    color:#0b0d12; }
  .b-critical{background:#ff4d4d;} .b-high{background:#ff7a45;} .b-medium{background:#f2c94c;}
  .b-low{background:#6fcf97;} .b-info{background:#8a93a2;}
  .ftitle { font-weight:700; } .fid { font:11px ui-monospace,monospace; color:#6b7280; }
  .fcat { font-size:10.5px; color:#8a93a2; border:1px solid #232a36; border-radius:4px;
    padding:1px 6px; margin-left:auto; letter-spacing:.06em; }
  .affected { margin:8px 0 2px; } .chip { display:inline-block; font:11px ui-monospace,monospace;
    background:#0b0d12; border:1px solid #232a36; border-radius:4px; padding:1px 6px; margin:0 4px 4px 0;
    color:#c9d1d9; }
  .desc { margin:8px 0; color:#c9d1d9; }
  .lbl { display:inline-block; font-size:10.5px; letter-spacing:.08em; color:#6b7280;
    text-transform:uppercase; margin-right:5px; }
  .evidence { margin:8px 0 4px; padding-left:18px; color:#9aa4b2; font-size:12.5px; }
  .evidence .src { color:#22c1a4; font:11px ui-monospace,monospace; }
  .refs { font-size:11.5px; margin:8px 0 0; word-break:break-all; }
  .empty { color:#6b7280; }
  footer { max-width:980px; margin:0 auto; padding:0 20px 40px; color:#4b5563; font-size:10.5px;
    letter-spacing:.05em; }
</style></head>
<body>
<header>
  <!--__LOGO__-->
  <div>
    <h1>REDNESS ASSESSMENT REPORT</h1>
    <div class="sub">__ENGAGEMENT__ &nbsp;|&nbsp; scope: __TARGET__ &nbsp;|&nbsp; __TOTAL__ finding(s)</div>
  </div>
</header>

<div id="graphwrap">
  <div id="graph"></div>
  <div id="rtour"><span class="pip"></span>AUTO-TOUR &nbsp;|&nbsp; tracing path to Domain Admin &nbsp;<span class="skip">click / drag to skip</span></div>
  <button id="rmapbtn" title="Toggle the world-map territory view"># Map</button>
  <div id="glegend"><b>ATTACK GRAPH</b> &nbsp; drag to orbit, scroll to zoom.
    <span class="dot" style="background:#7c6cf0"></span>domain
    <span class="dot" style="background:#22c1a4"></span>host
    <span class="dot" style="background:#ff2d2d"></span>owned
    <span class="dot" style="background:#ff884d"></span>relay
    <span class="dot" style="background:#ffcf33"></span>Domain Admin
    <span class="dot" style="background:#ff9f1c"></span>OT controller
    <span class="dot" style="background:#ff006e"></span>Process Impact
    &nbsp; red edges = attack paths.</div>
</div>

<main>
  <div class="stats"><!--__SUMMARY__--></div>
  <!--__CARDS__-->
</main>
<footer>Generated by REDNESS | Zero Science Lab. Self-contained report - the 3D graph runs offline.</footer>

<script>/*__VENDOR__*/</script>
<script>
(function(){
  var DATA = /*__GRAPH__*/;
  if (typeof ForceGraph3D === 'undefined' || !DATA.nodes) { return; }
  var TYPE_COLOR = { domain:'#7c6cf0', host:'#22c1a4', user:'#3aa0ff', share:'#e08a55',
    ca:'#f4d06a', template:'#f4d06a', adcs:'#f4d06a', group:'#a78bfa', ou:'#94a3b8',
    gpo:'#64748b', container:'#64748b', secret:'#ec4899', owned:'#ff2d2d', goal:'#ffcf33',
    relay:'#ff884d',
    plc:'#ff9f1c', rtu:'#ffb703', gateway:'#fb8500', controller:'#8ecae6',
    'field-device':'#90be6d', process:'#ff006e',            // OT controllers + Process Impact goal
    broker:'#00b4d8', database:'#48cae4', printer:'#b5838d', iot:'#95d5b2' };   // IoT / services
  var GOAL_TYPES = { goal:1, process:1 };                   // Domain Admin + OT Process Impact
  var SEV_COLOR = { critical:'#ff4d4d', high:'#ff7a45', medium:'#f2c94c', low:'#6fcf97',
    info:'#8a93a2' };
  // Severity as physics: worse findings swell larger, throb harder/faster, and are pulled toward
  // the centre so the criticals cluster and draw the eye.
  var SEV_SIZE = { critical:4.5, high:2.6, medium:1.1, low:0.3, info:0 };
  var SEV_AMP  = { critical:0.30, high:0.19, medium:0.10, low:0.05, info:0 };
  var SEV_SPD  = { critical:3.3, high:2.6, medium:2.0, low:1.6, info:1.4 };
  var SEV_PULL = { critical:1.0, high:0.6, medium:0.28, low:0.08, info:0 };
  var SEV_GLOW = { critical:0.18, high:0.12, medium:0.08, low:0.05, info:0.035 };
  function baseVal(n){
    var typeV = GOAL_TYPES[n.type]?9 : n.type==='domain'?8 : n.type==='owned'?5 : 3;
    return typeV + (SEV_SIZE[n.sev] || 0);
  }
  var G = ForceGraph3D()(document.getElementById('graph'))
    .backgroundColor('rgba(0,0,0,0)')          // transparent: the CSS starfield + vignette shows behind
    .graphData(DATA)
    .nodeLabel(function(n){ return n.label + (n.sev ? ' - ' + n.sev.toUpperCase() : ''); })
    .nodeColor(function(n){ return (n.type==='owned'||GOAL_TYPES[n.type]) ? TYPE_COLOR[n.type]
        : n.sev ? SEV_COLOR[n.sev] : (TYPE_COLOR[n.type] || '#9aa4b2'); })
    .nodeVal(function(n){ return n.val || baseVal(n); })
    .nodeResolution(20).nodeOpacity(0.3).nodeRelSize(5)
    .linkCurvature(function(l){ return l.attack ? 0.28 : 0.16; })
    .linkColor(function(l){ return l.attack ? (l.potential?'rgba(255,120,90,.6)':'rgba(255,55,55,.9)')
        : 'rgba(120,130,150,.35)'; })
    .linkWidth(function(l){ return (l.attack && !l.potential) ? 2.2 : 0; })
    .linkDirectionalParticles(function(l){ return l.attack ? (l.potential?2:5) : 2; })
    .linkDirectionalParticleWidth(function(l){ return l.attack ? 2.6 : 1.6; })
    .linkDirectionalParticleSpeed(function(l){ return l.attack ? 0.02 : 0.012; });
  G.d3VelocityDecay(0.3);
  var charge = G.d3Force('charge'); if (charge) charge.strength(-150);
  setTimeout(function(){ try { G.d3AlphaTarget(0.02).resumeAnimation(); } catch(e){} }, 2500);

  // severity as a force: pull each node toward the centre in proportion to its worst severity, so
  // the critical findings gravitate inward and cluster while low/info nodes drift outward.
  function severityForce(){
    var _n = [];
    var f = function(alpha){
      for (var i=0;i<_n.length;i++){ var n=_n[i]; var w=SEV_PULL[n.sev]||0; if(!w) continue;
        var k=alpha*w*0.09;
        if(n.x!==undefined) n.vx-=n.x*k; if(n.y!==undefined) n.vy-=n.y*k; if(n.z!==undefined) n.vz-=n.z*k; }
    };
    f.initialize = function(nn){ _n = nn; };
    return f;
  }
  try { G.d3Force('severity', severityForce()); } catch(e){}

  // ambient throb driven by severity: worse nodes breathe harder + faster, drawing the eye.
  (function throb(){
    var t = performance.now()/1000, any=false;
    (G.graphData().nodes||[]).forEach(function(n){
      if (n.__burst) return;
      var hv = (n.type==='goal'||n.type==='owned');
      var amp = SEV_AMP[n.sev] || 0, spd = SEV_SPD[n.sev] || 1.8;
      if (hv) amp = Math.max(amp, 0.16);
      if (amp <= 0) return;
      any = true; if (n.__ph===undefined) n.__ph = Math.random()*6.28;
      n.val = baseVal(n) * (1 + amp * Math.sin(t*spd + n.__ph));
    });
    if (any){ try { G.nodeVal(G.nodeVal()); } catch(e){} }
    requestAnimationFrame(throb);
  })();

  // glowing core inside each translucent orb (reuse the bundle's own three via .constructor)
  function core(n){
    var shell = n.__threeObj;
    if (!shell || !shell.material || !shell.geometry || !shell.children) return;
    var c = shell.children.find(function(x){ return x.__core; });
    if (!c){
      var Mesh = shell.constructor, Geo = shell.geometry.constructor, Mat = shell.material.constructor;
      var r = (shell.geometry.parameters && shell.geometry.parameters.radius) || 4;
      try { c = new Mesh(new Geo(r*0.5,16,16), new Mat({transparent:true,opacity:0.95})); }
      catch(e){ return; }
      c.__core = true; shell.add(c);
    }
    var col = shell.material.color;
    if (col && c.material.color){
      c.material.color.copy(col);
      if (c.material.color.offsetHSL) c.material.color.offsetHSL(0,-0.1,0.32);
      if (c.material.emissive){ c.material.emissive.copy(col); c.material.emissiveIntensity = 1.1; }
    }
    // fake bloom: an additive halo sphere bleeding light outward, brightness by severity
    var glow = shell.children.find(function(x){ return x.__glow; });
    if (!glow){
      var Mesh2=shell.constructor, Geo2=shell.geometry.constructor, Mat2=shell.material.constructor;
      var r2=(shell.geometry.parameters && shell.geometry.parameters.radius)||4;
      try { var gm=new Mat2({transparent:true, opacity:0.11}); gm.blending=2;   // AdditiveBlending
        if('depthWrite' in gm) gm.depthWrite=false;
        glow=new Mesh2(new Geo2(r2*1.42,16,12), gm); glow.__glow=true; shell.add(glow);
      } catch(e){ glow=null; }
    }
    if (glow && col && glow.material.color){
      glow.material.color.copy(col);
      if (glow.material.emissive) glow.material.emissive.copy(col);
      var hv=(n.type==='owned'||GOAL_TYPES[n.type]);
      var g=SEV_GLOW[n.sev]||0.05; if(hv) g=Math.max(g, n.type==='goal'?0.18:0.14);
      glow.material.opacity=g;
    }
  }
  (function loop(){
    var d = G.graphData(); if (d && d.nodes) d.nodes.forEach(core);
    requestAnimationFrame(loop);
  })();

  function size(){ var w = document.getElementById('graphwrap');
    G.width(w.clientWidth).height(w.clientHeight); }
  size(); window.addEventListener('resize', size);
  setTimeout(function(){ try { G.zoomToFit(600, 60); } catch(e){} }, 900);

  // ---- cinematic auto-tour: fly the attack path entry -> owned -> Domain Admin ----
  var highlight = new Set(), touring=false, tourAbort=false, tourPlayed=false, interacted=false;
  G.linkColor(function(l){ return highlight.has(l) ? '#ffffff'
        : l.attack ? (l.potential?'rgba(255,120,90,.6)':'rgba(255,55,55,.9)') : 'rgba(120,130,150,.35)'; })
   .linkWidth(function(l){ return highlight.has(l) ? 5 : ((l.attack && !l.potential) ? 2.2 : 0); })
   .linkDirectionalParticles(function(l){ return highlight.has(l) ? 8 : (l.attack ? (l.potential?2:5) : 2); });
  function refresh(){ G.linkColor(G.linkColor()); }
  var lid = function(x){ return (x && x.id!==undefined) ? x.id : x; };
  var byId = new Map(); (DATA.nodes||[]).forEach(function(n){ byId.set(n.id, n); });
  var sleep = function(ms){ return new Promise(function(r){ setTimeout(r, ms); }); };
  function order(){
    var al = (G.graphData().links||[]).filter(function(l){ return l.attack; });
    var depth = new Map();
    var frontier = (G.graphData().nodes||[]).filter(function(n){ return GOAL_TYPES[n.type]; })
                      .map(function(n){ return n.id; });
    frontier.forEach(function(g){ depth.set(g,0); }); var d=0;
    while(frontier.length){ var nx=[]; al.forEach(function(l){ var s=lid(l.source),t=lid(l.target);
      if(frontier.indexOf(t)>=0 && !depth.has(s)){ depth.set(s,d+1); nx.push(s); } }); frontier=nx; d++; }
    return al.slice().sort(function(a,b){ return (depth.get(lid(b.source))||0)-(depth.get(lid(a.source))||0); });
  }
  function camFor(s,t){ var D=160; if(!s||s.x===undefined) return {x:t.x,y:t.y,z:(t.z||0)+D};
    var dx=t.x-s.x,dy=t.y-s.y,dz=(t.z||0)-(s.z||0),L=Math.hypot(dx,dy,dz)||1; dx/=L;dy/=L;dz/=L;
    return {x:t.x-dx*D*0.65+55, y:t.y-dy*D*0.65+70, z:(t.z||0)-dz*D*0.65+D*0.9}; }
  function pulse(n){ var base=n.type==='goal'?9:5, t=0; n.__burst=true;   // let the finale own the size
    var iv=setInterval(function(){ t+=0.4; n.val=base+Math.abs(Math.sin(t))*6; G.nodeVal(G.nodeVal());
      if(t>Math.PI*3){ clearInterval(iv); n.__burst=false; n.val=undefined; G.nodeVal(G.nodeVal()); } }, 55); }
  function orbitGoal(goal){ var r=150, start=performance.now();
    (function spin(){ if(tourAbort||!touring) return; var e=(performance.now()-start)/1000; if(e>1.6) return;
      var a=e*1.6; try{ G.cameraPosition({x:goal.x+Math.cos(a)*r, y:goal.y+45, z:(goal.z||0)+Math.sin(a)*r}); }catch(_){}
      requestAnimationFrame(spin); })(); }
  function toast(on){ var e=document.getElementById('rtour'); if(e) e.classList.toggle('show', on); }
  function endTour(){ touring=false; tourAbort=false; highlight.clear(); refresh(); toast(false);
    try{ G.zoomToFit(700,55); }catch(e){} }
  function tour(auto){
    if(touring) return; var seq=order(); if(!seq.length) return;
    touring=true; tourAbort=false; tourPlayed=true; highlight.clear(); refresh(); toast(true);
    try{ G.zoomToFit(900,70); }catch(e){}
    (async function(){
      await sleep(1250); if(tourAbort) return endTour();
      for(var i=0;i<seq.length;i++){ if(tourAbort) return endTour(); var l=seq[i];
        highlight.add(l); refresh(); var s=byId.get(lid(l.source)), t=byId.get(lid(l.target));
        try{ for(var k=0;k<4;k++) G.emitParticles(l); }catch(e){}
        if(s&&s.type==='owned') pulse(s);
        if(t&&t.x!==undefined) G.cameraPosition(camFor(s,t), t, 1050);
        await sleep(1080); }
      if(tourAbort) return endTour();
      var goal=(G.graphData().nodes||[]).find(function(n){ return GOAL_TYPES[n.type]; });
      if(goal&&goal.x!==undefined){ G.cameraPosition({x:goal.x,y:goal.y+30,z:(goal.z||0)+150}, goal, 1000);
        await sleep(350); if(tourAbort) return endTour(); pulse(goal); orbitGoal(goal); }
      await sleep(1700); endTour();
    })();
  }
  function interact(){ interacted=true; if(touring) tourAbort=true; }
  try{ var rd=G.renderer().domElement; rd.addEventListener('pointerdown',interact,{passive:true});
    rd.addEventListener('wheel',interact,{passive:true}); }catch(e){}
  var th=document.getElementById('rtour'); if(th) th.onclick=function(){ tourAbort=true; };
  setTimeout(function(){ if(!tourPlayed && !interacted) tour(true); }, 2800);   // auto-play once, after layout settles

  // ---- compromise-spread shockwaves: a cascade rippling out from owned nodes along attack edges ----
  var spreading = false;
  function shockRing(n, color, dur, maxScale){
    var shell = n && n.__threeObj;
    if(!shell || !shell.geometry || !shell.material) return;
    var Mesh=shell.constructor, Geo=shell.geometry.constructor, Mat=shell.material.constructor;
    var r=(shell.geometry.parameters && shell.geometry.parameters.radius)||4, ring;
    try {
      var mat=new Mat({transparent:true, opacity:0.85, wireframe:true});
      if(mat.color&&mat.color.set) mat.color.set(color);
      if(mat.emissive){ mat.emissive.set(color); mat.emissiveIntensity=1.4; }
      if('depthWrite' in mat) mat.depthWrite=false;
      ring=new Mesh(new Geo(r,14,10), mat); ring.__shock=true; shell.add(ring);
    } catch(e){ return; }
    var t0=performance.now(), DUR=dur||900, MAX=maxScale||3.2;
    var done=function(){ if(ring&&ring.parent){ try{ ring.parent.remove(ring);
      ring.geometry.dispose(); ring.material.dispose(); }catch(e){} ring=null; } };
    (function fr(now){ if(!ring) return; var k=Math.min(1,(now-t0)/DUR); var s=1+k*MAX; ring.scale.set(s,s,s);
      if(ring.material) ring.material.opacity=0.85*(1-k); if(k<1) requestAnimationFrame(fr); else done(); })(t0);
    setTimeout(done, DUR+500);
  }
  async function spreadWave(){
    if(spreading||touring) return;
    var gd=G.graphData();
    var startIds=(gd.nodes||[]).filter(function(n){return n.type==='owned';}).map(function(n){return n.id;});
    if(!startIds.length) return;
    var attack=(gd.links||[]).filter(function(l){return l.attack;});
    spreading=true;
    var outBy=new Map(); attack.forEach(function(l){ var s=lid(l.source);
      if(!outBy.has(s)) outBy.set(s,[]); outBy.get(s).push(l); });
    var visited=new Set(startIds), frontier=startIds.slice();
    frontier.forEach(function(id){ shockRing(byId.get(id), '#ff3b3b'); });
    while(frontier.length){
      if(touring) break;
      var next=[];
      frontier.forEach(function(id){ (outBy.get(id)||[]).forEach(function(l){
        try{ for(var i=0;i<3;i++) G.emitParticles(l); }catch(e){}
        var t=lid(l.target); if(!visited.has(t)){ visited.add(t); next.push(t); } }); });
      if(!next.length) break;
      await sleep(520);
      next.forEach(function(id){ var n=byId.get(id); if(!n) return; var goal=GOAL_TYPES[n.type];
        shockRing(n, goal?'#ffcf33':'#ff7a45', goal?1100:900, goal?4.2:3.2); });
      frontier=next;
    }
    spreading=false;
  }
  setInterval(function(){ var gd=G.graphData();
    if(!touring && !spreading && (gd.nodes||[]).some(function(n){return n.type==='owned';})) spreadWave();
  }, 4200);

  // ---- world-map territory view (toggle; mirrors the live GUI) ----
  var mapMode=false, _discs=[], _mlabels=[], _sc={};
  var CONTINENTS=[
    {name:'DIRECTORY',cx:-300,cz:-70,color:0x2b3a67,types:['domain','host','user','share','template','ca','adcs','secret','group','ou','gpo','container']},
    {name:'COMPROMISE',cx:70,cz:-240,color:0x6a1b1b,types:['owned','goal','relay']},
    {name:'OT / ICS',cx:320,cz:40,color:0x6b4410,types:['plc','rtu','gateway','controller','field-device','process']},
    {name:'IoT / SERVICES',cx:-50,cz:240,color:0x0f4a52,types:['broker','database','printer','iot']}
  ];
  var _DEF={name:'OTHER',cx:230,cz:270,color:0x333a4e,types:[]};
  var _cf={}; CONTINENTS.forEach(function(c){c.types.forEach(function(t){_cf[t]=c;});});
  function _pspec(t){
    if(t==='goal'||t==='process')return{h:46,base:6.5,col:1.8};
    if(t==='owned'||t==='relay')return{h:24,base:9,col:3.2};
    if(t==='domain')return{h:20,base:12,col:3.8};
    if(t==='plc'||t==='rtu'||t==='gateway'||t==='controller'||t==='field-device'||t==='broker'||t==='database'||t==='printer'||t==='iot')return{h:13,base:8,col:2.8};
    return{h:6.5,base:10.5,col:5.0};}
  function _conOf(n){return _cf[n.type]||_DEF;}
  function _slot(c){var i=_sc[c.name]||0;_sc[c.name]=i+1;var a=i*2.399963,r=17*Math.sqrt(i+0.5);return{dx:Math.cos(a)*r,dz:Math.sin(a)*r};}
  function _tgt(n){if(n.__mt)return n.__mt;var c=_conOf(n),s=_slot(c);n.__mt={x:c.cx+s.dx,y:_isChess(n)?-9:_pspec(n.type).h,z:c.cz+s.dz};return n.__mt;}
  function _elas(k){if(k<=0)return 0;if(k>=1)return 1;var p=0.42;return Math.pow(2,-10*k)*Math.sin((k-p/4)*(2*Math.PI)/p)+1;}
  function _wob(n,t){var st=performance.now(),D=1050,sx=t.x+(Math.random()-0.5)*70,sy=t.y+110,sz=t.z+(Math.random()-0.5)*70;
    (function f(now){if(!mapMode)return;var k=Math.min(1,(now-st)/D),e=_elas(k);
      n.fx=n.x=sx+(t.x-sx)*e;n.fy=n.y=sy+(t.y-sy)*e;n.fz=n.z=sz+(t.z-sz)*e;
      if(k<1)requestAnimationFrame(f);else{n.fx=n.x=t.x;n.fy=n.y=t.y;n.fz=n.z=t.z;}})(st);}
  var _pieces=[];
  function _flat(Me,Ge,Ma,R,col,op,y,cx,cz,wire){var m=new Ma({transparent:true,opacity:op,wireframe:!!wire});
    if(m.color&&m.color.setHex)m.color.setHex(col);if('depthWrite' in m)m.depthWrite=false;
    var d=new Me(new Ge(R,wire?32:28,wire?2:24),m);d.position.set(cx,y,cz);d.scale.set(1,0.02,1);G.scene().add(d);_discs.push(d);}
  function _seed(s){var h=2166136261;for(var i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619);}return h>>>0;}
  function _rng(sd){var s=sd>>>0;return function(){s=(Math.imul(s,1664525)+1013904223)>>>0;return s/4294967296;};}
  function _cont(Me,Ge,Ma,c,R){var rnd=_rng(_seed(c.name));
    _flat(Me,Ge,Ma,R*1.30,0x1b3b57,0.11,-13,c.cx,c.cz);_flat(Me,Ge,Ma,R,c.color,0.26,-10,c.cx,c.cz);
    for(var i=0;i<7;i++){var a=(i/7)*2*Math.PI+rnd()*0.7,rr=R*(0.60+rnd()*0.5),br=R*(0.32+rnd()*0.30);
      _flat(Me,Ge,Ma,br,c.color,0.24,-10,c.cx+Math.cos(a)*rr,c.cz+Math.sin(a)*rr);}}
  function _mkDiscs(){_rmDiscs();var gd=G.graphData();var any=(gd.nodes||[]).find(function(x){return x.__threeObj;});if(!any)return;
    var Me=any.__threeObj.constructor,Ge=any.__threeObj.geometry.constructor,Ma=any.__threeObj.material.constructor;
    try{_flat(Me,Ge,Ma,620,0x0a1324,0.5,-16,-10,20);[180,320,470,600].forEach(function(rg){_flat(Me,Ge,Ma,rg,0x24436b,0.06,-14,-10,20,true);});}catch(e){}
    CONTINENTS.concat([_DEF]).forEach(function(c){var cnt=(gd.nodes||[]).filter(function(n){return _conOf(n)===c;}).length;if(!cnt)return;
      var R=Math.max(70,19*Math.sqrt(cnt)+44);try{_cont(Me,Ge,Ma,c,R);}catch(e){}});}
  function _rmDiscs(){_discs.forEach(function(d){try{G.scene().remove(d);d.geometry.dispose();d.material.dispose();}catch(e){}});_discs=[];}
  function _mkPieces(){_rmPieces();var gd=G.graphData();var any=(gd.nodes||[]).find(function(x){return x.__threeObj;});if(!any)return;
    var Me=any.__threeObj.constructor,Ge=any.__threeObj.geometry.constructor,Ma=any.__threeObj.material.constructor;
    (gd.nodes||[]).forEach(function(n){var t=n.__mt;if(!t)return;if(_isChess(n))return;var sp=_pspec(n.type);var hex=0x8aa0b8;try{hex=n.__threeObj.material.color.getHex();}catch(e){}
      try{var pm=new Ma({transparent:true,opacity:0.92});pm.color.setHex(hex);if('depthWrite' in pm)pm.depthWrite=false;
        var ped=new Me(new Ge(sp.base,20,10),pm);ped.position.set(t.x,1.0,t.z);ped.scale.set(1,0.06,1);G.scene().add(ped);_pieces.push(ped);}catch(e){}
      var h=t.y;if(h>3){try{var cm=new Ma({transparent:true,opacity:0.4});cm.color.setHex(hex);if('depthWrite' in cm)cm.depthWrite=false;
        var col=new Me(new Ge(1,12,8),cm);col.position.set(t.x,h/2,t.z);col.scale.set(sp.col,h/2,sp.col);G.scene().add(col);_pieces.push(col);}catch(e){}}});}
  function _rmPieces(){_pieces.forEach(function(p){try{G.scene().remove(p);p.geometry.dispose();p.material.dispose();}catch(e){}});_pieces=[];}
  var CHESS_PIECES=true, _PIECE_SCALE=0.9;
  var _PROFILE={
    pawn:[[8,0],[8,2],[4.5,4],[3.4,10],[5.2,12.5],[3.4,14.5],[2.8,21],[4.6,23.5],[5.4,27],[4.8,30],[2.4,32],[0,34]],
    rook:[[9.5,0],[9.5,2.5],[6,5],[5,7],[5,24],[6,26],[8.6,28],[9,32],[6.6,33],[6.6,37]],
    bishop:[[8,0],[8,2],[4.2,4],[3,10],[4.6,12],[3,14],[2.4,24],[4,26],[4.6,30],[3.6,36],[2,40],[2.6,42],[1.6,44],[0.6,48],[0,50]],
    queen:[[10,0],[10,2.5],[6,5.5],[5,8],[5,32],[7,35],[6,37],[4.2,46],[6,49],[7,52],[5,53.5],[3,55],[4.4,58],[2.2,59],[3.2,61],[0,64]],
    king:[[10,0],[10,2.5],[6,5.5],[5,8],[5,34],[7,37],[6,39],[4.4,50],[6.4,53],[6.6,56],[4.6,57.5],[2,59],[3,61],[2,63],[1.2,70],[0,72]]};
  var _KNIGHT_POLY=[[6,0],[6,5],[3.5,9],[3.5,17],[6.5,27],[3.5,31],[5,39],[2,35],[0.5,40],[-4,33],[-9,29],[-13,23],[-13.5,19],[-10,19],[-9,16],[-5,17],[-3.5,12],[-4.5,6],[-4.5,0]];
  var _EXTRUDE={knight:{poly:_KNIGHT_POLY,depth:7}};
  var _PIECE_FOR={goal:'king',process:'king',domain:'queen',owned:'rook',relay:'knight',
    plc:'bishop',rtu:'bishop',gateway:'bishop',controller:'bishop','field-device':'bishop',broker:'bishop',database:'bishop',printer:'bishop',iot:'bishop',
    host:'pawn',user:'pawn',share:'pawn',template:'pawn',ca:'pawn',adcs:'pawn',secret:'pawn',group:'pawn',ou:'pawn',gpo:'pawn',container:'pawn'};
  function _pieceKind(n){return CHESS_PIECES?(_PIECE_FOR[n.type]||null):null;}
  function _isChess(n){return !!_pieceKind(n);}
  var _GEOBUF=null,_F32=null,_ME=null,_MA=null,_gcache={};
  function _refs(){if(_GEOBUF&&_F32&&_ME&&_MA)return true;var any=(G.graphData().nodes||[]).find(function(x){return x.__threeObj&&x.__threeObj.geometry;});if(!any)return false;
    try{_GEOBUF=Object.getPrototypeOf(any.__threeObj.geometry.constructor);_F32=any.__threeObj.geometry.attributes.position.constructor;_ME=any.__threeObj.constructor;_MA=any.__threeObj.material.constructor;}catch(e){return false;}
    return !!(_GEOBUF&&_F32&&_ME&&_MA);}
  function _lathe(p,seg){var pos=[],idx=[],rows=p.length,s,i,a,ca,sa;
    for(s=0;s<=seg;s++){a=s/seg*Math.PI*2;ca=Math.cos(a);sa=Math.sin(a);for(i=0;i<rows;i++)pos.push(p[i][0]*ca,p[i][1],p[i][0]*sa);}
    for(s=0;s<seg;s++)for(i=0;i<rows-1;i++){var A=s*rows+i,B=(s+1)*rows+i,C=(s+1)*rows+i+1,D=s*rows+i+1;idx.push(A,B,D,B,C,D);}
    var g=new _GEOBUF();g.setAttribute('position',new _F32(pos,3));g.setIndex(idx);g.computeVertexNormals();return g;}
  function _sgn(p,a,b){return (p[0]-b[0])*(a[1]-b[1])-(a[0]-b[0])*(p[1]-b[1]);}
  function _inT(p,a,b,c){var d1=_sgn(p,a,b),d2=_sgn(p,b,c),d3=_sgn(p,c,a);return !(((d1<0)||(d2<0)||(d3<0))&&((d1>0)||(d2>0)||(d3>0)));}
  function _ear(pts){var n=pts.length,idx=[],i;for(i=0;i<n;i++)idx.push(i);var tris=[],area=0;for(i=0;i<n;i++){var a=pts[i],b=pts[(i+1)%n];area+=a[0]*b[1]-b[0]*a[1];}if(area<0)idx.reverse();
    var guard=0;while(idx.length>3&&guard++<2000){var clipped=false;for(i=0;i<idx.length;i++){var i0=idx[(i-1+idx.length)%idx.length],i1=idx[i],i2=idx[(i+1)%idx.length],a=pts[i0],b=pts[i1],c=pts[i2];
      if((b[0]-a[0])*(c[1]-a[1])-(b[1]-a[1])*(c[0]-a[0])<=0)continue;var ok=true;for(var k=0;k<idx.length;k++){var j=idx[k];if(j===i0||j===i1||j===i2)continue;if(_inT(pts[j],a,b,c)){ok=false;break;}}if(!ok)continue;
      tris.push([i0,i1,i2]);idx.splice(i,1);clipped=true;break;}if(!clipped)break;}if(idx.length===3)tris.push([idx[0],idx[1],idx[2]]);return tris;}
  function _extr(poly,depth){var n=poly.length,hz=depth/2,pos=[],idx=[],i;for(i=0;i<n;i++)pos.push(poly[i][0],poly[i][1],hz);for(i=0;i<n;i++)pos.push(poly[i][0],poly[i][1],-hz);
    var tris=_ear(poly);tris.forEach(function(t){idx.push(t[0],t[1],t[2]);});tris.forEach(function(t){idx.push(t[2]+n,t[1]+n,t[0]+n);});for(i=0;i<n;i++){var j=(i+1)%n;idx.push(i,j,j+n,i,j+n,i+n);}
    var g=new _GEOBUF();g.setAttribute('position',new _F32(pos,3));g.setIndex(idx);g.computeVertexNormals();return g;}
  function _pieceGeom(kind){if(_gcache[kind])return _gcache[kind];var g=_EXTRUDE[kind]?_extr(_EXTRUDE[kind].poly,_EXTRUDE[kind].depth):_lathe(_PROFILE[kind],24);return _gcache[kind]=g;}
  function _nodeHex(n){if(n.type==='owned'||GOAL_TYPES[n.type])return TYPE_COLOR[n.type]||'#9aa4b2';return n.sev?SEV_COLOR[n.sev]:(TYPE_COLOR[n.type]||'#9aa4b2');}
  function _pieceObj(n){var kind=_pieceKind(n);if(!kind||!_refs())return false;
    try{var mat=new _MA({color:_nodeHex(n)});if('side' in mat)mat.side=2;if(mat.emissive&&mat.emissive.set){mat.emissive.set(_nodeHex(n));mat.emissiveIntensity=0.22;}var m=new _ME(_pieceGeom(kind),mat);m.scale.setScalar(_PIECE_SCALE);return m;}catch(e){return false;}}
  function _mkLabels(){_rmLabels();var h=document.getElementById('rmaplabels');if(!h){h=document.createElement('div');h.id='rmaplabels';document.getElementById('graphwrap').appendChild(h);}
    var gd=G.graphData();CONTINENTS.forEach(function(c){if(!(gd.nodes||[]).some(function(n){return _conOf(n)===c;}))return;
      var d=document.createElement('div');d.className='rmaplabel';d.textContent=c.name;h.appendChild(d);_mlabels.push({el:d,c:c});});
    (function tick(){if(!mapMode)return;_mlabels.forEach(function(L){try{var p=G.graph2ScreenCoords(L.c.cx,2,L.c.cz);if(p){L.el.style.left=p.x+'px';L.el.style.top=p.y+'px';L.el.style.display='block';}}catch(e){L.el.style.display='none';}});requestAnimationFrame(tick);})();}
  function _rmLabels(){_mlabels.forEach(function(L){try{L.el.remove();}catch(e){}});_mlabels=[];}
  function enterMapR(){mapMode=true;tourAbort=true;interacted=true;_sc={};(G.graphData().nodes||[]).forEach(function(n){n.__mt=null;_wob(n,_tgt(n));});
    G.linkCurvature(function(l){return l.attack?0.5:0.3;});refresh();_mkDiscs();_mkLabels();_mkPieces();
    try{_refs();G.nodeThreeObject(_pieceObj);}catch(e){}
    try{G.d3ReheatSimulation&&G.d3ReheatSimulation();}catch(e){}
    setTimeout(function(){try{G.cameraPosition({x:0,y:600,z:560},{x:0,y:-20,z:20},1200);}catch(e){}},60);
    var b=document.getElementById('rmapbtn');if(b){b.textContent='# Graph';b.classList.add('on');}}
  function exitMapR(){mapMode=false;_rmDiscs();_rmLabels();_rmPieces();try{G.nodeThreeObject(null);}catch(e){}(G.graphData().nodes||[]).forEach(function(n){n.fx=undefined;n.fy=undefined;n.fz=undefined;n.__mt=null;});
    G.linkCurvature(function(l){return l.attack?0.28:0.16;});refresh();
    try{G.d3ReheatSimulation&&G.d3ReheatSimulation();}catch(e){}
    setTimeout(function(){try{G.zoomToFit(700,55);}catch(e){}},220);
    var b=document.getElementById('rmapbtn');if(b){b.textContent='# Map';b.classList.remove('on');}}
  var _mb=document.getElementById('rmapbtn');if(_mb)_mb.onclick=function(){mapMode?exitMapR():enterMapR();};
})();
</script>
</body></html>
"""
