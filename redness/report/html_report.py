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
_VENDOR = os.path.join(os.path.dirname(__file__), "..", "live", "web", "vendor",
                       "3d-force-graph.min.js")


def _esc(s: str) -> str:
    return html.escape(str(s or ""))


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
        refs = " · ".join(f'<a href="{_esc(r)}" rel="noopener">{_esc(r)}</a>' for r in f.references)
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
  header { padding:22px 28px 14px; border-bottom:1px solid #1c2230; }
  header h1 { margin:0; font-size:17px; letter-spacing:.14em; color:#ff5252; }
  header .sub { color:#8a93a2; font-size:12.5px; margin-top:4px; }
  #graphwrap { position:relative; height:62vh; min-height:360px; border-bottom:1px solid #1c2230;
    background:#0b0d12; }
  #graph { width:100%; height:100%; }
  #rtour { position:absolute; top:14px; left:50%; transform:translateX(-50%) translateY(-8px);
    z-index:5; background:rgba(20,8,10,.86); border:1px solid #7a1f1f; border-radius:20px;
    padding:7px 15px; font-size:11.5px; letter-spacing:.08em; color:#ffd7d0; cursor:pointer;
    opacity:0; transition:opacity .5s ease, transform .5s ease; box-shadow:0 4px 24px rgba(255,45,45,.25); }
  #rtour.show { opacity:1; transform:translateX(-50%) translateY(0); }
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
  <h1>REDNESS ASSESSMENT REPORT</h1>
  <div class="sub">__ENGAGEMENT__ &nbsp;·&nbsp; scope: __TARGET__ &nbsp;·&nbsp; __TOTAL__ finding(s)</div>
</header>

<div id="graphwrap">
  <div id="graph"></div>
  <div id="rtour"><span class="pip"></span>AUTO-TOUR &nbsp;·&nbsp; tracing path to Domain Admin &nbsp;<span class="skip">click / drag to skip</span></div>
  <div id="glegend"><b>ATTACK GRAPH</b> &nbsp; drag to orbit, scroll to zoom.
    <span class="dot" style="background:#7c6cf0"></span>domain
    <span class="dot" style="background:#22c1a4"></span>host
    <span class="dot" style="background:#ff2d2d"></span>owned
    <span class="dot" style="background:#ff884d"></span>relay
    <span class="dot" style="background:#ffcf33"></span>Domain Admin
    &nbsp; red edges = attack paths.</div>
</div>

<main>
  <div class="stats"><!--__SUMMARY__--></div>
  <!--__CARDS__-->
</main>
<footer>Generated by REDNESS · Zero Science Lab. Self-contained report - the 3D graph runs offline.</footer>

<script>/*__VENDOR__*/</script>
<script>
(function(){
  var DATA = /*__GRAPH__*/;
  if (typeof ForceGraph3D === 'undefined' || !DATA.nodes) { return; }
  var TYPE_COLOR = { domain:'#7c6cf0', host:'#22c1a4', user:'#3aa0ff', share:'#e08a55',
    ca:'#f4d06a', template:'#f4d06a', adcs:'#f4d06a', group:'#a78bfa', ou:'#94a3b8',
    gpo:'#64748b', container:'#64748b', secret:'#ec4899', owned:'#ff2d2d', goal:'#ffcf33',
    relay:'#ff884d' };
  var SEV_COLOR = { critical:'#ff4d4d', high:'#ff7a45', medium:'#f2c94c', low:'#6fcf97',
    info:'#8a93a2' };
  var G = ForceGraph3D()(document.getElementById('graph'))
    .backgroundColor('#0b0d12')
    .graphData(DATA)
    .nodeLabel(function(n){ return n.label + (n.sev ? ' - ' + n.sev.toUpperCase() : ''); })
    .nodeColor(function(n){ return (n.type==='owned'||n.type==='goal') ? TYPE_COLOR[n.type]
        : n.sev ? SEV_COLOR[n.sev] : (TYPE_COLOR[n.type] || '#9aa4b2'); })
    .nodeVal(function(n){ return n.val || (n.type==='goal'?9 : n.type==='domain'?8 : n.type==='owned'?5 : 3); })
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
    var frontier = (G.graphData().nodes||[]).filter(function(n){ return n.type==='goal'; })
                      .map(function(n){ return n.id; });
    frontier.forEach(function(g){ depth.set(g,0); }); var d=0;
    while(frontier.length){ var nx=[]; al.forEach(function(l){ var s=lid(l.source),t=lid(l.target);
      if(frontier.indexOf(t)>=0 && !depth.has(s)){ depth.set(s,d+1); nx.push(s); } }); frontier=nx; d++; }
    return al.slice().sort(function(a,b){ return (depth.get(lid(b.source))||0)-(depth.get(lid(a.source))||0); });
  }
  function camFor(s,t){ var D=160; if(!s||s.x===undefined) return {x:t.x,y:t.y,z:(t.z||0)+D};
    var dx=t.x-s.x,dy=t.y-s.y,dz=(t.z||0)-(s.z||0),L=Math.hypot(dx,dy,dz)||1; dx/=L;dy/=L;dz/=L;
    return {x:t.x-dx*D*0.65+55, y:t.y-dy*D*0.65+70, z:(t.z||0)-dz*D*0.65+D*0.9}; }
  function pulse(n){ var base=n.type==='goal'?9:5, t=0;
    var iv=setInterval(function(){ t+=0.4; n.val=base+Math.abs(Math.sin(t))*6; G.nodeVal(G.nodeVal());
      if(t>Math.PI*3){ clearInterval(iv); n.val=undefined; G.nodeVal(G.nodeVal()); } }, 55); }
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
      var goal=(G.graphData().nodes||[]).find(function(n){ return n.type==='goal'; });
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
      next.forEach(function(id){ var n=byId.get(id); if(!n) return; var goal=n.type==='goal';
        shockRing(n, goal?'#ffcf33':'#ff7a45', goal?1100:900, goal?4.2:3.2); });
      frontier=next;
    }
    spreading=false;
  }
  setInterval(function(){ var gd=G.graphData();
    if(!touring && !spreading && (gd.nodes||[]).some(function(n){return n.type==='owned';})) spreadWave();
  }, 4200);
})();
</script>
</body></html>
"""
