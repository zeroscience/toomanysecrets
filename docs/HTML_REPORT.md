# Self-contained HTML report - `--html`

The `.docx` is the formal deliverable; the **HTML report** is the one you can just double-click.
It is a single offline file that carries both the findings *and* the live 3D attack-graph, so a
client can explore the assessment with no server, no network, and no Word installed.

## Generate one
```bash
# during a scan
redness scan --targets examples/scope.txt -u USER -p PASS -d acme.local --html report.html

# or from a saved findings.json (also still writes the .docx unless --out '')
redness report findings.json --html report.html
redness demo --out sample.docx        # (the .docx sample; --html works on any findings.json)
```

## What's inside
- **The 3D attack-graph**, the same one the live GUI shows: domain -> hosts, findings coloured by
  severity, owned (compromised) nodes, the NTLM-relay node, and attack edges arcing to the
  **Domain Admin** goal. Drag to orbit, scroll to zoom - it runs entirely in the file.
- **Severity summary** (critical/high/medium/low/info counts).
- **Every finding**, grouped by severity, with description, impact, **remediation**, evidence, and
  reference links - the same content as the `.docx`.

## Self-contained, on purpose
The report inlines the vendored `3d-force-graph` bundle (which bundles three.js), so the whole
graph renders offline from the one `.html`. Expect the file to be ~1.3 MB because of that - the
trade for "email it and it just works."

## How the graph is captured
A scan records the exact node/edge event stream into `report.meta["graph"]`, so the HTML graph is
a true mirror of what streamed live. For a findings.json produced before this existed (or any
report without a captured graph), REDNESS reconstructs a graph from the findings - the attack-path
and relay overlay stay exact; individual host-to-finding edges are approximated (a saved report
doesn't record which host produced which finding).

Like every REDNESS output, keep generated reports out of git - `*.docx` and `findings*.json` are
already git-ignored; treat `*.html` reports the same (they contain engagement data).
