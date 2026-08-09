# CLAUDE.md — context for AI agents working on REDNESS

This file is how *both* researchers' Claude instances stay in sync. Read it first.

## What this is
Red-team **orchestrator + normalizer + reporter** for AD/Windows assessments.
It does NOT reimplement protocols — it drives NetExec, Impacket, Certipy and
normalizes their output into one findings model, then renders a `.docx` report.
Codename REDNESS; will be renamed later.

## The one rule that keeps two agents from colliding
`redness/findings.py` is **the contract**. Engines produce `Finding`s; the reporter
consumes them. Change it only deliberately, bump `SCHEMA_VERSION`, and log it in
`docs/DECISIONS.md`.

## Ownership seams (work in parallel, avoid merge conflicts)
- **Person A — engines/** : wrappers in `redness/engines/` that run tools and emit `Finding`s.
- **Person B — report/**  : `redness/report/` (docx) + packaging (the `.exe`).
Touch the other's directory only via a PR they review.

## Workflow
- Feature branches + PRs into `main`. Never commit to `main` directly.
- The *other human* (or their Claude) reviews before merge.
- Keep secrets and any client/engagement output OUT of git (see `.gitignore`).

## Run it
```
pip install -r requirements.txt
python -m redness.cli demo --out report.docx   # end-to-end, no DC needed
```

## Conventions
- Findings get stable `id` slugs (`smb-signing-not-required`), severity, category,
  impact, remediation, evidence, references.
- Every finding must carry remediation — this is a *report* tool, not just a scanner.

## Legal / ethics
Authorized assessments only. Assume written scope exists before running against any target.
```
