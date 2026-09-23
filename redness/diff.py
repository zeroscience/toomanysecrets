"""Retest diff: compare two findings.json reports (baseline vs current).

The retest deliverable. Given a prior scan and a fresh one, classify every finding as
**new**, **fixed**, **unchanged**, or **severity-changed** so an operator can show a client
exactly what a remediation round moved. Pure over the findings model (no I/O, no tools), so it
unit-tests against hand-built Reports and drives both the CLI `diff` command and a retest report.

A finding's identity for diffing is ``(id, sorted(affected))`` - the same issue on the same
host/account. That means:
  - same key in both, same severity  -> unchanged
  - same key in both, severity moved  -> changed (records the old severity)
  - key only in current              -> new
  - key only in baseline             -> fixed (it's gone on retest)
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .findings import Finding, Report, Severity

Key = tuple[str, tuple[str, ...]]


def finding_key(f: Finding) -> Key:
    """Identity of a finding for diffing: its stable id + the sorted set of affected assets."""
    return (f.id, tuple(sorted(f.affected)))


def _index(report: Report) -> dict[Key, Finding]:
    """Map every finding to its key. On a duplicate key within one report the last wins
    (they are the same issue on the same asset); order is otherwise irrelevant to a set diff."""
    return {finding_key(f): f for f in report.findings}


@dataclass
class DiffResult:
    """The classified delta between a baseline and a current report."""
    baseline_label: str
    current_label: str
    new: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    # (current finding, old severity) for issues whose severity moved between scans
    changed: list[tuple[Finding, Severity]] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "unchanged": len(self.unchanged),
            "changed": len(self.changed),
        }

    def regressed(self) -> bool:
        """True if the retest surfaced anything worse: any new finding, or a severity increase."""
        return bool(self.new) or any(cur.severity.rank > old.rank for cur, old in self.changed)

    def to_dict(self) -> dict:
        return {
            "baseline": self.baseline_label,
            "current": self.current_label,
            "counts": self.counts(),
            "new": [f.to_dict() for f in self.new],
            "fixed": [f.to_dict() for f in self.fixed],
            "unchanged": [f.to_dict() for f in self.unchanged],
            "changed": [
                {"old_severity": old.value, **cur.to_dict()} for cur, old in self.changed
            ],
        }

    def to_text(self) -> str:
        """Operator-facing summary: a count header then each bucket, most severe first."""
        c = self.counts()
        lines = [
            f"Retest diff: {self.baseline_label} -> {self.current_label}",
            f"  NEW:       {c['new']}",
            f"  FIXED:     {c['fixed']}",
            f"  CHANGED:   {c['changed']}  (severity moved)",
            f"  UNCHANGED: {c['unchanged']}",
        ]
        verdict = "REGRESSED (new or worse findings)" if self.regressed() else "no regressions"
        lines.append(f"  verdict:   {verdict}")

        def _line(f: Finding) -> str:
            where = f", ".join(f.affected) if f.affected else "-"
            return f"  [{f.severity.value.upper()}] {f.id}  {f.title}  ({where})"

        if self.new:
            lines.append("\n--- NEW ---")
            lines += [_line(f) for f in _sorted(self.new)]
        if self.fixed:
            lines.append("\n--- FIXED ---")
            lines += [_line(f) for f in _sorted(self.fixed)]
        if self.changed:
            lines.append("\n--- CHANGED (severity) ---")
            for cur, old in sorted(self.changed, key=lambda t: -t[0].severity.rank):
                arrow = "UP" if cur.severity.rank > old.rank else "DOWN"
                where = ", ".join(cur.affected) if cur.affected else "-"
                lines.append(
                    f"  [{old.value.upper()} -> {cur.severity.value.upper()}] {arrow}  "
                    f"{cur.id}  {cur.title}  ({where})")
        return "\n".join(lines)


def _sorted(fs: list[Finding]) -> list[Finding]:
    return sorted(fs, key=lambda f: (-f.severity.rank, f.category.value, f.id))


def diff_reports(baseline: Report, current: Report) -> DiffResult:
    """Classify every finding across the two reports into new / fixed / unchanged / changed."""
    base = _index(baseline)
    cur = _index(current)
    res = DiffResult(
        baseline_label=baseline.engagement or baseline.target or "baseline",
        current_label=current.engagement or current.target or "current",
    )
    for key, f in cur.items():
        if key not in base:
            res.new.append(f)
        elif f.severity != base[key].severity:
            res.changed.append((f, base[key].severity))
        else:
            res.unchanged.append(f)
    for key, f in base.items():
        if key not in cur:
            res.fixed.append(f)
    return res
