"""Report rendering from persisted, structured records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def render_json(record: dict[str, Any]) -> str:
    return json.dumps(record, indent=2, sort_keys=True) + "\n"


def render_markdown(record: dict[str, Any]) -> str:
    run = record["run"]
    findings = record["findings"]
    lines = [
        "# SENTINEL Passive Audit Report",
        "",
        f"- Run ID: `{run['id']}`",
        f"- Status: `{run['status']}`",
        f"- Target: `{run['target_url']}`",
        f"- Created: `{run['created_at']}`",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("No evidence-backed findings were recorded.")
    for finding in findings:
        lines.extend(
            [
                f"### {finding['title']}",
                "",
                f"Severity: **{finding['severity']}** · Confidence: **{finding['confidence']}** · Status: **{finding['status']}**",
                "",
                finding["rationale"],
                "",
                f"Remediation: {finding['remediation']}",
                "",
            ]
        )
    lines.extend(["## Limitations", "", "This report is generated from passive observations. Findings are hypotheses, not proof of exploitation.", ""])
    return "\n".join(lines)


def write_report(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
