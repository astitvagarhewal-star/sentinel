"""Local persistence with redacted evidence only."""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

from sentinel.models import AuditResult, Finding, Observation, TargetScope, utc_now


class AuditStore:
    def __init__(self, path: Path) -> None:
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS audit_runs (
                id TEXT PRIMARY KEY, created_at TEXT NOT NULL, status TEXT NOT NULL,
                target_url TEXT NOT NULL, scope_json TEXT NOT NULL, error_summary TEXT
            );
            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES audit_runs(id),
                final_url TEXT NOT NULL, status_code INTEGER NOT NULL, headers_json TEXT NOT NULL,
                content_type TEXT NOT NULL, collected_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES audit_runs(id),
                category TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
                confidence TEXT NOT NULL, status TEXT NOT NULL, rationale TEXT NOT NULL,
                remediation TEXT NOT NULL, evidence_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policy_events (
                id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES audit_runs(id),
                timestamp TEXT NOT NULL, action TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL
            );
            """
        )
        self.connection.commit()

    def save(self, target_url: str, scope: TargetScope, result: AuditResult) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT INTO audit_runs VALUES (?, ?, ?, ?, ?, ?)",
                (result.run_id, utc_now(), "completed" if not result.errors else "failed", target_url,
                 json.dumps(scope.as_dict()), "; ".join(result.errors) or None),
            )
            self.connection.execute(
                "INSERT INTO policy_events (run_id, timestamp, action, decision, reason) VALUES (?, ?, ?, ?, ?)",
                (result.run_id, utc_now(), "passive_audit", "allowed", "scope validated before collection"),
            )
            if result.observation:
                observation = result.observation
                self.connection.execute(
                    "INSERT INTO observations (run_id, final_url, status_code, headers_json, content_type, collected_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (result.run_id, observation.final_url, observation.status_code,
                     json.dumps(_redact_headers(observation.headers)), observation.content_type, observation.collected_at),
                )
            for finding in result.findings:
                self._save_finding(result.run_id, finding)

    def _save_finding(self, run_id: str, finding: Finding) -> None:
        self.connection.execute(
            "INSERT INTO findings (run_id, category, title, severity, confidence, status, rationale, remediation, evidence_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, finding.category, finding.title, finding.severity, finding.confidence,
             finding.status, finding.rationale, finding.remediation, json.dumps(finding.evidence)),
        )

    def get_run(self, run_id: str) -> dict[str, object] | None:
        run = self.connection.execute("SELECT * FROM audit_runs WHERE id = ?", (run_id,)).fetchone()
        if not run:
            return None
        findings = self.connection.execute("SELECT * FROM findings WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()
        return {"run": dict(run), "findings": [dict(row) for row in findings]}

    def close(self) -> None:
        self.connection.close()


def new_run_id() -> str:
    return str(uuid.uuid4())


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    sensitive = {"authorization", "cookie", "set-cookie", "proxy-authorization"}
    return {key: "[REDACTED]" if key.lower() in sensitive else value for key, value in headers.items()}
