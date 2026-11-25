from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from sentinel.models import AuditResult, Finding, Limits, Observation, TargetScope
from sentinel.persistence import AuditStore
from sentinel.reports import render_markdown


class PersistenceTests(unittest.TestCase):
    def test_store_redacts_sensitive_headers(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "audit.db"
            scope = TargetScope(("https://example.test",), ("example.test",), limits=Limits(max_response_bytes=1024))
            observation = Observation(
                "https://example.test", "https://example.test", 200,
                {"set-cookie": "secret", "server": "test"}, "body", "text/html",
            )
            finding = Finding("headers", "Example", "low", "high", "hypothesis", "reason", "fix", {"header": "x"})
            result = AuditResult("run-1", "https://example.test", observation, (finding,))
            store = AuditStore(path)
            store.save("https://example.test", scope, result)
            record = store.get_run("run-1")
            store.close()
            self.assertIsNotNone(record)
            assert record is not None
            self.assertIn("Example", render_markdown(record))
            import sqlite3
            connection = sqlite3.connect(path)
            saved_headers = connection.execute("SELECT headers_json FROM observations").fetchone()[0]
            self.assertNotIn("secret", saved_headers)
            self.assertIn("[REDACTED]", saved_headers)
