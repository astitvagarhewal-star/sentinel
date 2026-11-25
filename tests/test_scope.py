from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from sentinel.scope import ScopeError, load_scope, validate_url


def make_scope(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        """targets:
  - https://example.test
allowed_hosts:
  - example.test
allowed_schemes: [https]
allowed_ports: [443]
allowed_paths: ["/"]
mode: passive
limits:
  requests_per_second: 2
  max_requests: 10
  timeout_seconds: 5
  max_response_bytes: 1024
""",
        encoding="utf-8",
    )
    return load_scope(scope_file)


class ScopeTests(unittest.TestCase):
    def test_scope_parses_documented_yaml_subset(self) -> None:
        with TemporaryDirectory() as directory:
            scope = make_scope(Path(directory))
        self.assertEqual(scope.allowed_hosts, ("example.test",))
        self.assertEqual(scope.limits.max_requests, 10)

    def test_scope_rejects_credentials_and_unlisted_host(self) -> None:
        with TemporaryDirectory() as directory:
            scope = make_scope(Path(directory))
        with self.assertRaisesRegex(ScopeError, "embedded credentials"):
            validate_url("https://user:password@example.test", scope, resolve_dns=False)
        with self.assertRaisesRegex(ScopeError, "out of scope"):
            validate_url("https://other.test", scope, resolve_dns=False)

    def test_scope_rejects_private_dns_rebinding(self) -> None:
        with TemporaryDirectory() as directory:
            scope = make_scope(Path(directory))
        with patch("sentinel.scope.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]):
            with self.assertRaisesRegex(ScopeError, "unsafe"):
                validate_url("https://example.test", scope)

    def test_scope_accepts_public_dns(self) -> None:
        with TemporaryDirectory() as directory:
            scope = make_scope(Path(directory))
        with patch("sentinel.scope.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]):
            self.assertEqual(validate_url("https://example.test/path", scope), "https://example.test/path")
