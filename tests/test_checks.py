from __future__ import annotations

import unittest

from sentinel.checks import analyze_headers, discovered_same_origin_urls, technology_hints
from sentinel.models import Observation
from sentinel.orchestrator import verify_findings


def observation(headers: dict[str, str], body: str = "") -> Observation:
    return Observation("https://example.test", "https://example.test", 200, headers, body, "text/html")


class CheckTests(unittest.TestCase):
    def test_header_findings_are_evidence_backed(self) -> None:
        findings = analyze_headers(observation({}))
        self.assertEqual({item.category for item in findings}, {"security_headers"})
        self.assertTrue(all(item.evidence and item.status == "hypothesis" for item in findings))

    def test_inventory_stays_same_origin(self) -> None:
        urls = discovered_same_origin_urls(observation({}, '<a href="/account">a</a><a href="https://evil.test">b</a>'))
        self.assertEqual(urls, ("https://example.test/account",))

    def test_version_hints_and_deduplication(self) -> None:
        findings = analyze_headers(observation({"server": "nginx/1.24"}))
        verified = verify_findings(findings + findings)
        self.assertEqual(len(verified), len(findings))
        self.assertEqual(technology_hints(observation({"server": "nginx/1.24"})), ("server: nginx/1.24",))
