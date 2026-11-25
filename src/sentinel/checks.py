"""Deterministic passive analysis; no payloads or exploit attempts are generated."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from sentinel.models import Finding, Observation


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in {"a", "form", "script", "link"}:
            return
        for key, value in attrs:
            if key in {"href", "src", "action"} and value:
                self.links.add(value)


def discovered_same_origin_urls(observation: Observation) -> tuple[str, ...]:
    if "html" not in observation.content_type.lower():
        return ()
    extractor = _LinkExtractor()
    extractor.feed(observation.body_sample)
    origin = urlsplit(observation.final_url)
    urls = set()
    for link in extractor.links:
        resolved = urljoin(observation.final_url, link)
        parsed = urlsplit(resolved)
        if parsed.hostname == origin.hostname and parsed.scheme == origin.scheme:
            urls.add(resolved.split("#", 1)[0])
    return tuple(sorted(urls))


def analyze_headers(observation: Observation) -> tuple[Finding, ...]:
    headers = observation.headers
    findings: list[Finding] = []
    required = {
        "strict-transport-security": (
            "Missing HTTP Strict Transport Security",
            "Configure Strict-Transport-Security on HTTPS responses after verifying HTTPS-only operation.",
        ),
        "x-content-type-options": (
            "Missing X-Content-Type-Options",
            "Set X-Content-Type-Options: nosniff to reduce MIME-type confusion risks.",
        ),
        "content-security-policy": (
            "Missing Content Security Policy",
            "Deploy a restrictive, tested Content-Security-Policy suited to the application.",
        ),
        "referrer-policy": (
            "Missing Referrer-Policy",
            "Set a Referrer-Policy appropriate for the application's navigation flows.",
        ),
    }
    for name, (title, remediation) in required.items():
        if name not in headers:
            findings.append(
                Finding(
                    category="security_headers",
                    title=title,
                    severity="low",
                    confidence="high",
                    status="hypothesis",
                    rationale=f"The response did not include the `{name}` header.",
                    remediation=remediation,
                    evidence={"url": observation.final_url, "missing_header": name},
                )
            )
    server = headers.get("server")
    if server and re.search(r"\d", server):
        findings.append(
            Finding(
                category="information_disclosure",
                title="Version-bearing Server header",
                severity="info",
                confidence="medium",
                status="hypothesis",
                rationale="The Server header appears to disclose a product version.",
                remediation="Consider minimizing externally exposed server-version details where operationally feasible.",
                evidence={"url": observation.final_url, "header": "server", "value": server},
            )
        )
    return tuple(findings)


def technology_hints(observation: Observation) -> tuple[str, ...]:
    hints: set[str] = set()
    for name in ("server", "x-powered-by", "via"):
        value = observation.headers.get(name)
        if value:
            hints.add(f"{name}: {value}")
    return tuple(sorted(hints))
