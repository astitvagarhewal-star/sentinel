"""Deterministic workflow coordinating passive collection and evidence verification."""

from __future__ import annotations

from sentinel.checks import analyze_headers, discovered_same_origin_urls, technology_hints
from sentinel.http_client import PassiveHttpClient
from sentinel.models import AuditResult, Finding, TargetScope
from sentinel.persistence import new_run_id
from sentinel.scope import ScopeError, validate_url


def audit_target(target_url: str, scope: TargetScope, *, client: PassiveHttpClient | None = None) -> AuditResult:
    """Run a bounded passive audit; every pre-network policy check is repeated here."""
    run_id = new_run_id()
    try:
        target_url = validate_url(target_url, scope, resolve_dns=False)
        http = client or PassiveHttpClient(scope)
        observation = http.get(target_url)
        findings = verify_findings(analyze_headers(observation))
        return AuditResult(run_id, target_url, observation, findings)
    except (ScopeError, OSError, ValueError) as exc:
        return AuditResult(run_id, target_url, None, (), (str(exc),))


def verify_findings(candidates: tuple[Finding, ...]) -> tuple[Finding, ...]:
    """Reject malformed candidates and retain only evidence-backed hypotheses.

    This is deliberately deterministic. A future LLM triage layer may summarize these
    objects, but cannot mark findings verified or alter the enforcement path.
    """
    verified: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for finding in candidates:
        key = (finding.category, finding.title)
        if key in seen or not finding.evidence or not finding.remediation.strip():
            continue
        seen.add(key)
        verified.append(finding)
    return tuple(verified)


def passive_inventory(result: AuditResult) -> dict[str, object]:
    if result.observation is None:
        return {"technologies": [], "discovered_urls": []}
    return {
        "technologies": list(technology_hints(result.observation)),
        "discovered_urls": list(discovered_same_origin_urls(result.observation)),
    }
