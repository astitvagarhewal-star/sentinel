"""Typed domain objects. They intentionally carry no executable instructions."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class Limits:
    requests_per_second: float = 2.0
    max_requests: int = 50
    timeout_seconds: float = 10.0
    max_response_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        if not 0 < self.requests_per_second <= 20:
            raise ValueError("requests_per_second must be between 0 and 20")
        if not 1 <= self.max_requests <= 1_000:
            raise ValueError("max_requests must be between 1 and 1000")
        if not 1 <= self.timeout_seconds <= 60:
            raise ValueError("timeout_seconds must be between 1 and 60")
        if not 1_024 <= self.max_response_bytes <= 10_485_760:
            raise ValueError("max_response_bytes must be between 1024 and 10485760")


@dataclass(frozen=True)
class TargetScope:
    targets: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    allowed_schemes: tuple[str, ...] = ("https",)
    allowed_ports: tuple[int, ...] = (443,)
    allowed_paths: tuple[str, ...] = ("/",)
    mode: Literal["passive"] = "passive"
    limits: Limits = field(default_factory=Limits)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Observation:
    target_url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    body_sample: str
    content_type: str
    collected_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class Finding:
    category: str
    title: str
    severity: Literal["info", "low", "medium", "high"]
    confidence: Literal["low", "medium", "high"]
    status: Literal["hypothesis", "verified"]
    rationale: str
    remediation: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class AuditResult:
    run_id: str
    target_url: str
    observation: Observation | None
    findings: tuple[Finding, ...]
    errors: tuple[str, ...] = ()
