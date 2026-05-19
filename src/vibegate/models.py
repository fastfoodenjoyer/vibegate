from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(StrEnum):
    SHIP = "ship"
    NO_SHIP = "no-ship"


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: Severity
    message: str = Field(min_length=1)
    category: str | None = None
    blocking: bool = True
    references: list[str] = Field(default_factory=list)
    path: str | None = None
    line: int | None = Field(default=None, ge=1)
    snippet: str | None = None
    remediation: str | None = None


class ScanSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    total: int
    counts: dict[Severity, int]
    verdict: Verdict

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> ScanSummary:
        counts = {severity: 0 for severity in Severity}
        for finding in findings:
            counts[finding.severity] += 1

        has_blocking_high_risk_finding = any(
            finding.blocking and finding.severity in {Severity.HIGH, Severity.CRITICAL}
            for finding in findings
        )
        verdict = Verdict.NO_SHIP if has_blocking_high_risk_finding else Verdict.SHIP

        return cls(total=len(findings), counts=counts, verdict=verdict)
