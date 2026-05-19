from __future__ import annotations

from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from vibegate.models import Finding, ScanSummary
from vibegate.rules.secrets import CommittedEnvFileRule, HardcodedSecretRule
from vibegate.rules.telegram import TelegramWebhookSecretTokenRule


class ScanContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    root: Path


class Rule(Protocol):
    rule_id: str

    def scan(self, context: ScanContext) -> list[Finding]: ...


class ScanResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    findings: list[Finding]
    summary: ScanSummary


def default_rules() -> list[Rule]:
    return [CommittedEnvFileRule(), HardcodedSecretRule(), TelegramWebhookSecretTokenRule()]


class Scanner:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules = rules if rules is not None else default_rules()

    def scan(self, path: str | Path) -> ScanResult:
        root = Path(path).resolve()
        context = ScanContext(root=root)
        findings: list[Finding] = []

        for rule in self._rules:
            findings.extend(rule.scan(context))

        return ScanResult(findings=findings, summary=ScanSummary.from_findings(findings))
