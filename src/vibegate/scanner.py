from __future__ import annotations

from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from vibegate.models import Finding, ScanSummary
from vibegate.profiles import ProfileRegistry
from vibegate.rules.frontend import PublicFrontendSecretEnvRule
from vibegate.rules.python_backend import (
    DjangoDangerousSettingsRule,
    FastAPICorsWildcardCredentialsRule,
    FastAPIPublicDocsRule,
    FlaskDebugEnabledRule,
    UvicornReloadRule,
)
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
    active_profile_ids: list[str]


def default_rules() -> list[Rule]:
    return [
        CommittedEnvFileRule(),
        HardcodedSecretRule(),
        TelegramWebhookSecretTokenRule(),
        PublicFrontendSecretEnvRule(),
        FastAPICorsWildcardCredentialsRule(),
        FastAPIPublicDocsRule(),
        FlaskDebugEnabledRule(),
        DjangoDangerousSettingsRule(),
        UvicornReloadRule(),
    ]


class Scanner:
    def __init__(
        self,
        rules: list[Rule] | None = None,
        profile_registry: ProfileRegistry | None = None,
    ) -> None:
        self._rules = rules if rules is not None else default_rules()
        self._profile_registry = profile_registry if profile_registry is not None else ProfileRegistry.default()
        if rules is None or profile_registry is not None:
            self._validate_profile_rule_ids()

    def scan(self, path: str | Path, profile_ids: list[str] | None = None) -> ScanResult:
        root = Path(path).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Scan path does not exist: {root}")
        active_profile_ids = self._active_profile_ids(root, profile_ids)
        selected_rules = self._select_rules(active_profile_ids)
        context = ScanContext(root=root)
        findings: list[Finding] = []

        for rule in selected_rules:
            findings.extend(rule.scan(context))

        return ScanResult(
            findings=findings,
            summary=ScanSummary.from_findings(findings),
            active_profile_ids=active_profile_ids,
        )

    def _active_profile_ids(self, root: Path, profile_ids: list[str] | None) -> list[str]:
        if profile_ids is not None:
            return self._profile_registry.validate_profile_ids(profile_ids)
        return self._profile_registry.detect_profile_ids(root)

    def _select_rules(self, active_profile_ids: list[str]) -> list[Rule]:
        selected_rule_ids = set(self._profile_registry.baseline_rule_ids())
        selected_rule_ids.update(self._profile_registry.rule_ids_for_profiles(active_profile_ids))
        known_rule_ids = {
            rule_id
            for profile in self._profile_registry.list_profiles()
            for rule_id in profile.rule_ids
        }
        known_rule_ids.update(self._profile_registry.baseline_rule_ids())
        selected_rules: list[Rule] = []
        seen_rule_ids: set[str] = set()

        for rule in self._rules:
            if rule.rule_id in seen_rule_ids:
                continue
            if rule.rule_id in known_rule_ids and rule.rule_id not in selected_rule_ids:
                continue
            selected_rules.append(rule)
            seen_rule_ids.add(rule.rule_id)

        return selected_rules

    def _validate_profile_rule_ids(self) -> None:
        installed_rule_ids = {rule.rule_id for rule in self._rules}
        referenced_rule_ids = {
            rule_id
            for profile in self._profile_registry.list_profiles()
            for rule_id in profile.rule_ids
        }
        referenced_rule_ids.update(self._profile_registry.baseline_rule_ids())
        unknown_rule_ids = sorted(referenced_rule_ids - installed_rule_ids)
        if unknown_rule_ids:
            formatted_rule_ids = ", ".join(unknown_rule_ids)
            raise ValueError(f"Unknown rule IDs referenced by profiles: {formatted_rule_ids}")
