from pathlib import Path

import pytest

from vibegate.models import Finding, Severity, Verdict
from vibegate.profiles import Profile, ProfileRegistry
from vibegate.scanner import ScanContext, Scanner


class StaticRule:
    rule_id = "test.static"

    def scan(self, context: ScanContext) -> list[Finding]:
        assert context.root.exists()
        return [
            Finding(
                rule_id=self.rule_id,
                title="Static finding",
                severity=Severity.HIGH,
                message="A test rule emitted a finding.",
                path="app.py",
            )
        ]


class DuplicateStaticRule(StaticRule):
    rule_id = "secrets.hardcoded-token"


def test_scanner_runs_rules_and_returns_summary(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")

    result = Scanner(rules=[StaticRule()]).scan(tmp_path)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "test.static"
    assert result.summary.total == 1
    assert result.summary.verdict is Verdict.NO_SHIP


def test_scanner_uses_ship_verdict_when_rules_find_nothing(tmp_path: Path) -> None:
    result = Scanner(rules=[]).scan(tmp_path)

    assert result.findings == []
    assert result.summary.total == 0
    assert result.summary.verdict is Verdict.SHIP


def test_explicit_profiles_drive_active_profiles(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")

    result = Scanner().scan(tmp_path, profile_ids=["railway"])

    assert result.active_profile_ids == ["railway"]


def test_scanner_auto_detects_active_profiles(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")

    result = Scanner(rules=[]).scan(tmp_path)

    assert result.active_profile_ids == ["python-backend"]


def test_scanner_deduplicates_rules_across_profiles(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("OPENAI_API_KEY='sk-test-abc1234567890'\n", encoding="utf-8")
    scanner = Scanner(rules=[DuplicateStaticRule()])

    result = scanner.scan(tmp_path, profile_ids=["python-backend", "railway"])

    assert [finding.rule_id for finding in result.findings] == ["secrets.hardcoded-token"]


def test_no_profile_scan_runs_baseline_secret_rules(tmp_path: Path) -> None:
    (tmp_path / "secrets.txt").write_text(
        'OPENAI_API_KEY="sk-proj-abc1234567890abc1234567890"\n',
        encoding="utf-8",
    )

    result = Scanner().scan(tmp_path)

    assert result.active_profile_ids == []
    assert result.summary.verdict is Verdict.NO_SHIP
    assert any(finding.rule_id == "secrets.hardcoded-token" for finding in result.findings)


def test_explicit_telegram_profile_includes_committed_env_baseline(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("TELEGRAM_BOT_TOKEN=secret\n", encoding="utf-8")

    result = Scanner().scan(tmp_path, profile_ids=["telegram-bot"])

    assert result.active_profile_ids == ["telegram-bot"]
    assert any(finding.rule_id == "secrets.committed-env-file" for finding in result.findings)


def test_scanner_rejects_nonexistent_path(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing"

    with pytest.raises(FileNotFoundError, match="Scan path does not exist"):
        Scanner().scan(missing_path)


def test_scanner_rejects_profile_rule_ids_missing_from_installed_rules() -> None:
    registry = ProfileRegistry(
        profiles=[
            Profile(
                profile_id="broken",
                description="Broken profile.",
                rule_ids=("rules.missing",),
            )
        ]
    )

    with pytest.raises(ValueError, match="Unknown rule IDs referenced by profiles"):
        Scanner(profile_registry=registry)
