from pathlib import Path

from vibegate.models import Finding, Severity, Verdict
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
