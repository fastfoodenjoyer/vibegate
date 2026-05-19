from pathlib import Path

from vibegate.models import Severity
from vibegate.rules.secrets import CommittedEnvFileRule
from vibegate.scanner import ScanContext


def test_committed_env_file_rule_flags_dotenv_files(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("BOT_TOKEN=secret\n", encoding="utf-8")

    findings = CommittedEnvFileRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "secrets.committed-env-file"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].path == ".env"


def test_committed_env_file_rule_ignores_examples(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("BOT_TOKEN=\n", encoding="utf-8")

    findings = CommittedEnvFileRule().scan(ScanContext(root=tmp_path))

    assert findings == []
