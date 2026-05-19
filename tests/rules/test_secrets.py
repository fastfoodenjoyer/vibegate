from pathlib import Path

from vibegate.models import Severity
from vibegate.rules.secrets import CommittedEnvFileRule, HardcodedSecretRule
from vibegate.scanner import ScanContext, Scanner


FAKE_TELEGRAM_TOKEN = "123456789:AAabcdefghijklmnopqrstuvwxyzABCDEFG"
FAKE_OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL0123456789"
FAKE_STRIPE_SECRET_KEY = "".join(["sk", "_", "live", "_", "abcdefghijklmnopqrstuvwxyz012345"])


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


def test_committed_env_file_rule_ignores_untracked_local_dotenv_in_git_repo(tmp_path: Path) -> None:
    import subprocess

    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / ".env").write_text("BOT_TOKEN=local-secret\n", encoding="utf-8")
    (tmp_path / ".env.example").write_text("BOT_TOKEN=\n", encoding="utf-8")
    subprocess.run(["git", "add", ".env.example"], cwd=tmp_path, check=True, capture_output=True)

    findings = CommittedEnvFileRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_committed_env_file_rule_flags_tracked_dotenv_in_git_repo(tmp_path: Path) -> None:
    import subprocess

    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / ".env").write_text("BOT_TOKEN=committed-secret\n", encoding="utf-8")
    subprocess.run(["git", "add", ".env"], cwd=tmp_path, check=True, capture_output=True)

    findings = CommittedEnvFileRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].path == ".env"


def test_hardcoded_secret_rule_flags_telegram_bot_tokens_with_redacted_snippet(tmp_path: Path) -> None:
    (tmp_path / "bot.py").write_text(f'TELEGRAM = "{FAKE_TELEGRAM_TOKEN}"\n', encoding="utf-8")

    findings = HardcodedSecretRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "secrets.hardcoded-token"
    assert finding.severity is Severity.CRITICAL
    assert finding.path == "bot.py"
    assert finding.line == 1
    assert finding.snippet is not None
    assert FAKE_TELEGRAM_TOKEN not in finding.snippet
    assert "123456789:AA" in finding.snippet
    assert "[REDACTED]" in finding.snippet
    assert finding.remediation is not None


def test_hardcoded_secret_rule_flags_named_api_key_assignments(tmp_path: Path) -> None:
    (tmp_path / "settings.toml").write_text(f'OPENAI_API_KEY = "{FAKE_OPENAI_KEY}"\n', encoding="utf-8")

    findings = HardcodedSecretRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.path == "settings.toml"
    assert finding.line == 1
    assert FAKE_OPENAI_KEY not in (finding.snippet or "")
    assert "OPENAI_API_KEY" in (finding.snippet or "")


def test_hardcoded_secret_rule_does_not_duplicate_frontend_public_api_key_stripe_secret_value(
    tmp_path: Path,
) -> None:
    (tmp_path / ".env.local").write_text(
        f"NEXT_PUBLIC_API_KEY={FAKE_STRIPE_SECRET_KEY}\n",
        encoding="utf-8",
    )

    findings = HardcodedSecretRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_hardcoded_secret_rule_does_not_flag_public_api_key_with_google_public_key(tmp_path: Path) -> None:
    (tmp_path / ".env.local").write_text(
        "NEXT_PUBLIC_API_KEY=AIzaSyabcdefghijklmnopqrstuvwxyz012345\n",
        encoding="utf-8",
    )

    findings = HardcodedSecretRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_hardcoded_secret_rule_ignores_short_placeholder_assignments(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text("BOT_TOKEN: changeme\nSECRET_KEY: short\n", encoding="utf-8")

    findings = HardcodedSecretRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_hardcoded_secret_rule_ignores_common_example_token_placeholders(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("TELEGRAM_BOT_TOKEN=your_bot_token_here\n", encoding="utf-8")

    findings = HardcodedSecretRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_hardcoded_secret_rule_ignores_nonliteral_secret_assignments(tmp_path: Path) -> None:
    (tmp_path / "service.py").write_text(
        "secret_key = encryption_service.decrypt(provider.secret_key)\n"
        "token = provider.api_token\n",
        encoding="utf-8",
    )

    findings = HardcodedSecretRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_hardcoded_secret_rule_skips_binary_and_large_files(tmp_path: Path) -> None:
    (tmp_path / "image.png").write_bytes(b"\x89PNG\x00" + FAKE_TELEGRAM_TOKEN.encode())
    (tmp_path / "large.txt").write_text("x" * 1_100_000 + FAKE_TELEGRAM_TOKEN, encoding="utf-8")

    findings = HardcodedSecretRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_default_scanner_includes_hardcoded_secret_rule(tmp_path: Path) -> None:
    (tmp_path / "bot.txt").write_text(f"token={FAKE_TELEGRAM_TOKEN}\n", encoding="utf-8")

    result = Scanner().scan(tmp_path)

    assert any(finding.rule_id == "secrets.hardcoded-token" for finding in result.findings)
