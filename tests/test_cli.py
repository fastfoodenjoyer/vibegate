from typer.testing import CliRunner

from vibegate.cli import app


def test_scan_command_reports_ship_for_empty_project(tmp_path) -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0
    assert "Profiles:" in result.output
    assert "Verdict: ship" in result.output
    assert "0 findings" in result.output


def test_scan_command_reports_no_ship_for_committed_env_file(tmp_path) -> None:
    (tmp_path / ".env").write_text("BOT_TOKEN=secret\n", encoding="utf-8")
    runner = CliRunner()

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0
    assert "Verdict: no-ship" in result.output
    assert "1 findings" in result.output
    assert "Committed .env file" in result.output
    assert "[high]" in result.output


def test_scan_command_prints_active_profiles(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")
    runner = CliRunner()

    result = runner.invoke(app, ["scan", str(tmp_path), "--profile", "telegram-bot"])

    assert result.exit_code == 0
    assert "Profiles: telegram-bot" in result.output


def test_profiles_list_command_includes_expected_profiles() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["profiles", "list"])

    assert result.exit_code == 0
    assert "python-backend" in result.output
    assert "telegram-bot" in result.output
    assert "railway" in result.output
    assert "vps-docker" in result.output


def test_scan_command_rejects_unknown_profile(tmp_path) -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["scan", str(tmp_path), "--profile", "unknown"])

    assert result.exit_code != 0
    assert "Unknown profile 'unknown'" in result.output


def test_scan_command_rejects_nonexistent_path(tmp_path) -> None:
    missing_path = tmp_path / "missing"
    runner = CliRunner()

    result = runner.invoke(app, ["scan", str(missing_path)])

    assert result.exit_code != 0
    assert "Scan path does not exist" in result.output
