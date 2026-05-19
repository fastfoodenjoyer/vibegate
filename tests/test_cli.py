from typer.testing import CliRunner

from vibegate.cli import app


def test_scan_command_reports_ship_for_empty_project(tmp_path) -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0
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
