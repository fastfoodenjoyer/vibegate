from pathlib import Path

import pytest

from vibegate.profiles import ProfileRegistry, UnknownProfileError


def test_registry_lists_expected_profiles() -> None:
    registry = ProfileRegistry.default()

    profiles = registry.list_profiles()

    assert [profile.profile_id for profile in profiles] == [
        "python-backend",
        "telegram-bot",
        "railway",
        "vps-docker",
    ]
    assert all(profile.description for profile in profiles)


def test_auto_detection_detects_python_backend_from_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "python-backend" in active_profiles


def test_auto_detection_detects_python_backend_from_python_files(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "python-backend" in active_profiles


def test_auto_detection_detects_telegram_bot_from_webhook_code(tmp_path: Path) -> None:
    (tmp_path / "bot.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/telegram/webhook')\n"
        "async def telegram_webhook(update):\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "telegram-bot" in active_profiles


def test_auto_detection_does_not_detect_telegram_from_generic_webhook(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/stripe/webhook')\n"
        "async def stripe_webhook(request):\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "python-backend" in active_profiles
    assert "telegram-bot" not in active_profiles


def test_auto_detection_detects_telegram_bot_from_token_code(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text("TELEGRAM_BOT_TOKEN = 'env-value'\n", encoding="utf-8")

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "telegram-bot" in active_profiles


def test_unknown_profile_raises_clear_error() -> None:
    registry = ProfileRegistry.default()

    with pytest.raises(UnknownProfileError, match="Unknown profile 'unknown'"):
        registry.validate_profile_ids(["unknown"])
