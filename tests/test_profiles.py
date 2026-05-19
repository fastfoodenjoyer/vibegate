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
        "nextjs-vercel",
        "vite-frontend",
        "netlify-frontend",
        "supabase",
        "firebase",
        "stripe-webhooks",
        "authjs",
        "clerk",
        "github-actions",
        "node-api",
        "docker-vps",
        "coolify",
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


def test_auto_detection_detects_nextjs_vercel_from_next_dependency(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"next":"14.0.0"},"scripts":{"dev":"next dev"}}\n',
        encoding="utf-8",
    )

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "nextjs-vercel" in active_profiles


def test_auto_detection_detects_vite_frontend_from_vite_config(tmp_path: Path) -> None:
    (tmp_path / "vite.config.ts").write_text("export default {}\n", encoding="utf-8")

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "vite-frontend" in active_profiles


def test_auto_detection_detects_netlify_frontend_from_config(tmp_path: Path) -> None:
    (tmp_path / "netlify.toml").write_text("[build]\ncommand = 'npm run build'\n", encoding="utf-8")

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "netlify-frontend" in active_profiles


def test_auto_detection_detects_supabase_from_directory(tmp_path: Path) -> None:
    (tmp_path / "supabase").mkdir()

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "supabase" in active_profiles


def test_auto_detection_detects_firebase_from_config(tmp_path: Path) -> None:
    (tmp_path / "firebase.json").write_text('{"hosting": {}}\n', encoding="utf-8")

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "firebase" in active_profiles


def test_auto_detection_detects_stripe_webhooks_from_env_name(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("STRIPE_WEBHOOK_SECRET=whsec_example\n", encoding="utf-8")

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "stripe-webhooks" in active_profiles


def test_auto_detection_detects_authjs_from_nextauth_dependency(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"next-auth":"5.0.0"}}\n',
        encoding="utf-8",
    )

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "authjs" in active_profiles


def test_auto_detection_detects_clerk_from_dependency(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"@clerk/nextjs":"5.0.0"}}\n',
        encoding="utf-8",
    )

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "clerk" in active_profiles


def test_auto_detection_detects_clerk_from_svix_dependency(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"svix":"1.42.0"}}\n',
        encoding="utf-8",
    )

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "clerk" in active_profiles


def test_auto_detection_detects_clerk_from_svix_webhook_secret(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("CLERK_WEBHOOK_SECRET=whsec_example\n", encoding="utf-8")

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "clerk" in active_profiles


def test_auto_detection_detects_github_actions_from_workflow(tmp_path: Path) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yaml").write_text("name: CI\n", encoding="utf-8")

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "github-actions" in active_profiles


def test_auto_detection_detects_node_api_from_express_dependency(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"express":"4.18.0"}}\n',
        encoding="utf-8",
    )

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "node-api" in active_profiles


def test_auto_detection_detects_docker_vps_alias_from_compose(tmp_path: Path) -> None:
    (tmp_path / "compose.yaml").write_text("services: {}\n", encoding="utf-8")

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "vps-docker" in active_profiles
    assert "docker-vps" in active_profiles


def test_auto_detection_detects_coolify_from_config(tmp_path: Path) -> None:
    (tmp_path / "coolify.json").write_text('{"name":"demo"}\n', encoding="utf-8")

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "coolify" in active_profiles


def test_auto_detection_does_not_detect_stack_profiles_from_generic_package_json(
    tmp_path: Path,
) -> None:
    (tmp_path / "package.json").write_text(
        '{"scripts":{"test":"node test.js"},"dependencies":{"left-pad":"1.3.0"}}\n',
        encoding="utf-8",
    )

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "nextjs-vercel" not in active_profiles
    assert "vite-frontend" not in active_profiles
    assert "node-api" not in active_profiles


def test_auto_detection_does_not_detect_stripe_from_generic_webhook(tmp_path: Path) -> None:
    (tmp_path / "webhook.js").write_text("app.post('/webhook', handleWebhook)\n", encoding="utf-8")

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "stripe-webhooks" not in active_profiles


def test_auto_detection_does_not_detect_authjs_or_clerk_from_generic_auth_text(
    tmp_path: Path,
) -> None:
    (tmp_path / "auth.md").write_text("Document generic auth and clerk duties.\n", encoding="utf-8")

    active_profiles = ProfileRegistry.default().detect_profile_ids(tmp_path)

    assert "authjs" not in active_profiles
    assert "clerk" not in active_profiles


def test_unknown_profile_raises_clear_error() -> None:
    registry = ProfileRegistry.default()

    with pytest.raises(UnknownProfileError, match="Unknown profile 'unknown'"):
        registry.validate_profile_ids(["unknown"])
