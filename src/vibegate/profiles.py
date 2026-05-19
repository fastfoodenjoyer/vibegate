from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from vibegate.rules.secrets import ignored_path


@dataclass(frozen=True)
class Profile:
    profile_id: str
    description: str
    rule_ids: tuple[str, ...]


class UnknownProfileError(ValueError):
    def __init__(self, profile_id: str) -> None:
        super().__init__(f"Unknown profile '{profile_id}'")
        self.profile_id = profile_id


class ProfileRegistry:
    _baseline_rule_ids = ("secrets.committed-env-file", "secrets.hardcoded-token")
    _telegram_markers = re.compile(
        r"telegram|TELEGRAM_BOT_TOKEN|BOT_TOKEN|api\.telegram\.org|setWebhook|"
        r"(?<![A-Za-z0-9_-])\d{8,10}:AA[A-Za-z0-9_-]{33,}(?![A-Za-z0-9_-])",
        re.IGNORECASE,
    )

    def __init__(self, profiles: list[Profile]) -> None:
        self._profiles = profiles
        self._profiles_by_id = {profile.profile_id: profile for profile in profiles}

    @classmethod
    def default(cls) -> ProfileRegistry:
        hardcoded_secret_rule = "secrets.hardcoded-token"
        committed_env_rule = "secrets.committed-env-file"
        telegram_rule = "telegram.webhook-secret-token"
        return cls(
            profiles=[
                Profile(
                    profile_id="python-backend",
                    description="Python backend services and API applications.",
                    rule_ids=(committed_env_rule, hardcoded_secret_rule),
                ),
                Profile(
                    profile_id="telegram-bot",
                    description="Telegram bots using webhooks, polling, or Telegram bot tokens.",
                    rule_ids=(hardcoded_secret_rule, telegram_rule),
                ),
                Profile(
                    profile_id="railway",
                    description="Railway deployments and related project configuration.",
                    rule_ids=(committed_env_rule, hardcoded_secret_rule),
                ),
                Profile(
                    profile_id="vps-docker",
                    description="VPS-hosted Docker or Compose deployments.",
                    rule_ids=(committed_env_rule, hardcoded_secret_rule),
                ),
            ]
        )

    def list_profiles(self) -> list[Profile]:
        return list(self._profiles)

    def baseline_rule_ids(self) -> tuple[str, ...]:
        return self._baseline_rule_ids

    def validate_profile_ids(self, profile_ids: list[str]) -> list[str]:
        validated_profile_ids: list[str] = []
        seen_profile_ids: set[str] = set()
        for profile_id in profile_ids:
            if profile_id not in self._profiles_by_id:
                raise UnknownProfileError(profile_id)
            if profile_id in seen_profile_ids:
                continue
            validated_profile_ids.append(profile_id)
            seen_profile_ids.add(profile_id)
        return validated_profile_ids

    def detect_profile_ids(self, root: Path) -> list[str]:
        detected_profile_ids: list[str] = []
        if self._detects_python_backend(root):
            detected_profile_ids.append("python-backend")
        if self._detects_telegram_bot(root):
            detected_profile_ids.append("telegram-bot")
        if self._detects_railway(root):
            detected_profile_ids.append("railway")
        if self._detects_vps_docker(root):
            detected_profile_ids.append("vps-docker")
        return detected_profile_ids

    def rule_ids_for_profiles(self, profile_ids: list[str]) -> list[str]:
        self.validate_profile_ids(profile_ids)
        rule_ids: list[str] = []
        seen_rule_ids: set[str] = set()
        for profile_id in profile_ids:
            for rule_id in self._profiles_by_id[profile_id].rule_ids:
                if rule_id in seen_rule_ids:
                    continue
                rule_ids.append(rule_id)
                seen_rule_ids.add(rule_id)
        return rule_ids

    def _detects_python_backend(self, root: Path) -> bool:
        if (root / "pyproject.toml").is_file():
            return True
        if any(path.is_file() for path in self._iter_project_files(root, "*.py")):
            return True
        return any(path.is_file() and path.name.startswith(".env") for path in self._iter_project_files(root, ".env*"))

    def _detects_telegram_bot(self, root: Path) -> bool:
        for path in self._iter_project_files(root, "*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".py", ".env", ".toml", ".yaml", ".yml", ".json", ".txt"}:
                continue
            if self._too_large(path):
                continue
            content = self._read_text(path)
            if content is None:
                continue
            if self._telegram_markers.search(content):
                return True
            normalized_content = content.lower()
            if "bot" in normalized_content and "update" in normalized_content:
                return True
        return False

    def _detects_railway(self, root: Path) -> bool:
        return (root / "railway.toml").is_file() or (root / "nixpacks.toml").is_file()

    def _detects_vps_docker(self, root: Path) -> bool:
        docker_names = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
        return any((root / name).is_file() for name in docker_names)

    def _iter_project_files(self, root: Path, pattern: str) -> Iterator[Path]:
        for path in sorted(root.rglob(pattern)):
            if ignored_path(path, root):
                continue
            yield path

    def _too_large(self, path: Path) -> bool:
        try:
            return path.stat().st_size > 1_000_000
        except OSError as error:
            raise RuntimeError(f"Failed to stat {path}") from error

    def _read_text(self, path: Path) -> str | None:
        try:
            data = path.read_bytes()
        except OSError as error:
            raise RuntimeError(f"Failed to read {path}") from error
        if b"\x00" in data:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None
