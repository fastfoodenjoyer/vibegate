from __future__ import annotations

import json
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
        frontend_public_secret_rule = "frontend.public-secret-env"
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
                Profile(
                    profile_id="nextjs-vercel",
                    description="Next.js applications commonly deployed on Vercel.",
                    rule_ids=(committed_env_rule, hardcoded_secret_rule, frontend_public_secret_rule),
                ),
                Profile(
                    profile_id="vite-frontend",
                    description="Vite-powered frontend applications.",
                    rule_ids=(committed_env_rule, hardcoded_secret_rule, frontend_public_secret_rule),
                ),
                Profile(
                    profile_id="netlify-frontend",
                    description="Frontend applications configured for Netlify deployments.",
                    rule_ids=(committed_env_rule, hardcoded_secret_rule, frontend_public_secret_rule),
                ),
                Profile(
                    profile_id="supabase",
                    description="Applications using Supabase project configuration or credentials.",
                    rule_ids=(committed_env_rule, hardcoded_secret_rule, frontend_public_secret_rule),
                ),
                Profile(
                    profile_id="firebase",
                    description="Applications using Firebase project configuration or rules.",
                    rule_ids=(committed_env_rule, hardcoded_secret_rule, frontend_public_secret_rule),
                ),
                Profile(
                    profile_id="stripe-webhooks",
                    description="Applications receiving Stripe webhook events.",
                    rule_ids=(committed_env_rule, hardcoded_secret_rule),
                ),
                Profile(
                    profile_id="authjs",
                    description="Applications using Auth.js or NextAuth authentication.",
                    rule_ids=(committed_env_rule, hardcoded_secret_rule, frontend_public_secret_rule),
                ),
                Profile(
                    profile_id="clerk",
                    description="Applications using Clerk authentication.",
                    rule_ids=(committed_env_rule, hardcoded_secret_rule, frontend_public_secret_rule),
                ),
                Profile(
                    profile_id="github-actions",
                    description="Repositories with GitHub Actions workflows.",
                    rule_ids=(committed_env_rule, hardcoded_secret_rule),
                ),
                Profile(
                    profile_id="node-api",
                    description="Node.js API services using Express, Nest, or common server entrypoints.",
                    rule_ids=(committed_env_rule, hardcoded_secret_rule),
                ),
                Profile(
                    profile_id="docker-vps",
                    description="Alias for VPS-hosted Docker or Compose deployments.",
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
        if self._detects_nextjs_vercel(root):
            detected_profile_ids.append("nextjs-vercel")
        if self._detects_vite_frontend(root):
            detected_profile_ids.append("vite-frontend")
        if self._detects_netlify_frontend(root):
            detected_profile_ids.append("netlify-frontend")
        if self._detects_supabase(root):
            detected_profile_ids.append("supabase")
        if self._detects_firebase(root):
            detected_profile_ids.append("firebase")
        if self._detects_stripe_webhooks(root):
            detected_profile_ids.append("stripe-webhooks")
        if self._detects_authjs(root):
            detected_profile_ids.append("authjs")
        if self._detects_clerk(root):
            detected_profile_ids.append("clerk")
        if self._detects_github_actions(root):
            detected_profile_ids.append("github-actions")
        if self._detects_node_api(root):
            detected_profile_ids.append("node-api")
        if self._detects_vps_docker(root):
            detected_profile_ids.append("docker-vps")
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

    def _detects_nextjs_vercel(self, root: Path) -> bool:
        package_json = self._read_package_json(root)
        if package_json is None:
            return False
        return "next" in self._package_dependency_names(package_json) or self._package_script_uses(
            package_json,
            "next",
        )

    def _detects_vite_frontend(self, root: Path) -> bool:
        if any(root.glob("vite.config.*")):
            return True
        package_json = self._read_package_json(root)
        if package_json is None:
            return False
        return self._package_script_uses(package_json, "vite")

    def _detects_netlify_frontend(self, root: Path) -> bool:
        return (root / "netlify.toml").is_file()

    def _detects_supabase(self, root: Path) -> bool:
        if (root / "supabase").is_dir():
            return True
        return self._project_text_matches(
            root,
            re.compile(
                r"\b(NEXT_PUBLIC_)?SUPABASE_(URL|ANON_KEY|SERVICE_ROLE_KEY|JWT_SECRET)\b",
                re.IGNORECASE,
            ),
        )

    def _detects_firebase(self, root: Path) -> bool:
        firebase_names = {"firebase.json", "firestore.rules", "storage.rules"}
        return any((root / name).is_file() for name in firebase_names)

    def _detects_stripe_webhooks(self, root: Path) -> bool:
        return self._project_text_matches(
            root,
            re.compile(
                r"\bSTRIPE_WEBHOOK_SECRET\b|\bwhsec_[A-Za-z0-9_]+|"
                r"stripe\.webhooks\.constructEvent|stripe\.Webhook\.construct_event",
            ),
        )

    def _detects_authjs(self, root: Path) -> bool:
        package_json = self._read_package_json(root)
        if package_json is not None and self._package_dependency_names(package_json) & {
            "next-auth",
            "@auth/core",
            "@auth/nextjs",
        }:
            return True
        return self._project_text_matches(
            root,
            re.compile(r"\b(AUTH_SECRET|NEXTAUTH_SECRET|NEXTAUTH_URL)\b"),
        )

    def _detects_clerk(self, root: Path) -> bool:
        package_json = self._read_package_json(root)
        if package_json is not None:
            dependency_names = self._package_dependency_names(package_json)
            if any(name == "@clerk/nextjs" or name.startswith("@clerk/") for name in dependency_names):
                return True
        return self._project_text_matches(
            root,
            re.compile(r"\b(NEXT_PUBLIC_)?CLERK_[A-Z0-9_]+\b"),
        )

    def _detects_github_actions(self, root: Path) -> bool:
        workflow_dir = root / ".github" / "workflows"
        if not workflow_dir.is_dir():
            return False
        return any(path.is_file() and path.suffix in {".yml", ".yaml"} for path in workflow_dir.iterdir())

    def _detects_node_api(self, root: Path) -> bool:
        package_json = self._read_package_json(root)
        if package_json is not None and self._package_dependency_names(package_json) & {
            "express",
            "@nestjs/common",
            "@nestjs/core",
        }:
            return True
        for entrypoint in ("server.js", "server.ts", "app.js", "app.ts", "index.js", "index.ts"):
            path = root / entrypoint
            if not path.is_file() or self._too_large(path):
                continue
            content = self._read_text(path)
            if content is None:
                continue
            if re.search(r"\b(app|server)\.listen\s*\(", content) or "createServer(" in content:
                return True
        return False

    def _read_package_json(self, root: Path) -> dict[str, object] | None:
        path = root / "package.json"
        if not path.is_file() or self._too_large(path):
            return None
        content = self._read_text(path)
        if content is None:
            return None
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        return data

    def _package_dependency_names(self, package_json: dict[str, object]) -> set[str]:
        dependency_names: set[str] = set()
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            dependencies = package_json.get(key)
            if not isinstance(dependencies, dict):
                continue
            dependency_names.update(name for name in dependencies if isinstance(name, str))
        return dependency_names

    def _package_script_uses(self, package_json: dict[str, object], command: str) -> bool:
        scripts = package_json.get("scripts")
        if not isinstance(scripts, dict):
            return False
        command_pattern = re.compile(rf"(^|[\s;&|]){re.escape(command)}([\s:&|]|$)")
        return any(isinstance(script, str) and command_pattern.search(script) for script in scripts.values())

    def _project_text_matches(self, root: Path, pattern: re.Pattern[str]) -> bool:
        searchable_suffixes = {".env", ".js", ".jsx", ".ts", ".tsx", ".json", ".py"}
        for path in self._iter_project_files(root, "*"):
            if not path.is_file() or self._too_large(path):
                continue
            if path.name.startswith(".env") or path.suffix.lower() in searchable_suffixes:
                content = self._read_text(path)
                if content is not None and pattern.search(content):
                    return True
        return False

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
