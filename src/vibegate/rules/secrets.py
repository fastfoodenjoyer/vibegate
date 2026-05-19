from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from vibegate.models import Finding, Severity

if TYPE_CHECKING:
    from vibegate.scanner import ScanContext


IGNORED_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__"}


class CommittedEnvFileRule:
    rule_id = "secrets.committed-env-file"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for env_file in self._find_env_files(context.root):
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Committed .env file",
                    severity=Severity.HIGH,
                    message="A .env file is present in the project tree and may contain deploy tokens, API keys, or bot credentials.",
                    path=env_file.relative_to(context.root).as_posix(),
                    remediation="Remove committed .env files, rotate any exposed secrets, and commit a sanitized .env.example instead.",
                )
            )
        return findings

    def _find_env_files(self, root: Path) -> list[Path]:
        env_files: list[Path] = []

        for path in root.rglob(".env*"):
            if not path.is_file():
                continue
            if ignored_path(path, root):
                continue
            if path.name in {".env.example", ".env.sample", ".env.template"}:
                continue
            env_files.append(path)

        return sorted(env_files)


class HardcodedSecretRule:
    rule_id = "secrets.hardcoded-token"
    max_file_size_bytes = 1_000_000
    text_suffixes = {".py", ".env", ".toml", ".yaml", ".yml", ".json", ".txt"}

    _telegram_token_pattern = re.compile(r"(?<![A-Za-z0-9_-])(\d{8,10}:AA[A-Za-z0-9_-]{33,})(?![A-Za-z0-9_-])")
    _assignment_pattern = re.compile(
        r"(?P<key>OPENAI_API_KEY|ANTHROPIC_API_KEY|BOT_TOKEN|API_TOKEN|SECRET_KEY)"
        r"\s*(?:=|:)\s*"
        r"(?P<quote>[\"'])?"
        r"(?P<value>[A-Za-z0-9_./+=:@-]{20,})"
        r"(?P=quote)?",
        re.IGNORECASE,
    )

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for path in sorted(context.root.rglob("*")):
            if not path.is_file():
                continue
            if ignored_path(path, context.root):
                continue
            if not self._is_supported_text_file(path):
                continue
            if self._too_large(path):
                continue

            content = self._read_text(path)
            if content is None:
                continue

            for line_number, line in enumerate(content.splitlines(), start=1):
                telegram_matches = list(self._telegram_token_pattern.finditer(line))
                for match in telegram_matches:
                    token = match.group(1)
                    findings.append(
                        self._finding(
                            context=context,
                            path=path,
                            line_number=line_number,
                            title="Hardcoded Telegram bot token",
                            severity=Severity.CRITICAL,
                            message="A Telegram bot token appears to be hardcoded in a text file.",
                            snippet=redact_line(line, token),
                        )
                    )

                if telegram_matches:
                    continue

                for match in self._assignment_pattern.finditer(line):
                    value = match.group("value")
                    if self._looks_like_placeholder(value):
                        continue
                    findings.append(
                        self._finding(
                            context=context,
                            path=path,
                            line_number=line_number,
                            title="Hardcoded service token",
                            severity=Severity.HIGH,
                            message=f"{match.group('key')} appears to be assigned a hardcoded token value.",
                            snippet=redact_line(line, value),
                        )
                    )

        return findings

    def _finding(
        self,
        *,
        context: ScanContext,
        path: Path,
        line_number: int,
        title: str,
        severity: Severity,
        message: str,
        snippet: str,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=title,
            severity=severity,
            message=message,
            path=path.relative_to(context.root).as_posix(),
            line=line_number,
            snippet=snippet,
            remediation="Move the token into a secret manager or deployment environment variable, remove it from git history if committed, and rotate the exposed credential.",
        )

    def _is_supported_text_file(self, path: Path) -> bool:
        if path.name.startswith(".env"):
            return True
        return path.suffix.lower() in self.text_suffixes

    def _too_large(self, path: Path) -> bool:
        try:
            return path.stat().st_size > self.max_file_size_bytes
        except OSError:
            return True

    def _read_text(self, path: Path) -> str | None:
        try:
            data = path.read_bytes()
        except OSError:
            return None
        if b"\x00" in data:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def _looks_like_placeholder(self, value: str) -> bool:
        return value.lower() in {"changeme", "placeholder", "example", "dummy", "token", "secret", "your-token-here"}


def ignored_path(path: Path, root: Path) -> bool:
    return bool(IGNORED_DIRS.intersection(path.relative_to(root).parts))


def redact_line(line: str, secret: str) -> str:
    if len(secret) <= 12:
        replacement = "[REDACTED]"
    else:
        replacement = f"{secret[:12]}[REDACTED]"
    return line.replace(secret, replacement)
