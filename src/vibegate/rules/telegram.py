from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING

from vibegate.models import Finding, Severity
from vibegate.rules.secrets import ignored_path, redact_line

if TYPE_CHECKING:
    from vibegate.scanner import ScanContext


TELEGRAM_SECRET_HEADER = "X-Telegram-Bot-Api-Secret-Token"
_WEBHOOK_WORDS = ("webhook", "update", "telegram", "bot")
_TELEGRAM_API_TOKEN_PATTERN = re.compile(
    r"https://api\.telegram\.org/bot(?P<token>\d{8,10}:AA[A-Za-z0-9_-]{33,})/(?P<method>setWebhook|getUpdates)",
    re.IGNORECASE,
)


class TelegramWebhookSecretTokenRule:
    rule_id = "telegram.webhook-secret-token"
    max_file_size_bytes = 1_000_000

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for path in sorted(context.root.rglob("*.py")):
            if not path.is_file():
                continue
            if ignored_path(path, context.root):
                continue
            if self._too_large(path):
                continue

            content = self._read_text(path)
            if content is None:
                continue

            findings.extend(self._find_unprotected_webhooks(context, path, content))
            findings.extend(self._find_webhook_token_exposure(context, path, content))

        return findings

    def _find_unprotected_webhooks(self, context: ScanContext, path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
                continue
            if not self._looks_like_telegram_webhook_handler(node):
                continue
            if self._checks_secret_token(lines, node.lineno, getattr(node, "end_lineno", node.lineno)):
                continue

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Telegram webhook missing secret-token check",
                    severity=Severity.HIGH,
                    message="A Telegram-looking webhook handler appears to process updates without validating Telegram's secret-token header.",
                    path=path.relative_to(context.root).as_posix(),
                    line=node.lineno,
                    snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else None,
                    remediation=f"Set a secret_token when registering the webhook and reject requests whose {TELEGRAM_SECRET_HEADER} header does not match it before processing updates.",
                )
            )

        return findings

    def _find_webhook_token_exposure(self, context: ScanContext, path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []

        for line_number, line in enumerate(content.splitlines(), start=1):
            for match in _TELEGRAM_API_TOKEN_PATTERN.finditer(line):
                token = match.group("token")
                method = match.group("method")
                findings.append(
                    Finding(
                        rule_id="telegram.webhook-token-exposure",
                        title="Telegram webhook API URL exposes bot token",
                        severity=Severity.CRITICAL,
                        message=f"A Telegram {method} API URL contains a hardcoded bot token, which exposes webhook or polling credentials.",
                        path=path.relative_to(context.root).as_posix(),
                        line=line_number,
                        snippet=redact_line(line, token),
                        remediation="Move the Telegram bot token into a secret manager or deployment environment variable, rotate it if committed, and build webhook/polling API URLs at runtime without logging them.",
                    )
                )

        return findings

    def _looks_like_telegram_webhook_handler(self, node: ast.AsyncFunctionDef | ast.FunctionDef) -> bool:
        if any(word in node.name.lower() for word in _WEBHOOK_WORDS):
            return True

        for decorator in node.decorator_list:
            decorator_text = ast.unparse(decorator).lower()
            if any(word in decorator_text for word in _WEBHOOK_WORDS):
                return True

        return False

    def _checks_secret_token(self, lines: list[str], start_line: int, end_line: int) -> bool:
        body = "\n".join(lines[start_line - 1 : end_line]).lower()
        normalized = body.replace("-", "_")
        return TELEGRAM_SECRET_HEADER.lower() in body or TELEGRAM_SECRET_HEADER.lower().replace("-", "_") in normalized

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
