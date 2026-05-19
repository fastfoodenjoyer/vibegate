from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from vibegate.models import Finding, Severity

if TYPE_CHECKING:
    from vibegate.scanner import ScanContext


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
        ignored_dirs = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__"}
        env_files: list[Path] = []

        for path in root.rglob(".env*"):
            if not path.is_file():
                continue
            if ignored_dirs.intersection(path.relative_to(root).parts):
                continue
            if path.name in {".env.example", ".env.sample", ".env.template"}:
                continue
            env_files.append(path)

        return sorted(env_files)
