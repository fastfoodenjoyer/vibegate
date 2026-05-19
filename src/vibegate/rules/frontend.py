from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from vibegate.models import Finding, Severity
from vibegate.rules.secrets import ignored_path, redact_line

if TYPE_CHECKING:
    from vibegate.scanner import ScanContext


class PublicFrontendSecretEnvRule:
    rule_id = "frontend.public-secret-env"
    max_file_size_bytes = 1_000_000
    text_suffixes = {
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".mts",
        ".cts",
        ".json",
        ".toml",
        ".yaml",
        ".yml",
    }

    _public_secret_assignment_pattern = re.compile(
        r"(?P<name>\b(?:NEXT_PUBLIC|VITE|PUBLIC|REACT_APP)_[A-Z0-9_]*"
        r"(?:SECRET|TOKEN|PASSWORD|PRIVATE|DATABASE|SERVICE_ROLE|OPENAI_API_KEY|ANTHROPIC_API_KEY|STRIPE_SECRET|"
        r"CLERK_SECRET|AUTH_SECRET|NEXTAUTH_SECRET|AWS_SECRET|R2_SECRET)[A-Z0-9_]*\b)"
        r"\s*(?:=|:)\s*"
        r"(?P<quote>[\"'])?"
        r"(?P<value>[A-Za-z0-9_./+=:@$-]{12,})"
        r"(?P=quote)?",
        re.IGNORECASE,
    )
    _public_secret_reference_pattern = re.compile(
        r"\b(?P<name>(?:NEXT_PUBLIC|VITE|PUBLIC|REACT_APP)_[A-Z0-9_]*"
        r"(?:SECRET|TOKEN|PASSWORD|PRIVATE|DATABASE|SERVICE_ROLE|OPENAI_API_KEY|ANTHROPIC_API_KEY|STRIPE_SECRET|"
        r"CLERK_SECRET|AUTH_SECRET|NEXTAUTH_SECRET|AWS_SECRET|R2_SECRET)[A-Z0-9_]*)\b",
        re.IGNORECASE,
    )
    _public_secret_env_access_pattern = re.compile(
        r"(?:\bprocess\.env|\bimport\.meta\.env)"
        r"(?:\.\s*(?P<dot_name>(?:NEXT_PUBLIC|VITE|PUBLIC|REACT_APP)_[A-Z0-9_]*"
        r"(?:SECRET|TOKEN|PASSWORD|PRIVATE|DATABASE|SERVICE_ROLE|OPENAI_API_KEY|ANTHROPIC_API_KEY|STRIPE_SECRET|"
        r"CLERK_SECRET|AUTH_SECRET|NEXTAUTH_SECRET|AWS_SECRET|R2_SECRET)[A-Z0-9_]*)\b|"
        r"\[\s*['\"](?P<bracket_name>(?:NEXT_PUBLIC|VITE|PUBLIC|REACT_APP)_[A-Z0-9_]*"
        r"(?:SECRET|TOKEN|PASSWORD|PRIVATE|DATABASE|SERVICE_ROLE|OPENAI_API_KEY|ANTHROPIC_API_KEY|STRIPE_SECRET|"
        r"CLERK_SECRET|AUTH_SECRET|NEXTAUTH_SECRET|AWS_SECRET|R2_SECRET)[A-Z0-9_]*)['\"]\s*\])",
        re.IGNORECASE,
    )
    _public_generic_api_key_assignment_pattern = re.compile(
        r"(?P<name>\b(?:NEXT_PUBLIC|VITE|PUBLIC|REACT_APP)_API_KEY\b)"
        r"\s*(?:=|:)\s*"
        r"(?P<quote>[\"'])?"
        r"(?P<value>[A-Za-z0-9_./+=:@$-]{12,})"
        r"(?P=quote)?",
        re.IGNORECASE,
    )
    _known_secret_value_pattern = re.compile(
        r"^(?:sk-(?:live|test|proj)-[A-Za-z0-9_-]{24,}|sk_(?:live|test)_[A-Za-z0-9_]{24,}|"
        r"sk-ant-api03-[A-Za-z0-9_-]{24,}|sb_secret_[A-Za-z0-9_-]{24,}|whsec_[A-Za-z0-9_]{24,})$"
    )
    _real_looking_fallback_pattern = re.compile(
        r"(?P<quote>[\"'])"
        r"(?P<value>(?:sk-(?:live|test|proj)-[A-Za-z0-9_-]{24,}|sk_(?:live|test)_[A-Za-z0-9_]{24,}|"
        r"sk-ant-api03-[A-Za-z0-9_-]{24,}|pk_(?:live|test)_[A-Za-z0-9]{24,}|"
        r"sb_secret_[A-Za-z0-9_-]{24,}|whsec_[A-Za-z0-9_]{24,}))"
        r"(?P=quote)"
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
                findings.extend(self._scan_line(context, path, line_number, line))

        return findings

    def _scan_line(self, context: ScanContext, path: Path, line_number: int, line: str) -> list[Finding]:
        assignment_findings: list[Finding] = []
        matched_spans: list[tuple[int, int]] = []
        for match in self._public_secret_assignment_pattern.finditer(line):
            name = match.group("name")
            value = match.group("value").rstrip(",;)")
            if self._looks_like_placeholder(value):
                continue
            matched_spans.append(match.span("name"))
            assignment_findings.append(self._finding(context, path, line_number, line, name, value))

        if assignment_findings:
            return assignment_findings

        for match in self._public_generic_api_key_assignment_pattern.finditer(line):
            name = match.group("name")
            value = match.group("value").rstrip(",;)")
            if self._looks_like_placeholder(value):
                continue
            if not self._looks_like_known_secret_value(value):
                continue
            return [self._finding(context, path, line_number, line, name, value)]

        value_match = self._real_looking_fallback_pattern.search(line)
        env_access_match = self._public_secret_env_access_pattern.search(line)
        if env_access_match is not None:
            value = value_match.group("value") if value_match is not None else None
            if value is not None and self._looks_like_placeholder(value):
                return []
            name = env_access_match.group("dot_name") or env_access_match.group("bracket_name")
            return [self._finding(context, path, line_number, line, name, value)]

        reference_match = self._public_secret_reference_pattern.search(line)
        if reference_match is None or self._in_existing_span(reference_match.span("name"), matched_spans):
            return []
        if value_match is None:
            return []
        value = value_match.group("value")
        if self._looks_like_placeholder(value):
            return []
        return [self._finding(context, path, line_number, line, reference_match.group("name"), value)]

    def _finding(
        self,
        context: ScanContext,
        path: Path,
        line_number: int,
        line: str,
        name: str,
        value: str | None,
    ) -> Finding:
        message = f"{name} uses a client-exposed frontend environment variable prefix with a secret-like name."
        if value is not None:
            message = (
                f"{name} uses a client-exposed frontend environment variable prefix with a "
                "secret-like name and value."
            )
        return Finding(
            rule_id=self.rule_id,
            title="Public frontend environment variable exposes a secret",
            severity=Severity.HIGH,
            message=message,
            path=path.relative_to(context.root).as_posix(),
            line=line_number,
            snippet=redact_line(line.strip(), value) if value is not None else line.strip(),
            remediation=(
                "Remove the public frontend prefix from secret variables, keep the credential server-side only, "
                "rotate the exposed value if it was committed or deployed, and expose only non-sensitive public config to the client."
            ),
        )

    def _is_supported_text_file(self, path: Path) -> bool:
        if path.name.startswith(".env"):
            return True
        if path.suffix.lower() == ".env":
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
        normalized = value.strip().lower().strip('"\'`')
        if normalized in {
            "changeme",
            "change-me",
            "placeholder",
            "example",
            "dummy",
            "token",
            "secret",
            "password",
            "your-key-here",
            "your-secret-here",
        }:
            return True
        return any(marker in normalized for marker in ("your_", "your-", "_your_", "-your-", "example", "placeholder", "dummy"))

    def _looks_like_known_secret_value(self, value: str) -> bool:
        return self._known_secret_value_pattern.fullmatch(value.strip().strip('"\'`')) is not None

    def _in_existing_span(self, span: tuple[int, int], existing_spans: list[tuple[int, int]]) -> bool:
        return any(start <= span[0] and span[1] <= end for start, end in existing_spans)
