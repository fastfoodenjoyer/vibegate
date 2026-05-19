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


class PublicFrontendSourceMapRule:
    rule_id = "frontend.public-sourcemap"
    max_file_size_bytes = 1_000_000
    _example_dirs = {"docs", "test", "tests", "__tests__"}
    _next_config_names = {
        "next.config.js",
        "next.config.mjs",
        "next.config.cjs",
        "next.config.ts",
        "next.config.mts",
        "next.config.cts",
    }
    _vite_config_pattern = re.compile(r"^vite\.config\.(?:js|mjs|cjs|ts|mts|cts)$")
    _next_public_sourcemap_pattern = re.compile(
        r"(?:\bproductionBrowserSourceMaps\b|[\"']productionBrowserSourceMaps[\"'])\s*:\s*true\b"
    )
    _vite_blocking_sourcemap_value_pattern = re.compile(r"\s*(?:true\b|[\"'](?:inline|hidden)[\"'])")

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for path in sorted(context.root.rglob("*")):
            if not path.is_file():
                continue
            if ignored_path(path, context.root) or self._is_example_path(path, context.root):
                continue
            if self._is_public_source_map_artifact(path, context.root):
                findings.append(self._artifact_finding(context, path))
                continue
            if self._too_large(path):
                continue
            content = self._read_text(path)
            if content is None:
                continue
            findings.extend(self._config_findings(context, path, content))

        return findings

    def _config_findings(self, context: ScanContext, path: Path, content: str) -> list[Finding]:
        masked = self._mask_js_comments_and_non_key_strings(content)
        if path.name in self._next_config_names:
            return [
                self._config_finding(
                    context,
                    path,
                    content,
                    match.start(),
                    "Next.js productionBrowserSourceMaps is enabled for production builds.",
                )
                for match in self._next_public_sourcemap_pattern.finditer(masked)
            ]
        if self._vite_config_pattern.fullmatch(path.name) is not None:
            return [
                self._config_finding(
                    context,
                    path,
                    content,
                    index,
                    "Vite build.sourcemap is enabled for production builds.",
                )
                for index in self._vite_direct_sourcemap_indexes(content, masked)
            ]
        return []

    def _mask_js_comments_and_non_key_strings(self, content: str) -> str:
        chars = list(content)
        i = 0
        in_line_comment = False
        in_block_comment = False
        while i < len(chars):
            char = chars[i]
            next_char = chars[i + 1] if i + 1 < len(chars) else ""
            if in_line_comment:
                if char == "\n":
                    in_line_comment = False
                else:
                    chars[i] = " "
                i += 1
                continue
            if in_block_comment:
                if char == "*" and next_char == "/":
                    chars[i] = " "
                    chars[i + 1] = " "
                    in_block_comment = False
                    i += 2
                else:
                    if char != "\n":
                        chars[i] = " "
                    i += 1
                continue
            if char in {"'", '"', "`"}:
                string_end = self._string_end_index(content, i)
                if string_end is None:
                    string_end = len(content) - 1
                next_nonspace = self._next_nonspace_index(content, string_end + 1, len(content))
                if next_nonspace is None or content[next_nonspace] != ":":
                    for string_index in range(i, string_end + 1):
                        if chars[string_index] != "\n":
                            chars[string_index] = " "
                i = string_end + 1
                continue
            if char == "/" and next_char == "/":
                chars[i] = " "
                chars[i + 1] = " "
                in_line_comment = True
                i += 2
                continue
            if char == "/" and next_char == "*":
                chars[i] = " "
                chars[i + 1] = " "
                in_block_comment = True
                i += 2
                continue
            i += 1
        return "".join(chars)

    def _vite_direct_sourcemap_indexes(self, original: str, masked: str) -> list[int]:
        indexes: list[int] = []
        for build_match in re.finditer(r"(?:\bbuild\b|[\"']build[\"'])\s*:\s*\{", masked):
            object_start = masked.find("{", build_match.start())
            object_end = self._matching_brace_index(masked, object_start)
            if object_end is None:
                continue
            sourcemap_index = self._direct_sourcemap_index(original, masked, object_start + 1, object_end)
            if sourcemap_index is not None:
                indexes.append(sourcemap_index)
        return indexes

    def _direct_sourcemap_index(self, original: str, masked: str, start: int, end: int) -> int | None:
        depth = 1
        i = start
        while i < end:
            char = masked[i]
            if char == "{":
                depth += 1
                i += 1
                continue
            if char == "}":
                depth -= 1
                i += 1
                continue
            key_end = self._sourcemap_key_end(masked, i)
            if depth == 1 and key_end is not None:
                colon_index = self._next_nonspace_index(masked, key_end, end)
                if colon_index is not None and masked[colon_index] == ":":
                    value_match = self._vite_blocking_sourcemap_value_pattern.match(original, colon_index + 1)
                    if value_match is not None:
                        return i
            i += 1
        return None

    def _sourcemap_key_end(self, content: str, start: int) -> int | None:
        for key in ("sourcemap", '"sourcemap"', "'sourcemap'"):
            end = start + len(key)
            if content.startswith(key, start) and self._is_property_boundary(content, start, end):
                return end
        return None

    def _string_end_index(self, content: str, start: int) -> int | None:
        quote = content[start]
        escaped = False
        for index in range(start + 1, len(content)):
            char = content[index]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                return index
        return None

    def _matching_brace_index(self, content: str, open_index: int) -> int | None:
        depth = 0
        quote: str | None = None
        escaped = False
        for index in range(open_index, len(content)):
            char = content[index]
            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in {"'", '"', "`"}:
                quote = char
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
        return None

    def _next_nonspace_index(self, content: str, start: int, end: int) -> int | None:
        for index in range(start, end):
            if not content[index].isspace():
                return index
        return None

    def _is_property_boundary(self, content: str, start: int, end: int) -> bool:
        before = content[start - 1] if start > 0 else ""
        after = content[end] if end < len(content) else ""
        return not (before.isalnum() or before in {"_", "$", "."}) and not (after.isalnum() or after in {"_", "$"})

    def _config_finding(self, context: ScanContext, path: Path, content: str, index: int, message: str) -> Finding:
        line_number = content.count("\n", 0, index) + 1
        line = content.splitlines()[line_number - 1].strip()
        return Finding(
            rule_id=self.rule_id,
            title="Public production source maps exposed",
            severity=Severity.HIGH,
            message=message,
            path=path.relative_to(context.root).as_posix(),
            line=line_number,
            snippet=line,
            remediation=(
                "Disable production browser source maps for public frontend builds, remove exposed .map artifacts "
                "from public deploy output, and redeploy without public source maps."
            ),
        )

    def _artifact_finding(self, context: ScanContext, path: Path) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title="Public production source map artifact exposed",
            severity=Severity.HIGH,
            message="A source map artifact is present under a public frontend build output directory.",
            path=path.relative_to(context.root).as_posix(),
            remediation=(
                "Remove public .map artifacts from deployment output or configure the build to avoid emitting "
                "public production source maps."
            ),
        )

    def _is_public_source_map_artifact(self, path: Path, root: Path) -> bool:
        if path.suffix.lower() != ".map":
            return False
        parts = path.relative_to(root).parts
        if parts[0] in {"dist", "out", "build"}:
            return True
        return len(parts) > 2 and parts[0] == ".next" and parts[1] == "static"

    def _is_example_path(self, path: Path, root: Path) -> bool:
        return bool(self._example_dirs.intersection(path.relative_to(root).parts))

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
