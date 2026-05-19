from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING

from vibegate.models import Finding, Severity
from vibegate.rules.secrets import ignored_path

if TYPE_CHECKING:
    from vibegate.scanner import ScanContext


class FastAPICorsWildcardCredentialsRule:
    rule_id = "python.cors-wildcard-credentials"
    max_file_size_bytes = 1_000_000

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in _iter_python_files(context.root):
            tree = _parse_python(path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if not self._is_cors_configuration_call(node):
                    continue
                if not self._has_wildcard_origins(node):
                    continue
                if not self._has_credentials_enabled(node):
                    continue
                findings.append(
                    _finding(
                        context=context,
                        path=path,
                        line_number=node.lineno,
                        rule_id=self.rule_id,
                        title="CORS wildcard allows credentials",
                        message=(
                            "CORSMiddleware allows credentials while also allowing all origins. "
                            "Browsers reject this combination and permissive fallbacks can expose authenticated APIs."
                        ),
                        snippet=_line_at(path, node.lineno),
                        remediation=(
                            "Replace allow_origins=['*'] with an explicit list of trusted origins when "
                            "allow_credentials=True, or disable credentials for public unauthenticated APIs."
                        ),
                    )
                )
        return findings

    def _is_cors_configuration_call(self, node: ast.Call) -> bool:
        if _call_name(node.func) == "CORSMiddleware":
            return True
        if _call_attr_name(node.func) == "add_middleware" and node.args:
            return _expr_name(node.args[0]) == "CORSMiddleware"
        return False

    def _has_wildcard_origins(self, node: ast.Call) -> bool:
        keyword = _keyword(node, "allow_origins")
        if keyword is not None and _literal_list_contains(keyword.value, "*"):
            return True
        regex_keyword = _keyword(node, "allow_origin_regex")
        return regex_keyword is not None and self._is_wildcard_origin_regex(regex_keyword.value)

    def _is_wildcard_origin_regex(self, node: ast.expr) -> bool:
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            return False
        pattern = node.value.strip()
        return pattern in {".*", "^.*$"}

    def _has_credentials_enabled(self, node: ast.Call) -> bool:
        keyword = _keyword(node, "allow_credentials")
        if keyword is None:
            return False
        return isinstance(keyword.value, ast.Constant) and keyword.value.value is True


class FastAPIPublicDocsRule:
    rule_id = "python.fastapi-public-docs"
    max_file_size_bytes = 1_000_000
    _disabled_urls = {"docs_url", "redoc_url", "openapi_url"}

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in _iter_python_files(context.root):
            tree = _parse_python(path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not self._is_fastapi_call(node):
                    continue
                if self._all_public_docs_endpoints_disabled(node):
                    continue
                findings.append(
                    _finding(
                        context=context,
                        path=path,
                        line_number=node.lineno,
                        rule_id=self.rule_id,
                        title="FastAPI documentation endpoints appear public",
                        severity=Severity.MEDIUM,
                        blocking=False,
                        message=(
                            "FastAPI exposes Swagger UI, ReDoc, and OpenAPI schema endpoints by default. "
                            "Public API docs can disclose routes, schemas, and internal implementation details."
                        ),
                        snippet=_line_at(path, node.lineno),
                        remediation=(
                            "Disable public docs for deployed services with docs_url=None, redoc_url=None, "
                            "and openapi_url=None, or protect the docs behind authentication/network controls."
                        ),
                    )
                )
        return findings

    def _is_fastapi_call(self, node: ast.Call) -> bool:
        return _call_name(node.func) == "FastAPI" or _call_attr_name(node.func) == "FastAPI"

    def _all_public_docs_endpoints_disabled(self, node: ast.Call) -> bool:
        disabled_keyword_names = {
            keyword.arg
            for keyword in node.keywords
            if keyword.arg in self._disabled_urls and isinstance(keyword.value, ast.Constant) and keyword.value.value is None
        }
        return disabled_keyword_names == self._disabled_urls


class FlaskDebugEnabledRule:
    rule_id = "python.debug-enabled"
    max_file_size_bytes = 1_000_000
    _flask_debug_env_pattern = re.compile(r"^\s*FLASK_DEBUG\s*=\s*['\"]?(?:1|true|True|TRUE)['\"]?\s*(?:#.*)?$")

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in _iter_supported_files(context.root, suffixes={".py", ".env"}, env_files=True):
            content = _read_text(path)
            if content is None:
                continue
            if path.suffix.lower() == ".py":
                findings.extend(self._scan_python(context, path))
            if path.name.startswith(".env") or path.suffix.lower() == ".env":
                findings.extend(self._scan_env(context, path, content))
        return findings

    def _scan_python(self, context: ScanContext, path: Path) -> list[Finding]:
        tree = _parse_python(path)
        if tree is None:
            return []
        flask_app_names = self._flask_app_names(tree)
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and self._call_enables_debug(node, flask_app_names):
                findings.append(self._finding(context, path, node.lineno))
            elif isinstance(node, ast.Assign) and self._assignment_enables_debug(node, flask_app_names):
                findings.append(self._finding(context, path, node.lineno))
        return findings

    def _scan_env(self, context: ScanContext, path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            if self._flask_debug_env_pattern.search(line):
                findings.append(self._finding(context, path, line_number, line.strip()))
        return findings

    def _call_enables_debug(self, node: ast.Call, flask_app_names: set[str]) -> bool:
        if not self._is_flask_debug_run_call(node, flask_app_names):
            return False
        keyword = _keyword(node, "debug")
        return keyword is not None and isinstance(keyword.value, ast.Constant) and keyword.value.value is True

    def _is_flask_debug_run_call(self, node: ast.Call, flask_app_names: set[str]) -> bool:
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "run":
            return False
        if isinstance(node.func.value, ast.Name) and node.func.value.id in flask_app_names | {"app"}:
            return True
        return isinstance(node.func.value, ast.Call) and _call_name(node.func.value.func) == "Flask"

    def _flask_app_names(self, tree: ast.AST) -> set[str]:
        names: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                continue
            if _call_name(node.value.func) != "Flask":
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        return names

    def _assignment_enables_debug(self, node: ast.Assign, flask_app_names: set[str]) -> bool:
        if not _is_true(node.value):
            return False
        return any(self._is_flask_debug_assignment_target(target, flask_app_names) for target in node.targets)

    def _is_flask_debug_assignment_target(self, target: ast.expr, flask_app_names: set[str]) -> bool:
        if isinstance(target, ast.Attribute) and target.attr == "debug":
            return isinstance(target.value, ast.Name) and target.value.id in flask_app_names
        if not isinstance(target, ast.Subscript) or not _is_debug_key(target.slice):
            return False
        value = target.value
        return (
            isinstance(value, ast.Attribute)
            and value.attr == "config"
            and isinstance(value.value, ast.Name)
            and value.value.id in flask_app_names
        )

    def _finding(self, context: ScanContext, path: Path, line_number: int, snippet: str | None = None) -> Finding:
        return _finding(
            context=context,
            path=path,
            line_number=line_number,
            rule_id=self.rule_id,
            title="Python debug mode enabled",
            message="Debug mode is enabled in Python backend configuration and can expose interactive consoles or sensitive errors.",
            snippet=snippet if snippet is not None else _line_at(path, line_number),
            remediation="Disable Flask/Django debug mode in deployed environments and control it only through non-production local config.",
        )


class DjangoDangerousSettingsRule:
    rule_id = "python.django-dangerous-settings"
    max_file_size_bytes = 1_000_000
    _weak_secret_markers = (
        "change-me",
        "changeme",
        "django-insecure",
        "insecure",
        "placeholder",
        "your-secret",
        "your_secret",
        "secret-key",
        "secret_key",
    )

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in _iter_python_files(context.root):
            tree = _parse_python(path)
            if tree is None or not self._is_likely_django_settings_file(path, context.root):
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign):
                    continue
                name = self._assignment_name(node)
                if name == "DEBUG" and _is_true(node.value):
                    findings.append(self._finding(context, path, node.lineno, "Django DEBUG is enabled."))
                elif name == "ALLOWED_HOSTS" and _literal_list_contains(node.value, "*"):
                    findings.append(self._finding(context, path, node.lineno, "Django ALLOWED_HOSTS allows every host."))
                elif name == "SECRET_KEY" and self._is_weak_secret_key(node.value):
                    findings.append(self._finding(context, path, node.lineno, "Django SECRET_KEY is an obvious weak placeholder."))
        return findings

    def _assignment_name(self, node: ast.Assign) -> str | None:
        if len(node.targets) != 1:
            return None
        return _expr_name(node.targets[0])

    def _is_likely_django_settings_file(self, path: Path, root: Path) -> bool:
        relative_parts = path.relative_to(root).parts
        return path.name.startswith("settings") or "settings" in relative_parts[:-1]

    def _is_weak_secret_key(self, value: ast.expr) -> bool:
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return False
        normalized = value.value.lower()
        return any(marker in normalized for marker in self._weak_secret_markers)

    def _finding(self, context: ScanContext, path: Path, line_number: int, message: str) -> Finding:
        return _finding(
            context=context,
            path=path,
            line_number=line_number,
            rule_id=self.rule_id,
            title="Dangerous Django production setting",
            message=message,
            snippet=_line_at(path, line_number),
            remediation=(
                "Use environment-specific Django settings: set DEBUG=False, restrict ALLOWED_HOSTS "
                "to deployed domains, and load a strong SECRET_KEY from a deployment secret."
            ),
        )


class UvicornReloadRule:
    rule_id = "python.uvicorn-reload"
    max_file_size_bytes = 1_000_000
    _uvicorn_pattern = re.compile(r"\buvicorn\b")
    _reload_pattern = re.compile(r"(?:^|[\s,\"'])--reload(?:\s|$|[\"'])")
    _supported_names = {
        "Procfile",
        "railway.toml",
        "nixpacks.toml",
        "render.yaml",
        "render.yml",
        "fly.toml",
        "Dockerfile",
    }

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in sorted(context.root.rglob("*")):
            if not path.is_file() or ignored_path(path, context.root) or _is_test_path(path, context.root):
                continue
            if not self._is_supported_deployment_file(path):
                continue
            if _too_large(path, self.max_file_size_bytes):
                continue
            content = _read_text(path)
            if content is None:
                continue
            for line_number, line in enumerate(content.splitlines(), start=1):
                if self._uvicorn_pattern.search(line) and self._reload_pattern.search(line):
                    findings.append(
                        _finding(
                            context=context,
                            path=path,
                            line_number=line_number,
                            rule_id=self.rule_id,
                            title="Uvicorn reload enabled in deployment command",
                            message="A deployment script or command runs uvicorn with --reload, which is intended for local development only.",
                            snippet=line.strip(),
                            remediation="Remove --reload from production, Railway, Procfile, Docker, and package script commands.",
                        )
                    )
        return findings

    def _is_supported_deployment_file(self, path: Path) -> bool:
        if path.name in self._supported_names:
            return True
        return path.suffix.lower() in {".yml", ".yaml"} and (
            path.name.startswith("docker-compose") or path.name.startswith("compose")
        )


def _iter_python_files(root: Path) -> list[Path]:
    return list(_iter_supported_files(root, suffixes={".py"}, env_files=False))


def _iter_supported_files(root: Path, *, suffixes: set[str], env_files: bool) -> list[Path]:
    paths: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ignored_path(path, root) or _is_test_path(path, root):
            continue
        if _too_large(path, 1_000_000):
            continue
        suffix = path.suffix.lower()
        if suffix in suffixes or (env_files and (path.name.startswith(".env") or suffix == ".env")):
            paths.append(path)
    return paths


def _is_test_path(path: Path, root: Path) -> bool:
    relative_parts = path.relative_to(root).parts
    return any(part in {"tests", "test", "testing"} for part in relative_parts[:-1]) or path.name.startswith("test_")


def _parse_python(path: Path) -> ast.AST | None:
    content = _read_text(path)
    if content is None:
        return None
    try:
        return ast.parse(content, filename=str(path))
    except SyntaxError:
        return None


def _read_text(path: Path) -> str | None:
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


def _too_large(path: Path, max_file_size_bytes: int) -> bool:
    try:
        return path.stat().st_size > max_file_size_bytes
    except OSError:
        return True


def _keyword(node: ast.Call, name: str) -> ast.keyword | None:
    return next((keyword for keyword in node.keywords if keyword.arg == name), None)


def _expr_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _call_attr_name(node: ast.AST) -> str:
    return node.attr if isinstance(node, ast.Attribute) else ""


def _is_true(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_debug_key(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value == "DEBUG"


def _literal_list_contains(node: ast.expr, expected: str) -> bool:
    if not isinstance(node, ast.List | ast.Tuple | ast.Set):
        return False
    return any(isinstance(element, ast.Constant) and element.value == expected for element in node.elts)


def _line_at(path: Path, line_number: int) -> str | None:
    content = _read_text(path)
    if content is None:
        return None
    lines = content.splitlines()
    if line_number < 1 or line_number > len(lines):
        return None
    return lines[line_number - 1].strip()


def _finding(
    *,
    context: ScanContext,
    path: Path,
    line_number: int,
    rule_id: str,
    title: str,
    message: str,
    snippet: str | None,
    remediation: str,
    severity: Severity = Severity.HIGH,
    blocking: bool = True,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        message=message,
        blocking=blocking,
        path=path.relative_to(context.root).as_posix(),
        line=line_number,
        snippet=snippet,
        remediation=remediation,
    )
