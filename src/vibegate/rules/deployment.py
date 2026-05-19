from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from vibegate.models import Finding, Severity
from vibegate.rules.secrets import ignored_path

if TYPE_CHECKING:
    from vibegate.scanner import ScanContext


class DockerSocketMountedRule:
    rule_id = "deployment.docker-socket-mounted"
    max_file_size_bytes = 1_000_000
    _socket_mount_pattern = re.compile(
        r"(?<![\w/.-])/var/run/docker\.sock\s*:\s*[^\s,\]'\"]+"
    )

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in _iter_deployment_files(context.root):
            content = _read_text(path)
            if content is None:
                continue
            findings.extend(self._scan_content(context, path, content))
        return findings

    def _scan_content(self, context: ScanContext, path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []
        current_long: _LongVolumeState | None = None
        for line_number, line in enumerate(content.splitlines(), start=1):
            stripped = _strip_inline_comment(line).strip()
            if not stripped:
                continue
            if self._socket_mount_pattern.search(stripped):
                findings.append(self._finding(context, path, line_number, stripped))
                current_long = None
                continue
            if stripped.startswith("-"):
                if current_long is not None and current_long.is_docker_socket_bind():
                    findings.append(self._finding(context, path, current_long.finding_line(), current_long.snippet()))
                current_long = _LongVolumeState(line_number=line_number)
                self._update_long_volume(current_long, stripped[1:].strip(), line_number)
                continue
            if current_long is not None:
                self._update_long_volume(current_long, stripped, line_number)
        if current_long is not None and current_long.is_docker_socket_bind():
            findings.append(self._finding(context, path, current_long.finding_line(), current_long.snippet()))
        return findings

    def _update_long_volume(self, state: _LongVolumeState, item: str, line_number: int) -> None:
        key_value = re.match(r"^(type|source|src|target|dst|destination)\s*:\s*(.+?)\s*$", item)
        if key_value is None:
            return
        key = key_value.group(1)
        value = _unquote(key_value.group(2).strip())
        if key == "type":
            state.mount_type = value.lower()
        elif key in {"source", "src"}:
            state.source = value
            state.source_line = line_number
        elif key in {"target", "dst", "destination"}:
            state.target = value
            state.target_line = line_number

    def _finding(self, context: ScanContext, path: Path, line_number: int, snippet: str) -> Finding:
        return _finding(
            context=context,
            path=path,
            line_number=line_number,
            rule_id=self.rule_id,
            title="Docker socket mounted into application service",
            severity=Severity.CRITICAL,
            message=(
                "This deployment mounts /var/run/docker.sock into a container, "
                "which gives that container host-level Docker control."
            ),
            snippet=snippet,
            remediation=(
                "Remove the Docker socket bind mount from application services. "
                "Use a narrow deployment agent, CI/CD integration, or a rootless/isolated control plane instead."
            ),
        )


class DockerDaemonTcpRule:
    rule_id = "deployment.docker-daemon-tcp"
    max_file_size_bytes = 1_000_000
    _docker_tcp_pattern = re.compile(r"tcp://(\[[^\]]*\]|[^\s:'\"/]*)?:2375\b", re.IGNORECASE)

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in _iter_deployment_files(context.root):
            content = _read_text(path)
            if content is None:
                continue
            for line_number, line in enumerate(content.splitlines(), start=1):
                stripped = _strip_inline_comment(line).strip()
                if stripped and self._line_exposes_public_daemon(stripped):
                    findings.append(
                        _finding(
                            context=context,
                            path=path,
                            line_number=line_number,
                            rule_id=self.rule_id,
                            title="Docker daemon exposed over unauthenticated TCP",
                            severity=Severity.CRITICAL,
                            message=(
                                "The Docker daemon is configured on tcp://*:2375 or another non-loopback address. "
                                "Port 2375 is unauthenticated and can allow remote host takeover."
                            ),
                            snippet=stripped,
                            remediation=(
                                "Do not expose dockerd on TCP port 2375. Use the Unix socket locally, SSH contexts, "
                                "or mutually-authenticated TLS on a restricted management network."
                            ),
                        )
                    )
        return findings

    def _line_exposes_public_daemon(self, line: str) -> bool:
        for match in self._docker_tcp_pattern.finditer(line):
            host = (match.group(1) or "").strip("[]").lower()
            if host not in {"127.0.0.1", "localhost", "::1"}:
                return True
        return False


class PublicInternalPortRule:
    rule_id = "deployment.public-internal-port"
    max_file_size_bytes = 1_000_000
    _sensitive_ports = {5432, 6379, 27017, 3306, 9200, 9300, 15672, 5672, 11211, 1433, 1521}

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in _iter_compose_files(context.root):
            content = _read_text(path)
            if content is None:
                continue
            findings.extend(self._scan_compose_content(context, path, content))
        return findings

    def _scan_compose_content(self, context: ScanContext, path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []
        in_ports = False
        ports_indent = 0
        current_long: _LongPortState | None = None
        for line_number, line in enumerate(content.splitlines(), start=1):
            stripped = _strip_inline_comment(line).strip()
            if not stripped:
                continue
            indent = _indent_width(line)
            if in_ports and indent <= ports_indent and not stripped.startswith("-"):
                if current_long is not None:
                    findings.extend(self._finding_for_long_port(context, path, current_long))
                current_long = None
                in_ports = False
            if re.match(r"^ports\s*:\s*$", stripped):
                in_ports = True
                ports_indent = indent
                current_long = None
                continue
            inline_ports = _parse_inline_ports(stripped)
            if inline_ports is not None:
                for item in inline_ports:
                    short_port = _parse_short_port(item)
                    if short_port is not None and self._short_port_is_public_sensitive(short_port):
                        findings.append(self._finding(context, path, line_number, stripped))
                continue
            if not in_ports:
                continue
            if stripped.startswith("-"):
                if current_long is not None:
                    findings.extend(self._finding_for_long_port(context, path, current_long))
                current_long = _LongPortState(line_number=line_number)
                item = stripped[1:].strip()
                if not item:
                    continue
                short_port = _parse_short_port(item)
                if short_port is not None:
                    if self._short_port_is_public_sensitive(short_port):
                        findings.append(self._finding(context, path, line_number, line.strip()))
                    current_long = None
                    continue
                self._update_long_port(current_long, item, line_number)
                continue
            if current_long is not None:
                self._update_long_port(current_long, stripped, line_number)
        if in_ports and current_long is not None:
            findings.extend(self._finding_for_long_port(context, path, current_long))
        return findings

    def _update_long_port(self, state: _LongPortState, item: str, line_number: int) -> None:
        key_value = re.match(r"^(target|published|host_ip)\s*:\s*(.+?)\s*$", item)
        if key_value is None:
            return
        key = key_value.group(1)
        value = _unquote(key_value.group(2).strip())
        if key == "target":
            state.target = _parse_port(value)
            state.target_line = line_number
        elif key == "published":
            state.published = _parse_port(value)
        elif key == "host_ip":
            state.host_ip = value

    def _finding_for_long_port(self, context: ScanContext, path: Path, state: _LongPortState) -> list[Finding]:
        if _is_loopback_host(state.host_ip):
            return []
        sensitive_port = state.target if state.target in self._sensitive_ports else state.published
        if sensitive_port not in self._sensitive_ports:
            return []
        line_number = state.target_line or state.line_number
        return [self._finding(context, path, line_number, f"target/published port {sensitive_port}")]

    def _short_port_is_public_sensitive(self, port: _ShortPort) -> bool:
        if _is_loopback_host(port.host_ip):
            return False
        return port.host_port in self._sensitive_ports or port.container_port in self._sensitive_ports

    def _finding(self, context: ScanContext, path: Path, line_number: int, snippet: str) -> Finding:
        return _finding(
            context=context,
            path=path,
            line_number=line_number,
            rule_id=self.rule_id,
            title="Internal service port published publicly",
            severity=Severity.HIGH,
            message=(
                "A Docker Compose ports mapping publishes a database, cache, queue, or admin port on a public interface."
            ),
            snippet=snippet,
            remediation=(
                "Remove the public ports mapping, use expose: for service-to-service traffic, "
                "or bind the host port to 127.0.0.1 and access it through SSH/VPN/private networking."
            ),
        )


class HttpOnlyReverseProxyRule:
    rule_id = "deployment.http-only-reverse-proxy"
    max_file_size_bytes = 1_000_000

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in _iter_nginx_files(context.root):
            content = _read_text(path)
            if content is None:
                continue
            for block in _server_blocks(content):
                if self._is_http_only_reverse_proxy(block.text):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title="HTTP-only reverse proxy server block",
                            severity=Severity.MEDIUM,
                            message=(
                                "An nginx server block listens on port 80 and proxies traffic without an obvious "
                                "HTTPS listener, SSL configuration, or redirect to HTTPS."
                            ),
                            blocking=False,
                            path=path.relative_to(context.root).as_posix(),
                            line=block.line_number,
                            snippet=block.first_line,
                            remediation=(
                                "Terminate TLS for public traffic or redirect HTTP to HTTPS in this server block. "
                                "If TLS is handled by an upstream load balancer, document that exception."
                            ),
                        )
                    )
        return findings

    def _is_http_only_reverse_proxy(self, block: str) -> bool:
        normalized = "\n".join(_strip_inline_comment(line) for line in block.splitlines()).lower()
        listens_http = re.search(r"\blisten\s+(?:[^;]*:)?80(?:\s|;)", normalized) is not None
        proxies = "proxy_pass" in normalized
        has_tls = (
            re.search(r"\blisten\s+(?:[^;]*:)?443\b", normalized) is not None
            or " ssl" in normalized
            or "ssl_certificate" in normalized
        )
        redirects_https = re.search(r"\b(return|rewrite)\b[^;]*https://", normalized) is not None
        return listens_http and proxies and not has_tls and not redirects_https


@dataclass
class _ServerBlock:
    line_number: int
    text: str
    first_line: str


@dataclass
class _ShortPort:
    host_ip: str | None
    host_port: int | None
    container_port: int


@dataclass
class _LongPortState:
    line_number: int
    target: int | None = None
    target_line: int | None = None
    published: int | None = None
    host_ip: str | None = None


@dataclass
class _LongVolumeState:
    line_number: int
    mount_type: str | None = None
    source: str | None = None
    source_line: int | None = None
    target: str | None = None
    target_line: int | None = None

    def is_docker_socket_bind(self) -> bool:
        return self.source == "/var/run/docker.sock" and self.target is not None and self.mount_type in {None, "bind"}

    def finding_line(self) -> int:
        return self.target_line or self.source_line or self.line_number

    def snippet(self) -> str:
        return f"source: {self.source} target: {self.target}"



def _iter_deployment_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    supported_names = {"Dockerfile", "daemon.json", "railway.toml", "coolify.json"}
    supported_suffixes = {".yml", ".yaml", ".toml", ".json", ".env"}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ignored_path(path, root) or _is_test_path(path, root):
            continue
        if _too_large(path, 1_000_000):
            continue
        if path.name in supported_names or path.name.startswith(".env") or path.suffix.lower() in supported_suffixes:
            paths.append(path)
    return paths


def _iter_compose_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ignored_path(path, root) or _is_test_path(path, root):
            continue
        if _too_large(path, 1_000_000):
            continue
        if path.suffix.lower() in {".yml", ".yaml"} and (
            path.name.startswith("docker-compose") or path.name.startswith("compose")
        ):
            paths.append(path)
    return paths


def _iter_nginx_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ignored_path(path, root) or _is_test_path(path, root):
            continue
        if _too_large(path, 1_000_000):
            continue
        if path.name == "nginx.conf" or path.suffix.lower() == ".conf":
            paths.append(path)
    return paths


def _server_blocks(content: str) -> list[_ServerBlock]:
    blocks: list[_ServerBlock] = []
    lines = content.splitlines()
    in_block = False
    depth = 0
    start_line = 0
    block_lines: list[str] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = _strip_inline_comment(line).strip()
        if not in_block:
            if re.match(r"^server\s*{", stripped):
                in_block = True
                depth = stripped.count("{") - stripped.count("}")
                start_line = line_number
                block_lines = [line]
                if depth <= 0:
                    blocks.append(_ServerBlock(start_line, "\n".join(block_lines), stripped))
                    in_block = False
            continue
        block_lines.append(line)
        depth += stripped.count("{") - stripped.count("}")
        if depth <= 0:
            blocks.append(_ServerBlock(start_line, "\n".join(block_lines), block_lines[0].strip()))
            in_block = False
            block_lines = []
    return blocks



def _parse_inline_ports(line: str) -> list[str] | None:
    match = re.match(r"^ports\s*:\s*\[(.*)\]\s*$", line)
    if match is None:
        return None
    body = match.group(1).strip()
    if not body:
        return []
    items: list[str] = []
    for part in body.split(","):
        value = _unquote(part.strip())
        if value:
            items.append(value)
    return items



def _parse_short_port(item: str) -> _ShortPort | None:
    value = _unquote(item).strip()
    if re.search(r"\s", value):
        return None
    protocol_split = value.split("/", 1)[0]
    parts = _split_port_parts(protocol_split)
    if len(parts) == 1:
        container_port = _parse_port(parts[0])
        if container_port is not None:
            return _ShortPort(host_ip=None, host_port=None, container_port=container_port)
    if len(parts) == 2:
        host_port = _parse_port(parts[0])
        container_port = _parse_port(parts[1])
        if host_port is not None and container_port is not None:
            return _ShortPort(host_ip=None, host_port=host_port, container_port=container_port)
    if len(parts) == 3:
        host_port = _parse_port(parts[1])
        container_port = _parse_port(parts[2])
        if (host_port is not None or parts[1] == "") and container_port is not None:
            return _ShortPort(host_ip=parts[0], host_port=host_port, container_port=container_port)
    return None


def _split_port_parts(value: str) -> list[str]:
    if value.startswith("[") and "]:" in value:
        host, rest = value.split("]:", 1)
        return [host[1:], *rest.split(":")]
    return value.split(":")


def _parse_port(value: str | None) -> int | None:
    if value is None:
        return None
    match = re.search(r"\d+", _unquote(value))
    if match is None:
        return None
    port = int(match.group(0))
    if 1 <= port <= 65535:
        return port
    return None


def _is_loopback_host(host: str | None) -> bool:
    if host is None or host == "":
        return False
    normalized = host.strip().strip("[]").lower()
    return normalized == "localhost" or normalized == "::1" or normalized.startswith("127.")


def _strip_inline_comment(line: str) -> str:
    in_single = False
    in_double = False
    for index, character in enumerate(line):
        if character == "'" and not in_double:
            in_single = not in_single
        elif character == '"' and not in_single:
            in_double = not in_double
        elif character == "#" and not in_single and not in_double:
            return line[:index]
    return line


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _indent_width(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_test_path(path: Path, root: Path) -> bool:
    relative_parts = path.relative_to(root).parts
    return any(part in {"tests", "test", "testing"} for part in relative_parts[:-1]) or path.name.startswith("test_")


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


def _finding(
    *,
    context: ScanContext,
    path: Path,
    line_number: int,
    rule_id: str,
    title: str,
    severity: Severity,
    message: str,
    snippet: str,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        message=message,
        blocking=True,
        path=path.relative_to(context.root).as_posix(),
        line=line_number,
        snippet=snippet,
        remediation=remediation,
    )
