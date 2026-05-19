from pathlib import Path

from vibegate.models import Severity, Verdict
from vibegate.rules.deployment import (
    DockerDaemonTcpRule,
    DockerSocketMountedRule,
    HttpOnlyReverseProxyRule,
    PublicInternalPortRule,
)
from vibegate.scanner import ScanContext, Scanner


def test_docker_socket_mount_in_compose_blocks(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    image: demo\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )

    findings = DockerSocketMountedRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "deployment.docker-socket-mounted"
    assert finding.severity is Severity.CRITICAL
    assert finding.blocking is True
    assert finding.path == "docker-compose.yml"
    assert finding.line == 5


def test_docker_socket_long_form_bind_mount_blocks(tmp_path: Path) -> None:
    (tmp_path / "compose.yaml").write_text(
        "services:\n"
        "  app:\n"
        "    image: demo\n"
        "    volumes:\n"
        "      - type: bind\n"
        "        source: /var/run/docker.sock\n"
        "        target: /var/run/docker.sock\n",
        encoding="utf-8",
    )

    findings = DockerSocketMountedRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].line == 7


def test_docker_socket_bind_mount_to_alternate_container_target_blocks(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    image: demo\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/docker.sock\n",
        encoding="utf-8",
    )

    findings = DockerSocketMountedRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].line == 5


def test_docker_socket_reference_without_bind_mount_does_not_block(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "RUN test -S /var/run/docker.sock || true\n",
        encoding="utf-8",
    )

    findings = DockerSocketMountedRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_docker_socket_commented_mount_does_not_block(tmp_path: Path) -> None:
    (tmp_path / "compose.yaml").write_text(
        "services:\n"
        "  app:\n"
        "    image: demo\n"
        "    # volumes:\n"
        "    #   - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )

    findings = DockerSocketMountedRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_docker_daemon_public_tcp_url_blocks(tmp_path: Path) -> None:
    (tmp_path / ".env.production").write_text(
        "DOCKER_HOST=tcp://0.0.0.0:2375\n",
        encoding="utf-8",
    )
    (tmp_path / "daemon.json").write_text(
        '{"hosts":["unix:///var/run/docker.sock","tcp://0.0.0.0:2375"]}\n',
        encoding="utf-8",
    )

    findings = DockerDaemonTcpRule().scan(ScanContext(root=tmp_path))

    assert [finding.path for finding in findings] == [".env.production", "daemon.json"]
    assert all(finding.rule_id == "deployment.docker-daemon-tcp" for finding in findings)
    assert all(finding.severity is Severity.CRITICAL for finding in findings)


def test_docker_daemon_empty_host_tcp_url_blocks(tmp_path: Path) -> None:
    (tmp_path / ".env.production").write_text(
        "DOCKER_HOST=tcp://:2375\n",
        encoding="utf-8",
    )

    findings = DockerDaemonTcpRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].line == 1


def test_docker_daemon_commented_public_tcp_url_does_not_block(tmp_path: Path) -> None:
    (tmp_path / ".env.production").write_text(
        "# DOCKER_HOST=tcp://0.0.0.0:2375\n",
        encoding="utf-8",
    )

    findings = DockerDaemonTcpRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_docker_daemon_loopback_or_tls_port_does_not_block(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "DOCKER_HOST=tcp://127.0.0.1:2375\n"
        "OTHER_DOCKER_HOST=tcp://0.0.0.0:2376\n",
        encoding="utf-8",
    )

    findings = DockerDaemonTcpRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_compose_public_internal_ports_block(tmp_path: Path) -> None:
    (tmp_path / "compose.yaml").write_text(
        "services:\n"
        "  postgres:\n"
        "    image: postgres\n"
        "    ports:\n"
        "      - 5432:5432\n"
        "  redis:\n"
        "    image: redis\n"
        "    ports:\n"
        "      - \"0.0.0.0:6379:6379\"\n"
        "  rabbitmq:\n"
        "    image: rabbitmq:management\n"
        "    ports:\n"
        "      - target: 15672\n"
        "        published: 15672\n",
        encoding="utf-8",
    )

    findings = PublicInternalPortRule().scan(ScanContext(root=tmp_path))

    assert [finding.rule_id for finding in findings] == [
        "deployment.public-internal-port",
        "deployment.public-internal-port",
        "deployment.public-internal-port",
    ]
    assert [finding.line for finding in findings] == [5, 9, 13]
    assert all(finding.severity is Severity.HIGH for finding in findings)


def test_compose_inline_array_public_internal_ports_block(tmp_path: Path) -> None:
    (tmp_path / "compose.yaml").write_text(
        "services:\n"
        "  postgres:\n"
        "    image: postgres\n"
        "    ports: [\"5432:5432\"]\n",
        encoding="utf-8",
    )

    findings = PublicInternalPortRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].line == 4


def test_compose_short_ephemeral_sensitive_port_blocks(tmp_path: Path) -> None:
    (tmp_path / "compose.yaml").write_text(
        "services:\n"
        "  postgres:\n"
        "    image: postgres\n"
        "    ports: [\"5432\"]\n"
        "  redis:\n"
        "    image: redis\n"
        "    ports:\n"
        "      - \"6379\"\n"
        "  mysql:\n"
        "    image: mysql\n"
        "    ports:\n"
        "      - \"0.0.0.0::3306\"\n"
        "  loopback_mysql:\n"
        "    image: mysql\n"
        "    ports:\n"
        "      - \"127.0.0.1::3306\"\n",
        encoding="utf-8",
    )

    findings = PublicInternalPortRule().scan(ScanContext(root=tmp_path))

    assert [finding.line for finding in findings] == [4, 8, 12]
    assert all(finding.rule_id == "deployment.public-internal-port" for finding in findings)


def test_compose_long_target_only_ephemeral_sensitive_port_blocks(tmp_path: Path) -> None:
    (tmp_path / "compose.yaml").write_text(
        "services:\n"
        "  postgres:\n"
        "    image: postgres\n"
        "    ports:\n"
        "      - target: 5432\n"
        "  redis:\n"
        "    image: redis\n"
        "    ports:\n"
        "      - target: 6379\n"
        "        host_ip: 127.0.0.1\n",
        encoding="utf-8",
    )

    findings = PublicInternalPortRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].line == 5


def test_compose_loopback_and_expose_internal_ports_do_not_block(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  postgres:\n"
        "    image: postgres\n"
        "    ports:\n"
        "      - 127.0.0.1:5432:5432\n"
        "  redis:\n"
        "    image: redis\n"
        "    expose:\n"
        "      - 6379\n"
        "  mysql:\n"
        "    image: mysql\n"
        "    ports:\n"
        "      - \"[::1]:3306:3306\"\n",
        encoding="utf-8",
    )

    findings = PublicInternalPortRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_http_only_nginx_reverse_proxy_is_non_blocking_advisory(tmp_path: Path) -> None:
    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "    listen 80;\n"
        "    server_name example.com;\n"
        "    location / { proxy_pass http://app:8000; }\n"
        "}\n",
        encoding="utf-8",
    )

    findings = HttpOnlyReverseProxyRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "deployment.http-only-reverse-proxy"
    assert finding.severity is Severity.MEDIUM
    assert finding.blocking is False


def test_nginx_http_redirect_to_https_does_not_warn(tmp_path: Path) -> None:
    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "    listen 80;\n"
        "    return 301 https://$host$request_uri;\n"
        "}\n",
        encoding="utf-8",
    )

    findings = HttpOnlyReverseProxyRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_scanner_maps_deployment_rules_to_docker_profiles(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  db:\n"
        "    image: postgres\n"
        "    ports:\n"
        "      - 5432:5432\n",
        encoding="utf-8",
    )

    result = Scanner().scan(tmp_path, profile_ids=["vps-docker"])

    assert result.summary.verdict is Verdict.NO_SHIP
    assert any(finding.rule_id == "deployment.public-internal-port" for finding in result.findings)


def test_scanner_maps_deployment_rules_to_railway_profile(tmp_path: Path) -> None:
    (tmp_path / "railway.toml").write_text("[build]\nbuilder = 'DOCKERFILE'\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(
        "ENV DOCKER_HOST=tcp://0.0.0.0:2375\n",
        encoding="utf-8",
    )

    result = Scanner().scan(tmp_path, profile_ids=["railway"])

    assert any(finding.rule_id == "deployment.docker-daemon-tcp" for finding in result.findings)


def test_scanner_maps_deployment_rules_to_coolify_profile(tmp_path: Path) -> None:
    (tmp_path / "coolify.json").write_text('{"name":"demo"}\n', encoding="utf-8")
    (tmp_path / "compose.yaml").write_text(
        "services:\n"
        "  db:\n"
        "    image: postgres\n"
        "    ports: [\"5432:5432\"]\n",
        encoding="utf-8",
    )

    result = Scanner().scan(tmp_path, profile_ids=["coolify"])

    assert result.summary.verdict is Verdict.NO_SHIP
    assert any(finding.rule_id == "deployment.public-internal-port" for finding in result.findings)
