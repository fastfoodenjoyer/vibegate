from pathlib import Path

from vibegate.models import Severity, Verdict
from vibegate.rules.python_backend import (
    DjangoDangerousSettingsRule,
    FastAPICorsWildcardCredentialsRule,
    FastAPIPublicDocsRule,
    FlaskDebugEnabledRule,
    UvicornReloadRule,
)
from vibegate.scanner import ScanContext, Scanner


def test_fastapi_cors_wildcard_with_credentials_blocks(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi.middleware.cors import CORSMiddleware\n"
        "app.add_middleware(\n"
        "    CORSMiddleware,\n"
        "    allow_origins=['*'],\n"
        "    allow_credentials=True,\n"
        ")\n",
        encoding="utf-8",
    )

    findings = FastAPICorsWildcardCredentialsRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "python.cors-wildcard-credentials"
    assert finding.severity is Severity.HIGH
    assert finding.blocking is True
    assert finding.path == "app.py"
    assert finding.line == 2
    assert finding.remediation is not None


def test_fastapi_cors_wildcard_regex_with_credentials_blocks(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi.middleware.cors import CORSMiddleware\n"
        "app.add_middleware(\n"
        "    CORSMiddleware,\n"
        "    allow_origin_regex='.*',\n"
        "    allow_credentials=True,\n"
        ")\n",
        encoding="utf-8",
    )

    findings = FastAPICorsWildcardCredentialsRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "python.cors-wildcard-credentials"
    assert findings[0].line == 2


def test_fastapi_cors_wildcard_without_credentials_does_not_block(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=False)\n",
        encoding="utf-8",
    )

    findings = FastAPICorsWildcardCredentialsRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_fastapi_cors_ignores_test_fixtures(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_app.py").write_text(
        "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n",
        encoding="utf-8",
    )

    findings = FastAPICorsWildcardCredentialsRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_fastapi_default_docs_warns_non_blocking(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI(title='Demo API')\n",
        encoding="utf-8",
    )

    findings = FastAPIPublicDocsRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "python.fastapi-public-docs"
    assert finding.severity is Severity.MEDIUM
    assert finding.blocking is False
    assert finding.path == "app.py"
    assert finding.line == 2


def test_fastapi_docs_redoc_and_openapi_disabled_do_not_warn(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)\n",
        encoding="utf-8",
    )

    findings = FastAPIPublicDocsRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_flask_debug_true_blocks(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("app.run(debug=True)\n", encoding="utf-8")

    findings = FlaskDebugEnabledRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "python.debug-enabled"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].path == "app.py"
    assert findings[0].line == 1


def test_flask_debug_true_blocks_for_discovered_flask_app_alias(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "server = Flask(__name__)\n"
        "server.run(debug=True)\n",
        encoding="utf-8",
    )

    findings = FlaskDebugEnabledRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "python.debug-enabled"
    assert findings[0].path == "app.py"
    assert findings[0].line == 3


def test_generic_server_run_debug_true_without_flask_app_does_not_block(tmp_path: Path) -> None:
    (tmp_path / "worker.py").write_text("server.run(debug=True)\n", encoding="utf-8")

    findings = FlaskDebugEnabledRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_flask_debug_env_blocks(tmp_path: Path) -> None:
    (tmp_path / ".env.production").write_text("FLASK_DEBUG=1\n", encoding="utf-8")

    findings = FlaskDebugEnabledRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].path == ".env.production"


def test_flask_debug_quoted_env_blocks(tmp_path: Path) -> None:
    (tmp_path / ".env.production").write_text(
        'FLASK_DEBUG="1"\nFLASK_DEBUG=\'true\'\n',
        encoding="utf-8",
    )

    findings = FlaskDebugEnabledRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 2
    assert [finding.line for finding in findings] == [1, 2]


def test_flask_app_debug_assignment_blocks_when_flask_app_present(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "app.debug = True\n",
        encoding="utf-8",
    )

    findings = FlaskDebugEnabledRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "python.debug-enabled"
    assert findings[0].line == 3


def test_flask_config_debug_assignment_blocks_when_flask_app_present(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "app.config['DEBUG'] = True\n",
        encoding="utf-8",
    )

    findings = FlaskDebugEnabledRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "python.debug-enabled"
    assert findings[0].line == 3


def test_flask_debug_false_does_not_block(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "DEBUG = False\napp.run(debug=False)\nFLASK_DEBUG=0\n",
        encoding="utf-8",
    )

    findings = FlaskDebugEnabledRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_generic_debug_true_does_not_create_python_debug_finding(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        "DEBUG = True\nself.debug = True\nconfig.DEBUG = True\nconfig['DEBUG'] = True\n",
        encoding="utf-8",
    )

    findings = FlaskDebugEnabledRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_django_debug_true_only_creates_django_rule_not_debug_duplicate(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text("DEBUG = True\n", encoding="utf-8")

    debug_findings = FlaskDebugEnabledRule().scan(ScanContext(root=tmp_path))
    django_findings = DjangoDangerousSettingsRule().scan(ScanContext(root=tmp_path))

    assert debug_findings == []
    assert [finding.rule_id for finding in django_findings] == ["python.django-dangerous-settings"]


def test_django_dangerous_settings_blocks_assignments(tmp_path: Path) -> None:
    package_dir = tmp_path / "project"
    package_dir.mkdir()
    (package_dir / "settings.py").write_text(
        "DEBUG = True\n"
        "ALLOWED_HOSTS = ['*']\n"
        "SECRET_KEY = 'django-insecure-change-me'\n",
        encoding="utf-8",
    )

    findings = DjangoDangerousSettingsRule().scan(ScanContext(root=tmp_path))

    assert [finding.rule_id for finding in findings] == [
        "python.django-dangerous-settings",
        "python.django-dangerous-settings",
        "python.django-dangerous-settings",
    ]
    assert {finding.line for finding in findings} == {1, 2, 3}
    assert all(finding.severity is Severity.HIGH for finding in findings)


def test_django_docs_prose_and_safe_values_do_not_block(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("Set Django DEBUG=True only in local docs prose.\n", encoding="utf-8")
    (tmp_path / "settings.py").write_text(
        "DEBUG = False\nALLOWED_HOSTS = ['api.example.com']\nSECRET_KEY = os.environ['SECRET_KEY']\n",
        encoding="utf-8",
    )

    findings = DjangoDangerousSettingsRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_django_debug_in_generic_python_config_does_not_block(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text("DEBUG = True\n", encoding="utf-8")

    findings = DjangoDangerousSettingsRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_uvicorn_reload_blocks_productionish_scripts_and_commands(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.poe.tasks]\nserve = 'uvicorn app:app --host 0.0.0.0 --reload'\n",
        encoding="utf-8",
    )
    (tmp_path / "Procfile").write_text("web: uvicorn app:app --reload\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text('CMD ["uvicorn", "app:app", "--reload"]\n', encoding="utf-8")
    (tmp_path / "docker-compose.prod.yml").write_text(
        "services:\n  api:\n    command: uvicorn app:app --reload\n",
        encoding="utf-8",
    )

    findings = UvicornReloadRule().scan(ScanContext(root=tmp_path))

    assert [finding.path for finding in findings] == ["Dockerfile", "Procfile", "docker-compose.prod.yml"]
    assert all(finding.rule_id == "python.uvicorn-reload" for finding in findings)


def test_pyproject_dev_script_uvicorn_reload_does_not_block(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.poe.tasks]\nserve = 'uvicorn app:app --host 0.0.0.0 --reload'\n",
        encoding="utf-8",
    )

    findings = UvicornReloadRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_uvicorn_reload_ignores_python_tests_and_non_uvicorn_reload(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_server.py").write_text("command = 'uvicorn app:app --reload'\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("Run uvicorn app:app --reload locally.\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"scripts":{"dev":"vite --host 0.0.0.0 --reload"}}\n', encoding="utf-8")

    findings = UvicornReloadRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_python_backend_profile_runs_backend_safety_rules(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("app.run(debug=True)\n", encoding="utf-8")

    result = Scanner().scan(tmp_path, profile_ids=["python-backend"])

    assert result.summary.verdict is Verdict.NO_SHIP
    assert any(finding.rule_id == "python.debug-enabled" for finding in result.findings)


def test_deployment_profiles_run_uvicorn_reload_rule(tmp_path: Path) -> None:
    (tmp_path / "Procfile").write_text("web: uvicorn app:app --reload\n", encoding="utf-8")

    for profile_id in ("railway", "vps-docker", "docker-vps"):
        result = Scanner().scan(tmp_path, profile_ids=[profile_id])

        assert result.summary.verdict is Verdict.NO_SHIP
        assert any(finding.rule_id == "python.uvicorn-reload" for finding in result.findings)
