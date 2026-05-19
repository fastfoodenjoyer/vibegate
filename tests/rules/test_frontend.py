from pathlib import Path

from vibegate.models import Severity, Verdict
from vibegate.rules.frontend import PublicFrontendSecretEnvRule
from vibegate.scanner import ScanContext, Scanner


FAKE_SUPABASE_SERVICE_ROLE_KEY = "sb_secret_abcdefghijklmnopqrstuvwxyz1234567890"
FAKE_STRIPE_SECRET_KEY = "".join(
    ["sk", "_", "live", "_", "abcdefghijklmnopqrstuvwxyz1234567890"]
)
FAKE_OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL0123456789"
FAKE_ANTHROPIC_API_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL0123456789"


def test_public_frontend_secret_env_flags_next_public_supabase_service_role_key(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        f"NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY={FAKE_SUPABASE_SERVICE_ROLE_KEY}\n",
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "frontend.public-secret-env"
    assert finding.severity is Severity.HIGH
    assert finding.blocking is True
    assert finding.path == ".env"
    assert finding.line == 1
    assert FAKE_SUPABASE_SERVICE_ROLE_KEY not in (finding.snippet or "")
    assert "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY" in (finding.snippet or "")
    assert finding.remediation is not None


def test_public_frontend_secret_env_flags_vite_stripe_secret_key(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config.ts").write_text(
        f'const key = "VITE_STRIPE_SECRET_KEY={FAKE_STRIPE_SECRET_KEY}";\n',
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].path == "src/config.ts"
    assert findings[0].line == 1
    assert FAKE_STRIPE_SECRET_KEY not in (findings[0].snippet or "")


def test_public_frontend_secret_env_flags_react_app_openai_api_key(tmp_path: Path) -> None:
    (tmp_path / "app.jsx").write_text(
        f"export const key = process.env.REACT_APP_OPENAI_API_KEY ?? '{FAKE_OPENAI_API_KEY}';\n",
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].path == "app.jsx"
    assert findings[0].line == 1
    assert "REACT_APP_OPENAI_API_KEY" in findings[0].message


def test_public_frontend_secret_env_flags_vite_anthropic_api_key(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        f"VITE_ANTHROPIC_API_KEY={FAKE_ANTHROPIC_API_KEY}\n",
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].path == ".env"
    assert findings[0].line == 1
    assert "VITE_ANTHROPIC_API_KEY" in findings[0].message
    assert FAKE_ANTHROPIC_API_KEY not in (findings[0].snippet or "")


def test_public_frontend_secret_env_flags_generic_next_public_api_key_with_openai_value(
    tmp_path: Path,
) -> None:
    (tmp_path / ".env").write_text(
        f"NEXT_PUBLIC_API_KEY={FAKE_OPENAI_API_KEY}\n",
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].path == ".env"
    assert findings[0].line == 1
    assert "NEXT_PUBLIC_API_KEY" in findings[0].message
    assert FAKE_OPENAI_API_KEY not in (findings[0].snippet or "")


def test_public_frontend_secret_env_flags_generic_next_public_api_key_with_stripe_secret_value(
    tmp_path: Path,
) -> None:
    (tmp_path / ".env").write_text(
        f"NEXT_PUBLIC_API_KEY={FAKE_STRIPE_SECRET_KEY}\n",
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "frontend.public-secret-env"
    assert findings[0].path == ".env"
    assert findings[0].line == 1
    assert "NEXT_PUBLIC_API_KEY" in findings[0].message
    assert FAKE_STRIPE_SECRET_KEY not in (findings[0].snippet or "")


def test_public_frontend_secret_env_flags_ts_generic_public_api_key_with_stripe_secret_value(
    tmp_path: Path,
) -> None:
    (tmp_path / "config.ts").write_text(
        f'export const config = {{ NEXT_PUBLIC_API_KEY: "{FAKE_STRIPE_SECRET_KEY}" }};\n',
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "frontend.public-secret-env"
    assert findings[0].path == "config.ts"
    assert findings[0].line == 1
    assert "NEXT_PUBLIC_API_KEY" in findings[0].message
    assert FAKE_STRIPE_SECRET_KEY not in (findings[0].snippet or "")


def test_public_frontend_secret_env_flags_generic_vite_api_key_with_anthropic_value(
    tmp_path: Path,
) -> None:
    (tmp_path / ".env").write_text(
        f"VITE_API_KEY={FAKE_ANTHROPIC_API_KEY}\n",
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].path == ".env"
    assert findings[0].line == 1
    assert "VITE_API_KEY" in findings[0].message
    assert FAKE_ANTHROPIC_API_KEY not in (findings[0].snippet or "")


def test_public_frontend_secret_env_flags_next_public_source_reference_without_literal(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.ts").write_text(
        "export const key = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n",
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].path == "app.ts"
    assert findings[0].line == 1
    assert "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY" in findings[0].message


def test_public_frontend_secret_env_flags_vite_source_reference_without_literal(
    tmp_path: Path,
) -> None:
    (tmp_path / "config.ts").write_text(
        "export const key = import.meta.env.VITE_STRIPE_SECRET_KEY;\n",
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].path == "config.ts"
    assert findings[0].line == 1
    assert "VITE_STRIPE_SECRET_KEY" in findings[0].message


def test_public_frontend_secret_env_ignores_public_generic_api_key_google_maps_value(
    tmp_path: Path,
) -> None:
    (tmp_path / ".env").write_text(
        "NEXT_PUBLIC_GOOGLE_MAPS_API_KEY=AIzaSyD-publicBrowserKey1234567890\n",
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_public_frontend_secret_env_ignores_generic_public_api_key_google_browser_value(
    tmp_path: Path,
) -> None:
    (tmp_path / ".env").write_text(
        "NEXT_PUBLIC_API_KEY=AIzaSyD-publicBrowserKey1234567890\n",
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_public_frontend_secret_env_ignores_public_generic_api_key_firebase_value(
    tmp_path: Path,
) -> None:
    (tmp_path / ".env").write_text(
        "VITE_FIREBASE_API_KEY=AIzaSyD-publicFirebaseKey1234567890\n",
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_public_frontend_secret_env_flags_suffix_env_file(tmp_path: Path) -> None:
    (tmp_path / "production.env").write_text(
        f"NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY={FAKE_SUPABASE_SERVICE_ROLE_KEY}\n",
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert len(findings) == 1
    assert findings[0].path == "production.env"


def test_public_frontend_secret_env_flags_js_ts_module_variants(tmp_path: Path) -> None:
    for suffix in (".mjs", ".cjs", ".mts", ".cts"):
        (tmp_path / f"config{suffix}").write_text(
            "export const key = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n",
            encoding="utf-8",
        )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert [finding.path for finding in findings] == [
        "config.cjs",
        "config.cts",
        "config.mjs",
        "config.mts",
    ]


def test_public_frontend_secret_env_ignores_public_non_secret_config(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("NEXT_PUBLIC_SITE_URL=https://example.com\n", encoding="utf-8")

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_public_frontend_secret_env_ignores_example_placeholders(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text(
        "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=your-service-role-key\n"
        "VITE_STRIPE_SECRET_KEY=sk_test_your_key_here\n",
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_public_frontend_secret_env_ignores_documentation_without_real_value(tmp_path: Path) -> None:
    (tmp_path / "docs.yaml").write_text(
        "warning: Do not expose NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY in your frontend.\n",
        encoding="utf-8",
    )

    findings = PublicFrontendSecretEnvRule().scan(ScanContext(root=tmp_path))

    assert findings == []


def test_nextjs_vercel_profile_runs_public_frontend_secret_env_rule(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"next":"14.0.0"}}\n',
        encoding="utf-8",
    )
    (tmp_path / ".env.local").write_text(
        f"NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY={FAKE_SUPABASE_SERVICE_ROLE_KEY}\n",
        encoding="utf-8",
    )

    result = Scanner().scan(tmp_path, profile_ids=["nextjs-vercel"])

    assert result.summary.verdict is Verdict.NO_SHIP
    assert any(finding.rule_id == "frontend.public-secret-env" for finding in result.findings)


def test_vite_frontend_profile_runs_public_frontend_secret_env_rule(tmp_path: Path) -> None:
    (tmp_path / "vite.config.ts").write_text("export default {}\n", encoding="utf-8")
    (tmp_path / ".env").write_text(
        f"VITE_STRIPE_SECRET_KEY={FAKE_STRIPE_SECRET_KEY}\n",
        encoding="utf-8",
    )

    result = Scanner().scan(tmp_path, profile_ids=["vite-frontend"])

    assert result.summary.verdict is Verdict.NO_SHIP
    assert any(finding.rule_id == "frontend.public-secret-env" for finding in result.findings)


def test_firebase_profile_runs_public_frontend_secret_env_rule_for_public_known_secret_value(
    tmp_path: Path,
) -> None:
    (tmp_path / "firebase.json").write_text('{"hosting": {}}\n', encoding="utf-8")
    (tmp_path / ".env").write_text(
        f"NEXT_PUBLIC_API_KEY={FAKE_OPENAI_API_KEY}\n",
        encoding="utf-8",
    )

    result = Scanner().scan(tmp_path, profile_ids=["firebase"])

    assert result.summary.verdict is Verdict.NO_SHIP
    assert any(finding.rule_id == "frontend.public-secret-env" for finding in result.findings)


def test_frontend_public_secret_rule_runs_for_additional_frontend_profiles(tmp_path: Path) -> None:
    (tmp_path / "production.env").write_text(
        f"NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY={FAKE_SUPABASE_SERVICE_ROLE_KEY}\n",
        encoding="utf-8",
    )

    for profile_id in ("netlify-frontend", "supabase", "authjs", "clerk"):
        result = Scanner().scan(tmp_path, profile_ids=[profile_id])

        assert result.summary.verdict is Verdict.NO_SHIP
        assert any(finding.rule_id == "frontend.public-secret-env" for finding in result.findings)
