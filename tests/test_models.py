from vibegate.models import Finding, ScanSummary, Severity, Verdict


def test_finding_requires_actionable_fields() -> None:
    finding = Finding(
        rule_id="secrets.env-file",
        title="Committed .env file",
        severity=Severity.HIGH,
        message=".env files often contain deploy tokens and bot credentials.",
        path=".env",
        remediation="Move secrets to the deployment provider and commit .env.example instead.",
    )

    assert finding.rule_id == "secrets.env-file"
    assert finding.severity is Severity.HIGH
    assert finding.path == ".env"


def test_scan_summary_counts_findings_by_severity_and_blocks_high_risk_shipping() -> None:
    findings = [
        Finding(
            rule_id="secrets.telegram-token",
            title="Telegram bot token exposed",
            severity=Severity.CRITICAL,
            message="A Telegram bot token appears in source code.",
        ),
        Finding(
            rule_id="docs.env-example-missing",
            title="Missing .env.example",
            severity=Severity.LOW,
            message="Project reads environment variables but does not document them.",
        ),
    ]

    summary = ScanSummary.from_findings(findings)

    assert summary.total == 2
    assert summary.counts[Severity.CRITICAL] == 1
    assert summary.counts[Severity.LOW] == 1
    assert summary.verdict is Verdict.NO_SHIP


def test_scan_summary_allows_shipping_when_high_finding_is_advisory() -> None:
    findings = [
        Finding(
            rule_id="runtime.latest-python",
            title="Runtime uses latest Python",
            severity=Severity.HIGH,
            message="Pinning a Python minor version improves deploy reproducibility.",
            blocking=False,
        )
    ]

    summary = ScanSummary.from_findings(findings)

    assert summary.verdict is Verdict.SHIP


def test_scan_summary_blocks_high_finding_by_default() -> None:
    findings = [
        Finding(
            rule_id="secrets.env-file",
            title="Committed .env file",
            severity=Severity.HIGH,
            message=".env files often contain deploy tokens and bot credentials.",
        )
    ]

    summary = ScanSummary.from_findings(findings)

    assert summary.verdict is Verdict.NO_SHIP


def test_finding_references_default_does_not_share_mutable_list() -> None:
    first = Finding(
        rule_id="runtime.latest-python",
        title="Runtime uses latest Python",
        severity=Severity.HIGH,
        message="Pinning a Python minor version improves deploy reproducibility.",
    )
    second = Finding(
        rule_id="docs.env-example-missing",
        title="Missing .env.example",
        severity=Severity.LOW,
        message="Project reads environment variables but does not document them.",
    )

    assert first.references == []
    assert second.references == []
    assert first.references is not second.references


def test_scan_summary_allows_shipping_when_only_low_or_info_findings_exist() -> None:
    findings = [
        Finding(
            rule_id="docs.env-example-missing",
            title="Missing .env.example",
            severity=Severity.LOW,
            message="Project reads environment variables but does not document them.",
        )
    ]

    summary = ScanSummary.from_findings(findings)

    assert summary.verdict is Verdict.SHIP
