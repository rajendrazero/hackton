from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel_x.reporting.models import AssessmentReport, Finding
from sentinel_x.reporting.store import (
    ReportError,
    export_json,
    export_markdown,
    load_report,
    save_report,
)


def test_report_requires_findings_status_to_have_evidence() -> None:
    with pytest.raises(ValidationError, match="must contain at least one finding"):
        AssessmentReport(
            source_tool="Semgrep",
            target="project",
            category="code",
            execution_status="findings",
        )


def test_clean_status_cannot_contain_findings() -> None:
    finding = Finding(
        source_tool="Semgrep",
        target="project",
        category="code",
        description="A finding",
        evidence="line 1",
    )

    with pytest.raises(ValidationError, match="cannot contain findings"):
        AssessmentReport(
            source_tool="Semgrep",
            target="project",
            category="code",
            execution_status="clean",
            findings=[finding],
        )


def test_json_report_round_trip_and_markdown_export(tmp_path: Path) -> None:
    report = AssessmentReport(
        source_tool="OSV-Scanner",
        source_version="2.0.0",
        target="project",
        category="dependencies",
        execution_status="findings",
        exit_code=1,
        findings=[
            Finding(
                source_tool="OSV-Scanner",
                target="project",
                category="vulnerable_dependency",
                severity="HIGH",
                description="GHSA-test affects demo@1.0",
                evidence="GHSA-test; token=[REDACTED]",
                remediation="Upgrade the affected package.",
                advisory_url="https://osv.dev/vulnerability/GHSA-test",
            )
        ],
    )

    path = save_report(report, tmp_path)
    loaded = load_report(report.report_id, tmp_path)
    exported = export_json(loaded)
    markdown = export_markdown(loaded)

    assert path.exists()
    assert loaded.report_id == report.report_id
    assert '"execution_status": "findings"' in exported
    assert "GHSA-test" in markdown
    assert "token=[REDACTED]" in markdown


def test_latest_report_rejects_invalid_json(tmp_path: Path) -> None:
    (tmp_path / "bad.json").write_text('{"unexpected": true}', encoding="utf-8")

    with pytest.raises(ReportError, match="schema validation"):
        load_report(directory=tmp_path)


def test_schema_error_does_not_echo_sensitive_report_values(tmp_path: Path) -> None:
    report_id = "a" * 32
    (tmp_path / f"{report_id}.json").write_text(
        '{"report_id":"' + report_id + '","source_tool":"test",'
        '"target":"project","category":"test","execution_status":"unknown",'
        '"message":"password: super-secret"}',
        encoding="utf-8",
    )

    with pytest.raises(ReportError) as error:
        load_report(report_id, tmp_path)

    assert "super-secret" not in str(error.value)


def test_report_id_is_path_safe(tmp_path: Path) -> None:
    with pytest.raises(ReportError, match="32-character"):
        load_report("..\\secret", tmp_path)


def test_report_schema_redacts_sensitive_fields_and_metrics() -> None:
    report = AssessmentReport(
        source_tool="Semgrep",
        target="project",
        category="code",
        execution_status="completed",
        message="Authorization: Bearer super-secret",
        metrics={"contact": "owner@example.test", "cookie": "session=abc123"},
    )

    assert "super-secret" not in (report.message or "")
    assert report.metrics == {
        "contact": "[REDACTED_EMAIL]",
        "cookie": "[REDACTED]",
    }
