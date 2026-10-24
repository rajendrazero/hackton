from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinel_x.cli import app
from sentinel_x.reporting.models import AssessmentReport
from sentinel_x.reporting.store import save_report
from sentinel_x.safety.targets import (
    add_target,
    get_target,
    set_active_scan_authorization,
)
from sentinel_x.tools.discovery import ToolInfo, ToolStatus

runner = CliRunner()


def test_tools_list_shows_missing_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sentinel_x.cli.discover_tools",
        lambda: (
            ToolInfo(
                "Grafana k6",
                ToolStatus.AVAILABLE,
                executable="C:\\tools\\k6.exe",
                version="v2.2.0",
            ),
            ToolInfo(
                "Semgrep",
                ToolStatus.NOT_FOUND,
                details="install Semgrep",
            ),
        ),
    )

    result = runner.invoke(app, ["tools", "list"])

    assert result.exit_code == 0
    assert "available" in result.stdout
    assert "not_found" in result.stdout
    assert "C:\\tools\\k6.exe" in result.stdout


def test_tools_check_uses_nonzero_exit_for_unavailable_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sentinel_x.cli.discover_tools",
        lambda: (
            ToolInfo("Nuclei", ToolStatus.VERSION_CHECK_FAILED, details="timeout"),
        ),
    )

    result = runner.invoke(app, ["tools", "check"])

    assert result.exit_code == 1
    assert "version_check_failed" in result.stdout


def test_target_add_rejects_external_host_and_registers_loopback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))

    denied = runner.invoke(app, ["target", "add", "external", "https://example.com"])
    accepted = runner.invoke(app, ["target", "add", "local", "http://localhost:8000"])
    shown = runner.invoke(app, ["target", "show", "local"])

    assert denied.exit_code == 2
    assert accepted.exit_code == 0
    assert "active testing is not authorized" in accepted.stdout
    assert shown.exit_code == 0
    assert "not authorized" in shown.stdout


def test_target_authorization_requires_explicit_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    add_target("local", "http://127.0.0.1:8080")

    declined = runner.invoke(app, ["target", "authorize", "local"], input="n\n")
    confirmed = runner.invoke(app, ["target", "authorize", "local"], input="y\n")

    assert declined.exit_code == 1
    assert get_target("local").active_scan_authorized is True
    assert get_target("local").active_scan_authorized_at is not None
    assert confirmed.exit_code == 0
    assert "Active tests authorized" in confirmed.stdout


def test_rate_limit_test_prompts_before_running_k6(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    add_target("local", "http://127.0.0.1:8000")
    set_active_scan_authorization("local", True)
    monkeypatch.setattr(
        "sentinel_x.cli.run_k6",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("declined test must not execute k6")
        ),
    )

    result = runner.invoke(app, ["ratelimit", "test", "local"], input="n\n")

    assert result.exit_code == 1
    assert "maximum VUs: 5" in result.stdout
    assert "Test cancelled" in result.stdout


def test_report_export_json_writes_validated_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    report = AssessmentReport(
        source_tool="OSV-Scanner",
        target="project",
        category="dependencies",
        execution_status="clean",
    )
    save_report(report)
    destination = tmp_path / "exports" / "latest.json"

    result = runner.invoke(
        app,
        ["report", "export", report.report_id, "--format", "json", "--output", str(destination)],
    )

    assert result.exit_code == 0
    assert json.loads(destination.read_text(encoding="utf-8"))["execution_status"] == "clean"
