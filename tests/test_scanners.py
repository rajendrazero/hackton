from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from sentinel_x.adapters import scanners
from sentinel_x.adapters.process import ProcessResult
from sentinel_x.safety.targets import TargetError
from sentinel_x.tools.discovery import ToolInfo, ToolStatus

FIXTURES = Path(__file__).parent / "fixtures"
AVAILABLE_OSV = ToolInfo(
    name="OSV-Scanner",
    status=ToolStatus.AVAILABLE,
    executable="osv-scanner.exe",
    version="2.0.0",
)
AVAILABLE_SEMGREP = ToolInfo(
    name="Semgrep",
    status=ToolStatus.AVAILABLE,
    executable="semgrep.exe",
    version="1.100.0",
)


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("kind", "fixture", "expected_tool", "expected_status"),
    [
        ("dependencies", "osv_findings.json", AVAILABLE_OSV, "findings"),
        ("code", "semgrep_findings.json", AVAILABLE_SEMGREP, "findings"),
    ],
)
def test_scanner_adapters_parse_fixture_and_pass_safe_argv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: scanners.ScanKind,
    fixture: str,
    expected_tool: ToolInfo,
    expected_status: str,
) -> None:
    (tmp_path / "sample.py").write_text("print('sample')\n", encoding="utf-8")
    monkeypatch.setattr(scanners, "check_tool", lambda _: expected_tool)
    command: dict[str, Any] = {}

    def fake_popen(argv: list[str], **kwargs: Any) -> Any:
        command["argv"] = argv
        command.update(kwargs)

        class Process:
            returncode = 0

            def __init__(self) -> None:
                self.stdout = BytesIO(read_fixture(fixture).encode("utf-8"))
                self.stderr = BytesIO(b"")

            def poll(self) -> int:
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                return self.returncode

        return Process()

    monkeypatch.setattr("sentinel_x.adapters.process.subprocess.Popen", fake_popen)

    result = scanners.run_scan(kind, tmp_path)

    assert result.execution_status == expected_status
    assert len(result.findings) >= 1
    assert command["shell"] is False
    assert command["argv"][-1] == str(tmp_path.resolve())
    assert result.source_version == expected_tool.version
    if kind == "dependencies":
        assert command["argv"][1:6] == [
            "--offline",
            "scan",
            "source",
            "--format",
            "json",
        ]
    else:
        assert command["argv"][1:4] == ["scan", "--json", "--metrics=off"]


def test_osv_clean_fixture_is_distinct_from_failures() -> None:
    findings = scanners.parse_osv_output(read_fixture("osv_clean.json"), "project", "2.0")

    assert findings == []


def test_semgrep_evidence_redacts_sensitive_values() -> None:
    findings = scanners.parse_semgrep_output(
        read_fixture("semgrep_findings.json"), "project", "1.100.0"
    )
    evidence = "\n".join(finding.evidence for finding in findings)
    descriptions = "\n".join(finding.description for finding in findings)

    assert "do-not-leak" not in evidence
    assert "hidden@example.test" not in descriptions
    assert "[REDACTED" in evidence + descriptions


def test_nonzero_exit_with_structured_findings_remains_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "requirements.txt").write_text("demo==1\n", encoding="utf-8")
    monkeypatch.setattr(scanners, "check_tool", lambda _: AVAILABLE_OSV)
    monkeypatch.setattr(
        scanners,
        "run_process",
        lambda *args, **kwargs: ProcessResult(
            returncode=1, stdout=read_fixture("osv_findings.json"), stderr="advisory found"
        ),
    )

    report = scanners.run_scan("dependencies", tmp_path)

    assert report.execution_status == "findings"
    assert report.exit_code == 1
    assert report.message is not None


def test_nonzero_exit_without_findings_is_tool_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "requirements.txt").write_text("demo==1\n", encoding="utf-8")
    monkeypatch.setattr(scanners, "check_tool", lambda _: AVAILABLE_OSV)
    monkeypatch.setattr(
        scanners,
        "run_process",
        lambda *args, **kwargs: ProcessResult(
            returncode=7, stdout=json.dumps({"results": []}), stderr="network failure"
        ),
    )

    report = scanners.run_scan("dependencies", tmp_path)

    assert report.execution_status == "tool_error"
    assert report.exit_code == 7
    assert "network failure" in (report.message or "")


def test_missing_scanner_is_not_reported_as_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "requirements.txt").write_text("demo==1\n", encoding="utf-8")
    monkeypatch.setattr(
        scanners,
        "check_tool",
        lambda _: ToolInfo(
            name="OSV-Scanner",
            status=ToolStatus.NOT_FOUND,
            details="install OSV-Scanner",
        ),
    )
    monkeypatch.setattr(
        scanners,
        "run_process",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("tool must not run")),
    )

    report = scanners.run_scan("dependencies", tmp_path)

    assert report.execution_status == "not_installed"


def test_invalid_structured_output_is_a_tool_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "requirements.txt").write_text("demo==1\n", encoding="utf-8")
    monkeypatch.setattr(scanners, "check_tool", lambda _: AVAILABLE_OSV)
    monkeypatch.setattr(
        scanners,
        "run_process",
        lambda *args, **kwargs: ProcessResult(returncode=0, stdout="not json", stderr=""),
    )

    report = scanners.run_scan("dependencies", tmp_path)

    assert report.execution_status == "tool_error"
    assert "parse" in (report.message or "")


def test_semgrep_json_errors_are_not_clean_even_when_exit_code_is_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "sample.py").write_text("pass\n", encoding="utf-8")
    monkeypatch.setattr(scanners, "check_tool", lambda _: AVAILABLE_SEMGREP)
    output = json.dumps({"results": [], "errors": [{"message": "parse failure"}]})
    monkeypatch.setattr(
        scanners,
        "run_process",
        lambda *args, **kwargs: ProcessResult(returncode=0, stdout=output, stderr=""),
    )

    report = scanners.run_scan("code", tmp_path)

    assert report.execution_status == "tool_error"
    assert "scanner errors" in (report.message or "")


def test_semgrep_nonzero_exit_preserves_findings_but_is_tool_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "sample.py").write_text("pass\n", encoding="utf-8")
    monkeypatch.setattr(scanners, "check_tool", lambda _: AVAILABLE_SEMGREP)
    monkeypatch.setattr(
        scanners,
        "run_process",
        lambda *args, **kwargs: ProcessResult(
            returncode=2,
            stdout=read_fixture("semgrep_findings.json"),
            stderr="scanner failed after output",
        ),
    )

    report = scanners.run_scan("code", tmp_path)

    assert report.execution_status == "tool_error"
    assert len(report.findings) == 2
    assert report.exit_code == 2


def test_scan_scope_rejects_filesystem_root() -> None:
    with pytest.raises(TargetError, match="filesystem root"):
        scanners.validate_scan_path(Path(Path.cwd().anchor))


def test_scan_scope_applies_file_count_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "one.txt").write_text("1", encoding="utf-8")
    (tmp_path / "two.txt").write_text("2", encoding="utf-8")
    monkeypatch.setattr(scanners, "MAX_SCAN_FILES", 1)

    with pytest.raises(TargetError, match="file limit"):
        scanners.validate_scan_path(tmp_path)
