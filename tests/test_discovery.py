from __future__ import annotations

from typing import Any

import pytest

from sentinel_x.adapters.process import ProcessResult
from sentinel_x.tools.discovery import (
    ToolSpec,
    ToolStatus,
    check_tool,
    discover_tools,
)

SPEC = ToolSpec(
    name="Example",
    executables=("example.exe",),
    version_args=("--version",),
    documentation="https://example.test/docs",
)


def test_available_tool_reports_version_and_location(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sentinel_x.tools.discovery.shutil.which", lambda _: "C:\\tools\\example.exe")
    monkeypatch.setattr(
        "sentinel_x.tools.discovery.run_process",
        lambda *args, **kwargs: ProcessResult(
            0, stdout="Example 1.2.3\n", stderr=""
        ),
    )

    result = check_tool(SPEC)

    assert result.status is ToolStatus.AVAILABLE
    assert result.version == "Example 1.2.3"
    assert result.executable == "C:\\tools\\example.exe"


def test_missing_tool_does_not_run_version_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sentinel_x.tools.discovery.shutil.which", lambda _: None)
    monkeypatch.setattr(
        "sentinel_x.tools.discovery.run_process",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected run")),
    )

    result = check_tool(SPEC)

    assert result.status is ToolStatus.NOT_FOUND
    assert "not found" in (result.details or "")


def test_version_timeout_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sentinel_x.tools.discovery.shutil.which", lambda _: "example.exe")

    monkeypatch.setattr(
        "sentinel_x.tools.discovery.run_process",
        lambda *args, **kwargs: ProcessResult(
            returncode=-15,
            stdout="",
            stderr="",
            error="process exceeded timeout",
            timed_out=True,
        ),
    )

    result = check_tool(SPEC, timeout=0.25)

    assert result.status is ToolStatus.VERSION_CHECK_FAILED
    assert "0.25s" in (result.details or "")


def test_nonzero_or_empty_version_output_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sentinel_x.tools.discovery.shutil.which", lambda _: "example.exe")
    monkeypatch.setattr(
        "sentinel_x.tools.discovery.run_process",
        lambda *args, **kwargs: ProcessResult(
            7, stdout="", stderr="version command failed"
        ),
    )

    result = check_tool(SPEC)

    assert result.status is ToolStatus.VERSION_CHECK_FAILED
    assert "status 7" in (result.details or "")
    assert "version command failed" in (result.details or "")


def test_one_version_timeout_does_not_stop_other_tool_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sentinel_x.tools.discovery.shutil.which",
        lambda executable: f"C:\\tools\\{executable}",
    )

    def fake_version(argv: list[str], **kwargs: Any) -> ProcessResult:
        if "nuclei.exe" in argv[0]:
            return ProcessResult(
                -15,
                stdout="",
                stderr="",
                error="process exceeded timeout",
                timed_out=True,
            )
        return ProcessResult(0, stdout=f"{argv[0]} v1.0\n", stderr="")

    monkeypatch.setattr("sentinel_x.tools.discovery.run_process", fake_version)

    results = discover_tools()

    assert len(results) == 5
    assert results[1].status is ToolStatus.VERSION_CHECK_FAILED
    assert results[4].status is ToolStatus.AVAILABLE
