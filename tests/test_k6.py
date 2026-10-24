from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sentinel_x.adapters import k6
from sentinel_x.adapters.process import ProcessResult
from sentinel_x.safety.targets import TargetError, TargetRecord
from sentinel_x.tools.discovery import ToolInfo, ToolStatus

SUMMARY = Path(__file__).parent / "fixtures" / "k6_summary.json"
K6_TOOL = ToolInfo(
    name="Grafana k6",
    status=ToolStatus.AVAILABLE,
    executable="k6.exe",
    version="v2.2.0",
)


def make_target(authorized: bool = True) -> TargetRecord:
    return TargetRecord(
        name="local-api",
        url="http://127.0.0.1:8080",
        registered_at=datetime.now(UTC),
        active_scan_authorized=authorized,
        active_scan_authorized_at=datetime.now(UTC) if authorized else None,
    )


def test_smoke_profile_has_low_fixed_bounds() -> None:
    max_vus, stages = k6.validate_load_profile("smoke", None, 30, 5)

    assert max_vus == 5
    assert sum(stage["duration"] for stage in stages) == 30
    assert max(stage["target"] for stage in stages) == 5


def test_gradual_profile_requires_explicit_bounded_vus() -> None:
    with pytest.raises(TargetError, match="requires --max-vus"):
        k6.validate_load_profile("gradual", None, 60, 5)
    with pytest.raises(TargetError, match="between 1 and 10"):
        k6.validate_load_profile("gradual", 11, 60, 5)
    with pytest.raises(TargetError, match="request rate"):
        k6.validate_load_profile("gradual", 5, 60, 11)


def test_k6_script_disables_redirects_and_quotes_target() -> None:
    malicious_path = "http://localhost/a%22%3Bhttp.get(%22https://example.test%22)"
    script = k6.build_k6_script(malicious_path, [{"duration": 10, "target": 1}])

    assert "maxRedirects: 0" in script
    assert "discardResponseBodies: true" in script
    assert "localhost: '127.0.0.1'" in script
    assert "summaryTrendStats: ['med', 'p(90)', 'p(95)', 'p(99)']" in script
    assert "executor: 'ramping-vus'" in script
    assert "gracefulStop: '0s'" in script
    assert "gracefulRampDown: '0s'" in script
    assert '"target": 1' in script
    assert "response.error" in script
    target_line = next(line for line in script.splitlines() if line.startswith("const targetUrl"))
    assert target_line.endswith(";")
    assert target_line.count('"') == 2
    assert "%22%3B" in target_line


def test_normalizes_k6_summary_fixture() -> None:
    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))

    metrics = k6.normalize_k6_summary(summary)

    assert metrics["latency_ms"] == {"p50": 34.5, "p90": 55.0, "p95": 72.0, "p99": 99.0}
    assert metrics["throughput_requests_per_second"] == 2.5
    assert metrics["request_count"] == 10
    assert metrics["http_429_count"] == 1
    assert metrics["request_timeout_count"] == 0
    assert metrics["request_error_percent"] == 10.0


def test_k6_adapter_uses_mocked_process_and_saves_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(k6, "check_tool", lambda _: K6_TOOL)
    invocation: dict[str, Any] = {}

    def fake_process(
        argv: list[str],
        *,
        timeout: float,
        cwd: str | None = None,
        env: Any = None,
    ) -> ProcessResult:
        invocation["argv"] = argv
        invocation["timeout"] = timeout
        invocation["env"] = env
        assert cwd is not None
        script = (Path(cwd) / "sentinel_test.js").read_text(encoding="utf-8")
        assert "maxRedirects: 0" in script
        (Path(cwd) / "summary.json").write_text(
            SUMMARY.read_text(encoding="utf-8"), encoding="utf-8"
        )
        return ProcessResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(k6, "run_process", fake_process)

    report = k6.run_k6(
        make_target(),
        profile="smoke",
        requests_per_second=3,
    )

    assert report.execution_status == "completed"
    assert report.metrics is not None
    assert report.metrics["request_rate_cap_per_second"] == 3
    assert report.metrics["request_budget_upper_bound"] == 150
    assert report.metrics["http_429_count"] == 1
    assert invocation["argv"][2:7] == [
        "run",
        "--rps=3",
        "--max-redirects=0",
        "--no-usage-report",
        "--quiet",
    ]
    assert not any(
        key.casefold().startswith("k6_") or key.casefold() in {
            "http_proxy", "https_proxy", "all_proxy", "no_proxy"
        }
        for key in invocation["env"]
    )
    assert invocation["timeout"] <= 180


def test_k6_adapter_rejects_unauthorized_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        k6, "check_tool", lambda _: (_ for _ in ()).throw(AssertionError("must not check"))
    )

    with pytest.raises(TargetError, match="not authorized"):
        k6.run_k6(make_target(False), profile="smoke")


def test_k6_process_failure_is_not_a_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(k6, "check_tool", lambda _: K6_TOOL)
    monkeypatch.setattr(
        k6,
        "run_process",
        lambda *args, **kwargs: ProcessResult(
            returncode=99, stdout="", stderr="test interrupted"
        ),
    )

    report = k6.run_k6(make_target(), profile="smoke")

    assert report.execution_status == "tool_error"
    assert report.exit_code == 99


def test_k6_timeout_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(k6, "check_tool", lambda _: K6_TOOL)
    monkeypatch.setattr(
        k6,
        "run_process",
        lambda *args, **kwargs: ProcessResult(
            returncode=-15,
            stdout="",
            stderr="",
            error="process exceeded timeout",
            timed_out=True,
        ),
    )

    report = k6.run_k6(make_target(), profile="smoke")

    assert report.execution_status == "timeout"
