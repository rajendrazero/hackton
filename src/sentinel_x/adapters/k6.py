from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Literal

from sentinel_x.adapters.process import run_process
from sentinel_x.redaction import redact
from sentinel_x.reporting.models import AssessmentReport
from sentinel_x.safety.targets import TargetError, TargetRecord, normalize_loopback_url
from sentinel_x.tools.discovery import TOOL_SPECS, ToolStatus, check_tool

LoadProfile = Literal["smoke", "gradual"]
MAX_VUS = 10
MAX_DURATION_SECONDS = 120
MAX_REQUESTS_PER_SECOND = 10
PROCESS_TIMEOUT_SECONDS = 180
MAX_SUMMARY_BYTES = 5 * 1024 * 1024


def validate_load_profile(
    profile: LoadProfile,
    max_vus: int | None,
    duration_seconds: int,
    requests_per_second: int,
) -> tuple[int, list[dict[str, int]]]:
    if profile == "smoke":
        if max_vus not in (None, 5):
            raise TargetError("smoke profile has a fixed maximum of 5 VUs")
        if duration_seconds not in (30,):
            raise TargetError("smoke profile has a fixed duration of 30 seconds")
        vus = 5
        stages = [
            {"duration": 10, "target": 1},
            {"duration": 10, "target": 5},
            {"duration": 10, "target": 0},
        ]
    else:
        if max_vus is None or not 1 <= max_vus <= MAX_VUS:
            raise TargetError(
                f"gradual profile requires --max-vus between 1 and {MAX_VUS}"
            )
        if not 30 <= duration_seconds <= MAX_DURATION_SECONDS:
            raise TargetError(
                f"gradual duration must be between 30 and {MAX_DURATION_SECONDS} seconds"
            )
        vus = max_vus
        ramp = duration_seconds // 3
        hold = duration_seconds // 3
        down = duration_seconds - ramp - hold
        stages = [
            {"duration": ramp, "target": vus},
            {"duration": hold, "target": vus},
            {"duration": down, "target": 0},
        ]
    if not 1 <= requests_per_second <= MAX_REQUESTS_PER_SECOND:
        raise TargetError(
            f"request rate must be between 1 and {MAX_REQUESTS_PER_SECOND} per second"
        )
    return vus, stages


def build_k6_script(url: str, stages: list[dict[str, int]]) -> str:
    if not stages or any(
        stage["duration"] < 1
        or not 0 <= stage["target"] <= MAX_VUS
        for stage in stages
    ):
        raise TargetError(f"k6 stages must stay within 0..{MAX_VUS} VUs")
    if sum(stage["duration"] for stage in stages) > MAX_DURATION_SECONDS:
        raise TargetError(
            f"k6 stages cannot exceed {MAX_DURATION_SECONDS} seconds in total"
        )
    safe_url = json.dumps(normalize_loopback_url(url))
    safe_stages = json.dumps(
        [{"duration": f"{stage['duration']}s", "target": stage["target"]} for stage in stages]
    )
    return (
        "import http from 'k6/http';\n"
        "import { Counter } from 'k6/metrics';\n"
        "import { sleep } from 'k6';\n"
        f"const targetUrl = {safe_url};\n"
        "const statuses = new Counter('sentinel_http_status');\n"
        "const requestTimeouts = new Counter('sentinel_request_timeouts');\n"
        "export const options = {\n"
        "  discardResponseBodies: true,\n"
        "  maxRedirects: 0,\n"
        "  hosts: { localhost: '127.0.0.1' },\n"
        "  summaryTrendStats: ['med', 'p(90)', 'p(95)', 'p(99)'],\n"
        "  scenarios: {\n"
        "    default: {\n"
        "      executor: 'ramping-vus',\n"
        "      startVUs: 0,\n"
        "      gracefulStop: '0s',\n"
        "      gracefulRampDown: '0s',\n"
        f"      stages: {safe_stages},\n"
        "    },\n"
        "  },\n"
        "};\n"
        "export default function () {\n"
        "  const response = http.get(targetUrl, { timeout: '5s' });\n"
        "  statuses.add(1, { status: String(response.status) });\n"
        "  if (response.error && /timeout/i.test(response.error)) {\n"
        "    requestTimeouts.add(1);\n"
        "  }\n"
        "  sleep(1);\n"
        "}\n"
        "export function handleSummary(data) {\n"
        "  return { 'summary.json': JSON.stringify(data) };\n"
        "}\n"
    )


def _metric_count(metric: Any) -> float:
    if not isinstance(metric, dict):
        return 0.0
    values = metric.get("values", {})
    if not isinstance(values, dict):
        return 0.0
    try:
        return float(values.get("count", 0))
    except (TypeError, ValueError):
        return 0.0


def normalize_k6_summary(summary: dict[str, Any]) -> dict[str, Any]:
    metrics = summary.get("metrics", {})
    if not isinstance(metrics, dict):
        raise TypeError("k6 summary metrics must be an object")
    duration = metrics.get("http_req_duration", {})
    duration_values = duration.get("values", {}) if isinstance(duration, dict) else {}
    request_rate = metrics.get("http_reqs", {})
    request_values = (
        request_rate.get("values", {}) if isinstance(request_rate, dict) else {}
    )
    failed = metrics.get("http_req_failed", {})
    failed_values = failed.get("values", {}) if isinstance(failed, dict) else {}

    status_counts: dict[str, int] = {}
    for name, metric in metrics.items():
        if not isinstance(name, str) or not name.startswith(
            "sentinel_http_status{status:"
        ):
            continue
        status = name.removeprefix("sentinel_http_status{status:").removesuffix("}")
        status_counts[status] = int(_metric_count(metric))
    request_timeouts = int(_metric_count(metrics.get("sentinel_request_timeouts")))
    def get_number(values: Any, key: str) -> float | None:
        if not isinstance(values, dict) or values.get(key) is None:
            return None
        try:
            return float(values[key])
        except (TypeError, ValueError):
            return None

    return {
        "latency_ms": {
            "p50": get_number(duration_values, "med")
            or get_number(duration_values, "p(50)"),
            "p90": get_number(duration_values, "p(90)"),
            "p95": get_number(duration_values, "p(95)"),
            "p99": get_number(duration_values, "p(99)"),
        },
        "throughput_requests_per_second": get_number(request_values, "rate"),
        "request_count": int(_metric_count(request_rate)),
        "request_error_percent": (
            (get_number(failed_values, "rate") or 0.0) * 100
            if isinstance(failed_values, dict) and "rate" in failed_values
            else None
        ),
        "http_429_count": status_counts.get("429", 0),
        "http_status_counts": status_counts,
        "request_timeout_count": request_timeouts,
    }


def run_k6(
    target: TargetRecord,
    *,
    profile: LoadProfile,
    max_vus: int | None = None,
    duration_seconds: int = 30,
    requests_per_second: int = 5,
) -> AssessmentReport:
    if not target.active_scan_authorized:
        raise TargetError(
            f"target {target.name!r} is registered but not authorized for active tests; "
            "use 'sentinel target authorize' after confirming ownership"
        )
    url = normalize_loopback_url(target.url)
    vus, stages = validate_load_profile(
        profile, max_vus, duration_seconds, requests_per_second
    )
    tool = check_tool(TOOL_SPECS[4])
    if tool.status != ToolStatus.AVAILABLE or tool.executable is None:
        return AssessmentReport(
            source_tool=tool.name,
            source_version=tool.version,
            target=target.name,
            scope=url,
            category="rate_limit",
            execution_status="not_installed",
            message=tool.details or "k6 was not found or failed its version check",
        )

    script = build_k6_script(url, stages)
    with tempfile.TemporaryDirectory(prefix="sentinel-k6-") as temporary:
        workdir = Path(temporary)
        script_path = workdir / "sentinel_test.js"
        config_path = workdir / "k6_config.json"
        summary_path = workdir / "summary.json"
        script_path.write_text(script, encoding="utf-8")
        config_path.write_text("{}\n", encoding="utf-8")
        child_env = {
            key: value
            for key, value in os.environ.items()
            if not key.casefold().startswith("k6_")
            and key.casefold()
            not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
        }
        process = run_process(
            [
                tool.executable,
                f"--config={config_path}",
                "run",
                f"--rps={requests_per_second}",
                "--max-redirects=0",
                "--no-usage-report",
                "--quiet",
                str(script_path),
            ],
            timeout=PROCESS_TIMEOUT_SECONDS,
            cwd=str(workdir),
            env=child_env,
        )
        if process.cancelled:
            return AssessmentReport(
                source_tool=tool.name,
                source_version=tool.version,
                target=target.name,
                scope=url,
                category="rate_limit",
                execution_status="cancelled",
                exit_code=process.returncode,
                message=process.error or "k6 test cancelled by user",
            )
        if process.timed_out:
            return AssessmentReport(
                source_tool=tool.name,
                source_version=tool.version,
                target=target.name,
                scope=url,
                category="rate_limit",
                execution_status="timeout",
                exit_code=process.returncode,
                message=process.error,
            )
        if process.error:
            return AssessmentReport(
                source_tool=tool.name,
                source_version=tool.version,
                target=target.name,
                scope=url,
                category="rate_limit",
                execution_status="tool_error",
                exit_code=process.returncode,
                message=process.error,
            )
        if process.returncode != 0:
            return AssessmentReport(
                source_tool=tool.name,
                source_version=tool.version,
                target=target.name,
                scope=url,
                category="rate_limit",
                execution_status="tool_error",
                exit_code=process.returncode,
                message=redact(
                    process.stderr or f"k6 exited with status {process.returncode}"
                ),
            )
        if not summary_path.is_file() or summary_path.stat().st_size > MAX_SUMMARY_BYTES:
            return AssessmentReport(
                source_tool=tool.name,
                source_version=tool.version,
                target=target.name,
                scope=url,
                category="rate_limit",
                execution_status="tool_error",
                exit_code=process.returncode,
                message="k6 did not create a bounded JSON summary artifact",
            )
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            metrics = normalize_k6_summary(summary)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            return AssessmentReport(
                source_tool=tool.name,
                source_version=tool.version,
                target=target.name,
                scope=url,
                category="rate_limit",
                execution_status="tool_error",
                exit_code=process.returncode,
                message=redact(f"could not parse k6 summary: {exc}"),
            )

    return AssessmentReport(
        source_tool=tool.name,
        source_version=tool.version,
        target=target.name,
        category="rate_limit",
        execution_status="completed",
        exit_code=process.returncode,
        message=(
            "Rate-limit test completed; inspect response status, success/error ratio, "
            "latency, and timeouts before drawing conclusions."
        ),
        metrics={
            "profile": profile,
            "max_vus": vus,
            "duration_seconds": sum(stage["duration"] for stage in stages),
            "request_rate_cap_per_second": requests_per_second,
            "request_budget_upper_bound": (
                vus * sum(stage["duration"] for stage in stages)
            ),
            **metrics,
        },
    )
