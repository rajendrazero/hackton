from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import ValidationError

from sentinel_x.reporting.models import AssessmentReport
from sentinel_x.safety.targets import default_state_dir


class ReportError(ValueError):
    """Raised when a report cannot be loaded, validated, or saved."""


def report_dir() -> Path:
    return default_state_dir() / "reports"


def save_report(report: AssessmentReport, directory: Path | None = None) -> Path:
    destination_dir = directory or report_dir()
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / f"{report.report_id}.json"
    temporary = destination.with_suffix(".json.tmp")
    try:
        temporary.write_text(
            report.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(destination)
    except OSError as exc:
        raise ReportError(f"could not save report {destination}: {exc}") from exc
    return destination


def load_report(report_id: str = "latest", directory: Path | None = None) -> AssessmentReport:
    source_dir = directory or report_dir()
    if report_id == "latest":
        candidates = list(source_dir.glob("*.json"))
        if not candidates:
            raise ReportError(f"no reports found in {source_dir}")
        source = max(candidates, key=lambda item: item.stat().st_mtime_ns)
    else:
        if re.fullmatch(r"[A-Fa-f0-9]{32}", report_id) is None:
            raise ReportError("report ID must be a 32-character hexadecimal ID")
        source = source_dir / f"{report_id}.json"

    try:
        raw = source.read_text(encoding="utf-8")
        return AssessmentReport.model_validate_json(raw)
    except FileNotFoundError as exc:
        raise ReportError(f"report {report_id!r} was not found") from exc
    except (OSError, UnicodeError, ValidationError, ValueError) as exc:
        if isinstance(exc, ValidationError):
            issues = "; ".join(
                f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
                for error in exc.errors(include_input=False)
            )
            raise ReportError(f"report failed schema validation: {issues}") from exc
        raise ReportError(f"could not validate report {source}: {exc}") from exc


def export_json(report: AssessmentReport, destination: Path | None = None) -> str:
    data = report.model_dump(mode="json")
    encoded = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if destination is not None:
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(encoded, encoding="utf-8")
        except OSError as exc:
            raise ReportError(f"could not export report to {destination}: {exc}") from exc
    return encoded


def export_markdown(report: AssessmentReport) -> str:
    lines = [
        f"# Sentinel X report {report.report_id}",
        "",
        f"- Checked at: {report.checked_at.isoformat()}",
        f"- Tool: {report.source_tool} ({report.source_version or 'version unknown'})",
        f"- Target: {report.target}",
        f"- Scope: {report.scope or report.target}",
        f"- Category: {report.category}",
        f"- Execution status: {report.execution_status}",
        f"- Exit code: {report.exit_code if report.exit_code is not None else 'n/a'}",
    ]
    if report.message:
        lines.extend(["", f"> {report.message}"])
    lines.extend(["", "## Findings"])
    if not report.findings:
        lines.extend(
            [
                "",
                (
                    "No findings were reported. This does not imply a failed or "
                    "unperformed assessment was clean."
                ),
            ]
        )
    for finding in report.findings:
        evidence = finding.evidence.replace("`", "\\`")
        lines.extend(
            [
                "",
                f"### {finding.finding_id}: {finding.description}",
                "",
                f"- Severity: {finding.severity or 'unknown'}",
                f"- Validation: {finding.validation_status}",
                f"- Evidence: `{evidence}`",
            ]
        )
        if finding.remediation:
            lines.append(f"- Remediation: {finding.remediation}")
        if finding.advisory_url:
            lines.append(f"- Advisory: {finding.advisory_url}")
    if report.metrics:
        lines.extend(["", "## Metrics", "", "```json"])
        lines.append(json.dumps(report.metrics, indent=2, ensure_ascii=False))
        lines.append("```")
    return "\n".join(lines) + "\n"
