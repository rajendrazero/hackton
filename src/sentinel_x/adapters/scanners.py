from __future__ import annotations

import json
import os
import re
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from sentinel_x.adapters.process import ProcessResult, run_process
from sentinel_x.redaction import redact
from sentinel_x.reporting.models import AssessmentReport, Finding
from sentinel_x.safety.targets import TargetError
from sentinel_x.tools.discovery import TOOL_SPECS, ToolInfo, ToolStatus, check_tool

ScanKind = Literal["dependencies", "code"]
MAX_SCAN_FILES = 25_000
MAX_SCAN_BYTES = 512 * 1024 * 1024
EXCLUDED_DIRS = {".git", ".venv", "venv", "node_modules", "build", "dist"}


def _scan_scope(path: Path) -> str:
    target = path.name or str(path)
    if path.is_file():
        return f"local file: {target}"
    return (
        f"local directory; max {MAX_SCAN_FILES:,} files / "
        f"{MAX_SCAN_BYTES // (1024 * 1024)} MiB; excludes "
        + ", ".join(sorted(EXCLUDED_DIRS))
    )


def _is_link_or_junction(path: Path) -> bool:
    junction_check = getattr(path, "is_junction", None)
    return path.is_symlink() or (callable(junction_check) and junction_check())


def validate_scan_path(value: str | Path) -> Path:
    requested_path = Path(value).expanduser()
    if _is_link_or_junction(requested_path):
        raise TargetError("symbolic-link and junction scan paths are not allowed")
    try:
        path = requested_path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise TargetError(f"scan path does not exist or cannot be resolved: {exc}") from exc
    if not path.is_file() and not path.is_dir():
        raise TargetError("scan path must be a regular file or directory")
    if path.parent == path:
        raise TargetError("scanning a filesystem root is not allowed")

    file_count = 0
    total_bytes = 0
    if path.is_file():
        file_count = 1
        total_bytes = path.stat().st_size
    else:
        for current, directories, filenames in os.walk(path, followlinks=False):
            directories[:] = [
                name
                for name in directories
                if name.casefold() not in EXCLUDED_DIRS
                and not _is_link_or_junction(Path(current) / name)
            ]
            for filename in filenames:
                file_path = Path(current) / filename
                if _is_link_or_junction(file_path):
                    continue
                try:
                    total_bytes += file_path.stat().st_size
                except OSError as exc:
                    raise TargetError(f"cannot inspect scan file {file_path}: {exc}") from exc
                file_count += 1
                if file_count > MAX_SCAN_FILES:
                    raise TargetError(
                        f"scan scope exceeds the {MAX_SCAN_FILES:,}-file limit"
                    )
                if total_bytes > MAX_SCAN_BYTES:
                    raise TargetError(
                        f"scan scope exceeds the {MAX_SCAN_BYTES // (1024 * 1024)} MiB limit"
                    )
    if file_count > MAX_SCAN_FILES:
        raise TargetError(f"scan scope exceeds the {MAX_SCAN_FILES:,}-file limit")
    if total_bytes > MAX_SCAN_BYTES:
        raise TargetError(
            f"scan scope exceeds the {MAX_SCAN_BYTES // (1024 * 1024)} MiB limit"
        )
    return path


def _finding_id(tool: str, target: str, key: str) -> str:
    digest = sha256(f"{tool}\0{target}\0{key}".encode()).hexdigest()
    return digest[:16]


def _as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def parse_osv_output(output: str, target: str, version: str | None) -> list[Finding]:
    document = json.loads(output)
    if not isinstance(document, dict) or not isinstance(document.get("results"), list):
        raise TypeError("OSV-Scanner JSON must contain a results array")
    findings: list[Finding] = []
    for result in document["results"]:
        if not isinstance(result, dict):
            raise TypeError("OSV-Scanner result entries must be objects")
        result_data = result
        packages = result_data.get("packages")
        if not isinstance(packages, list):
            raise TypeError("OSV-Scanner result packages must be an array")
        for package_entry in packages:
            if not isinstance(package_entry, dict):
                raise TypeError("OSV-Scanner package entries must be objects")
            package_data = package_entry
            package = package_data.get("package")
            if not isinstance(package, dict):
                raise TypeError("OSV-Scanner package metadata must be an object")
            vulnerabilities = package_data.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                raise TypeError("OSV-Scanner vulnerabilities must be an array")
            for vulnerability_entry in vulnerabilities:
                if not isinstance(vulnerability_entry, dict):
                    raise TypeError("OSV-Scanner vulnerability entries must be objects")
                vulnerability = vulnerability_entry
                raw_advisory_id = vulnerability.get("id")
                if not isinstance(raw_advisory_id, str) or not raw_advisory_id:
                    raise TypeError("OSV-Scanner vulnerability IDs must be non-empty strings")
                advisory_id = (
                    re.sub(
                        r"[^A-Za-z0-9._-]",
                        "_",
                        raw_advisory_id,
                    )[:200]
                    or "unknown"
                )
                aliases = vulnerability.get("aliases", [])
                if not isinstance(aliases, list):
                    aliases = []
                package_name = redact(str(package.get("name", "unknown")), 200)
                package_version = redact(str(package.get("version", "unknown")), 100)
                ecosystem = redact(str(package.get("ecosystem", "unknown")), 100)
                severity: str | None = None
                database_specific = _as_mapping(
                    vulnerability.get("database_specific")
                )
                if database_specific.get("severity") is not None:
                    severity = redact(str(database_specific["severity"]), 100)
                findings.append(
                    Finding(
                        finding_id=_finding_id(
                            "OSV-Scanner",
                            target,
                            f"{advisory_id}:{package_name}:{package_version}",
                        ),
                        source_tool="OSV-Scanner",
                        source_version=version,
                        target=target,
                        category="vulnerable_dependency",
                        severity=severity,
                        description=(
                            f"{advisory_id} affects {package_name}@{package_version}"
                        ),
                        evidence=redact(
                            f"advisory={advisory_id}; aliases={aliases}; "
                            f"package={ecosystem}:{package_name}@{package_version}"
                        ),
                        remediation="Upgrade to a version not affected by this advisory.",
                        advisory_url=f"https://osv.dev/vulnerability/{advisory_id}",
                    )
                )
    return findings


def _parse_semgrep_document(
    document: Any, target: str, version: str | None
) -> list[Finding]:
    if not isinstance(document, dict) or not isinstance(document.get("results"), list):
        raise TypeError("Semgrep JSON must contain a results array")
    findings: list[Finding] = []
    for item in document["results"]:
        if not isinstance(item, dict):
            raise TypeError("Semgrep result entries must be objects")
        result = item
        extra = _as_mapping(result.get("extra"))
        start = _as_mapping(result.get("start"))
        check_id = result.get("check_id")
        if not isinstance(check_id, str) or not check_id:
            raise TypeError("Semgrep result check_id must be a non-empty string")
        location = redact(str(result.get("path", "unknown")), 500)
        line = start.get("line", "unknown")
        snippet = extra.get("lines", "")
        findings.append(
            Finding(
                finding_id=_finding_id(
                    "Semgrep", target, f"{check_id}:{location}:{line}"
                ),
                source_tool="Semgrep",
                source_version=version,
                target=target,
                category="static_analysis",
                severity=(
                    redact(str(extra["severity"]), 100)
                    if extra.get("severity") is not None
                    else None
                ),
                description=redact(str(extra.get("message", check_id))),
                evidence=redact(
                    f"rule={check_id}; file={location}; line={line}; "
                    f"snippet={snippet}"
                ),
                remediation="Review the flagged code and apply the rule-specific fix.",
            )
        )
    return findings


def parse_semgrep_output(output: str, target: str, version: str | None) -> list[Finding]:
    return _parse_semgrep_document(json.loads(output), target, version)


def _scanner_report(
    kind: ScanKind,
    path: Path,
    tool: ToolInfo,
    process: ProcessResult,
) -> AssessmentReport:
    category = "dependencies" if kind == "dependencies" else "code"
    target = path.name or str(path)
    scope = _scan_scope(path)
    if process.cancelled:
        return AssessmentReport(
            source_tool=tool.name,
            source_version=tool.version,
            target=target,
            scope=scope,
            category=category,
            execution_status="cancelled",
            exit_code=process.returncode,
            message=process.error or "scanner cancelled by user",
        )
    if process.timed_out:
        return AssessmentReport(
            source_tool=tool.name,
            source_version=tool.version,
            target=target,
            scope=scope,
            category=category,
            execution_status="timeout",
            exit_code=process.returncode,
            message=process.error,
        )
    if process.error:
        return AssessmentReport(
            source_tool=tool.name,
            source_version=tool.version,
            target=target,
            scope=scope,
            category=category,
            execution_status="tool_error",
            exit_code=process.returncode,
            message=process.error,
        )

    try:
        if kind == "dependencies":
            findings = parse_osv_output(process.stdout, target, tool.version)
            structured_errors: list[Any] = []
        else:
            document = json.loads(process.stdout)
            findings = _parse_semgrep_document(document, target, tool.version)
            raw_errors = _as_mapping(document).get("errors", [])
            structured_errors = (
                raw_errors if isinstance(raw_errors, list) else ["invalid errors field"]
            )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        return AssessmentReport(
            source_tool=tool.name,
            source_version=tool.version,
            target=target,
            scope=scope,
            category=category,
            execution_status="tool_error",
            exit_code=process.returncode,
            message=redact(f"could not parse structured scanner output: {exc}"),
        )

    if structured_errors:
        safe_errors = redact(str(structured_errors))
        return AssessmentReport(
            source_tool=tool.name,
            source_version=tool.version,
            target=target,
            scope=scope,
            category=category,
            execution_status="tool_error",
            exit_code=process.returncode,
            message=f"Semgrep reported scanner errors: {safe_errors}",
            findings=findings,
        )
    if process.returncode != 0 and (not findings or kind == "code"):
        return AssessmentReport(
            source_tool=tool.name,
            source_version=tool.version,
            target=target,
            scope=scope,
            category=category,
            execution_status="tool_error",
            exit_code=process.returncode,
            message=redact(
                process.stderr
                or f"{tool.name} exited with status {process.returncode}"
            ),
            findings=findings,
        )
    return AssessmentReport(
        source_tool=tool.name,
        source_version=tool.version,
        target=target,
        scope=scope,
        category=category,
        execution_status="findings" if findings else "clean",
        exit_code=process.returncode,
        message=(
            "Scanner returned findings with a nonzero exit code."
            if findings and process.returncode != 0
            else None
        ),
        findings=findings,
    )


def run_scan(
    kind: ScanKind, value: str | Path, timeout: float = 300.0
) -> AssessmentReport:
    path = validate_scan_path(value)
    tool = check_tool(TOOL_SPECS[2] if kind == "dependencies" else TOOL_SPECS[3])
    target = path.name or str(path)
    scope = _scan_scope(path)
    category = "dependencies" if kind == "dependencies" else "code"
    if tool.status != ToolStatus.AVAILABLE or tool.executable is None:
        return AssessmentReport(
            source_tool=tool.name,
            source_version=tool.version,
            target=target,
            scope=scope,
            category=category,
            execution_status="not_installed",
            message=tool.details or f"{tool.name} is not installed or failed its version check",
        )

    if kind == "dependencies":
        argv = [
            tool.executable,
            "--offline",
            "scan",
            "source",
            "--format",
            "json",
            str(path),
        ]
    else:
        argv = [
            tool.executable,
            "scan",
            "--json",
            "--metrics=off",
            "--config",
            "p/default",
            str(path),
        ]
    process = run_process(argv, timeout=timeout)
    return _scanner_report(kind, path, tool, process)
