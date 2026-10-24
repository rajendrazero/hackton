from __future__ import annotations

import shutil
from dataclasses import dataclass
from enum import StrEnum

from sentinel_x.adapters.process import run_process
from sentinel_x.redaction import redact


class ToolStatus(StrEnum):
    AVAILABLE = "available"
    NOT_FOUND = "not_found"
    VERSION_CHECK_FAILED = "version_check_failed"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    executables: tuple[str, ...]
    version_args: tuple[str, ...]
    documentation: str


@dataclass(frozen=True)
class ToolInfo:
    name: str
    status: ToolStatus
    executable: str | None = None
    version: str | None = None
    details: str | None = None


TOOL_SPECS = (
    ToolSpec(
        name="OWASP ZAP",
        executables=("zap.exe", "zap.bat", "zap"),
        version_args=("-version",),
        documentation="https://www.zaproxy.org/docs/desktop/cmdline/",
    ),
    ToolSpec(
        name="Nuclei",
        executables=("nuclei.exe", "nuclei"),
        version_args=("-version",),
        documentation="https://docs.projectdiscovery.io/opensource/nuclei/running",
    ),
    ToolSpec(
        name="OSV-Scanner",
        executables=("osv-scanner.exe", "osv-scanner"),
        version_args=("--version",),
        documentation="https://google.github.io/osv-scanner/",
    ),
    ToolSpec(
        name="Semgrep",
        executables=("semgrep.exe", "semgrep"),
        version_args=("--version",),
        documentation="https://semgrep.dev/docs/cli-reference",
    ),
    ToolSpec(
        name="Grafana k6",
        executables=("k6.exe", "k6"),
        version_args=("version",),
        documentation="https://grafana.com/docs/k6/latest/",
    ),
)


def check_tool(spec: ToolSpec, timeout: float = 5.0) -> ToolInfo:
    executable = next(
        (path for name in spec.executables if (path := shutil.which(name))),
        None,
    )
    if executable is None:
        return ToolInfo(
            name=spec.name,
            status=ToolStatus.NOT_FOUND,
            details=f"executable not found on PATH; installation: {spec.documentation}",
        )

    result = run_process(
        [executable, *spec.version_args],
        timeout=timeout,
        max_output_bytes=64 * 1024,
    )
    if result.timed_out:
        return ToolInfo(
            name=spec.name,
            status=ToolStatus.VERSION_CHECK_FAILED,
            executable=executable,
            details=(
                f"version check exceeded {timeout:g}s timeout; "
                f"see {spec.documentation}"
            ),
        )
    if result.error:
        return ToolInfo(
            name=spec.name,
            status=ToolStatus.VERSION_CHECK_FAILED,
            executable=executable,
            details=f"{result.error}; see {spec.documentation}",
        )

    output = (result.stdout or result.stderr).strip()
    if result.returncode != 0 or not output:
        detail = f"version command exited with status {result.returncode}"
        if output:
            detail = f"{detail}: {redact(output, 300)}"
        return ToolInfo(
            name=spec.name,
            status=ToolStatus.VERSION_CHECK_FAILED,
            executable=executable,
            details=f"{detail}; see {spec.documentation}",
        )

    return ToolInfo(
        name=spec.name,
        status=ToolStatus.AVAILABLE,
        executable=executable,
        version=redact(output.splitlines()[0], 300),
    )


def discover_tools(timeout: float = 5.0) -> tuple[ToolInfo, ...]:
    return tuple(check_tool(spec, timeout=timeout) for spec in TOOL_SPECS)
