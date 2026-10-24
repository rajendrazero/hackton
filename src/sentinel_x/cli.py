from __future__ import annotations

from pathlib import Path
from typing import Literal

import typer
from rich.console import Console
from rich.table import Table

from sentinel_x import __version__
from sentinel_x.adapters.k6 import LoadProfile, run_k6, validate_load_profile
from sentinel_x.adapters.scanners import ScanKind, run_scan
from sentinel_x.doctor import check_environment
from sentinel_x.reporting.models import AssessmentReport
from sentinel_x.reporting.store import (
    ReportError,
    export_json,
    export_markdown,
    load_report,
    save_report,
)
from sentinel_x.safety.targets import (
    TargetError,
    add_target,
    get_target,
    load_targets,
    set_active_scan_authorization,
)
from sentinel_x.tools.discovery import ToolInfo, ToolStatus, discover_tools

app = typer.Typer(
    name="sentinel",
    help="Safety-first security assessment CLI.",
    no_args_is_help=True,
    invoke_without_command=True,
    add_completion=False,
)
console = Console()
tools_app = typer.Typer(no_args_is_help=True, help="Discover installed security tools.")
target_app = typer.Typer(no_args_is_help=True, help="Manage loopback assessment targets.")
scan_app = typer.Typer(no_args_is_help=True, help="Run local source and dependency scans.")
ratelimit_app = typer.Typer(no_args_is_help=True, help="Run bounded k6 tests.")
report_app = typer.Typer(no_args_is_help=True, help="View and export assessment reports.")
app.add_typer(tools_app, name="tools")
app.add_typer(target_app, name="target")
app.add_typer(scan_app, name="scan")
app.add_typer(ratelimit_app, name="ratelimit")
app.add_typer(report_app, name="report")


def _display_tool_table(tools: tuple[ToolInfo, ...]) -> None:
    table = Table(title="Security tool discovery")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Version")
    table.add_column("Executable")
    table.add_column("Details")
    for tool in tools:
        table.add_row(
            tool.name,
            tool.status.value,
            tool.version or "-",
            tool.executable or "-",
            tool.details or "",
        )
    console.print(table)


def _display_report(report: AssessmentReport, report_path: Path) -> None:
    table = Table(title="Assessment result")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Report ID", report.report_id)
    table.add_row("Tool", f"{report.source_tool} {report.source_version or ''}".strip())
    table.add_row("Target", report.target)
    table.add_row("Scope", report.scope or report.target)
    table.add_row("Category", report.category)
    table.add_row("Execution", report.execution_status)
    table.add_row("Findings", str(len(report.findings)))
    table.add_row("Saved report", str(report_path))
    console.print(table)
    if report.message:
        console.print(report.message)
    for finding in report.findings:
        console.print(
            f"[bold]{finding.severity or 'unknown'}[/bold] "
            f"{finding.finding_id}: {finding.description}"
        )


def _exit_for_status(status: str) -> int:
    return {
        "clean": 0,
        "completed": 0,
        "findings": 1,
        "tool_error": 2,
        "timeout": 3,
        "cancelled": 130,
        "not_installed": 4,
    }[status]


def _persist_and_display(report: AssessmentReport) -> None:
    try:
        report_path = save_report(report)
    except ReportError as exc:
        console.print(f"[red]Could not save report:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    _display_report(report, report_path)
    exit_code = _exit_for_status(report.execution_status)
    if exit_code:
        raise typer.Exit(code=exit_code)


def _target_error(exc: TargetError) -> None:
    console.print(f"[red]Target or scope error:[/red] {exc}")
    raise typer.Exit(code=2) from exc


def _report_error(exc: ReportError) -> None:
    console.print(f"[red]Report error:[/red] {exc}")
    raise typer.Exit(code=2) from exc


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        help="Show the Sentinel X version and exit.",
        is_eager=True,
    ),
) -> None:
    if version:
        console.print(f"Sentinel X {__version__}")
        raise typer.Exit()


@app.command()
def doctor() -> None:
    """Check the Python runtime and required CLI packages."""
    checks = check_environment()
    table = Table(title="Sentinel X environment")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Details")

    for check in checks:
        table.add_row(check.name, check.status, check.details)

    console.print(table)
    if any(check.status == "FAIL" for check in checks):
        raise typer.Exit(code=1)


@tools_app.command("list")
def tools_list() -> None:
    """List discovered tools and their version-check status."""
    _display_tool_table(discover_tools())


@tools_app.command("check")
def tools_check() -> None:
    """Check all supported tool executables and versions."""
    tools = discover_tools()
    _display_tool_table(tools)
    if any(tool.status != ToolStatus.AVAILABLE for tool in tools):
        raise typer.Exit(code=1)


@target_app.command("add")
def target_add(name: str, url: str) -> None:
    """Register a loopback target; this does not authorize active tests."""
    try:
        target = add_target(name, url)
    except TargetError as exc:
        _target_error(exc)
    console.print(
        f"Registered [bold]{target.name}[/bold] at {target.url}; "
        "active testing is not authorized."
    )


@target_app.command("show")
def target_show(name: str | None = typer.Argument(None)) -> None:
    """Show one registered target or the full target registry."""
    try:
        targets = (get_target(name),) if name else load_targets()
    except TargetError as exc:
        _target_error(exc)
    if not targets:
        console.print("No targets are registered.")
        return
    table = Table(title="Registered targets")
    table.add_column("Name")
    table.add_column("URL")
    table.add_column("Registered")
    table.add_column("Active tests")
    table.add_column("Authorization time")
    for target in targets:
        table.add_row(
            target.name,
            target.url,
            target.registered_at.isoformat(),
            "authorized" if target.active_scan_authorized else "not authorized",
            (
                target.active_scan_authorized_at.isoformat()
                if target.active_scan_authorized_at
                else "-"
            ),
        )
    console.print(table)


@target_app.command("authorize")
def target_authorize(name: str) -> None:
    """Explicitly authorize active testing for a registered loopback target."""
    try:
        target = get_target(name)
    except TargetError as exc:
        _target_error(exc)
    console.print(
        f"Target: {target.name} ({target.url})\n"
        "This grants Sentinel X permission to run bounded active tests from this machine."
    )
    if not typer.confirm(
        "Do you own or have explicit authorization to test this target?",
        default=False,
    ):
        console.print("Authorization not changed.")
        raise typer.Exit(code=1)
    try:
        updated = set_active_scan_authorization(name, True)
    except TargetError as exc:
        _target_error(exc)
    console.print(f"Active tests authorized for [bold]{updated.name}[/bold].")


@target_app.command("revoke")
def target_revoke(name: str) -> None:
    """Revoke active-testing authorization for a target."""
    try:
        target = set_active_scan_authorization(name, False)
    except TargetError as exc:
        _target_error(exc)
    console.print(f"Active testing authorization revoked for {target.name}.")


@scan_app.command("dependencies")
def scan_dependencies(
    path: Path = typer.Argument(...),
    timeout: int = typer.Option(300, min=1, max=1800, help="Maximum scanner runtime in seconds."),
) -> None:
    """Scan a local dependency/source directory with OSV-Scanner."""
    _run_local_scan("dependencies", path, timeout)


@scan_app.command("code")
def scan_code(
    path: Path = typer.Argument(...),
    timeout: int = typer.Option(300, min=1, max=1800, help="Maximum scanner runtime in seconds."),
) -> None:
    """Scan local source code with Semgrep."""
    _run_local_scan("code", path, timeout)


def _run_local_scan(kind: ScanKind, path: Path, timeout: int) -> None:
    try:
        report = run_scan(kind, path, timeout=float(timeout))
    except TargetError as exc:
        _target_error(exc)
    _persist_and_display(report)


@ratelimit_app.command("test")
def ratelimit_test(
    target_name: str,
    profile: LoadProfile = typer.Option(
        "smoke", help="Conservative profile: smoke or explicitly bounded gradual."
    ),
    max_vus: int | None = typer.Option(
        None,
        min=1,
        max=10,
        help="Required for gradual; maximum is 10 virtual users.",
    ),
    duration_seconds: int = typer.Option(
        30, "--duration", min=30, max=120, help="Gradual profile duration in seconds."
    ),
    requests_per_second: int = typer.Option(
        5, "--rps", min=1, max=10, help="Global request-rate cap."
    ),
) -> None:
    """Run a confirmed, low-rate k6 test against an authorized loopback target."""
    try:
        target = get_target(target_name)
        vus, stages = validate_load_profile(
            profile, max_vus, duration_seconds, requests_per_second
        )
    except TargetError as exc:
        _target_error(exc)
    total_duration = sum(stage["duration"] for stage in stages)
    console.print(
        f"Target: {target.name} ({target.url})\n"
        f"Profile: {profile}; maximum VUs: {vus}; duration: {total_duration}s; "
        f"request cap: {requests_per_second}/s; request budget upper bound: "
        f"{vus * total_duration}\n"
        "Redirects are disabled. Press Ctrl+C for emergency stop."
    )
    if not target.active_scan_authorized:
        _target_error(
            TargetError(
                "target is registered but not authorized for active testing; "
                "run 'sentinel target authorize' first"
            )
        )
    if not typer.confirm(
        "Start this active load test now?",
        default=False,
    ):
        console.print("Test cancelled.")
        raise typer.Exit(code=1)
    try:
        current_target = get_target(target_name)
        if (
            not current_target.active_scan_authorized
            or current_target.url != target.url
        ):
            _target_error(
                TargetError(
                    "target authorization or URL changed after confirmation; review "
                    "the target and confirm a new test"
                )
            )
        report = run_k6(
            current_target,
            profile=profile,
            max_vus=max_vus,
            duration_seconds=duration_seconds,
            requests_per_second=requests_per_second,
        )
    except TargetError as exc:
        _target_error(exc)
    _persist_and_display(report)


@report_app.command("latest")
def report_latest() -> None:
    """Display the latest saved assessment report."""
    try:
        report = load_report()
    except ReportError as exc:
        _report_error(exc)
    console.print(export_markdown(report))


@report_app.command("export")
def report_export(
    report_id: str = typer.Argument("latest"),
    output_format: Literal["json", "markdown"] = typer.Option(
        "json", "--format", help="Export format."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="Write the export to this path instead of the terminal."
    ),
) -> None:
    """Export a validated report as JSON or Markdown."""
    try:
        report = load_report(report_id)
        content = (
            export_json(report, output)
            if output_format == "json"
            else export_markdown(report)
        )
    except ReportError as exc:
        _report_error(exc)
    if output is None:
        typer.echo(content, nl=False)
    else:
        console.print(f"Exported report {report.report_id} to {output}.")
