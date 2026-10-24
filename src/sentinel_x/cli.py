from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from sentinel_x import __version__
from sentinel_x.doctor import check_environment

app = typer.Typer(
    name="sentinel",
    help="Safety-first security assessment CLI.",
    no_args_is_help=True,
    invoke_without_command=True,
    add_completion=False,
)
console = Console()


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
