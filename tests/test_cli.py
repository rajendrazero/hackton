from typer.testing import CliRunner

from sentinel_x import __version__
from sentinel_x.cli import app

runner = CliRunner()


def test_help_lists_doctor() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "doctor" in result.stdout


def test_version_option() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert f"Sentinel X {__version__}" in result.stdout


def test_doctor_reports_runtime_and_dependencies() -> None:
    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "Sentinel X environment" in result.stdout
    assert "Python" in result.stdout
    assert "typer" in result.stdout
    assert "rich" in result.stdout
