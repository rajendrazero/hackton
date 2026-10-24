from __future__ import annotations

import sys
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    details: str


def check_environment() -> tuple[DoctorCheck, ...]:
    python_version = sys.version_info
    python_ok = python_version >= (3, 11)
    checks = [
        DoctorCheck(
            name="Python",
            status="OK" if python_ok else "FAIL",
            details=f"{python_version.major}.{python_version.minor}.{python_version.micro}"
            + (" (>= 3.11 required)" if not python_ok else ""),
        )
    ]

    for package in ("typer", "rich"):
        try:
            installed_version = version(package)
        except PackageNotFoundError:
            checks.append(
                DoctorCheck(
                    name=package,
                    status="FAIL",
                    details="not installed; install Sentinel X with its project dependencies",
                )
            )
        else:
            checks.append(
                DoctorCheck(name=package, status="OK", details=installed_version)
            )

    return tuple(checks)
