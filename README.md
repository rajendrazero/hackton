# Sentinel X CLI

Sentinel X is a safety-first command-line toolkit for security assessment. This
initial release implements the CLI entry point and `sentinel doctor`; scanner
integrations and assessment commands are not available yet.

## Requirements

- Python 3.11 or newer.

## Install for development

Create and activate a virtual environment, then install the project and its
test dependencies:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Run

```powershell
sentinel --help
sentinel --version
sentinel doctor
```

`doctor` checks the Python runtime and required CLI packages. It does not run or
claim to have run any security scanner.

## Current scope

The first implementation stage contains only the CLI skeleton and environment
doctor. Target authorization, safety controls, scanner adapters, incident
analysis, rate-limit testing, and unified reporting remain unimplemented. Do
not use this release to assess a target.

## Tests

```powershell
python -m pytest
```
