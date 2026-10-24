# Sentinel X CLI

Sentinel X is a safety-first Python command-line toolkit. It has no web
frontend, dashboard, API server, or background service.

## Requirements and install

- Python 3.11 or newer.
- Install external tools separately; Sentinel X never pretends a missing tool
  ran.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
sentinel --help
sentinel doctor
```

## Implemented commands

```text
sentinel doctor
sentinel tools list
sentinel tools check
sentinel target add <name> <url>
sentinel target show [name]
sentinel target authorize <name>
sentinel target revoke <name>
sentinel scan dependencies <path> [--timeout 300]
sentinel scan code <path> [--timeout 300]
sentinel ratelimit test <target> [--profile smoke|gradual]
sentinel report latest
sentinel report export [report-id] [--format json|markdown] [--output path]
```

`tools list` reports each tool independently with `available`, `not_found`, or
`version_check_failed`, its version when known, executable path, and
installation documentation. `tools check` returns exit code 1 when any
supported tool is missing or its version could not be checked.

External executables are started with argument arrays, without `shell=True`,
with timeouts, process cancellation, and bounded captured output. OSV-Scanner
JSON and Semgrep JSON are parsed independently. A nonzero scanner exit without
structured findings is an error, not a clean result. Semgrep findings are read
from its JSON output; its local `scan` command does not need CI's findings exit
code. OSV-Scanner may access vulnerability data, and Semgrep's `p/default`
configuration can require network access to fetch rules.

OSV-Scanner always runs with `--offline`: dependency names and versions are not
sent to an external service. It requires a previously populated local database;
without one the result is an explicit tool error, never a clean scan. See the
[official offline-mode guide](https://google.github.io/osv-scanner/usage/offline-mode/)
to prepare a local database separately.

Scanner paths are resolved locally and limited to 25,000 files / 512 MiB per
run. The `.git`, virtual environment, `node_modules`, `build`, and `dist`
directories are excluded. Filesystem roots and symlink/junction scan paths are
rejected.

## Target safety

Target configuration is YAML at `%APPDATA%\sentinel-x\targets.yaml` on Windows
(or `$XDG_CONFIG_HOME/sentinel-x/targets.yaml` on other platforms). Override
the state directory with `SENTINEL_HOME` when needed.

For now, only `localhost`, `127.0.0.1`, and `::1` with HTTP or HTTPS are
accepted. External target authorization is not implemented. Registration is
not active-test permission: `sentinel target authorize <name>` requires an
explicit confirmation and records its timestamp; `sentinel target revoke
<name>` removes the authorization.

## k6 rate-limit test

The k6 adapter only accepts an authorized registered loopback target, disables
redirects, and confirms the profile before execution. It caps request rate at
10 requests/second, virtual users at 10, per-request timeout at 5 seconds, and
test duration at 120 seconds. Each VU waits at least one second after each
request, providing a finite request budget no greater than VUs multiplied by
test duration. Response bodies are discarded.

- `smoke`: fixed 5 VUs maximum and 30 seconds.
- `gradual`: `--max-vus 1..10` is required; `--duration` is 30..120 seconds.
- `--rps` is 1..10 and defaults to 5.
- Press **Ctrl+C** to stop early. The interrupted execution is saved as a
  cancelled report when the process can be stopped cleanly.

No load test runs as part of unit or integration tests. An HTTP 429 alone is
not treated as proof that rate limiting is adequate; reports also include
latency percentiles, request throughput, status counts, failed-request ratio,
and request timeouts where k6 reports them.

## Reports and exit codes

Validated JSON reports are stored under `%APPDATA%\sentinel-x\reports` on
Windows. `report export` supports JSON and Markdown. Reports distinguish
`clean`, `findings`, `tool_error`, `timeout`, `cancelled`, `not_installed`, and
`completed`; secrets and email addresses are redacted before persistence.
The shared report schema records source tool/version, target and scope,
timestamp, category, execution status, and metrics. Each finding records an ID,
severity and confidence when known, redacted evidence, remediation, validation
status, and an advisory reference when available. Missing scanner output is
reported as an execution status, not as a clean finding.

Assessment exit codes: `0` clean/completed, `1` findings or user-declined
confirmation, `2` invalid scope/configuration or tool error, `3` timeout,
`4` tool not installed, and `130` cancelled.

## Tool availability and official references

`sentinel tools list` is the source of truth for tools detected on the current
machine. Initial Windows audit detected k6 v2.2.0; ZAP, Nuclei, OSV-Scanner,
and Semgrep were not on `PATH`. Tool documentation:

- [OWASP ZAP command line](https://www.zaproxy.org/docs/desktop/cmdline/)
- [Nuclei running guide](https://docs.projectdiscovery.io/opensource/nuclei/running)
- [OSV-Scanner usage and JSON output](https://google.github.io/osv-scanner/usage/)
- [Semgrep CLI reference and exit codes](https://semgrep.dev/docs/cli-reference)
- [Grafana k6 options reference](https://grafana.com/docs/k6/latest/using-k6/k6-options/reference/)
- [Grafana k6 custom summary output](https://grafana.com/docs/k6/latest/results-output/end-of-test/custom-summary/)

## Not implemented

OWASP ZAP and Nuclei are discovery-only; their scan adapters are not
implemented. Website inspection, active web scanning, incident log analysis,
RCE risk assessment, external target authorization, and automated installation
of security tools are not available. Do not treat their absence as a clean
assessment.

## Quality checks

```powershell
python -m pytest
ruff check src tests
mypy src tests
python -m pip check
python -m pip wheel --no-deps .
```
