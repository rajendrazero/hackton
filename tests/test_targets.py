from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel_x.safety.targets import (
    TargetError,
    add_target,
    get_target,
    load_targets,
    normalize_loopback_url,
    set_active_scan_authorization,
)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("HTTP://LOCALHOST:8080/app", "http://localhost:8080/app"),
        ("https://127.0.0.1/", "https://127.0.0.1/"),
        ("http://[::1]:9000/health", "http://[::1]:9000/health"),
    ],
)
def test_normalizes_loopback_urls(url: str, expected: str) -> None:
    assert normalize_loopback_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "ftp://localhost",
        "http://example.com",
        "http://192.168.1.5",
        "http://169.254.169.254",
        "http://localhost.evil.test",
        "http://user:pass@localhost",
        "http://localhost/?token=secret",
        "http://localhost/#fragment",
        "http://local host",
        "http://localhost?",
        "http://localhost#",
        "http://localhost:",
        "http://localhost:0",
        "http://localhost:70000",
        "http://[fe80::1%25eth0]",
    ],
)
def test_rejects_unsafe_or_invalid_urls(url: str) -> None:
    with pytest.raises(TargetError):
        normalize_loopback_url(url)


def test_registration_is_separate_from_active_authorization(tmp_path: Path) -> None:
    registry = tmp_path / "targets.yaml"
    created = add_target("local-api", "http://localhost:8080/api", registry)

    assert created.url == "http://localhost:8080/api"
    assert created.active_scan_authorized is False
    assert get_target("LOCAL-API", registry).active_scan_authorized is False

    authorized = set_active_scan_authorization("local-api", True, registry)

    assert authorized.active_scan_authorized is True
    assert load_targets(registry) == (authorized,)
    assert "version: 1" in registry.read_text(encoding="utf-8")


def test_duplicate_name_is_rejected_case_insensitively(tmp_path: Path) -> None:
    registry = tmp_path / "targets.yaml"
    add_target("api", "http://localhost:8000", registry)

    with pytest.raises(TargetError, match="already registered"):
        add_target("API", "http://127.0.0.1:8000", registry)


def test_rejected_url_credentials_are_not_echoed(tmp_path: Path) -> None:
    with pytest.raises(TargetError) as error:
        add_target("api", "http://user:top-secret@localhost", tmp_path / "targets.yaml")

    assert "top-secret" not in str(error.value)


def test_duplicate_yaml_keys_are_rejected(tmp_path: Path) -> None:
    registry = tmp_path / "targets.yaml"
    registry.write_text("version: 1\nversion: 1\ntargets: []\n", encoding="utf-8")

    with pytest.raises(TargetError, match="duplicate YAML key"):
        load_targets(registry)


def test_unknown_yaml_fields_are_rejected(tmp_path: Path) -> None:
    registry = tmp_path / "targets.yaml"
    registry.write_text(
        "version: 1\ntargets:\n"
        "  - name: api\n"
        "    url: http://localhost\n"
        f"    registered_at: {datetime.now(UTC).isoformat()}\n"
        "    active_scan_authorized: true\n"
        "    trusted: true\n",
        encoding="utf-8",
    )

    with pytest.raises(TargetError, match="invalid target registry entry"):
        load_targets(registry)


def test_naive_registration_timestamp_is_rejected(tmp_path: Path) -> None:
    registry = tmp_path / "targets.yaml"
    registry.write_text(
        "version: 1\ntargets:\n"
        "  - name: api\n"
        "    url: http://localhost\n"
        "    registered_at: '2026-01-01T12:00:00'\n",
        encoding="utf-8",
    )

    with pytest.raises(TargetError, match="include a timezone"):
        load_targets(registry)
