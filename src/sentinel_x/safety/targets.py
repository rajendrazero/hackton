from __future__ import annotations

import ipaddress
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from sentinel_x.redaction import redact


class TargetError(ValueError):
    """Raised when a target or target registry is invalid."""


class TargetRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=64)
    url: str
    registered_at: datetime
    active_scan_authorized: bool = False
    active_scan_authorized_at: datetime | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value) is None:
            raise ValueError(
                "target names must start with a letter or digit and contain only "
                "letters, digits, '.', '_' or '-'"
            )
        return value

    @field_validator("url")
    @classmethod
    def validate_and_normalize_url(cls, value: str) -> str:
        return normalize_loopback_url(value)

    @field_validator("registered_at")
    @classmethod
    def require_timezone_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("registered_at must include a timezone")
        return value.astimezone(UTC)

    @field_validator("active_scan_authorized_at")
    @classmethod
    def normalize_authorization_timestamp(
        cls, value: datetime | None
    ) -> datetime | None:
        if value is not None:
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("authorization timestamp must include a timezone")
            return value.astimezone(UTC)
        return None

    @model_validator(mode="after")
    def validate_authorization_record(self) -> TargetRecord:
        if self.active_scan_authorized != (self.active_scan_authorized_at is not None):
            raise ValueError(
                "active scan authorization and its timestamp must be set together"
            )
        return self


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise TargetError(f"duplicate YAML key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def normalize_loopback_url(value: str) -> str:
    if not value or value != value.strip() or any(char.isspace() for char in value):
        raise TargetError("URL must be non-empty and contain no whitespace")

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise TargetError(f"invalid target URL: {exc}") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetError("target URL scheme must be http or https")
    if not parsed.netloc or hostname is None:
        raise TargetError("target URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise TargetError("credentials in target URLs are not allowed")
    if parsed.netloc.endswith(":"):
        raise TargetError("target URL port must not be empty")
    if "?" in value or "#" in value:
        raise TargetError("target URL query strings and fragments are not allowed")
    if port is not None and not 1 <= port <= 65535:
        raise TargetError("target URL port must be between 1 and 65535")
    if "%" in hostname:
        raise TargetError("encoded hostnames and IPv6 zone identifiers are not allowed")

    host = hostname.lower()
    is_loopback = host == "localhost"
    if not is_loopback:
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = False
    if not is_loopback:
        raise TargetError(
            "only localhost, 127.0.0.1, and ::1 loopback targets are allowed; "
            "external target authorization is not implemented"
        )

    if ":" in host:
        authority_host = f"[{host}]"
    else:
        authority_host = host
    authority = authority_host if port is None else f"{authority_host}:{port}"
    return urlunsplit((parsed.scheme.lower(), authority, parsed.path, "", ""))


def default_state_dir() -> Path:
    override = os.environ.get("SENTINEL_HOME")
    if override:
        return Path(override).expanduser()
    if os.name == "nt" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "sentinel-x"
    if os.environ.get("XDG_CONFIG_HOME"):
        return Path(os.environ["XDG_CONFIG_HOME"]) / "sentinel-x"
    return Path.home() / ".config" / "sentinel-x"


def default_registry_path() -> Path:
    return default_state_dir() / "targets.yaml"


def load_targets(path: Path | None = None) -> tuple[TargetRecord, ...]:
    registry_path = path or default_registry_path()
    if not registry_path.exists():
        return ()
    try:
        document = yaml.load(
            registry_path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader
        )
    except (OSError, UnicodeError) as exc:
        raise TargetError(
            f"could not read target registry {redact(str(registry_path))}: {redact(str(exc))}"
        ) from exc
    except (TypeError, yaml.YAMLError) as exc:
        mark = getattr(exc, "problem_mark", None)
        line = getattr(mark, "line", None)
        suffix = f" at line {line + 1}" if isinstance(line, int) else ""
        raise TargetError(f"target registry contains invalid YAML{suffix}") from exc
    except TargetError as exc:
        raise TargetError(f"invalid target registry {registry_path}: {exc}") from exc

    if not isinstance(document, dict) or set(document) != {"version", "targets"}:
        raise TargetError("target registry must contain only 'version' and 'targets'")
    if document["version"] != 1 or not isinstance(document["targets"], list):
        raise TargetError("unsupported target registry version or invalid targets list")

    try:
        targets = tuple(TargetRecord.model_validate(item) for item in document["targets"])
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ValidationError):
            messages = "; ".join(
                str(error["msg"]) for error in exc.errors(include_input=False)
            )
            raise TargetError(f"invalid target registry entry: {messages}") from exc
        raise TargetError("invalid target registry entry") from exc
    names = [target.name.casefold() for target in targets]
    if len(set(names)) != len(names):
        raise TargetError("target names must be unique, ignoring letter case")
    return targets


def save_targets(targets: tuple[TargetRecord, ...], path: Path | None = None) -> None:
    registry_path = path or default_registry_path()
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "targets": [
            target.model_dump(mode="json")
            for target in sorted(targets, key=lambda item: item.name.casefold())
        ],
    }
    temporary = registry_path.with_suffix(f"{registry_path.suffix}.tmp")
    try:
        temporary.write_text(
            yaml.safe_dump(payload, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        temporary.replace(registry_path)
    except OSError as exc:
        raise TargetError(f"could not save target registry {registry_path}: {exc}") from exc


def add_target(
    name: str, url: str, path: Path | None = None
) -> TargetRecord:
    targets = load_targets(path)
    if any(target.name.casefold() == name.casefold() for target in targets):
        raise TargetError(f"target {name!r} is already registered")
    try:
        target = TargetRecord(
            name=name,
            url=url,
            registered_at=datetime.now(UTC),
            active_scan_authorized=False,
        )
    except ValidationError as exc:
        messages = "; ".join(
            str(error["msg"]) for error in exc.errors(include_input=False)
        )
        raise TargetError(f"invalid target: {messages}") from exc
    save_targets((*targets, target), path)
    return target


def get_target(name: str, path: Path | None = None) -> TargetRecord:
    target = next(
        (item for item in load_targets(path) if item.name.casefold() == name.casefold()),
        None,
    )
    if target is None:
        raise TargetError(f"target {name!r} is not registered")
    return target


def set_active_scan_authorization(
    name: str, authorized: bool, path: Path | None = None
) -> TargetRecord:
    targets = load_targets(path)
    updated: list[TargetRecord] = []
    selected: TargetRecord | None = None
    for target in targets:
        if target.name.casefold() == name.casefold():
            selected = target.model_copy(
                update={
                    "active_scan_authorized": authorized,
                    "active_scan_authorized_at": (
                        datetime.now(UTC) if authorized else None
                    ),
                }
            )
            updated.append(selected)
        else:
            updated.append(target)
    if selected is None:
        raise TargetError(f"target {name!r} is not registered")
    save_targets(tuple(updated), path)
    return selected
