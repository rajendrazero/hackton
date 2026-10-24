from __future__ import annotations

import re
from typing import Any

_HEADER_SECRET = re.compile(
    r"(?im)^(\s*(?:authorization|cookie|set-cookie)\s*:\s*)[^\r\n]*"
)
_SECRET_PATTERNS = (
    re.compile(
        r"(?i)\b(authorization|cookie|set-cookie|password|passwd|token|api[_-]?key)"
        r"(\s*[:=]\s*)(?:Bearer\s+|Basic\s+)?"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    ),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)([?&](?:token|api[_-]?key|password)=)[^&\s]+"),
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def redact(value: str, limit: int = 4_000) -> str:
    redacted = _HEADER_SECRET.sub(r"\1[REDACTED]", value)
    redacted = _SECRET_PATTERNS[0].sub(r"\1\2[REDACTED]", redacted)
    redacted = _SECRET_PATTERNS[1].sub("Bearer [REDACTED]", redacted)
    redacted = _SECRET_PATTERNS[2].sub(r"\1[REDACTED]", redacted)
    return _EMAIL.sub("[REDACTED_EMAIL]", redacted)[:limit]


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            safe_key = redact(str(key))
            if re.search(
                r"(?i)(authorization|cookie|set-cookie|password|passwd|token|api[_-]?key)",
                str(key),
            ):
                cleaned[safe_key] = "[REDACTED]"
            else:
                cleaned[safe_key] = redact_value(item)
        return cleaned
    return value
