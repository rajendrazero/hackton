from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sentinel_x.redaction import redact_value

ExecutionStatus = Literal[
    "clean",
    "findings",
    "tool_error",
    "timeout",
    "cancelled",
    "not_installed",
    "completed",
]


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    source_tool: str
    source_version: str | None = None
    target: str
    scope: str | None = None
    category: str
    severity: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    description: str
    evidence: str
    remediation: str | None = None
    advisory_url: str | None = None
    validation_status: Literal["unvalidated", "validated", "rejected"] = "unvalidated"

    @field_validator("*", mode="before")
    @classmethod
    def redact_sensitive_values(cls, value: Any) -> Any:
        return redact_value(value)

    @model_validator(mode="after")
    def populate_default_scope(self) -> Finding:
        if self.scope is None:
            self.scope = self.target
        return self


class AssessmentReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_id: str = Field(default_factory=lambda: uuid4().hex)
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_tool: str
    source_version: str | None = None
    target: str
    scope: str | None = None
    category: str
    execution_status: ExecutionStatus
    exit_code: int | None = None
    message: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    metrics: dict[str, Any] | None = None

    @field_validator("*", mode="before")
    @classmethod
    def redact_sensitive_values(cls, value: Any) -> Any:
        return redact_value(value)

    @model_validator(mode="after")
    def validate_status_and_findings(self) -> AssessmentReport:
        if self.scope is None:
            self.scope = self.target
        if self.execution_status == "clean" and self.findings:
            raise ValueError("a clean report cannot contain findings")
        if self.execution_status == "findings" and not self.findings:
            raise ValueError("a findings report must contain at least one finding")
        return self
