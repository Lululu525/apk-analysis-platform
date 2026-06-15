from __future__ import annotations

from typing import Literal, Any
from pydantic import BaseModel, Field, ConfigDict

Severity = Literal["critical", "high", "medium", "low", "info"]
JobStatus = Literal["success", "failed"]


class ExtensibleSchema(BaseModel):
    model_config = ConfigDict(extra="allow")


class FirmwareInfo(ExtensibleSchema):
    name: str
    sha256: str | None = None
    uri: str | None = None
    file_path: str | None = None
    size_bytes: int | None = None
    file_type: str | None = None


class DeviceMeta(ExtensibleSchema):
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    arch_hint: str | None = None


class Options(ExtensibleSchema):
    run_static_scan: bool = True
    severity_threshold: Severity = "medium"


class AnalyzeRequest(ExtensibleSchema):
    schema_version: str = "1.0"
    job_id: str
    submitted_at: str | None = None
    firmware: FirmwareInfo
    device_meta: DeviceMeta | None = None
    options: Options = Field(default_factory=Options)


class Finding(ExtensibleSchema):
    id: str
    title: str
    severity: Severity
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    category: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str | None = None
    cwe: list[str] = Field(default_factory=list)
    cve_examples: list[str] = Field(default_factory=list)

    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    score_breakdown: dict[str, Any] = Field(default_factory=dict)


class ReportSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    risk_score: int = Field(ge=0, le=100)
    risk_level: str = "Info"
    counts: dict[Severity, int] = Field(default_factory=dict)


class Artifacts(ExtensibleSchema):
    logs_path: str | None = None
    extracted_path: str | None = None
    features_path: str | None = None
    ml_features_path: str | None = None
    strings_path: str | None = None
    pdf_path: str | None = None


class AnalyzeReport(ExtensibleSchema):
    schema_version: str = "1.0"
    job_id: str
    status: JobStatus
    started_at: str
    finished_at: str
    summary: ReportSummary
    findings: list[Finding] = Field(default_factory=list)
    artifacts: Artifacts = Field(default_factory=Artifacts)
    errors: list[str] = Field(default_factory=list)
