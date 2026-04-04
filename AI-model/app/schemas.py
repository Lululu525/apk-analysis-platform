from __future__ import annotations

from typing import Optional, Literal, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

Severity = Literal["critical", "high", "medium", "low", "info"]
JobStatus = Literal["success", "failed"]


class ExtensibleSchema(BaseModel):
    model_config = ConfigDict(extra="allow")


class StrictSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0"


class FirmwareInfo(ExtensibleSchema):
    name: str
    sha256: Optional[str] = None
    uri: Optional[str] = None
    file_path: Optional[str] = None
    size_bytes: Optional[int] = None
    file_type: Optional[str] = None


class DeviceMeta(ExtensibleSchema):
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    arch_hint: Optional[str] = None


class Options(ExtensibleSchema):
    run_static_scan: bool = True
    run_behavior_analysis: bool = False
    severity_threshold: Severity = "medium"


class AnalyzeRequest(ExtensibleSchema):
    schema_version: str = "1.0"
    job_id: str
    submitted_at: Optional[str] = None
    firmware: FirmwareInfo
    device_meta: Optional[DeviceMeta] = None
    options: Options = Field(default_factory=Options)


class Finding(ExtensibleSchema):
    finding_id: str
    title: str
    severity: Severity
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    category: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation: Optional[str] = None
    cwe: List[str] = Field(default_factory=list)
    cve_examples: List[str] = Field(default_factory=list)

    description: Optional[str] = None
    exploitability: Optional[float] = None
    impact: Optional[float] = None
    exposure: Optional[float] = None
    data_sensitivity: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    score_breakdown: Dict[str, Any] = Field(default_factory=dict)


class ReportSummary(StrictSchema):
    risk_score: int = Field(ge=0, le=100)
    risk_level: str = "Info"
    counts: Dict[Severity, int] = Field(default_factory=dict)


class Artifacts(ExtensibleSchema):
    logs_path: Optional[str] = None
    extracted_path: Optional[str] = None
    features_path: Optional[str] = None
    strings_path: Optional[str] = None
    pdf_path: Optional[str] = None


class AnalyzeReport(ExtensibleSchema):
    schema_version: str = "1.0"
    job_id: str
    status: JobStatus
    started_at: str
    finished_at: str
    summary: ReportSummary
    findings: List[Finding] = Field(default_factory=list)
    artifacts: Artifacts = Field(default_factory=Artifacts)
    errors: List[str] = Field(default_factory=list)