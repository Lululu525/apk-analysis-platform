from __future__ import annotations

from typing import Optional, Literal, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

Severity = Literal["critical", "high", "medium", "low", "info"]
JobStatus = Literal["success", "failed"]

# 用於「可擴充」區域：允許未知欄位（後端可隨時加欄位，前端不會爆掉）
class ExtensibleSchema(BaseModel):
    model_config = ConfigDict(extra="allow")

# 用於「核心契約」：禁止未知欄位（避免核心被亂加、亂改）
class StrictSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0"


class FirmwareInfo(ExtensibleSchema):
    name: str
    sha256: Optional[str] = None
    uri: Optional[str] = None
    file_path: Optional[str] = None
    size_bytes: Optional[int] = None
    file_type: Optional[str] = None   # "apk" | "firmware" | "elf" | "unknown" — auto-detected if omitted


class DeviceMeta(ExtensibleSchema):
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    arch_hint: Optional[str] = None


class Options(ExtensibleSchema):
    run_static_scan: bool = True
    run_behavior_analysis: bool = False
    severity_threshold: Severity = "medium"


# AnalyzeRequest 可擴充（後端最常新增欄位）
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
    confidence: float = Field(ge=0.0, le=1.0)
    category: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation: Optional[str] = None
    cwe: List[str] = Field(default_factory=list)
    cve_examples: List[str] = Field(default_factory=list)


# 核心 summary 結構，禁止亂加欄位（後端要加欄位要改 schema 版本）
class ReportSummary(StrictSchema):
    risk_score: int = Field(ge=0, le=100)
    counts: Dict[Severity, int] = Field(default_factory=dict)


class Artifacts(ExtensibleSchema):
    logs_path: Optional[str] = None
    extracted_path: Optional[str] = None
    features_path: Optional[str] = None
    strings_path: Optional[str] = None


# report 本體可擴充（未來加 capabilities / metrics）
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