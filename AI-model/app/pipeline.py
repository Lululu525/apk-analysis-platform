"""
Top-level pipeline router.

Routes incoming AnalyzeRequest to the correct sub-pipeline based on file type:
  apk      → pipeline_apk.run()
  firmware → pipeline_firmware.run()
  elf      → pipeline_firmware.run()   (single ELF binary treated as firmware)
  unknown  → pipeline_firmware.run()   (best-effort)
"""
from __future__ import annotations

from pathlib import Path

from .schemas import AnalyzeRequest, AnalyzeReport
from .extractors.type_detector import detect, FileType
from . import pipeline_firmware, pipeline_apk


def run_pipeline(req: AnalyzeRequest, output_dir: Path | None = None) -> AnalyzeReport:
    file_type = _resolve_file_type(req)

    if file_type == "apk":
        return pipeline_apk.run(req, output_dir=output_dir)

    # firmware | elf | unknown → firmware pipeline
    return pipeline_firmware.run(req, output_dir=output_dir)


def _resolve_file_type(req: AnalyzeRequest) -> FileType:
    # Caller may supply an explicit hint
    hint = (req.firmware.file_type or "").lower().strip()
    if hint in ("apk", "firmware", "elf", "unknown"):
        return hint  # type: ignore[return-value]

    # Auto-detect from the actual file
    fp = req.firmware.file_path
    if fp:
        path = Path(fp)
        if path.exists():
            return detect(path)

    return "unknown"


# ── kept for backward-compatibility (old pipeline.run_cli callers) ────────────

from typing import Tuple
import json

from .schemas import AnalyzeReport


def run_cli(input_json: Path, report_json: Path, output_dir: Path | None = None) -> Tuple[AnalyzeReport, str]:
    from .schemas import AnalyzeRequest
    data = json.loads(input_json.read_text(encoding="utf-8"))
    req = AnalyzeRequest.model_validate(data)
    report = run_pipeline(req, output_dir=output_dir)
    report_json.parent.mkdir(parents=True, exist_ok=True)
    report_json.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return report, report_json.as_posix()
