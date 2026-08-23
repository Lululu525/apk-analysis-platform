from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json

from .pdf_report import generate_pdf_report as _generate_structured_pdf

APP_ROOT = Path(__file__).resolve().parents[2]
STORAGE_DIR = APP_ROOT / "storage" / "objects" / "apks"
REQUEST_DIR = APP_ROOT / "metadata" / "requests"
RESULT_DIR = APP_ROOT / "metadata" / "results"
ARTIFACTS_DIR = APP_ROOT / "metadata" / "artifacts"
PDF_DIR = APP_ROOT / "metadata" / "pdfs"

AI_MODEL_ROOT = APP_ROOT.parent / "AI-model"


def ensure_directories() -> None:
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    REQUEST_DIR.mkdir(parents=True, exist_ok=True)
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    PDF_DIR.mkdir(parents=True, exist_ok=True)


def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def request_path(sample_id: str) -> Path:
    return REQUEST_DIR / f"{sample_id}.request.json"


def result_path(sample_id: str) -> Path:
    return RESULT_DIR / f"{sample_id}.report.json"


def artifacts_path(sample_id: str) -> Path:
    return ARTIFACTS_DIR / sample_id


def pdf_path(sample_id: str) -> Path:
    return PDF_DIR / f"{sample_id}.report.pdf"


def build_request_payload(row) -> dict:
    sample_id, sha256, filename, uploaded_at, storage_path, status = row
    return {
        "schema_version": "1.0",
        "job_id": sample_id,
        "sample": {
            "sample_id": sample_id,
            "name": filename,
            "file_path": storage_path,
            "sha256": sha256,
            "uploaded_at": uploaded_at,
        },
        "apk_meta": {
            "package_name": None,
            "version_name": None,
            "version_code": None,
            "arch_hint": "unknown",
        },
        "options": {
            "run_static_scan": True,
            "run_behavior_analysis": False,
            "severity_threshold": "medium",
        },
    }


def save_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def generate_pdf_report(sample_row, report: dict, output_pdf_path: Path) -> None:
    """Backward-compatible public wrapper used by tasks.py and main.py."""
    _generate_structured_pdf(sample_row, report, output_pdf_path)
