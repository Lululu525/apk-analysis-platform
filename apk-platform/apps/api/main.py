from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import uuid
import json
import subprocess
import os
import math
from typing import Any

from .db import (
    init_db,
    insert_sample,
    get_sample_by_id,
    update_sample_status,
    count_samples,
    list_samples_paginated,
)

APP_ROOT = Path(__file__).resolve().parents[2]
STORAGE_DIR = APP_ROOT / "storage" / "objects" / "apks"
REQUEST_DIR = APP_ROOT / "metadata" / "requests"
RESULT_DIR = APP_ROOT / "metadata" / "results"
ARTIFACTS_DIR = APP_ROOT / "metadata" / "artifacts"
PDF_DIR = APP_ROOT / "metadata" / "pdfs"

AI_MODEL_ROOT = APP_ROOT.parent / "AI-model"
MODEL_PYTHON = os.getenv("MODEL_PYTHON", "python")
MODEL_MODULE = os.getenv("MODEL_MODULE", "app.main")

app = FastAPI(title="APK Analysis Platform API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class UploadResponse(BaseModel):
    sample_id: str
    sha256: str
    filename: str
    status: str


class StatusUpdateRequest(BaseModel):
    status: str


ALLOWED_STATUSES = {"received", "queued", "running", "finished", "failed"}


@app.on_event("startup")
def on_startup():
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    REQUEST_DIR.mkdir(parents=True, exist_ok=True)
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    PDF_DIR.mkdir(parents=True, exist_ok=True)
    init_db()


def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_or_404(sample_id: str):
    row = get_sample_by_id(sample_id)
    if not row:
        raise HTTPException(status_code=404, detail="Sample not found")
    return row


def _request_path(sample_id: str) -> Path:
    return REQUEST_DIR / f"{sample_id}.request.json"


def _result_path(sample_id: str) -> Path:
    return RESULT_DIR / f"{sample_id}.report.json"


def _artifacts_path(sample_id: str) -> Path:
    return ARTIFACTS_DIR / sample_id


def _pdf_path(sample_id: str) -> Path:
    return PDF_DIR / f"{sample_id}.report.pdf"


def _build_request_payload(row) -> dict:
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


def _save_json(path: Path, obj: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_json_or_500(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Invalid JSON file: {path.name}") from exc


def _serialize_sample_row(row) -> dict:
    return {
        "sample_id": row[0],
        "sha256": row[1],
        "filename": row[2],
        "uploaded_at": row[3],
        "storage_path": row[4],
        "status": row[5],
    }


def _safe_text(value: Any) -> str:
    if value is None:
        return "-"
    return str(value)


def _escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _write_minimal_pdf(path: Path, title: str, lines: list[str]):
    content_lines = []
    y = 800

    content_lines.append("BT")
    content_lines.append("/F1 18 Tf")
    content_lines.append(f"50 {y} Td")
    content_lines.append(f"({_escape_pdf_text(title)}) Tj")
    content_lines.append("ET")

    y -= 30
    for line in lines:
        if y < 50:
            break
        content_lines.append("BT")
        content_lines.append("/F1 11 Tf")
        content_lines.append(f"50 {y} Td")
        content_lines.append(f"({_escape_pdf_text(line)}) Tj")
        content_lines.append("ET")
        y -= 16

    stream = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects = []

    def add_obj(obj_bytes: bytes):
        objects.append(obj_bytes)

    add_obj(b"<< /Type /Catalog /Pages 2 0 R >>")
    add_obj(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    add_obj(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"
    )
    add_obj(
        b"<< /Length "
        + str(len(stream)).encode("ascii")
        + b" >>\nstream\n"
        + stream
        + b"\nendstream"
    )
    add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    pdf = bytearray()
    pdf.extend(b"%PDF-1.4\n")

    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode("ascii"))
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")

    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))

    pdf.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF"
        ).encode("ascii")
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pdf)


def _generate_pdf_report(sample_row, report: dict, pdf_path: Path):
    sample_id, sha256, filename, uploaded_at, storage_path, status = sample_row

    summary = report.get("summary", {}) or {}
    counts = summary.get("counts", {}) or {}
    findings = report.get("findings", []) or []
    errors = report.get("errors", []) or []

    lines = [
        f"Sample ID: {sample_id}",
        f"Filename: {filename}",
        f"Uploaded At: {uploaded_at}",
        f"Status: {_safe_text(report.get('status', status))}",
        f"Risk Score: {_safe_text(summary.get('risk_score'))}",
        "",
        f"Critical: {_safe_text(counts.get('critical', 0))}",
        f"High: {_safe_text(counts.get('high', 0))}",
        f"Medium: {_safe_text(counts.get('medium', 0))}",
        f"Low: {_safe_text(counts.get('low', 0))}",
        f"Info: {_safe_text(counts.get('info', 0))}",
        "",
        "Findings:",
    ]

    if findings:
        for index, finding in enumerate(findings, start=1):
            lines.append(
                f"{index}. [{_safe_text(finding.get('severity', 'info')).upper()}] "
                f"{_safe_text(finding.get('title', 'Untitled Finding'))}"
            )
            lines.append(f"   ID: {_safe_text(finding.get('id'))}")
            lines.append(f"   Desc: {_safe_text(finding.get('description'))}")
    else:
        lines.append("No findings.")

    lines.append("")
    lines.append("Errors:")
    if errors:
        for index, error in enumerate(errors, start=1):
            lines.append(f"{index}. {_safe_text(error)}")
    else:
        lines.append("No errors.")

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        pdf_path.parent.mkdir(parents=True, exist_ok=True)

        c = canvas.Canvas(str(pdf_path), pagesize=A4)
        _, height = A4
        x = 50
        y = height - 50

        c.setFont("Helvetica-Bold", 18)
        c.drawString(x, y, "APK Analysis Report")
        y -= 28

        c.setFont("Helvetica", 11)
        for line in lines:
            if y < 50:
                c.showPage()
                c.setFont("Helvetica", 11)
                y = height - 50

            c.drawString(x, y, line[:110])
            y -= 16

        c.save()

    except Exception:
        _write_minimal_pdf(pdf_path, "APK Analysis Report", lines)


def _ensure_pdf_for_sample(sample_row) -> Path:
    sample_id = sample_row[0]
    result_path = _result_path(sample_id)
    pdf_path = _pdf_path(sample_id)

    if pdf_path.exists():
        return pdf_path

    if not result_path.exists():
        raise HTTPException(status_code=404, detail="Result not generated yet, PDF unavailable")

    report = _load_json_or_500(result_path)
    _generate_pdf_report(sample_row, report, pdf_path)
    return pdf_path


@app.post("/v1/samples/upload", response_model=UploadResponse)
async def upload_apk(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk is allowed")

    data = await file.read()
    if len(data) < 1024:
        raise HTTPException(status_code=400, detail="File too small to be a valid APK")

    sha256 = sha256_bytes(data)
    sample_id = str(uuid.uuid4())
    storage_path = STORAGE_DIR / f"{sample_id}.apk"
    storage_path.write_bytes(data)
    uploaded_at = utc_now_iso()

    insert_sample(
        sample_id=sample_id,
        sha256=sha256,
        filename=file.filename,
        uploaded_at=uploaded_at,
        storage_path=str(storage_path),
        status="received",
    )

    return UploadResponse(
        sample_id=sample_id,
        sha256=sha256,
        filename=file.filename,
        status="received",
    )


@app.get("/v1/samples/{sample_id}")
def get_sample(sample_id: str):
    row = _row_or_404(sample_id)
    return _serialize_sample_row(row)


@app.get("/v1/samples")
def get_samples(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    query: str = Query(default="", description="Search keyword for filename"),
):
    normalized_query = query.strip()
    total = count_samples(normalized_query if normalized_query else None)
    offset = (page - 1) * page_size

    rows = list_samples_paginated(
        limit=page_size,
        offset=offset,
        query=normalized_query if normalized_query else None,
    )

    items = [_serialize_sample_row(row) for row in rows]
    total_pages = math.ceil(total / page_size) if total > 0 else 1

    return {
        "items": items,
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
        "query": normalized_query,
    }


@app.get("/v1/samples/{sample_id}/status")
def get_sample_status(sample_id: str):
    row = _row_or_404(sample_id)
    return {
        "sample_id": row[0],
        "status": row[5],
        "uploaded_at": row[3],
        "filename": row[2],
    }


@app.get("/v1/samples/{sample_id}/request")
def get_sample_request(sample_id: str):
    row = _row_or_404(sample_id)
    path = _request_path(sample_id)

    if not path.exists():
        payload = _build_request_payload(row)
        _save_json(path, payload)

    return _load_json_or_500(path)


@app.get("/v1/samples/{sample_id}/result")
def get_sample_result(sample_id: str):
    row = _row_or_404(sample_id)
    path = _result_path(sample_id)
    pdf_path = _pdf_path(sample_id)

    if not path.exists():
        return {
            "sample_id": row[0],
            "status": row[5],
            "result_ready": False,
            "message": "Result not generated yet.",
        }

    report = _load_json_or_500(path)
    artifacts = report.get("artifacts", {}) or {}
    artifacts["pdf_path"] = str(pdf_path) if pdf_path.exists() else None
    report["artifacts"] = artifacts

    return {
        "sample_id": row[0],
        "status": row[5],
        "result_ready": True,
        "result": report,
    }


@app.get("/v1/samples/{sample_id}/report.pdf")
def download_sample_pdf(sample_id: str):
    row = _row_or_404(sample_id)
    pdf_path = _ensure_pdf_for_sample(row)

    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="PDF file not found")

    download_name = f"{row[2]}.report.pdf"
    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=download_name,
    )


@app.post("/v1/samples/{sample_id}/run-analysis")
def run_analysis(sample_id: str):
    row = _row_or_404(sample_id)

    request_path = _request_path(sample_id)
    result_path = _result_path(sample_id)
    artifacts_path = _artifacts_path(sample_id)
    pdf_path = _pdf_path(sample_id)

    request_payload = _build_request_payload(row)
    _save_json(request_path, request_payload)
    artifacts_path.mkdir(parents=True, exist_ok=True)

    update_sample_status(sample_id, "running")

    cmd = [
        MODEL_PYTHON,
        "-m",
        MODEL_MODULE,
        "--in",
        str(request_path),
        "--out",
        str(result_path),
        "--artifacts",
        str(artifacts_path),
    ]

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            cwd=str(AI_MODEL_ROOT),
        )

        update_sample_status(sample_id, "finished")

        if result_path.exists():
            report = _load_json_or_500(result_path)
            _generate_pdf_report(row, report, pdf_path)

        return {
            "sample_id": sample_id,
            "status": "finished",
            "request_path": str(request_path),
            "result_path": str(result_path),
            "artifacts_path": str(artifacts_path),
            "pdf_path": str(pdf_path) if pdf_path.exists() else None,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "command": cmd,
        }

    except subprocess.CalledProcessError as exc:
        update_sample_status(sample_id, "failed")
        return {
            "sample_id": sample_id,
            "status": "failed",
            "request_path": str(request_path),
            "result_path": str(result_path),
            "artifacts_path": str(artifacts_path),
            "pdf_path": None,
            "stdout": exc.stdout,
            "stderr": exc.stderr,
            "command": cmd,
        }
    except FileNotFoundError as exc:
        update_sample_status(sample_id, "failed")
        return {
            "sample_id": sample_id,
            "status": "failed",
            "request_path": str(request_path),
            "result_path": str(result_path),
            "artifacts_path": str(artifacts_path),
            "pdf_path": None,
            "stdout": "",
            "stderr": str(exc),
            "command": cmd,
        }


@app.post("/v1/samples/{sample_id}/run-mock")
def run_mock(sample_id: str):
    row = _row_or_404(sample_id)

    request_path = _request_path(sample_id)
    result_path = _result_path(sample_id)
    artifacts_path = _artifacts_path(sample_id)
    pdf_path = _pdf_path(sample_id)

    artifacts_path.mkdir(parents=True, exist_ok=True)

    request_payload = _build_request_payload(row)
    _save_json(request_path, request_payload)

    update_sample_status(sample_id, "running")

    report_payload = {
        "schema_version": "1.0",
        "job_id": sample_id,
        "status": "success",
        "started_at": utc_now_iso(),
        "finished_at": utc_now_iso(),
        "summary": {
            "schema_version": "1.0",
            "risk_score": 72,
            "counts": {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 0,
                "info": 1,
            },
        },
        "findings": [
            {
                "id": "DEMO-001",
                "severity": "high",
                "title": "Mock suspicious permission usage",
                "description": "This is a mock finding for end-to-end demo.",
                "remediation": "Review the requested permissions and verify whether they are necessary.",
            }
        ],
        "artifacts": {
            "logs_path": None,
            "extracted_path": None,
            "features_path": str(artifacts_path / f"{sample_id}.features.json"),
            "pdf_path": str(pdf_path),
        },
        "errors": [],
    }

    _save_json(result_path, report_payload)
    _save_json(
        artifacts_path / f"{sample_id}.features.json",
        {
            "sample_id": sample_id,
            "permissions": ["READ_SMS", "ACCESS_FINE_LOCATION"],
            "api_calls": [
                "SmsManager.sendTextMessage",
                "LocationManager.getLastKnownLocation",
            ],
        },
    )

    _generate_pdf_report(row, report_payload, pdf_path)
    update_sample_status(sample_id, "finished")

    return {
        "sample_id": sample_id,
        "status": "finished",
        "request_path": str(request_path),
        "result_path": str(result_path),
        "artifacts_path": str(artifacts_path),
        "pdf_path": str(pdf_path),
    }


@app.patch("/v1/samples/{sample_id}/status")
def patch_sample_status(sample_id: str, body: StatusUpdateRequest):
    new_status = body.status.strip().lower()

    if new_status not in ALLOWED_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Allowed: {sorted(ALLOWED_STATUSES)}",
        )

    updated = update_sample_status(sample_id, new_status)
    if updated == 0:
        raise HTTPException(status_code=404, detail="Sample not found")

    row = _row_or_404(sample_id)
    return _serialize_sample_row(row)