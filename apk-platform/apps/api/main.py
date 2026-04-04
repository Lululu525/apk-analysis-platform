from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from celery.result import AsyncResult
import uuid
import math
import json

from celery_app import celery_app
from .tasks import analyze_sample_task
from .db import (
    init_db,
    insert_sample,
    get_sample_by_id,
    update_sample_status,
    count_samples,
    list_samples_paginated,
)
from .service import (
    STORAGE_DIR,
    sha256_bytes,
    utc_now_iso,
    request_path as _request_path,
    result_path as _result_path,
    artifacts_path as _artifacts_path,
    pdf_path as _pdf_path,
    build_request_payload as _build_request_payload,
    save_json as _save_json,
    load_json as _load_json_or_500,
    generate_pdf_report as _generate_pdf_report,
    ensure_directories,
)


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
    ensure_directories()
    init_db()


@app.get("/")
def root():
    return {
        "message": "APK Analysis Platform API is running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


def _row_or_404(sample_id: str):
    row = get_sample_by_id(sample_id)
    if not row:
        raise HTTPException(status_code=404, detail="Sample not found")
    return row


def _serialize_sample_row(row) -> dict:
    return {
        "sample_id": row[0],
        "sha256": row[1],
        "filename": row[2],
        "uploaded_at": row[3],
        "storage_path": row[4],
        "status": row[5],
    }


def _ensure_pdf_for_sample(sample_row):
    sample_id = sample_row[0]
    rep_path = _result_path(sample_id)
    out_pdf_path = _pdf_path(sample_id)

    if out_pdf_path.exists():
        return out_pdf_path

    if not rep_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Result not generated yet, PDF unavailable",
        )

    report = _load_json_or_500(rep_path)
    _generate_pdf_report(sample_row, report, out_pdf_path)
    return out_pdf_path


@app.post("/v1/samples/upload", response_model=UploadResponse)
async def upload_apk(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk is allowed")

    data = await file.read()
    if len(data) < 1024:
        raise HTTPException(
            status_code=400,
            detail="File too small to be a valid APK",
        )

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
    query: str = Query(
        default="",
        description="Search keyword for filename or sample id",
    ),
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
    req_path = _request_path(sample_id)

    if not req_path.exists():
        payload = _build_request_payload(row)
        _save_json(req_path, payload)

    return _load_json_or_500(req_path)


@app.get("/v1/samples/{sample_id}/result")
def get_sample_result(sample_id: str):
    row = _row_or_404(sample_id)
    rep_path = _result_path(sample_id)
    out_pdf_path = _pdf_path(sample_id)

    if not rep_path.exists():
        return {
            "sample_id": row[0],
            "status": row[5],
            "result_ready": False,
            "message": "Result not generated yet.",
        }

    report = _load_json_or_500(rep_path)
    artifacts = report.get("artifacts", {}) or {}
    artifacts["pdf_path"] = str(out_pdf_path) if out_pdf_path.exists() else None
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
    out_pdf_path = _ensure_pdf_for_sample(row)

    if not out_pdf_path.exists():
        raise HTTPException(status_code=404, detail="PDF file not found")

    download_name = f"{row[2]}.report.pdf"
    return FileResponse(
        path=str(out_pdf_path),
        media_type="application/pdf",
        filename=download_name,
    )


@app.post("/v1/samples/{sample_id}/run-analysis")
def run_analysis(sample_id: str):
    _row_or_404(sample_id)

    update_sample_status(sample_id, "queued")
    task = analyze_sample_task.delay(sample_id)

    return {
        "sample_id": sample_id,
        "status": "queued",
        "task_id": task.id,
        "message": "Analysis task has been queued.",
    }


@app.get("/v1/tasks/{task_id}")
def get_task_status(task_id: str):
    result = AsyncResult(task_id, app=celery_app)

    response = {
        "task_id": task_id,
        "state": result.state,
    }

    if result.successful():
        response["result"] = result.result
    elif result.failed():
        response["error"] = str(result.result)

    return response


@app.post("/v1/samples/{sample_id}/run-mock")
def run_mock(sample_id: str):
    row = _row_or_404(sample_id)

    req_path = _request_path(sample_id)
    rep_path = _result_path(sample_id)
    art_path = _artifacts_path(sample_id)
    out_pdf_path = _pdf_path(sample_id)

    art_path.mkdir(parents=True, exist_ok=True)

    request_payload = _build_request_payload(row)
    _save_json(req_path, request_payload)

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
            "risk_level": "High",
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
                "remediation": (
                    "Review the requested permissions and verify whether they are necessary."
                ),
            }
        ],
        "artifacts": {
            "logs_path": None,
            "extracted_path": None,
            "features_path": str(art_path / f"{sample_id}.features.json"),
            "pdf_path": str(out_pdf_path),
        },
        "errors": [],
    }

    _save_json(rep_path, report_payload)

    _save_json(
        art_path / f"{sample_id}.features.json",
        {
            "sample_id": sample_id,
            "permissions": ["READ_SMS", "ACCESS_FINE_LOCATION"],
            "api_calls": [
                "SmsManager.sendTextMessage",
                "LocationManager.getLastKnownLocation",
            ],
        },
    )

    _generate_pdf_report(row, report_payload, out_pdf_path)
    update_sample_status(sample_id, "finished")

    return {
        "sample_id": sample_id,
        "status": "finished",
        "request_path": str(req_path),
        "result_path": str(rep_path),
        "artifacts_path": str(art_path),
        "pdf_path": str(out_pdf_path),
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