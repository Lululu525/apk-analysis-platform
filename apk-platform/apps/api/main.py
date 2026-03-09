from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import uuid
import json
import subprocess
import os

from .db import (
    init_db,
    insert_sample,
    get_sample_by_id,
    list_samples,
    update_sample_status,
)

APP_ROOT = Path(__file__).resolve().parents[2]
STORAGE_DIR = APP_ROOT / "storage" / "objects" / "apks"
REQUEST_DIR = APP_ROOT / "metadata" / "requests"
RESULT_DIR = APP_ROOT / "metadata" / "results"
ARTIFACTS_DIR = APP_ROOT / "metadata" / "artifacts"

<<<<<<< HEAD
# AI-model 專案根目錄
AI_MODEL_ROOT = APP_ROOT.parent / "AI-model"

# 預設使用目前啟動 FastAPI 的 Python
=======
AI_MODEL_ROOT = APP_ROOT.parent / "AI-model"

>>>>>>> 8725b20 (Fix analyzer invocation using python -m app.main)
MODEL_PYTHON = os.getenv("MODEL_PYTHON", "python")

# 使用 module 模式執行 AI-model
MODEL_MODULE = os.getenv("MODEL_MODULE", "app.main")

app = FastAPI(title="APK Analysis Platform API")


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
    return {
        "sample_id": row[0],
        "sha256": row[1],
        "filename": row[2],
        "uploaded_at": row[3],
        "storage_path": row[4],
        "status": row[5],
    }


@app.get("/v1/samples")
def get_samples(limit: int = 20):
    rows = list_samples(limit)
    result = []
    for row in rows:
        result.append(
            {
                "sample_id": row[0],
                "sha256": row[1],
                "filename": row[2],
                "uploaded_at": row[3],
                "storage_path": row[4],
                "status": row[5],
            }
        )
    return result


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

    if not path.exists():
        return {
            "sample_id": row[0],
            "status": row[5],
            "result_ready": False,
            "message": "Result not generated yet.",
        }

    report = _load_json_or_500(path)
    return {
        "sample_id": row[0],
        "status": row[5],
        "result_ready": True,
        "result": report,
    }


@app.post("/v1/samples/{sample_id}/run-analysis")
def run_analysis(sample_id: str):
    row = _row_or_404(sample_id)

    request_path = _request_path(sample_id)
    result_path = _result_path(sample_id)
    artifacts_path = _artifacts_path(sample_id)

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
        return {
            "sample_id": sample_id,
            "status": "finished",
            "request_path": str(request_path),
            "result_path": str(result_path),
            "artifacts_path": str(artifacts_path),
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
            }
        ],
        "artifacts": {
            "logs_path": None,
            "extracted_path": None,
            "features_path": str(artifacts_path / f"{sample_id}.features.json"),
        },
        "errors": [],
    }

    _save_json(result_path, report_payload)
    _save_json(
        artifacts_path / f"{sample_id}.features.json",
        {
            "sample_id": sample_id,
            "permissions": ["READ_SMS", "ACCESS_FINE_LOCATION"],
            "api_calls": ["SmsManager.sendTextMessage", "LocationManager.getLastKnownLocation"],
        },
    )

    update_sample_status(sample_id, "finished")

    return {
        "sample_id": sample_id,
        "status": "finished",
        "request_path": str(request_path),
        "result_path": str(result_path),
        "artifacts_path": str(artifacts_path),
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
    return {
        "sample_id": row[0],
        "sha256": row[1],
        "filename": row[2],
        "uploaded_at": row[3],
        "storage_path": row[4],
        "status": row[5],
    }
