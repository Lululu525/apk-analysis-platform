import os
import sys
import subprocess

from celery_app import celery_app
from apps.api.db import get_sample_by_id, update_sample_status
from apps.api.service import (
    AI_MODEL_ROOT,
    build_request_payload,
    save_json,
    load_json,
    request_path,
    result_path,
    artifacts_path,
    pdf_path,
    generate_pdf_report,
)

MODEL_PYTHON = os.getenv("MODEL_PYTHON", sys.executable)
MODEL_MODULE = os.getenv("MODEL_MODULE", "app.main")


@celery_app.task(bind=True)
def analyze_sample_task(self, sample_id: str) -> dict:
    row = get_sample_by_id(sample_id)
    if not row:
        return {
            "sample_id": sample_id,
            "status": "failed",
            "error": "Sample not found",
        }

    req_path = request_path(sample_id)
    rep_path = result_path(sample_id)
    art_path = artifacts_path(sample_id)
    out_pdf_path = pdf_path(sample_id)

    request_payload = build_request_payload(row)
    save_json(req_path, request_payload)
    art_path.mkdir(parents=True, exist_ok=True)

    update_sample_status(sample_id, "running")

    cmd = [
        MODEL_PYTHON,
        "-m",
        MODEL_MODULE,
        "--in",
        str(req_path),
        "--out",
        str(rep_path),
        "--artifacts",
        str(art_path),
    ]

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            cwd=str(AI_MODEL_ROOT),
        )

        if not rep_path.exists():
            update_sample_status(sample_id, "failed")
            return {
                "sample_id": sample_id,
                "status": "failed",
                "stderr": "Analysis finished but report.json was not generated.",
                "stdout": completed.stdout,
                "command": cmd,
            }

        report = load_json(rep_path)
        generate_pdf_report(row, report, out_pdf_path)
        update_sample_status(sample_id, "finished")

        return {
            "sample_id": sample_id,
            "status": "finished",
            "result_path": str(rep_path),
            "artifacts_path": str(art_path),
            "pdf_path": str(out_pdf_path) if out_pdf_path.exists() else None,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "command": cmd,
        }

    except subprocess.CalledProcessError as exc:
        update_sample_status(sample_id, "failed")
        return {
            "sample_id": sample_id,
            "status": "failed",
            "stdout": exc.stdout,
            "stderr": exc.stderr,
            "command": cmd,
        }

    except FileNotFoundError as exc:
        update_sample_status(sample_id, "failed")
        return {
            "sample_id": sample_id,
            "status": "failed",
            "stdout": "",
            "stderr": str(exc),
            "command": cmd,
        }