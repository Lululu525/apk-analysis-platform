from pathlib import Path
from datetime import datetime, timezone
from typing import Any
import hashlib
import json

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


def safe_text(value: Any) -> str:
    if value is None:
        return "-"
    return str(value)


def escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def write_minimal_pdf(path: Path, title: str, lines: list[str]) -> None:
    content_lines = []
    y = 800

    content_lines.append("BT")
    content_lines.append("/F1 18 Tf")
    content_lines.append(f"50 {y} Td")
    content_lines.append(f"({escape_pdf_text(title)}) Tj")
    content_lines.append("ET")

    y -= 30
    for line in lines:
        if y < 50:
            break
        content_lines.append("BT")
        content_lines.append("/F1 11 Tf")
        content_lines.append(f"50 {y} Td")
        content_lines.append(f"({escape_pdf_text(line)}) Tj")
        content_lines.append("ET")
        y -= 16

    stream = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects = []

    def add_obj(obj_bytes: bytes) -> None:
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


def generate_pdf_report(sample_row, report: dict, output_pdf_path: Path) -> None:
    sample_id, sha256, filename, uploaded_at, storage_path, status = sample_row

    summary = report.get("summary", {}) or {}
    counts = summary.get("counts", {}) or {}
    findings = report.get("findings", []) or []
    errors = report.get("errors", []) or []

    lines = [
        f"Sample ID: {sample_id}",
        f"Filename: {filename}",
        f"Uploaded At: {uploaded_at}",
        f"Status: {safe_text(report.get('status', status))}",
        f"Risk Score: {safe_text(summary.get('risk_score'))}",
        f"Risk Level: {safe_text(summary.get('risk_level'))}",
        "",
        f"Critical: {safe_text(counts.get('critical', 0))}",
        f"High: {safe_text(counts.get('high', 0))}",
        f"Medium: {safe_text(counts.get('medium', 0))}",
        f"Low: {safe_text(counts.get('low', 0))}",
        f"Info: {safe_text(counts.get('info', 0))}",
        "",
        "Findings:",
    ]

    if findings:
        for index, finding in enumerate(findings, start=1):
            lines.append(
                f"{index}. [{safe_text(finding.get('severity', 'info')).upper()}] "
                f"{safe_text(finding.get('title', 'Untitled Finding'))}"
            )
            lines.append(f"   ID: {safe_text(finding.get('id'))}")
            lines.append(f"   Desc: {safe_text(finding.get('description'))}")
    else:
        lines.append("No findings.")

    lines.append("")
    lines.append("Errors:")
    if errors:
        for index, error in enumerate(errors, start=1):
            lines.append(f"{index}. {safe_text(error)}")
    else:
        lines.append("No errors.")

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        output_pdf_path.parent.mkdir(parents=True, exist_ok=True)

        c = canvas.Canvas(str(output_pdf_path), pagesize=A4)
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
        write_minimal_pdf(output_pdf_path, "APK Analysis Report", lines)