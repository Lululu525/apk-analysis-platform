"""Regenerate one or all stored APK PDF reports.

Usage:
    python regenerate_reports.py
    python regenerate_reports.py <sample_id>
"""

from __future__ import annotations

from pathlib import Path
import argparse
import sys


ROOT = Path(__file__).resolve().parent
API_ROOT = ROOT / "apk-platform"
sys.path.insert(0, str(API_ROOT))

from apps.api.db import get_connection, get_sample_by_id  # noqa: E402
from apps.api.service import generate_pdf_report, load_json, pdf_path, result_path  # noqa: E402


def _rows(sample_id: str | None):
    if sample_id:
        row = get_sample_by_id(sample_id)
        return [row] if row else []
    with get_connection() as connection:
        return connection.execute(
            "SELECT sample_id, sha256, filename, uploaded_at, storage_path, status FROM samples ORDER BY uploaded_at"
        ).fetchall()


def regenerate(sample_id: str | None = None) -> int:
    rows = _rows(sample_id)
    if sample_id and not rows:
        print(f"Sample not found: {sample_id}", file=sys.stderr)
        return 1
    generated = 0
    skipped = 0
    for row in rows:
        report_file = result_path(row[0])
        if not report_file.is_file():
            print(f"[SKIP] {row[0]}: report.json not available")
            skipped += 1
            continue
        output = pdf_path(row[0])
        generate_pdf_report(row, load_json(report_file), output)
        print(f"[OK] {row[0]} -> {output}")
        generated += 1
    print(f"Generated: {generated}; skipped: {skipped}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Regenerate stored security-report PDFs")
    parser.add_argument("sample_id", nargs="?")
    args = parser.parse_args()
    raise SystemExit(regenerate(args.sample_id))
