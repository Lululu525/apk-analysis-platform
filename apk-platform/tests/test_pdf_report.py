from pathlib import Path
import sys

from pypdf import PdfReader


API_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(API_ROOT))

from apps.api.pdf_report import download_filename, generate_pdf_report


def _row(filename: str = "DemoRiskyApp.apk"):
    return ("sample-1", "sha256", filename, "2026-07-28T12:00:00+08:00", "sample.apk", "finished")


def _report(finding=None):
    return {
        "job_id": "sample-1",
        "status": "success",
        "finished_at": "2026-07-28T12:10:00+08:00",
        "summary": {"risk_score": 25, "risk_level": "Low", "counts": {"low": 1}},
        "findings": [finding] if finding else [],
        "artifacts": {},
        "errors": [],
    }


def test_pdf_is_generated_non_empty_and_multi_page(tmp_path):
    output = tmp_path / "report.pdf"
    generate_pdf_report(_row(), _report(), output)
    assert output.stat().st_size > 0
    assert len(PdfReader(str(output)).pages) >= 4


def test_finding_without_evidence_and_chinese_content(tmp_path):
    output = tmp_path / "中文報告.pdf"
    finding = {
        "id": "ZH-001",
        "severity": "medium",
        "title": "中文安全發現",
        "description": "此元件可能暴露敏感資料。",
        "remediation": "請限制匯出元件的存取權限。",
    }
    generate_pdf_report(_row("測試應用程式.apk"), _report(finding), output)
    assert output.is_file()
    assert output.stat().st_size > 0


def test_missing_artifacts_are_labeled_not_available(tmp_path):
    output = tmp_path / "report.pdf"
    generate_pdf_report(_row(), _report(), output)
    text = "\n".join(page.extract_text() or "" for page in PdfReader(str(output)).pages)
    assert "Not available" in text


def test_download_filename_removes_apk_extension():
    assert download_filename("DemoRiskyApp.apk") == "DemoRiskyApp_security_report.pdf"
    assert download_filename("中文檔名.APK") == "中文檔名_security_report.pdf"
    assert download_filename("sample") == "sample_security_report.pdf"


def test_ml_assessment_is_separate_from_static_findings(tmp_path):
    output = tmp_path / "separate.pdf"
    report = _report({
        "id": "STATIC-001",
        "category": "android_component",
        "severity": "medium",
        "title": "Static finding",
        "evidence": {"component": "ExampleActivity"},
    })
    report["findings"].append({
        "id": "ML_RISK_ASSESSMENT",
        "category": "ml_risk_assessment",
        "severity": "info",
        "title": "ML model risk assessment",
        "evidence": {
            "app_risk_probability": 0.75,
            "model_version": "test-model",
            "component_predictions": [{"row_id": "must-not-be-expanded"}],
        },
    })
    generate_pdf_report(_row(), report, output)
    text = "\n".join(page.extract_text() or "" for page in PdfReader(str(output)).pages)
    assert "Machine Learning Assessment" in text
    assert "Static finding" in text
    assert "test-model" in text
    assert "must-not-be-expanded" not in text
