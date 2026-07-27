"""Structured, Unicode-capable APK security PDF reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable
import json

from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate,
    PageBreak,
    Paragraph,
    Table,
    TableStyle,
)
from xml.sax.saxutils import escape


NAVY = colors.HexColor("#0B2239")
TEXT = colors.HexColor("#182534")
MUTED = colors.HexColor("#607086")
BORDER = colors.HexColor("#CAD6E2")
ORANGE = colors.HexColor("#F5A15F")


def _register_fonts() -> tuple[str, str]:
    """Register a CJK font available on Windows, with portable fallbacks."""
    candidates = [
        ("C:/Windows/Fonts/msjh.ttc", "C:/Windows/Fonts/msjhbd.ttc"),
        ("C:/Windows/Fonts/mingliu.ttc", "C:/Windows/Fonts/mingliub.ttc"),
        ("C:/Windows/Fonts/simsun.ttc", "C:/Windows/Fonts/simhei.ttf"),
        ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ]
    for regular, bold in candidates:
        if Path(regular).exists():
            try:
                pdfmetrics.registerFont(TTFont("ReportUnicode", regular, subfontIndex=0))
                bold_path = bold if Path(bold).exists() else regular
                pdfmetrics.registerFont(TTFont("ReportUnicodeBold", bold_path, subfontIndex=0))
                return "ReportUnicode", "ReportUnicodeBold"
            except Exception:
                continue
    return "Helvetica", "Helvetica-Bold"


FONT, FONT_BOLD = _register_fonts()


def _value(value: Any, default: str = "Not available") -> str:
    if value is None or value == "" or value == [] or value == {}:
        return default
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    text = _value(value)
    return Paragraph(escape(text).replace("\n", "<br/>"), style)


def _read_json(path: Any) -> dict[str, Any]:
    if not path:
        return {}
    try:
        candidate = Path(str(path))
        return json.loads(candidate.read_text(encoding="utf-8")) if candidate.is_file() else {}
    except (OSError, ValueError, TypeError):
        return {}


def _artifact_json(report: dict[str, Any], artifact_dir: Path, key: str, suffix: str) -> dict[str, Any]:
    artifacts = report.get("artifacts") or {}
    explicit = _read_json(artifacts.get(key))
    if explicit:
        return explicit
    sample_id = str(report.get("job_id") or "")
    return _read_json(artifact_dir / f"{sample_id}.{suffix}")


def download_filename(original_filename: str) -> str:
    """Return a Unicode-safe, non-duplicated report download name."""
    name = Path(original_filename or "report").name
    stem = name[:-4] if name.lower().endswith(".apk") else name
    return f"{stem}_security_report.pdf"


def _decorate_page(canvas, doc) -> None:
    width, height = A4
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, height - 18 * mm, width, 18 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont(FONT_BOLD, 10)
    canvas.drawString(16 * mm, height - 11.5 * mm, "APK Risk Analysis Platform")
    canvas.setFont(FONT, 7.5)
    canvas.drawRightString(
        width - 16 * mm,
        height - 11.5 * mm,
        "Reverse Engineering + Privilege Escalation + ML Risk Scoring",
    )
    canvas.setFillColor(MUTED)
    canvas.setFont(FONT, 8)
    canvas.drawString(16 * mm, 10 * mm, f"Generated report | Page {doc.page}")
    canvas.restoreState()


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("Title", parent=base["Title"], fontName=FONT_BOLD, fontSize=22, leading=27, textColor=NAVY, alignment=TA_LEFT, spaceAfter=6),
        "subtitle": ParagraphStyle("Subtitle", parent=base["BodyText"], fontName=FONT, fontSize=8.5, leading=12, textColor=MUTED, spaceAfter=8),
        "h1": ParagraphStyle("H1", parent=base["Heading1"], fontName=FONT_BOLD, fontSize=14, leading=18, textColor=NAVY, spaceBefore=7, spaceAfter=7),
        "h2": ParagraphStyle("H2", parent=base["Heading2"], fontName=FONT_BOLD, fontSize=10, leading=13, textColor=NAVY, spaceBefore=3, spaceAfter=4),
        "body": ParagraphStyle("Body", parent=base["BodyText"], fontName=FONT, fontSize=8.2, leading=11, textColor=TEXT, spaceAfter=4),
        "small": ParagraphStyle("Small", parent=base["BodyText"], fontName=FONT, fontSize=7.2, leading=9.2, textColor=TEXT),
        "header": ParagraphStyle("Header", parent=base["BodyText"], fontName=FONT_BOLD, fontSize=7.4, leading=9.2, textColor=colors.white),
    }


def _table(rows: list[list[Any]], widths: list[float], styles: dict[str, ParagraphStyle], header: bool = True) -> Table:
    data: list[list[Paragraph]] = []
    for row_index, row in enumerate(rows):
        style = styles["header"] if header and row_index == 0 else styles["small"]
        data.append([_paragraph(cell, style) for cell in row])
    table = Table(data, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    commands = [
        ("GRID", (0, 0), (-1, -1), 0.45, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        commands.extend([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)])
    table.setStyle(TableStyle(commands))
    return table


def _flatten_evidence(evidence: Any) -> list[str]:
    if evidence is None:
        return []
    if isinstance(evidence, dict):
        values: list[str] = []
        for key, value in evidence.items():
            if isinstance(value, list):
                values.extend(f"{key}: {_value(item)}" for item in value)
            else:
                values.append(f"{key}: {_value(value)}")
        return values
    if isinstance(evidence, list):
        return [_value(item) for item in evidence]
    return [_value(evidence)]


def _risk_chart(findings: list[dict[str, Any]], styles: dict[str, ParagraphStyle]) -> Drawing:
    levels = ["High", "Medium", "Low"]
    values = [sum(len(_flatten_evidence(f.get("evidence"))) for f in findings if str(f.get("severity", "")).lower() == level.lower()) for level in levels]
    drawing = Drawing(470, 120)
    chart = HorizontalBarChart()
    chart.x = 85
    chart.y = 20
    chart.height = 78
    chart.width = 350
    chart.data = [values]
    chart.categoryAxis.categoryNames = levels
    chart.categoryAxis.labels.fontName = FONT_BOLD
    chart.categoryAxis.labels.fontSize = 8
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(max(values, default=0), 1)
    chart.valueAxis.visible = False
    chart.bars[0].fillColor = ORANGE
    chart.barWidth = 10
    drawing.add(chart)
    drawing.add(String(0, 108, "Evidence Used Count by Finding Risk Level", fontName=FONT_BOLD, fontSize=9, fillColor=NAVY))
    return drawing


def _feature_value(features: dict[str, Any], *paths: Iterable[str]) -> Any:
    for path in paths:
        current: Any = features
        for key in path:
            current = current.get(key) if isinstance(current, dict) else None
        if current not in (None, "", [], {}):
            return current
    return None


def generate_pdf_report(sample_row, report: dict[str, Any], output_pdf_path: Path) -> None:
    sample_id, _sha256, filename, uploaded_at, _storage_path, status = sample_row
    artifact_dir = output_pdf_path.parents[1] / "artifacts" / str(sample_id)
    features = _artifact_json(report, artifact_dir, "features_path", "features.json")
    ml_predictions = _artifact_json(report, artifact_dir, "ml_predictions_path", "ml_predictions.json")
    findings = [item for item in (report.get("findings") or []) if isinstance(item, dict)]
    summary = report.get("summary") or {}
    styles = _styles()
    story: list[Any] = []

    manifest = features.get("manifest_analysis") or {}
    package_name = manifest.get("package_name") or _feature_value(features, ("apk", "package_name"))
    application = manifest.get("app_name") or Path(str(filename)).stem
    generated = report.get("finished_at") or report.get("started_at") or uploaded_at
    scoring_method = summary.get("scoring_method") or report.get("scoring_method")
    formula = summary.get("formula") or report.get("formula")

    story.extend([
        Paragraph("APK Security Analysis Report", styles["title"]),
        Paragraph("Privilege escalation, sensitive API exposure and ML-assisted risk assessment", styles["subtitle"]),
        _table([
            ["Application", application, "Package", package_name],
            ["File", filename, "Generated", generated],
            ["Risk Score", summary.get("risk_score"), "Risk Level", summary.get("risk_level")],
            ["Scoring Method", scoring_method, "Formula", formula],
        ], [28*mm, 61*mm, 32*mm, 57*mm], styles, header=False),
        Paragraph("Executive Summary", styles["h1"]),
        Paragraph(
            f"Analysis status: {_value(report.get('status') or status)}. "
            f"The report contains {len(findings)} recorded finding(s). Values shown below come from the analysis report and available artifacts; unavailable modules are not estimated.",
            styles["body"],
        ),
        Paragraph("Risk Score Breakdown", styles["h1"]),
    ])
    breakdown: dict[str, Any] = {}
    for finding in findings:
        for key, value in (finding.get("score_breakdown") or {}).items():
            if isinstance(value, (int, float)):
                breakdown[key] = round(float(breakdown.get(key, 0)) + value, 4)
    rows = [["Evidence Category", "Points"]] + ([[k.replace("_", " ").title(), v] for k, v in breakdown.items()] if breakdown else [["Finding score breakdown", "Not available"]])
    story.extend([_table(rows, [135*mm, 43*mm], styles), PageBreak()])

    evidence_counts = {level: sum(len(_flatten_evidence(f.get("evidence"))) for f in findings if str(f.get("severity", "")).lower() == level.lower()) for level in ("high", "medium", "low")}
    finding_counts = {level: sum(1 for f in findings if str(f.get("severity", "")).lower() == level) for level in ("high", "medium", "low")}
    permissions = manifest.get("permissions") or features.get("permissions")
    exported = manifest.get("exported_components") or features.get("exported_components")
    sensitive_hits = features.get("api_calls") or _feature_value(features, ("sensitive_api_hits",), ("api", "hits"))
    story.extend([
        Paragraph("Evidence Used by Risk Level", styles["h1"]),
        _risk_chart(findings, styles),
        _table([["Risk Level", "Finding Count", "Evidence Used Count"]] + [[level.title(), finding_counts[level], evidence_counts[level]] for level in ("high", "medium", "low")], [60*mm, 59*mm, 59*mm], styles),
        Paragraph("Core Extracted Features", styles["h1"]),
        _table([
            ["Feature", "Value"],
            ["Permission Count", manifest.get("permissions_count") if manifest else (len(permissions) if isinstance(permissions, list) else None)],
            ["Dangerous Permission Count", features.get("dangerous_permission_count")],
            ["Sensitive API Hits", len(sensitive_hits) if isinstance(sensitive_hits, list) else sensitive_hits],
            ["Exported Components", manifest.get("exported_count") if manifest else (len(exported) if isinstance(exported, list) else None)],
            ["Strings Count", _feature_value(features, ("stats", "strings_count"))],
            ["ML Prediction Artifact", "Available" if ml_predictions else "Not available"],
        ], [102*mm, 76*mm], styles),
        Paragraph("User Recommendations", styles["h1"]),
    ])
    recommendations = [f.get("remediation") for f in findings if f.get("remediation")]
    if recommendations:
        for recommendation in recommendations:
            story.append(Paragraph(f"- {escape(str(recommendation))}", styles["body"]))
    else:
        story.append(Paragraph("Not available", styles["body"]))
    story.append(PageBreak())

    overview_rows = [
        ["Module", "Status / Score", "Summary"],
        ["Static Analysis", report.get("status") or status, "Permissions, components, strings and rule findings"],
        ["ML Risk Scoring", "Available" if ml_predictions else "Not available", "Loaded only from ML prediction artifacts"],
        ["Sandbox", "Not run", "Dynamic sandbox analysis is not executed by the current pipeline"],
        ["Community Insight", "Not available", "No community insight data source is currently connected"],
    ]
    finding_rows = [["#", "Severity", "Finding", "Explanation", "Evidence Used"]]
    if findings:
        for index, finding in enumerate(findings, 1):
            finding_rows.append([index, finding.get("severity"), finding.get("title"), finding.get("description"), "; ".join(_flatten_evidence(finding.get("evidence"))) or "Not available"])
    else:
        finding_rows.append(["-", "Not available", "No findings recorded", "Not available", "Not available"])
    story.extend([
        Paragraph("Overview Modules", styles["h1"]),
        _table(overview_rows, [38*mm, 35*mm, 105*mm], styles),
        Paragraph("Security Findings", styles["h1"]),
        _table(finding_rows, [8*mm, 20*mm, 38*mm, 55*mm, 57*mm], styles),
        Paragraph("Dangerous Permissions", styles["h1"]),
        _table([["Permission"]] + ([[item] for item in permissions] if isinstance(permissions, list) and permissions else [["Not available"]]), [178*mm], styles),
        PageBreak(),
    ])

    artifacts = report.get("artifacts") or {}
    reverse_rows = [
        ["Layer", "Status / Count", "Purpose"],
        ["Extracted APK", "Available" if artifacts.get("extracted_path") and Path(str(artifacts.get("extracted_path"))).exists() else "Not available", "Decoded APK content used by static analysis"],
        ["Features JSON", "Available" if features else "Not available", "Structured metadata and extracted feature counts"],
        ["Strings", "Available" if artifacts.get("strings_path") and Path(str(artifacts.get("strings_path"))).exists() else "Not available", "Strings produced by the reverse-engineering pipeline"],
        ["ML predictions", "Available" if ml_predictions else "Not available", "Machine-learning prediction artifact"],
    ]
    story.extend([Paragraph("Sensitive API Hits", styles["h1"])])
    if isinstance(sensitive_hits, list) and sensitive_hits:
        story.append(_table([["API / Evidence"]] + [[hit] for hit in sensitive_hits], [178*mm], styles))
    else:
        story.append(Paragraph("Not available", styles["body"]))
    story.extend([
        Paragraph("Reverse Engineering Evidence", styles["h1"]),
        _table(reverse_rows, [42*mm, 38*mm, 98*mm], styles),
        Paragraph("Methodology", styles["h1"]),
        Paragraph(
            "This report summarizes the existing static APK pipeline output. It reads report.json, finding evidence and score breakdowns, features.json, and ML prediction artifacts when present. Missing or unexecuted data is labeled Not available or Not run; no synthetic scores or findings are introduced.",
            styles["body"],
        ),
        PageBreak(),
    ])

    output_pdf_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(output_pdf_path),
        pagesize=A4,
        leftMargin=16*mm,
        rightMargin=16*mm,
        topMargin=27*mm,
        bottomMargin=18*mm,
        title=download_filename(str(filename)),
        author="APK Risk Analysis Platform",
    )
    doc.build(story, onFirstPage=_decorate_page, onLaterPages=_decorate_page)
