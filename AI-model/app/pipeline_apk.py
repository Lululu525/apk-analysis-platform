"""
APK analysis pipeline.

Steps:
  1. Hash + basic metadata (entry count, declared permissions stub)
  2. Unzip APK → extract .dex / .so / res/ individually
  3. String extraction per file (disassembly-first strategy)
  4. Rule-based scan on combined strings
  5. Network service detection from strings

Note:
  - AndroidManifest.xml inside APK is binary XML; aapt/androguard needed for full parse.
  - .dex string tables are largely ASCII → system `strings` finds them well.
  - .so native libs → objdump .rodata gives cleanest output.
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from .schemas import AnalyzeRequest, AnalyzeReport, Artifacts, Finding
from .detectors.rules import scan_text_for_rules
from .detectors.strings_detector import extract_strings, extract_strings_from_dir
from .detectors.network_detector import scan_strings as net_scan_strings
from .extractors.dex_parser import extract_strings_from_dex
from .extractors.androguard_analyzer import (
    analyze_apk, to_findings as ag_to_findings, ANDROGUARD_AVAILABLE,
)
from .report.builder import build_report


def _now_iso() -> str:
    return datetime.now(timezone(timedelta(hours=8))).isoformat()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


# Files inside APK worth scanning
_SCAN_SUFFIXES = {".dex", ".so", ".xml", ".json", ".txt", ".js", ".html", ".properties", ".conf", ".cfg"}
_SKIP_PREFIXES = {"res/drawable", "res/mipmap", "res/anim", "res/color", "res/raw/"}


def _should_scan_entry(name: str) -> bool:
    name_lower = name.lower()
    for prefix in _SKIP_PREFIXES:
        if name_lower.startswith(prefix):
            return False
    suffix = Path(name).suffix.lower()
    return suffix in _SCAN_SUFFIXES or suffix == ""


def _extract_apk(apk_path: Path, dest: Path) -> tuple[int, list[str]]:
    """
    Unzip APK into dest directory.
    Returns (extracted_count, skipped_list).
    """
    dest.mkdir(parents=True, exist_ok=True)
    extracted = 0
    skipped: list[str] = []

    try:
        with zipfile.ZipFile(apk_path) as zf:
            for entry in zf.infolist():
                if entry.is_dir():
                    continue
                if not _should_scan_entry(entry.filename):
                    skipped.append(entry.filename)
                    continue
                out_path = dest / entry.filename
                out_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    out_path.write_bytes(zf.read(entry.filename))
                    extracted += 1
                except Exception:
                    skipped.append(entry.filename)
    except zipfile.BadZipFile as e:
        return 0, [f"BadZipFile: {e}"]

    return extracted, skipped


def run(req: AnalyzeRequest, output_dir: Path | None = None) -> AnalyzeReport:
    started_at = _now_iso()
    errors: list[str] = []
    findings: list[Finding] = []

    fp = req.firmware.file_path
    if not fp:
        errors.append("firmware.file_path (APK path) is missing.")
        return build_report(req.job_id, started_at, findings, Artifacts(), errors)

    apk_path = Path(fp)
    if not apk_path.exists():
        errors.append(f"APK file not found: {apk_path}")
        return build_report(req.job_id, started_at, findings, Artifacts(), errors)

    # ── 1. Basic metadata ────────────────────────────────────────────────────
    try:
        sha256 = _sha256_file(apk_path)
        size_bytes = apk_path.stat().st_size
        with zipfile.ZipFile(apk_path) as zf:
            all_entries = zf.namelist()
    except Exception as e:
        errors.append(f"failed to read APK: {e}")
        return build_report(req.job_id, started_at, findings, Artifacts(), errors)

    # ── 2. Unzip into temp dir for per-file scanning ─────────────────────────
    extract_dir: Path | None = None
    strings_list: list[str] = []
    strings_method = "none"
    extracted_count = 0

    if output_dir:
        extract_dir = output_dir / "apk_extracted"
        extracted_count, _ = _extract_apk(apk_path, extract_dir)

    if extract_dir and extract_dir.exists() and extracted_count > 0:
        # .dex → DEX string table parser (accurate, no garbage)
        for dex_file in sorted(extract_dir.rglob("*.dex")):
            dex_strings = extract_strings_from_dex(dex_file, min_len=6, limit=3000)
            strings_list.extend(dex_strings)

        # .so / other non-dex files → disassembly-first strategy
        per_file = extract_strings_from_dir(
            extract_dir,
            min_len=6,
            per_file_limit=1000,
            file_limit=40,
        )
        for fname, s_list in per_file.items():
            if not fname.endswith(".dex"):   # already handled above
                strings_list.extend(s_list)

        strings_method = "dex_parser+per_file"
    else:
        # Fallback: scan the raw APK bytes (less effective but always available)
        strings_list, strings_method = extract_strings(apk_path, min_len=6)

    strings_list = strings_list[:5000]

    # ── 3. Rule-based scan ───────────────────────────────────────────────────
    if req.options.run_static_scan:
        findings.extend(scan_text_for_rules("\n".join(strings_list)))

    # ── 4. Network indicators ────────────────────────────────────────────────
    findings.extend(net_scan_strings(strings_list))

    # ── 5. Androguard: manifest + component + permission analysis ─────────────
    if ANDROGUARD_AVAILABLE:
        ag_result = analyze_apk(apk_path)
        findings.extend(ag_to_findings(ag_result))
        if not ag_result.success:
            # 解析失敗（例如 manifest 非 binary XML）→ info finding，不讓整個 job 失敗
            findings.append(Finding(
                finding_id="ANDROGUARD_PARSE_ERROR",
                title="androguard 無法解析此 APK 的 manifest",
                severity="info",
                confidence=1.0,
                category="analysis_limitation",
                evidence={"errors": (ag_result.errors or [])[:3]},
                remediation="確認 APK 為合法格式；混淆或加固的 APK 可能導致解析失敗。",
            ))
    else:
        findings.append(Finding(
            finding_id="TOOL_ANDROGUARD_MISSING",
            title="androguard 未安裝 — manifest / 權限 / 元件分析略過",
            severity="info",
            confidence=1.0,
            category="analysis_limitation",
            evidence={"hint": "pip install androguard>=4.0"},
            remediation="安裝 androguard 以啟用 AndroidManifest 權限與元件越權分析。",
        ))

    # ── Artifacts ────────────────────────────────────────────────────────────
    artifacts = Artifacts()
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

        features: dict[str, Any] = {
            "job_id": req.job_id,
            "apk": {
                "name": req.firmware.name,
                "sha256": sha256,
                "size_bytes": size_bytes,
                "total_entries": len(all_entries),
                "extracted_for_scan": extracted_count,
            },
            "device_meta": req.device_meta.model_dump() if req.device_meta else None,
            "options": req.options.model_dump(),
            "stats": {
                "strings_count": len(strings_list),
                "strings_method": strings_method,
            },
        }

        features_path = output_dir / f"{req.job_id}.features.json"
        features_path.write_text(json.dumps(features, indent=2, ensure_ascii=False))
        artifacts.features_path = str(features_path)

        strings_path = output_dir / f"{req.job_id}.strings.txt"
        strings_path.write_text("\n".join(strings_list[:2000]), errors="ignore")
        artifacts.strings_path = str(strings_path)

        if extract_dir:
            artifacts.extracted_path = str(extract_dir)

    return build_report(req.job_id, started_at, findings, artifacts, errors)
