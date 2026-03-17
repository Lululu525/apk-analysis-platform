"""
Firmware analysis pipeline.

Steps:
  1. Hash + entropy quick stats
  2. binwalk extraction  (graceful fallback)
  3. String extraction   (disassembly-first: rodata → system strings → python)
  4. Rule-based scan     (rules.py — includes CWE/CVE)
  5. Network service detection
  6. Filesystem config analysis  (runs only if binwalk extracted a FS)
  7. checksec on extracted ELF binaries
"""
from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from .schemas import AnalyzeRequest, AnalyzeReport, Artifacts, Finding
from .detectors.rules import scan_text_for_rules
from .detectors.strings_detector import extract_strings, extract_strings_from_dir
from .detectors.network_detector import scan_filesystem as net_scan_fs, scan_strings as net_scan_strings
from .detectors.fs_analyzer import scan_filesystem as fs_scan
from .detectors.checksec_detector import scan_directory as checksec_scan_dir
from .extractors.binwalk_extractor import extract as binwalk_extract
from .report.builder import build_report


def _now_iso() -> str:
    return datetime.now(timezone(timedelta(hours=8))).isoformat()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def run(req: AnalyzeRequest, output_dir: Path | None = None) -> AnalyzeReport:
    started_at = _now_iso()
    errors: list[str] = []
    findings: list[Finding] = []

    fp = req.firmware.file_path
    if not fp:
        errors.append("firmware.file_path is missing.")
        return build_report(req.job_id, started_at, findings, Artifacts(), errors)

    firmware_path = Path(fp)
    if not firmware_path.exists():
        errors.append(f"firmware file not found: {firmware_path}")
        return build_report(req.job_id, started_at, findings, Artifacts(), errors)

    # ── 1. Quick stats ───────────────────────────────────────────────────────
    try:
        sha256 = _sha256_file(firmware_path)
        size_bytes = firmware_path.stat().st_size
        raw_head = firmware_path.read_bytes()[:2_000_000]
        entropy = _shannon_entropy(raw_head)
    except Exception as e:
        errors.append(f"failed to read firmware: {e}")
        return build_report(req.job_id, started_at, findings, Artifacts(), errors)

    # ── 1b. Entropy check ────────────────────────────────────────────────────
    # > 7.5 bits/byte = very likely encrypted or packed; warn the user
    # > 7.8 = almost certainly encrypted (random-looking)
    if entropy > 7.5:
        findings.append(Finding(
            finding_id="HIGH_ENTROPY_ENCRYPTED",
            title="Firmware appears to be encrypted or heavily compressed",
            severity="medium",
            confidence=min(1.0, round((entropy - 7.5) / 0.5, 2)),  # scales 0→1 as entropy 7.5→8.0
            category="analysis_limitation",
            cwe=["CWE-311"],
            evidence={
                "entropy_bits_per_byte": round(entropy, 4),
                "threshold": 7.5,
                "note": "Shannon entropy near maximum (8.0) indicates encryption or strong compression. "
                        "Static analysis results may be incomplete.",
            },
            remediation=(
                "Obtain the decryption key or unpack the firmware before analysis. "
                "For QNAP .uxn: the firmware is AES-encrypted; use vendor SDK or known CVE decryptors."
                if ".uxn" in firmware_path.name.lower()
                else "Unpack or decrypt the firmware before static analysis."
            ),
        ))

    # ── 2. binwalk extraction ────────────────────────────────────────────────
    extracted_dir: Path | None = None
    binwalk_signatures: list[str] = []

    if output_dir:
        bw_out = output_dir / "extracted"
        bw_result = binwalk_extract(firmware_path, bw_out)

        if bw_result.tool_missing:
            findings.append(Finding(
                finding_id="TOOL_BINWALK_MISSING",
                title="binwalk not installed — filesystem extraction skipped",
                severity="info",
                confidence=1.0,
                category="analysis_limitation",
                evidence={"hint": "pip install binwalk  or  brew install binwalk"},
                remediation="Install binwalk to enable deep filesystem extraction.",
            ))
        elif not bw_result.success:
            errors.extend(bw_result.errors)
        else:
            extracted_dir = bw_result.extracted_dir
            binwalk_signatures = bw_result.signatures

    # ── 3. String extraction (disassembly-first) ──────────────────────────────
    strings_list: list[str] = []
    strings_method = "none"

    if extracted_dir and extracted_dir.is_dir():
        # Pull strings from every file in the extracted FS
        per_file = extract_strings_from_dir(extracted_dir)
        for s_list in per_file.values():
            strings_list.extend(s_list)
        strings_method = "extracted_fs"
    else:
        # Fall back to analysing the raw firmware blob
        strings_list, strings_method = extract_strings(firmware_path)

    strings_list = strings_list[:5000]  # hard cap

    # ── 4. Rule-based scan ───────────────────────────────────────────────────
    if req.options.run_static_scan:
        text_for_rules = "\n".join(strings_list)
        findings.extend(scan_text_for_rules(text_for_rules))

    # ── 5. Network service detection ─────────────────────────────────────────
    if extracted_dir and extracted_dir.is_dir():
        findings.extend(net_scan_fs(extracted_dir))
    else:
        findings.extend(net_scan_strings(strings_list))

    # ── 6. Filesystem config analysis ────────────────────────────────────────
    if extracted_dir and extracted_dir.is_dir():
        findings.extend(fs_scan(extracted_dir))

    # ── 7. checksec on extracted ELFs ────────────────────────────────────────
    checksec_available = False
    if extracted_dir and extracted_dir.is_dir():
        cs_findings, checksec_available = checksec_scan_dir(extracted_dir)
        findings.extend(cs_findings)
    if not checksec_available:
        findings.append(Finding(
            finding_id="TOOL_CHECKSEC_MISSING",
            title="checksec not installed — binary hardening checks skipped",
            severity="info",
            confidence=1.0,
            category="analysis_limitation",
            evidence={"hint": "brew install checksec"},
            remediation="Install checksec to scan ELF binaries for NX/canary/PIE/RELRO.",
        ))

    # ── Artifacts ────────────────────────────────────────────────────────────
    artifacts = Artifacts()
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

        features: dict[str, Any] = {
            "job_id": req.job_id,
            "firmware": {
                "name": req.firmware.name,
                "sha256": sha256,
                "size_bytes": size_bytes,
            },
            "device_meta": req.device_meta.model_dump() if req.device_meta else None,
            "options": req.options.model_dump(),
            "stats": {
                "entropy_head_2mb": round(entropy, 4),
                "strings_count": len(strings_list),
                "strings_method": strings_method,
                "binwalk_signatures": binwalk_signatures[:50],
                "extraction_available": extracted_dir is not None,
            },
        }

        features_path = output_dir / f"{req.job_id}.features.json"
        features_path.write_text(json.dumps(features, indent=2, ensure_ascii=False))
        artifacts.features_path = str(features_path)

        strings_path = output_dir / f"{req.job_id}.strings.txt"
        strings_path.write_text("\n".join(strings_list[:2000]), errors="ignore")

        if extracted_dir:
            artifacts.extracted_path = str(extracted_dir)

    return build_report(req.job_id, started_at, findings, artifacts, errors)
