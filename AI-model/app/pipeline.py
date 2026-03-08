from __future__ import annotations
from typing import Tuple, List, Dict, Any
from datetime import datetime, timezone, timedelta
from pathlib import Path
import json
import hashlib
import math

from .schemas import AnalyzeRequest, AnalyzeReport, Artifacts, Finding
from .detectors.rules import scan_text_for_rules
from .report.builder import build_report


def _now_iso() -> str:
    tz_utc_8 = timezone(timedelta(hours=8)) 
    return datetime.now(tz_utc_8).isoformat()


def _load_request(path: Path) -> AnalyzeRequest:
    data = json.loads(path.read_text(encoding="utf-8"))
    return AnalyzeRequest.model_validate(data)


def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _shannon_entropy(data: bytes) -> float:
    """0~8 bits/byte。越高通常代表越像壓縮/加密/隨機。"""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def _extract_printable_strings(data: bytes, min_len: int = 4, limit: int = 5000) -> List[str]:
    """
    簡化版 strings：抽可印字元序列（不追求完美，先可用）。
    limit 防止爆量。
    """
    out: List[str] = []
    buf: List[int] = []

    def flush():
        nonlocal buf, out
        if len(buf) >= min_len:
            s = bytes(buf).decode("ascii", errors="ignore")
            if s:
                out.append(s)
        buf = []

    for b in data:
        if 32 <= b <= 126:  # printable ASCII
            buf.append(b)
        else:
            flush()
            if len(out) >= limit:
                break
    flush()
    return out[:limit]


def run_pipeline(req: AnalyzeRequest, output_dir: Path | None = None) -> AnalyzeReport:
    started_at = _now_iso()
    errors: List[str] = []
    findings: List[Finding] = []

    fp = req.firmware.file_path
    if not fp:
        errors.append("firmware.file_path is missing (CLI mode expects local path).")
        return build_report(req.job_id, started_at, findings, Artifacts(), errors)

    firmware_path = Path(fp)
    if not firmware_path.exists():
        errors.append(f"firmware file not found: {firmware_path}")
        return build_report(req.job_id, started_at, findings, Artifacts(), errors)

    # 讀一小段做 quick features（避免超大檔卡死）
    try:
        raw_head = firmware_path.read_bytes()[:2_000_000]  # 2MB for quick stats
    except Exception as e:
        errors.append(f"failed to read firmware: {e}")
        return build_report(req.job_id, started_at, findings, Artifacts(), errors)

    # ---- Feature Extraction (human-readable) ----
    try:
        sha256 = _sha256_file(firmware_path)
        size_bytes = firmware_path.stat().st_size
        entropy = _shannon_entropy(raw_head)
        strings_list = _extract_printable_strings(raw_head, min_len=4, limit=3000)

        # 一些簡單統計
        strings_count = len(strings_list)
        suspicious_hits = {
            "password": sum("password" in s.lower() for s in strings_list),
            "api_key": sum("api" in s.lower() and "key" in s.lower() for s in strings_list),
            "private_key": sum("PRIVATE KEY" in s for s in strings_list),
            "telnetd": sum("telnetd" in s.lower() for s in strings_list),
            "dropbear": sum("dropbear" in s.lower() for s in strings_list),
        }

        features: Dict[str, Any] = {
            "job_id": req.job_id,
            "firmware": {
                "name": req.firmware.name,
                "sha256": sha256,
                "size_bytes": size_bytes,
            },
            "device_meta": (req.device_meta.model_dump() if req.device_meta else None),
            "options": req.options.model_dump(),
            "stats": {
                "entropy_head_2mb": round(entropy, 4),
                "strings_count_head_2mb": strings_count,
                "suspicious_hits_head_2mb": suspicious_hits,
            },
        }
    except Exception as e:
        errors.append(f"feature extraction failed: {e}")
        return build_report(req.job_id, started_at, findings, Artifacts(), errors)

    # ---- Detectors (MVP: rule-based on extracted strings) ----
    if req.options.run_static_scan:
        # 把 strings 合併成 text 再跑你原本的 rule detector（保持行為一致）
        text_for_rules = "\n".join(strings_list)
        findings.extend(scan_text_for_rules(text_for_rules))

    # ---- Artifacts ----
    artifacts = Artifacts()
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

        # features.json：可讀可用，適合後續 ML 訓練
        features_path = output_dir / f"{req.job_id}.features.json"
        features_path.write_text(json.dumps(features, indent=2, ensure_ascii=False), encoding="utf-8")
        artifacts.features_path = str(features_path)

        # strings.txt：可選，給人 debug 用（不再是亂碼）
        strings_path = output_dir / f"{req.job_id}.strings.txt"
        strings_path.write_text("\n".join(strings_list[:2000]), encoding="utf-8", errors="ignore")

    return build_report(req.job_id, started_at, findings, artifacts, errors)


def run_cli(input_json: Path, report_json: Path, output_dir: Path | None = None) -> Tuple[AnalyzeReport, str]:
    req = _load_request(input_json)
    report = run_pipeline(req, output_dir=output_dir)
    report_json.parent.mkdir(parents=True, exist_ok=True)
    report_json.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return report, report_json.as_posix()