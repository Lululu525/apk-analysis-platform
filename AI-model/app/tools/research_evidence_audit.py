"""Audit research claims against immutable experiment artifacts.

The audit is intentionally independent from model code.  It makes the population,
evaluation design, Gold-set role, and source artifact explicit before a metric is
allowed into a report or presentation.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "research-evidence-claims-v1"
REQUIRED_FIELDS = {
    "claim_id",
    "population_id",
    "unit_count",
    "apk_count",
    "metric_name",
    "metric_value",
    "evaluation_design",
    "gold_role",
    "claim_scope",
    "artifact_path",
    "artifact_sha256",
    "json_pointer",
}
EVALUATION_DESIGNS = {
    "independent_holdout",
    "group_cross_validation",
    "leave_one_apk_out",
    "same_batch_fit",
    "training_only",
    "descriptive",
}
GOLD_ROLES = {
    "untouched_evaluation_only",
    "tuning_or_rule_design",
    "training_labels",
    "not_applicable",
}
CLAIM_SCOPES = {
    "generalization",
    "internal_validation",
    "descriptive",
    "static_possible_path",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_pointer(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise ValueError("json_pointer 必須是空字串或以 / 開頭")
    value = document
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            try:
                value = value[int(token)]
            except (ValueError, IndexError) as exc:
                raise ValueError(f"JSON pointer list index 不存在：{token}") from exc
        elif isinstance(value, dict) and token in value:
            value = value[token]
        else:
            raise ValueError(f"JSON pointer 欄位不存在：{token}")
    return value


def _parse_nonnegative_int(value: str, field: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{field} 必須是非負整數") from exc
    if parsed < 0 or str(parsed) != value.strip():
        raise ValueError(f"{field} 必須是非負整數")
    return parsed


def _resolve_artifact(root: Path, relative_path: str) -> Path:
    if not relative_path.strip():
        raise ValueError("artifact_path 不得為空")
    root = root.resolve()
    artifact = (root / relative_path).resolve()
    if artifact != root and root not in artifact.parents:
        raise ValueError("artifact_path 不得離開 artifact root")
    return artifact


def audit_checksum_manifest(checksum_csv: Path, artifact_root: Path) -> dict[str, Any]:
    """Verify every file declared by the portable evidence package inventory."""
    errors: list[dict[str, str]] = []
    files: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    with checksum_csv.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        if len(fields) < 2:
            raise ValueError("checksum CSV 至少需要相對路徑與 SHA256 兩欄")
        path_field, sha_field = fields[:2]
        for line_number, raw in enumerate(reader, 2):
            relative_path = (raw.get(path_field) or "").strip().replace("\\", "/")
            expected_sha = (raw.get(sha_field) or "").strip().lower()
            row_errors: list[str] = []
            if not relative_path:
                row_errors.append("附件相對路徑不得為空")
            elif relative_path in seen_paths:
                row_errors.append("附件相對路徑必須唯一")
            seen_paths.add(relative_path)
            if len(expected_sha) != 64 or any(c not in "0123456789abcdef" for c in expected_sha):
                row_errors.append("SHA256 必須是 64 位小寫十六進位")
            actual_sha = None
            try:
                artifact = _resolve_artifact(artifact_root, relative_path)
                if not artifact.is_file():
                    raise ValueError("附件不存在")
                actual_sha = sha256_file(artifact)
                if actual_sha != expected_sha:
                    row_errors.append("附件 SHA-256 與清單不符")
            except (OSError, ValueError) as exc:
                row_errors.append(str(exc))
            for message in row_errors:
                errors.append({"line": str(line_number), "path": relative_path, "message": message})
            files.append({
                "path": relative_path,
                "expected_sha256": expected_sha,
                "actual_sha256": actual_sha,
                "status": "error" if row_errors else "verified",
            })
    return {
        "checksum_file": str(checksum_csv),
        "summary": {
            "file_count": len(files),
            "verified_count": sum(row["status"] == "verified" for row in files),
            "error_count": len(errors),
        },
        "errors": errors,
        "files": files,
    }


def audit_claims(claims_csv: Path, artifact_root: Path) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    audited: list[dict[str, Any]] = []
    seen_claims: set[str] = set()
    populations: dict[str, tuple[int, int]] = {}

    with claims_csv.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = {field.strip() for field in reader.fieldnames or []}
        missing = sorted(REQUIRED_FIELDS - fields)
        if missing:
            raise ValueError(f"claims CSV 缺少必要欄位：{', '.join(missing)}")

        for line_number, raw in enumerate(reader, 2):
            row = {key.strip(): (value or "").strip() for key, value in raw.items() if key}
            claim_id = row["claim_id"] or f"line-{line_number}"
            row_errors: list[str] = []
            row_warnings: list[str] = []

            if not row["claim_id"]:
                row_errors.append("claim_id 不得為空")
            elif claim_id in seen_claims:
                row_errors.append("claim_id 必須唯一")
            seen_claims.add(claim_id)

            try:
                unit_count = _parse_nonnegative_int(row["unit_count"], "unit_count")
                apk_count = _parse_nonnegative_int(row["apk_count"], "apk_count")
                if unit_count and not apk_count:
                    row_errors.append("unit_count 大於 0 時 apk_count 不得為 0")
                population = (unit_count, apk_count)
                previous = populations.setdefault(row["population_id"], population)
                if not row["population_id"]:
                    row_errors.append("population_id 不得為空")
                elif previous != population:
                    row_errors.append("同一 population_id 的 unit_count/apk_count 不一致")
            except ValueError as exc:
                unit_count = apk_count = 0
                row_errors.append(str(exc))

            try:
                metric_value = float(row["metric_value"])
                if not math.isfinite(metric_value):
                    raise ValueError
            except ValueError:
                metric_value = None
                row_errors.append("metric_value 必須是有限數值")

            design = row["evaluation_design"]
            gold_role = row["gold_role"]
            scope = row["claim_scope"]
            if design not in EVALUATION_DESIGNS:
                row_errors.append("evaluation_design 不在允許清單")
            if gold_role not in GOLD_ROLES:
                row_errors.append("gold_role 不在允許清單")
            if scope not in CLAIM_SCOPES:
                row_errors.append("claim_scope 不在允許清單")

            if scope == "generalization":
                if design != "independent_holdout":
                    row_errors.append("泛化主張必須使用 independent_holdout")
                if gold_role != "untouched_evaluation_only":
                    row_errors.append("泛化主張的 Gold 必須只用於未接觸的最終評估")
            if design in {"same_batch_fit", "training_only"} and scope not in {
                "descriptive", "internal_validation"
            }:
                row_errors.append("同批擬合或訓練結果只能作描述或內部驗證")
            if gold_role == "tuning_or_rule_design" and scope == "generalization":
                row_errors.append("規則設計曾參考 Gold，不得宣稱泛化")
            if "link" in row["metric_name"].lower() and scope != "static_possible_path":
                row_warnings.append("linkage 指標應標為 static_possible_path，避免誤稱資料流或漏洞")

            actual_sha = None
            source_value = None
            try:
                artifact = _resolve_artifact(artifact_root, row["artifact_path"])
                if not artifact.is_file():
                    raise ValueError("原始 artifact 不存在")
                actual_sha = sha256_file(artifact)
                expected_sha = row["artifact_sha256"].lower()
                if len(expected_sha) != 64 or any(c not in "0123456789abcdef" for c in expected_sha):
                    row_errors.append("artifact_sha256 必須是 64 位小寫十六進位")
                elif actual_sha != expected_sha:
                    row_errors.append("artifact SHA-256 與宣告值不符")
                document = json.loads(artifact.read_text(encoding="utf-8-sig"))
                source_value = _json_pointer(document, row["json_pointer"])
                if metric_value is not None and isinstance(source_value, (int, float)):
                    if not math.isclose(metric_value, float(source_value), rel_tol=1e-12, abs_tol=1e-12):
                        row_errors.append("metric_value 與 JSON pointer 指向的原始值不符")
                else:
                    row_errors.append("JSON pointer 必須指向數值")
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                row_errors.append(str(exc))

            for message in row_errors:
                errors.append({"claim_id": claim_id, "message": message})
            for message in row_warnings:
                warnings.append({"claim_id": claim_id, "message": message})
            audited.append({
                "claim_id": claim_id,
                "population_id": row["population_id"],
                "unit_count": unit_count,
                "apk_count": apk_count,
                "metric_name": row["metric_name"],
                "metric_value": metric_value,
                "source_value": source_value,
                "evaluation_design": design,
                "gold_role": gold_role,
                "claim_scope": scope,
                "artifact_path": row["artifact_path"],
                "artifact_sha256_actual": actual_sha,
                "json_pointer": row["json_pointer"],
                "status": "error" if row_errors else "verified",
            })

    return {
        "schema_version": SCHEMA_VERSION,
        "claims_file": str(claims_csv),
        "artifact_root": str(artifact_root),
        "summary": {
            "claim_count": len(audited),
            "verified_count": sum(row["status"] == "verified" for row in audited),
            "error_count": len(errors),
            "warning_count": len(warnings),
            "population_count": len(populations),
        },
        "errors": errors,
        "warnings": warnings,
        "claims": audited,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="稽核研究簡報指標的母體、評估邊界與原始證據")
    parser.add_argument("--claims", type=Path, required=True, help="research claims CSV")
    parser.add_argument("--artifact-root", type=Path, required=True, help="原始 JSON 所在根目錄")
    parser.add_argument("--out", type=Path, required=True, help="稽核報告 JSON")
    parser.add_argument("--checksums", type=Path, help="可選：整包附件 SHA-256 清單 CSV")
    args = parser.parse_args(argv)
    report = audit_claims(args.claims, args.artifact_root)
    if args.checksums:
        report["package_integrity"] = audit_checksum_manifest(args.checksums, args.artifact_root)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    console_summary = {"claims": report["summary"]}
    if "package_integrity" in report:
        console_summary["package_integrity"] = report["package_integrity"]["summary"]
    print(json.dumps(console_summary, ensure_ascii=False))
    package_errors = report.get("package_integrity", {}).get("errors", [])
    return 2 if report["errors"] or package_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
