"""固定 50 APK coverage membership；不產生標籤，也不執行訓練或工具分析。"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import io
import json
import math
import os
import platform
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import adjusted_rand_score, silhouette_score
from sklearn.preprocessing import StandardScaler
from threadpoolctl import threadpool_limits

from .flowdroid_poc import sha256_file

VERSION = "golden-50-v1"
SEED = 20260823
COUNT_FIELDS = (
    "component_activity_count", "component_service_count", "component_provider_count",
    "component_receiver_count", "component_evidence_row_count",
    "unique_exported_component_name_count", "sensitive_api_call_site_count",
    "sensitive_api_caller_count",
)
DIRECT_FIELDS = (
    "sensitive_api_direct_component_caller_count", "sensitive_api_direct_entry_caller_count",
)
FEATURES = [f"log1p({f.removeprefix('component_') if f in COUNT_FIELDS[:4] else f})"
            for f in COUNT_FIELDS] + ["direct_component_ratio", "direct_entry_ratio"]
CONFIG = {
    "membership_version": VERSION, "sample_count": 50,
    "scaler": "StandardScaler", "with_mean": True, "with_std": True,
    "kmeans": {"n_clusters": 17, "random_state": SEED, "n_init": 50,
               "init": "k-means++", "algorithm": "lloyd", "max_iter": 300, "tol": 0.0001},
    "sensitivity_k": [15, 17, 20], "features": FEATURES,
    "count_source_fields": list(COUNT_FIELDS), "ratio_numerators": list(DIRECT_FIELDS),
    "ratio_denominator": "sensitive_api_caller_count", "zero_denominator_value": 0.0,
    "candidate_sort": "sha256 ascending", "numeric_threads": 1,
    "cluster_id": "centroid lexicographic order; minimum member SHA breaks ties",
    "selection": "unused package first; representative nearest centroid; diverse/third max-min within cluster; coverage_fill lowest selected/population ratio",
    "cluster_visit_order": "distinct package count ascending, cluster ID ascending",
    "tie_break": "SHA256(seed + colon + APK SHA256), ascending",
    "scope": "coverage sampling only; no labels or predictions",
    "freeze_policy": "refuse existing membership or metadata; never replace APK for tool failure/no path/unknown",
}


def fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def feature_vector(row: dict[str, str]) -> list[float]:
    counts = [float(row[f]) for f in (*COUNT_FIELDS, *DIRECT_FIELDS)]
    if any(not math.isfinite(v) or v < 0 or not v.is_integer() for v in counts):
        raise ValueError("coverage counts 必須是有限非負整數")
    callers = counts[7]
    if any(v > callers for v in counts[8:]):
        raise ValueError("direct caller count 不得超過全部 distinct callers")
    return [math.log1p(v) for v in counts[:8]] + [v / callers if callers else 0.0 for v in counts[8:]]


def load_candidates(pilot_csv: Path, canonical_csv: Path) -> tuple[list[dict], dict]:
    """只讀 CSV；成功 rows 嚴格驗證，失敗 rows 的既有格式瑕疵保留於稽核。"""
    with canonical_csv.open(encoding="utf-8-sig", newline="") as handle:
        canonical = list(csv.DictReader(handle))
    by_sha = {}
    for line, row in enumerate(canonical, 2):
        sha = row["sha256"].strip()
        if sha in by_sha:
            raise ValueError("canonical SHA-256 不唯一")
        by_sha[sha] = (line, row)
    required = {"parse_status", "validation_status", "sha256_match", "expected_sha256",
                "computed_sha256", "sample_id", "source_path", "canonical_row_number",
                "parsed_package_name", *COUNT_FIELDS, *DIRECT_FIELDS}
    candidates = {}; excluded = []; aliases = {}; total = 0; success = 0
    with pilot_csv.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not required <= {f.strip() for f in reader.fieldnames or []}:
            raise ValueError("pilot CSV 缺少必要欄位")
        for line, raw in enumerate(reader, 2):
            total += 1
            row = {k.strip(): (v or "").strip() for k, v in raw.items() if k is not None}
            if row["parse_status"] != "success":
                excluded.append({"sample_id": row["sample_id"], "status": row["parse_status"],
                                 "csv_record": line, "extra_cells": len(raw.get(None, []))})
                continue
            success += 1
            if None in raw or any(v is None for v in raw.values()):
                raise ValueError("parse-success row 欄位數不正確")
            sha = row["expected_sha256"]
            if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
                raise ValueError("無效的 SHA-256")
            if (row["validation_status"] != "valid" or row["sha256_match"].lower() != "true"
                    or row["computed_sha256"] != sha):
                raise ValueError("parse-success APK 的既有 identity validation 未通過")
            canonical_line, source = by_sha[sha]
            if (source["sample_id"] != row["sample_id"] or source["source_path"] != row["source_path"]
                    or canonical_line != int(row["canonical_row_number"])):
                raise ValueError("pilot 與 canonical source reference 不符")
            package = row["parsed_package_name"]
            if not package or (source.get("package_name") and source["package_name"] != package):
                raise ValueError("package name 缺失或與 canonical 不一致")
            candidate = {
                "sha256": sha, "sample_id": row["sample_id"], "source_path": row["source_path"],
                "canonical_row_number": canonical_line, "package_name": package,
                "version_code": source.get("version_code", ""), "version_name": source.get("version_name", ""),
                "known_lineage_group": source.get("lineage_group", "") or source.get("lineage_id", ""),
                "features": feature_vector(row), "tie_break": hashlib.sha256(f"{SEED}:{sha}".encode()).hexdigest(),
            }
            if sha in candidates and candidate != candidates[sha]:
                raise ValueError("重複 SHA-256 的 feature／identity 資訊衝突")
            candidates[sha] = candidate
            aliases.setdefault(sha, []).append(line)
    rows = sorted(candidates.values(), key=lambda r: r["sha256"])
    # 同 package 或明確 known lineage 的傳遞閉包；certificate 不單獨當作 lineage。
    parent = {r["sha256"]: r["sha256"] for r in rows}
    def root(sha):
        while parent[sha] != sha:
            sha = parent[sha]
        return sha
    seen = {}
    for r in rows:
        keys = [("package", r["package_name"])]
        if r["known_lineage_group"]:
            keys.append(("lineage", r["known_lineage_group"]))
        for key in keys:
            if key in seen:
                a, b = sorted((root(r["sha256"]), root(seen[key])))
                parent[b] = a
            seen[key] = r["sha256"]
    for r in rows:
        r["package_group"] = "pkg:" + fingerprint(r["package_name"])
        r["lineage_group"] = "lineage:" + root(r["sha256"])
        r["version_group"] = (
            "version:" + fingerprint([r["package_name"], r["version_code"], r["version_name"]])
            if r["version_code"] or r["version_name"] else "unknown-version:" + r["sha256"]
        )
    return rows, {"input_row_count": total, "parse_success_count": success,
                  "candidate_count": len(rows), "dedupe_count": success - len(rows),
                  "excluded_rows": excluded,
                  "duplicate_sha_rows": {sha: lines for sha, lines in aliases.items() if len(lines) > 1}}


def select_members(x: np.ndarray, labels: np.ndarray, centers: np.ndarray, rows: list[dict], count=50):
    """分輪照顧各群，package novelty 優先，距離與 SHA tie-break 決定候選。"""
    if len(rows) < count:
        raise ValueError("候選 APK 不足")
    members = {c: np.flatnonzero(labels == c).tolist() for c in range(len(centers))}
    order = sorted(members, key=lambda c: (len({rows[i]["package_name"] for i in members[c]}), c))
    selected = []; used = set(); packages = set(); picks = {c: [] for c in members}
    def choose(c, role):
        available = [i for i in members[c] if i not in used]
        if not available:
            return
        def distance(i):
            if not picks[c]:
                return float(np.linalg.norm(x[i] - centers[c]))
            return min(float(np.linalg.norm(x[i] - x[j])) for j in picks[c])
        i = min(available, key=lambda i: (rows[i]["package_name"] in packages,
                distance(i) if role == "representative" else -distance(i), rows[i]["tie_break"]))
        selected.append({"index": i, "selection_role": role, "selection_rank": len(selected) + 1,
                         "selection_distance": distance(i),
                         "package_novel_at_selection": rows[i]["package_name"] not in packages})
        picks[c].append(i); used.add(i); packages.add(rows[i]["package_name"])
    for role in ["representative", "diverse", "third"]:
        for c in order:
            if len(selected) < count:
                choose(c, role)
    while len(selected) < count:
        available = [c for c in members if len(picks[c]) < len(members[c])]
        c = min(available, key=lambda c: (
            not any(i not in used and rows[i]["package_name"] not in packages for i in members[c]),
            len(picks[c]) / len(members[c]), c))
        choose(c, "coverage_fill")
    return selected


def build_selection(rows: list[dict]) -> tuple[list[dict], dict]:
    if len(rows) < 50:
        raise ValueError("必須至少有 50 個唯一 APK")
    rows = sorted(rows, key=lambda r: r["sha256"])
    raw = np.array([r["features"] for r in rows], dtype=np.float64)
    # 避免 joblib 在 Windows 查詢實體核心時以 CP950 解碼外部指令；所有數值工作固定單執行緒。
    previous = os.environ.get("LOKY_MAX_CPU_COUNT")
    os.environ["LOKY_MAX_CPU_COUNT"] = "1"
    fits = {}
    try:
        with threadpool_limits(limits=1):
            scaler = StandardScaler().fit(raw)
            x = scaler.transform(raw)
            for k in CONFIG["sensitivity_k"]:
                model = KMeans(**{**CONFIG["kmeans"], "n_clusters": k}).fit(x)
                if len(set(model.labels_)) != k:
                    raise ValueError("有效 clusters 少於 K；拒絕靜默凍結")
                order = sorted(range(k), key=lambda c: (tuple(model.cluster_centers_[c]),
                               min(rows[i]["sha256"] for i in np.flatnonzero(model.labels_ == c))))
                remap = {old: new for new, old in enumerate(order)}
                labels = np.array([remap[int(c)] for c in model.labels_])
                centers = model.cluster_centers_[order]
                selected = select_members(x, labels, centers, rows)
                fits[k] = {"labels": labels, "centers": centers, "selected": selected,
                           "inertia": float(model.inertia_), "iterations": int(model.n_iter_),
                           "silhouette": float(silhouette_score(x, labels))}
    finally:
        if previous is None:
            os.environ.pop("LOKY_MAX_CPU_COUNT", None)
        else:
            os.environ["LOKY_MAX_CPU_COUNT"] = previous
    main = fits[17]
    scaler_state = {"mean": scaler.mean_.tolist(), "scale": scaler.scale_.tolist(),
                    "variance": scaler.var_.tolist(), "n_samples_seen": int(scaler.n_samples_seen_)}
    matrix_hash = fingerprint([{ "sha256": r["sha256"], "features": r["features"]} for r in rows])
    config_hash = fingerprint(CONFIG)
    feature_config_hash = fingerprint({"feature_matrix": matrix_hash, "config": config_hash,
                                       "scaler": fingerprint(scaler_state)})
    membership = []
    for pick in main["selected"]:
        i = pick["index"];r = rows[i];c = int(main["labels"][i])
        membership.append({
            "membership_id": f"{VERSION}:{r['sha256']}", "sha256": r["sha256"],
            **{f: r[f] for f in ["sample_id", "source_path", "canonical_row_number", "package_name",
                                "version_code", "version_name", "package_group", "version_group",
                                "known_lineage_group", "lineage_group", "tie_break"]},
            "cluster_id": c, "cluster_size": int(sum(main["labels"] == c)),
            "cluster_distance": format(float(np.linalg.norm(x[i] - main["centers"][c])), ".17g"),
            **{f: pick[f] for f in ["selection_role", "selection_rank", "package_novel_at_selection"]},
            "selection_distance": format(pick["selection_distance"], ".17g"),
            "representativeness_basis": "nearest_centroid_with_package_priority" if pick["selection_role"] == "representative" else "max_min_distance_to_selected_in_cluster_with_package_priority",
            "feature_config_sha256": feature_config_hash, "membership_version": VERSION,
        })
    main_shas = {r["sha256"] for r in membership}
    sensitivity = {}
    for k, fit in fits.items():
        shas = [rows[pick["index"]]["sha256"] for pick in fit["selected"]]
        intersection = len(main_shas & set(shas))
        sensitivity[str(k)] = {
            "inertia": fit["inertia"], "silhouette": fit["silhouette"], "iterations": fit["iterations"],
            "cluster_sizes": np.bincount(fit["labels"]).tolist(), "selected_count": len(shas),
            "selected_package_count": len({rows[pick["index"]]["package_name"] for pick in fit["selected"]}),
            "selected_cluster_count": len({int(fit["labels"][pick["index"]]) for pick in fit["selected"]}),
            "overlap_with_k17": intersection, "jaccard_with_k17": intersection / (100 - intersection),
            "adjusted_rand_with_k17": float(adjusted_rand_score(main["labels"], fit["labels"])),
            "selected_sha256": shas, "membership_sha256": fingerprint(sorted(shas)),
        }
    selected_groups = {r["lineage_group"] for r in membership}
    return membership, {
        "config": CONFIG, "config_sha256": config_hash, "feature_list": FEATURES,
        "scaler_state": scaler_state, "scaler_sha256": fingerprint(scaler_state),
        "feature_matrix_sha256": matrix_hash, "feature_config_sha256": feature_config_hash,
        "cluster_centers_standardized": main["centers"].tolist(), "sensitivity": sensitivity,
        "candidate_registry": [{**r, "cluster_id": int(main["labels"][i]),
            "golden_member": r["sha256"] in main_shas,
            "excluded_from_future_training_by_golden_group": r["lineage_group"] in selected_groups}
            for i, r in enumerate(rows)],
        "membership_sha256": fingerprint(sorted(main_shas)),
        "unique_selected_packages": len({r["package_name"] for r in membership}),
        "golden_group_sibling_sha256": [r["sha256"] for r in rows
            if r["lineage_group"] in selected_groups and r["sha256"] not in main_shas],
        "lineage_limit": "同 package 或明確 canonical lineage 的傳遞閉包；未推斷未知跨 package 關係，不以 certificate 單獨推定 lineage。",
        "package_uniqueness_limit": "以 package novelty 優先的 deterministic heuristic；若結果為 50 個 package，即達到 50 APK 的 uniqueness 上限。",
    }


def freeze_membership(pilot_csv: Path, output_dir: Path, pilot_metadata: Path | None = None):
    targets = [output_dir / "golden_50_membership.csv", output_dir / "golden_50_selection_metadata.json"]
    if any(f.exists() for f in targets):
        raise FileExistsError("membership 已凍結或已有部分產物；拒絕覆寫／替換，請先稽核既有檔案")
    pilot_metadata = pilot_metadata or pilot_csv.with_name("run_metadata.json")
    origin = json.loads(pilot_metadata.read_text(encoding="utf-8"))
    canonical_csv = Path(origin["canonical_csv"])
    input_hash = sha256_file(pilot_csv);canonical_hash = sha256_file(canonical_csv)
    if canonical_hash != origin["canonical_csv_sha256"]:
        raise ValueError("canonical CSV 已改變，與 pilot provenance 不符")
    rows, counts = load_candidates(pilot_csv, canonical_csv)
    if counts["input_row_count"] != 300 or counts["parse_success_count"] != 297:
        raise ValueError("指定 pilot 必須是 300 rows／297 parse-success")
    membership, metadata = build_selection(rows)
    # 對唯一候選重新驗證來源身分，不以實體目錄掃描定義 membership。
    for row in rows:
        if sha256_file(Path(row["source_path"])) != row["sha256"]:
            raise ValueError(f"APK source SHA-256 不符：{row['sha256']}")
    if sha256_file(pilot_csv) != input_hash or sha256_file(canonical_csv) != canonical_hash:
        raise ValueError("選樣期間輸入 CSV 發生變更")
    timestamp = datetime.now(timezone(timedelta(hours=8))).isoformat()
    for r in membership:
        r.update({"canonical_csv_reference": str(canonical_csv), "canonical_csv_sha256": canonical_hash,
                  "membership_freeze_timestamp": timestamp})
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(membership[0]), lineterminator="\n")
    writer.writeheader();writer.writerows(membership)
    payload = buffer.getvalue().encode("utf-8-sig")
    metadata.update({"schema_version": "golden-50-selection-metadata-v1", "counts": counts,
        "membership_freeze_timestamp": timestamp, "pilot_csv_reference": str(pilot_csv.resolve()),
        "pilot_csv_sha256": input_hash, "pilot_metadata_sha256": sha256_file(pilot_metadata),
        "canonical_csv_reference": str(canonical_csv), "canonical_csv_sha256": canonical_hash,
        "candidate_population_sha256": fingerprint(sorted(r["sha256"] for r in rows)),
        "membership_csv_sha256": hashlib.sha256(payload).hexdigest(),
        "generator_source_sha256": sha256_file(Path(__file__)),
        "environment": {"python": platform.python_version(), **{name: importlib.metadata.version(name)
            for name in ["scikit-learn", "numpy", "scipy", "threadpoolctl"]}},
        "source_sha256_verified_count": len(rows), "produces_gold_labels": False,
        "membership_hash_definition": "SHA256 of canonical JSON sorted SHA256 list; excludes freeze timestamp",
        "determinism_scope": "固定輸入內容、config、seed 與已記錄 numerical library versions；候選先依 SHA 排序，數值單執行緒。CSV timestamp 不屬於 membership identity。",
    })
    output_dir.mkdir(parents=True, exist_ok=True)
    with targets[0].open("xb") as f:
        f.write(payload)
    with targets[1].open("x", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2, allow_nan=False);f.write("\n")
    return metadata


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pilot-csv", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("dataset/authz_v2"))
    args = parser.parse_args(argv)
    result = freeze_membership(args.pilot_csv, args.output_dir)
    print(json.dumps({"membership_sha256": result["membership_sha256"], "counts": result["counts"],
                      "unique_selected_packages": result["unique_selected_packages"]}, ensure_ascii=True))


if __name__ == "__main__":
    main()
