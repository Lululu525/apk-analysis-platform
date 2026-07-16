"""
real_world_collect.py
=======================
批次處理真實世界 APK（MalDroid 2020 等外部資料集），沿用既有 toy_apk_validate.py
的 pipeline 呼叫慣例，補齊三件 toy 流程不需要、但真實世界資料需要的事：
  1. 計算 apk_sha256、讀取 package_name/version_name
  2. 依 Finding 的 category 判斷 app 級 label（privilege_escalation /
     ipc_privilege_escalation 兩個 category 只要出現任一個 finding 就算 label=1）
  3. 用擴充後的 schema 把結果附加寫入 ground_truth.csv，並印出人工抽查優先清單

前提：
  - 在 AI-model/ 目錄下執行（與 toy_apk_validate.py 相同慣例）
  - 真實世界 APK 已依類別分類放好，例如：
      dataset/real_world_apks/benign/*.apk
      dataset/real_world_apks/banking/*.apk
      dataset/real_world_apks/sms/*.apk
    （資料夾名稱本身會被當作 origin_label 寫入 ground_truth.csv）

用法：
  # 一次處理多個類別子資料夾
  python real_world_collect.py --dataset-dir dataset/real_world_apks --origin-dataset maldroid2020

  # 只處理單一類別資料夾（--origin-label 用來指定類別名稱）
  python real_world_collect.py --dataset-dir dataset/real_world_apks/benign \\
      --origin-dataset maldroid2020 --origin-label benign

注意：
  - 這個腳本只負責「跑 pipeline → 判斷 label → 寫入 ground_truth.csv」，
    不含隨機抽樣邏輯——抽樣請在丟進這個資料夾之前，先手動或用其他腳本篩選好
    30–40 個目標子集，避免把 MalDroid 2020 全量（數千筆）都跑過一次 pipeline。
  - label_source 固定寫 "rule_weak_label"（不是 "manual"）：這批標籤是規則引擎
    自動判斷出來的，還沒經過人工驗證，需要另外做 PLAN.md Task 5 規定的人工抽查。
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

AI_MODEL_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(AI_MODEL_ROOT))

from app.tools.parse_manifest import build_features  # noqa: E402  沿用既有 extractor

PIPELINE_INPUT_DIR = AI_MODEL_ROOT / "dataset" / "pipeline_inputs"
PIPELINE_OUTPUT_DIR = AI_MODEL_ROOT / "dataset" / "pipeline_outputs"
PIPELINE_ARTIFACTS_DIR = AI_MODEL_ROOT / "dataset" / "pipeline_artifacts"
GROUND_TRUTH_CSV = AI_MODEL_ROOT / "dataset" / "labels" / "ground_truth.csv"

FIELDNAMES = [
    "apk_filename", "package_name", "version_name", "apk_sha256",
    "source", "origin_dataset", "scenario", "case_id",
    "label", "label_source", "origin_label", "note",
]

# privilege_rules.py 裡所有跟越權/IPC 風險相關的 Finding，category 只會是這兩種
# 其中之一（見 Layer 1/2 = privilege_escalation，Layer 3 = ipc_privilege_escalation）。
# 用 category 判斷，不用 id 前綴字串比對，才不會漏掉 COMBO_*、DANGEROUS_PERMISSIONS_*
# 這類非五大類但仍屬於同一組規則引擎輸出的 finding，也不怕之後 KAN-39 敏感 API
# 模組併入後新增的 category（例如 sensitive_api_usage）被誤算進來。
RELEVANT_CATEGORIES = {"privilege_escalation", "ipc_privilege_escalation"}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_pipeline(jid: str, apk_path: Path) -> dict:
    """與 toy_apk_validate.py 的 run_pipeline 完全相同的呼叫方式，沿用既有 pipeline 介面。"""
    PIPELINE_INPUT_DIR.mkdir(parents=True, exist_ok=True)
    PIPELINE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    PIPELINE_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    input_json = {
        "job_id": jid,
        "sample": {
            "name": apk_path.name,
            "file_path": str(apk_path.relative_to(AI_MODEL_ROOT)).replace("\\", "/"),
        },
        "options": {
            "run_static_scan": True,
            "severity_threshold": "low",
        },
    }

    input_path = PIPELINE_INPUT_DIR / f"{jid}_input.json"
    output_path = PIPELINE_OUTPUT_DIR / f"{jid}_output.json"
    artifacts_path = PIPELINE_ARTIFACTS_DIR / jid

    input_path.write_text(json.dumps(input_json, ensure_ascii=False, indent=2), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-m", "app.main",
         "--in", str(input_path),
         "--out", str(output_path),
         "--artifacts", str(artifacts_path)],
        cwd=str(AI_MODEL_ROOT),
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"  ❌ Pipeline 失敗：{jid}")
        print(result.stderr[-2000:])
        return {"summary": {}, "findings": [], "_pipeline_failed": True}

    return json.loads(output_path.read_text(encoding="utf-8"))


def derive_label(findings: list[dict]) -> tuple[int, list[str]]:
    """回傳 (label, triggered_finding_ids)。label=1 代表 findings 中至少有一個
    屬於 RELEVANT_CATEGORIES 的 finding；triggered 是那些 finding 的 id 清單，
    供 note 欄位與人工抽查排序使用。"""
    triggered = [
        f.get("id", "")
        for f in findings
        if f.get("category") in RELEVANT_CATEGORIES
    ]
    return (1 if triggered else 0), triggered


def load_existing_rows() -> list[dict]:
    if not GROUND_TRUTH_CSV.exists():
        return []
    with GROUND_TRUTH_CSV.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def append_rows(new_rows: list[dict]) -> None:
    """讀出既有列 + 附加新列，整份重寫（避免手動 append 造成 header 不一致）。"""
    existing = load_existing_rows()
    GROUND_TRUTH_CSV.parent.mkdir(parents=True, exist_ok=True)
    with GROUND_TRUTH_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(existing + new_rows)


def collect_one(apk_path: Path, origin_dataset: str, origin_label: str) -> dict:
    jid = f"{origin_dataset}_{origin_label}_{apk_path.stem}"
    print(f"\n{'='*60}\n  處理：{apk_path.name}（{origin_label}）\n{'='*60}")

    sha256 = sha256_of(apk_path)

    try:
        features = build_features(apk_path)
        package_name = features.get("package_name") or "<UNKNOWN>"
        version_name = features.get("version_name") or "<UNKNOWN>"
    except Exception as e:  # noqa: BLE001 — 蒐集階段容錯優先，壞掉的樣本記錄後繼續跑下一個
        print(f"  ⚠️  package_name/version_name 讀取失敗：{e}")
        package_name, version_name = "<UNKNOWN>", "<UNKNOWN>"

    report = run_pipeline(jid, apk_path)
    findings = report.get("findings", [])
    summary = report.get("summary", {})
    label, triggered = derive_label(findings)

    risk_score = summary.get("risk_score", "N/A")
    risk_level = summary.get("risk_level", "N/A")
    print(f"  風險分數：{risk_score}｜label={label}｜觸發：{triggered or '無'}")

    return {
        "apk_filename": apk_path.name,
        "package_name": package_name,
        "version_name": version_name,
        "apk_sha256": sha256,
        "source": "real_world",
        "origin_dataset": origin_dataset,
        "scenario": "",
        "case_id": "",
        "label": label,
        "label_source": "rule_weak_label",
        "origin_label": origin_label,
        "note": (
            f"risk_score={risk_score}; risk_level={risk_level}; "
            f"triggered={','.join(triggered) or 'none'}"
        ),
    }


def _discover_apk_jobs(dataset_dir: Path, origin_label_override: str | None) -> list[tuple[Path, str]]:
    """若 dataset_dir 底下直接是一堆 .apk，用 --origin-label（或資料夾名稱）當類別；
    若底下是子資料夾（多類別），用各子資料夾名稱當 origin_label。"""
    jobs: list[tuple[Path, str]] = []
    direct_apks = sorted(dataset_dir.glob("*.apk"))
    if direct_apks:
        label = origin_label_override or dataset_dir.name
        jobs.extend((p, label) for p in direct_apks)
        return jobs

    for sub in sorted(p for p in dataset_dir.iterdir() if p.is_dir()):
        for apk in sorted(sub.glob("*.apk")):
            jobs.append((apk, sub.name))
    return jobs


def main() -> None:
    parser = argparse.ArgumentParser(description="真實世界 APK 批次蒐集腳本")
    parser.add_argument("--dataset-dir", required=True,
                         help="APK 所在資料夾（可以是單一類別資料夾，或含多個類別子資料夾）")
    parser.add_argument("--origin-dataset", required=True,
                         help="外部資料集名稱，例如 maldroid2020")
    parser.add_argument("--origin-label",
                         help="若 --dataset-dir 是單一類別資料夾，指定類別名稱"
                              "（例如 benign / banking_malware / sms_malware）；"
                              "若 --dataset-dir 底下是多個子資料夾則不需指定")
    args = parser.parse_args()

    dataset_dir = Path(args.dataset_dir)
    if not dataset_dir.is_absolute():
        dataset_dir = AI_MODEL_ROOT / dataset_dir

    if not dataset_dir.exists():
        print(f"❌ 資料夾不存在：{dataset_dir}")
        sys.exit(1)

    apk_jobs = _discover_apk_jobs(dataset_dir, args.origin_label)
    if not apk_jobs:
        print(f"❌ 在 {dataset_dir} 底下找不到任何 .apk 檔案")
        sys.exit(1)

    print(f"共找到 {len(apk_jobs)} 個 APK，開始逐一處理...")

    new_rows: list[dict] = []
    for apk_path, origin_label in apk_jobs:
        try:
            new_rows.append(collect_one(apk_path, args.origin_dataset, origin_label))
        except Exception as e:  # noqa: BLE001 — 單一樣本失敗不應中斷整批蒐集
            print(f"  ❌ 處理失敗，跳過：{apk_path.name}（{e}）")

    if not new_rows:
        print("\n⚠️  沒有任何樣本成功處理，ground_truth.csv 未變動。")
        return

    append_rows(new_rows)
    print(f"\n✅ 完成，共寫入 {len(new_rows)} 列到 {GROUND_TRUTH_CSV}")

    # 人工抽查優先清單：label=1 優先，其次依 risk_score 由高到低排序
    def _risk_score_of(row: dict) -> float:
        try:
            return float(row["note"].split("risk_score=")[1].split(";")[0])
        except (IndexError, ValueError):
            return -1.0

    priority = sorted(new_rows, key=lambda r: (-(r["label"]), -_risk_score_of(r)))
    sample_size = min(12, len(priority))
    print(f"\n📋 建議人工抽查優先順序（前 {sample_size} 筆，PLAN.md Task 5 的抽樣複核用）：")
    for r in priority[:sample_size]:
        print(f"  [{r['label']}] {r['apk_filename']}（{r['origin_label']}）— {r['note']}")


if __name__ == "__main__":
    main()
