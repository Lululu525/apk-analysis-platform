"""
check_launcher_pattern.py

系統性檢查：真實世界資料裡被判 exported-unprotected 的元件，是否幾乎都
只是該 App 的 MAIN/LAUNCHER 進入點（Android 系統設計上必然 exported、
且只接受系統呼叫，攻擊者無法塞入任何自訂資料），而不是真的可能被惡意
利用的自訂進入點（例如接受自訂 action、可被外部呼叫並處理攻擊者控制
資料的 Activity/Receiver）。

用這支腳本一次掃過全部真實世界 APK，量化回答「規則是否系統性過寬」，
不用一個個手動開檔案猜。

用法：
    python check_launcher_pattern.py --dataset-dir dataset/real_world_apks
"""
from __future__ import annotations

import argparse
from pathlib import Path

from app.extractors.androguard_analyzer import analyze_apk

LAUNCHER_ACTIONS = {"android.intent.action.MAIN"}
LAUNCHER_CATEGORIES = {"android.intent.category.LAUNCHER"}


def is_launcher_only(result, exported_name: str) -> bool:
    """檢查某個 exported 元件，是否只有 MAIN/LAUNCHER 這組 intent-filter，
    沒有任何其他自訂 action/category（也沒有完全沒有 intent-filter 但仍
    exported 的情況，那種反而更需要人工看，不算「純 launcher」）。
    """
    for comp in result.components or []:
        if comp.name != exported_name:
            continue
        filters = comp.intent_filters or []
        if not filters:
            return False
        for f in filters:
            actions = set(f.get("actions") or [])
            categories = set(f.get("categories") or [])
            if actions - LAUNCHER_ACTIONS:
                return False
            if categories - LAUNCHER_CATEGORIES:
                return False
        return True
    return False


def _component_permission(comp) -> bool:
    """簡化版保護判斷：只要有任何 permissions_required 就算有保護。
    （provider 的 read/write 分側判斷在這裡不需要，因為這支腳本只看
    activity/receiver 的 exported-unprotected 情況。）
    """
    return bool(comp.permissions_required)


def main() -> None:
    parser = argparse.ArgumentParser(description="檢查 exported-unprotected 是否多半只是 launcher activity")
    parser.add_argument("--dataset-dir", type=Path, required=True)
    args = parser.parse_args()

    total_flagged = 0
    launcher_only_count = 0
    rows: list[str] = []

    apk_files = sorted(args.dataset_dir.rglob("*.apk"))
    if not apk_files:
        print(f"[FAIL] 在 {args.dataset_dir} 找不到任何 .apk 檔案")
        return

    for apk_path in apk_files:
        try:
            result = analyze_apk(apk_path)
        except Exception as exc:
            rows.append(f"[ERROR] {apk_path.name}: {exc}")
            continue

        if not result.success:
            rows.append(f"[SKIP] {apk_path.name}: 分析失敗 ({result.errors})")
            continue

        exported = [
            comp.name
            for comp in (result.components or [])
            if comp.exported and not _component_permission(comp) and comp.name
        ]

        if not exported:
            continue

        all_launcher_only = all(is_launcher_only(result, name) for name in exported)
        total_flagged += 1
        if all_launcher_only:
            launcher_only_count += 1

        marker = "純 launcher（可能是誤報）" if all_launcher_only else "含非-launcher元件（值得細看）"
        label = result.package_name or apk_path.name
        rows.append(f"{label}: exported_unprotected={exported}  [{marker}]")

    for r in rows:
        print(r)

    print(f"\n===== 統計 =====")
    print(f"總計 {total_flagged} 個 App 被判定有 exported-unprotected 元件")
    if total_flagged:
        pct = launcher_only_count / total_flagged * 100
        print(f"其中 {launcher_only_count} 個（{pct:.1f}%）唯一的觸發原因是純 MAIN/LAUNCHER 進入點")
        print(f"其餘 {total_flagged - launcher_only_count} 個含有非-launcher 的 exported 元件，優先排入人工抽查")


if __name__ == "__main__":
    main()
