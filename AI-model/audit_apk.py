"""
audit_apk.py

人工抽查用的單一 APK 深度檢視工具。直接呼叫 analyze_apk() 加上兩個
Finding 判斷函式（findings_from_analysis / check_combinations），跳過
app.main 的 request.json 介面，一次印出：

  1. 套件資訊、SDK 版本、完整權限清單
  2. 所有元件（activity/service/provider/receiver），含 exported/
     permission 狀態與 intent-filter 內容
  3. 規則引擎實際產生的 Finding 清單（id、severity、confidence、
     evidence、remediation）
  4. 原始 AndroidManifest.xml 的可讀文字版，供人工核對元件在真實
     manifest 裡的完整脈絡（例如是否還有其他你沒注意到的屬性）

用法：
    python audit_apk.py <sha256前綴>

會在 dataset/real_world_apks/ 底下依前綴找檔案。
"""
from __future__ import annotations

import sys
from pathlib import Path
from xml.etree import ElementTree as ET

from app.extractors.androguard_analyzer import analyze_apk
from app.detectors.android_static_detector import findings_from_analysis
from app.detectors.privilege_rules import check_combinations

SEARCH_ROOT = Path("dataset/real_world_apks")


def find_apk(prefix: str) -> Path | None:
    matches = list(SEARCH_ROOT.rglob(f"{prefix}*.apk"))
    if not matches:
        return None
    if len(matches) > 1:
        print(f"[WARN] 前綴 {prefix} 找到多個檔案，取第一個: {matches}")
    return matches[0]


def main() -> None:
    if len(sys.argv) != 2:
        print("用法: python audit_apk.py <sha256前綴>", file=sys.stderr)
        raise SystemExit(1)

    prefix = sys.argv[1]
    apk_path = find_apk(prefix)
    if apk_path is None:
        print(f"[FAIL] 找不到符合 {prefix}*.apk 的檔案", file=sys.stderr)
        raise SystemExit(1)

    print(f"檔案: {apk_path}\n")

    result = analyze_apk(apk_path)
    if not result.success:
        print(f"[FAIL] 分析失敗: {result.errors}")
        return

    print("=" * 70)
    print("基本資訊")
    print("=" * 70)
    print(f"package_name  : {result.package_name}")
    print(f"version_name  : {result.version_name}")
    print(f"min/target sdk: {result.min_sdk} / {result.target_sdk}")
    perms = result.permissions or {}
    print(f"permission 數量: {len(perms)}")
    for p in sorted(perms.keys()):
        print(f"  - {p}")

    print()
    print("=" * 70)
    print("元件清單（含 exported / permission 狀態）")
    print("=" * 70)
    for comp in result.components or []:
        print(f"[{comp.type}] {comp.name}")
        print(f"    exported={comp.exported}  permissions_required={comp.permissions_required}")
        if comp.intent_filters:
            for f in comp.intent_filters:
                print(f"    intent-filter: {f}")
        print()

    print("=" * 70)
    print("規則引擎產生的 Finding 清單（實際被 ground_truth.csv 的 triggered 欄位引用的來源）")
    print("=" * 70)
    findings = list(findings_from_analysis(result)) + list(check_combinations(result))
    if not findings:
        print("(無 finding 觸發)")
    for f in findings:
        print(f"\n[{f.id}] severity={f.severity}  confidence={f.confidence}")
        print(f"  title    : {f.title}")
        print(f"  evidence : {f.evidence}")
        if getattr(f, "remediation", None):
            print(f"  remediation: {f.remediation}")

    print()
    print("=" * 70)
    print("原始 AndroidManifest.xml（可讀文字版，供人工核對用）")
    print("=" * 70)
    from androguard.misc import AnalyzeAPK
    apk, _, _ = AnalyzeAPK(str(apk_path))
    axml = apk.get_android_manifest_axml()
    if axml is None:
        print("[FAIL] 無法取得 AndroidManifest axml")
        return
    manifest_xml = axml.get_xml_obj()
    print(ET.tostring(manifest_xml, encoding="unicode"))


if __name__ == "__main__":
    main()
