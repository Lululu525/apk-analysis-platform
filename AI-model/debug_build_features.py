"""
debug_build_features.py

直接呼叫 app.tools.parse_manifest.build_features()，跳過 app.main 的
--in/--out/--artifacts subprocess 介面（那個介面需要後端建構的 request.json，
不適合單獨拿來對某幾個特定 APK 做除錯）。

用法：在跟 real_world_collect.py 同一層目錄下（同一個 venv）執行：

    python debug_build_features.py

會在 dataset/real_world_apks/ 底下用 sha256 前綴找出對應檔案，對這 4 個
可疑 APK 分別呼叫 build_features()，印出回傳內容或完整的例外 traceback。
"""
from __future__ import annotations

import pprint
import traceback
from pathlib import Path

from app.tools.parse_manifest import build_features

# 待查的 4 個可疑 sha256（前綴即可，腳本會自動找檔）
SUSPECT_PREFIXES = [
    "079c8e2e22da",  # benign, package_name=<UNKNOWN>, risk=15
    "710c74b43ab2",  # benign, package_name=<UNKNOWN>, risk=3
    "afb5973323a9",  # benign, package_name=<UNKNOWN>, risk=3
    "2f702269d243",  # sms, risk_score=N/A -- 最優先確認這一個
    "3383038023b8",  # 對照組：同樣是 sms，但正確觸發 risk=99，用來比對 components 結構是否一樣
]

SEARCH_ROOT = Path("dataset/real_world_apks")


def find_apk(prefix: str) -> Path | None:
    matches = list(SEARCH_ROOT.rglob(f"{prefix}*.apk"))
    if not matches:
        return None
    if len(matches) > 1:
        print(f"[WARN] 前綴 {prefix} 找到多個檔案，取第一個: {matches}")
    return matches[0]


def main() -> None:
    for prefix in SUSPECT_PREFIXES:
        apk_path = find_apk(prefix)
        print(f"\n=== {prefix} ===")
        if apk_path is None:
            print(f"[FAIL] 在 {SEARCH_ROOT} 底下找不到符合 {prefix}*.apk 的檔案，"
                  f"確認路徑或檔名前綴是否正確")
            continue

        print(f"檔案: {apk_path}")
        try:
            result = build_features(str(apk_path)) # type: ignore
        except Exception:
            print("[EXCEPTION] build_features() 拋出例外：")
            traceback.print_exc()
            continue

        if isinstance(result, dict):
            print(f"回傳 dict，keys={list(result.keys())}")
            pprint.pprint(result, depth=3, compact=True)
        else:
            print(f"回傳型別: {type(result)}")
            pprint.pprint(result)


if __name__ == "__main__":
    main()