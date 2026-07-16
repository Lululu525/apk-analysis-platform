
"""
sample_real_world_apks.py

從解壓後的 MalDroid 2020 各類別資料夾（Benign / Banking / SMS2）隨機抽樣，
複製（不是搬移，保留原始下載）到 real_world_collect.py 需要的資料夾結構：

    dataset/real_world_apks/benign/*.apk
    dataset/real_world_apks/banking/*.apk
    dataset/real_world_apks/sms/*.apk

用法範例（依你計畫裡的建議數量：Benign 15–20、Banking 10、SMS 10）：

    python sample_real_world_apks.py \
        --benign-src "C:/Users/s1002/Downloads/MalDroid-2020/APKs/Benign" --benign-n 18 \
        --banking-src "C:/Users/s1002/Downloads/MalDroid-2020/APKs/Banking" --banking-n 10 \
        --sms-src "C:/Users/s1002/Downloads/MalDroid-2020/APKs/SMS" --sms-n 10 \
        --out-dir dataset/real_world_apks

固定 random seed（預設 42，跟 split_dataset.py 用同一個值，方便若之後要重跑
時抽到同一批檔案；如果你想要每次抽不同的樣本，加 --seed 改成別的值即可）。

只複製檔案，不會刪除或搬動來源資料夾裡的任何東西；重複執行會先清空
--out-dir 底下對應類別的子資料夾再重新複製，避免新舊批次混在一起算錯數量。
"""
from __future__ import annotations

import argparse
import random
import shutil
import sys
from pathlib import Path

DEFAULT_SEED = 42


def collect_apk_files(src_dir: Path) -> list[Path]:
    """列出 src_dir 底下所有看起來是 APK 的檔案（含子資料夾，不限副檔名大小寫）。"""
    if not src_dir.exists():
        return []
    return sorted(
        p for p in src_dir.rglob("*")
        if p.is_file() and p.suffix.lower() == ".apk"
    )


def sample_and_copy(src_dir: Path, n: int, out_dir: Path, seed: int, label: str) -> int:
    files = collect_apk_files(src_dir)
    if not files:
        print(f"[FAIL] {label}: 在 {src_dir} 找不到任何 .apk 檔案，確認路徑跟改副檔名是否都做完了", file=sys.stderr)
        return 0

    if len(files) < n:
        print(
            f"[WARN] {label}: 來源只有 {len(files)} 個檔案，少於目標 {n} 個，"
            f"將全部使用（{len(files)} 個）",
            file=sys.stderr,
        )
        chosen = files
    else:
        rng = random.Random(seed)
        chosen = rng.sample(files, n)

    # 清空該類別的輸出資料夾，避免舊批次殘留
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for f in chosen:
        shutil.copy2(f, out_dir / f.name)

    print(f"[OK] {label}: 從 {len(files)} 個檔案中抽出 {len(chosen)} 個 -> {out_dir}")
    return len(chosen)


def main() -> None:
    parser = argparse.ArgumentParser(description="從 MalDroid 2020 各類別隨機抽樣，整理成 real_world_collect.py 需要的資料夾結構")
    parser.add_argument("--benign-src", type=Path, required=True)
    parser.add_argument("--banking-src", type=Path, required=True)
    parser.add_argument("--sms-src", type=Path, required=True)
    parser.add_argument("--benign-n", type=int, default=18, help="預設 18，落在建議的 15–20 區間中間")
    parser.add_argument("--banking-n", type=int, default=10)
    parser.add_argument("--sms-n", type=int, default=10)
    parser.add_argument("--out-dir", type=Path, default=Path("dataset/real_world_apks"))
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()

    total = 0
    total += sample_and_copy(args.benign_src, args.benign_n, args.out_dir / "benign", args.seed, "benign")
    total += sample_and_copy(args.banking_src, args.banking_n, args.out_dir / "banking", args.seed, "banking")
    total += sample_and_copy(args.sms_src, args.sms_n, args.out_dir / "sms", args.seed, "sms")

    print(f"\n總計抽出 {total} 個 APK -> {args.out_dir}")
    if not (30 <= total <= 40):
        print(f"[NOTE] 目標區間是 30–40 個，目前總數 {total} 個，若差太多可調整 --benign-n/--banking-n/--sms-n 重跑", file=sys.stderr)


if __name__ == "__main__":
    main()
