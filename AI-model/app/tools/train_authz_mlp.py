"""M2：vanilla MLP，在 I／S 弱標籤上訓練。設定見 `docs/slb_config_spec_v1.md`。

執行順序第 5c 項（ADR-0002）。M3（加 SLB）之後會沿用本模組的架構、資料載入與
可重現性設定，唯一差別是 SLB 機制本身——這是 M2／M3 差距能歸因於 SLB 的前提。

與 M1 的區隔：`app/ml/trainer.py` 與 `app/ml/encoder.py` 是 M1 的 Random Forest
洩漏基線，刻意包含 `exported`、`protected`、`permission`，**不得修改也不得與本模組混用**。

三條不變量：

1. **不讀 Gold。** 本模組在任何模式下都不載入 `gold_review_log.jsonl`，也不計算任何
   Gold 指標。epoch 預算、threshold 與超參數一律不得由 Gold 決定
   （`authz_label_spec.md` §10）。評估是另一個獨立步驟。
2. **不做 early stopping、不做 checkpoint selection。** 報告使用最後一個 epoch 的模型。
   兩者都需要一把訓練資料以外的尺，而此處沒有可用的尺（spec §1.1）。
3. **abstain 不進訓練。** `observed_authz_label` 為 `null` 的 268 筆依
   `authz_lf_spec_v1.md` §5 排除；它們會在推論階段單獨輸出作為研究發現，不參與 loss。

`--diagnose` 執行 spec §1.3 已凍結的規則，機械地算出 `TOTAL_EPOCHS`。規則在
`517187e` 先 commit、之後才執行，順序見 git 歷史。
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import os
import random
from pathlib import Path
from typing import Any, Mapping, Sequence

# deterministic cuBLAS matmul 的前提，必須在 import torch 之前設定（spec §1b.1）。
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")

import numpy as np
import torch
from torch import nn

MODEL_VERSION = "authz-mlp-m2-v1"

DEFAULT_FEATURES = Path("dataset/authz_v2/features_training.jsonl")
DEFAULT_LABELS = Path("dataset/authz_v2/observed_labels_training.jsonl")
DEFAULT_OUTPUT_DIR = Path("dataset/authz_v2/models")
DEFAULT_DIAGNOSTIC = Path("dataset/authz_v2/experiments/epoch_budget_diagnostic.json")

# --- spec §1b 凍結的超參數，不得由任何搜尋決定 -------------------------------
HIDDEN_SIZES = (128, 64)
DROPOUT = 0.3
LEARNING_RATE = 1e-3
BATCH_SIZE = 64
SEEDS = (20260823, 20260824, 20260825)

# --- spec §1.3 凍結的 epoch 決定規則 ----------------------------------------
DIAGNOSTIC_EPOCHS = 600
DIAGNOSTIC_SEED = 20260823
PLATEAU_WINDOW = 5
PLATEAU_TOLERANCE = 0.01
EPOCH_SAFETY_FACTOR = 3
EPOCH_ROUNDING = 50

LABEL_INDEX = {"negative": 0, "positive": 1}

LOGGER = logging.getLogger(__name__)


# --- 資料 ---------------------------------------------------------------------


def load_dataset(
    features_path: Path, labels_path: Path
) -> tuple[np.ndarray, np.ndarray, list[str], list[str]]:
    """回傳 (X, y, feature_names, review_unit_ids)。只含有標籤的 unit。"""
    features: dict[str, Mapping[str, int]] = {}
    with features_path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                features[row["review_unit_id"]] = row["features"]
    labels: dict[str, str | None] = {}
    with labels_path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                labels[row["review_unit_id"]] = row["observed_authz_label"]
    if not features:
        raise ValueError(f"{features_path} 沒有任何 feature。")
    missing = set(labels) - set(features)
    if missing:
        raise ValueError(f"{len(missing)} 筆 unit 有標籤但沒有 feature，無法訓練。")

    names = sorted(next(iter(features.values())))
    unit_ids = sorted(uid for uid, label in labels.items() if label is not None)
    matrix = np.array(
        [[features[uid][name] for name in names] for uid in unit_ids], dtype=np.float32
    )
    targets = np.array([LABEL_INDEX[labels[uid]] for uid in unit_ids], dtype=np.int64)
    return matrix, targets, names, unit_ids


def class_weights(targets: np.ndarray) -> torch.Tensor:
    """反比於訓練池實際頻率（spec §1b）。不以 Gold 分布設定。"""
    counts = np.bincount(targets, minlength=len(LABEL_INDEX)).astype(np.float64)
    if (counts == 0).any():
        raise ValueError(f"有類別在訓練資料中不存在：{counts}")
    weights = counts.sum() / (len(counts) * counts)
    return torch.tensor(weights, dtype=torch.float32)


# --- 模型 ---------------------------------------------------------------------


def build_model(input_dim: int) -> nn.Module:
    """31 → 128 → 64 → 2。輸出 2 個神經元，SLB 的 EMA 與 pseudo-label 在 softmax 上運作。"""
    layers: list[nn.Module] = []
    previous = input_dim
    for size in HIDDEN_SIZES:
        layers += [nn.Linear(previous, size), nn.ReLU(), nn.Dropout(DROPOUT)]
        previous = size
    layers.append(nn.Linear(previous, len(LABEL_INDEX)))
    return nn.Sequential(*layers)


def set_determinism(seed: int) -> None:
    """spec §1b.1。CUDA 上可重現性只在同一張卡與同一組驅動下成立。"""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False
    torch.use_deterministic_algorithms(True)


def resolve_device(requested: str) -> torch.device:
    if requested == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("要求 cuda 但 torch.cuda.is_available() 為 False。")
    return torch.device(requested)


def environment_fingerprint(device: torch.device) -> dict[str, Any]:
    """寫入 audit log；CUDA 的可重現性有環境條件，必須連同環境一起記錄。"""
    fingerprint: dict[str, Any] = {
        "torch": torch.__version__,
        "numpy": np.__version__,
        "device": str(device),
        "cublas_workspace_config": os.environ.get("CUBLAS_WORKSPACE_CONFIG"),
        "cudnn_deterministic": torch.backends.cudnn.deterministic,
        "cudnn_benchmark": torch.backends.cudnn.benchmark,
    }
    if device.type == "cuda":
        fingerprint.update(
            {
                "cuda_build": torch.version.cuda,
                "gpu_name": torch.cuda.get_device_name(0),
                "gpu_capability": "sm_%d%d" % torch.cuda.get_device_capability(0),
            }
        )
    return fingerprint


# --- 訓練 ---------------------------------------------------------------------


def train(
    matrix: np.ndarray,
    targets: np.ndarray,
    epochs: int,
    seed: int,
    device: torch.device,
) -> tuple[nn.Module, list[dict[str, float]]]:
    """固定 epoch 數訓練，回傳模型與每個 epoch 的訓練指標。

    不做 early stopping、不做 checkpoint selection（spec §1.1）。
    """
    set_determinism(seed)
    model = build_model(matrix.shape[1]).to(device)
    loss_fn = nn.CrossEntropyLoss(weight=class_weights(targets).to(device))
    optimiser = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    inputs = torch.from_numpy(matrix).to(device)
    labels = torch.from_numpy(targets).to(device)
    generator = torch.Generator().manual_seed(seed)

    history: list[dict[str, float]] = []
    for epoch in range(1, epochs + 1):
        model.train()
        order = torch.randperm(len(inputs), generator=generator).to(device)
        total_loss = 0.0
        for start in range(0, len(order), BATCH_SIZE):
            batch = order[start : start + BATCH_SIZE]
            optimiser.zero_grad(set_to_none=True)
            loss = loss_fn(model(inputs[batch]), labels[batch])
            loss.backward()
            optimiser.step()
            total_loss += loss.item() * len(batch)
        model.eval()
        with torch.no_grad():
            predictions = model(inputs).argmax(dim=1)
            accuracy = (predictions == labels).float().mean().item()
        history.append(
            {"epoch": epoch, "loss": total_loss / len(order), "accuracy": accuracy}
        )
    return model, history


# --- spec §1.3 的 epoch 決定規則 ---------------------------------------------


def moving_average(values: Sequence[float], window: int) -> list[float]:
    return [
        sum(values[max(0, i - window + 1) : i + 1]) / len(values[max(0, i - window + 1) : i + 1])
        for i in range(len(values))
    ]


def epoch_budget(history: Sequence[Mapping[str, float]]) -> dict[str, Any]:
    """機械套用 spec §1.3。規則已於 517187e 先 commit，本函式只執行它。"""
    smoothed = moving_average([row["accuracy"] for row in history], PLATEAU_WINDOW)
    peak = max(smoothed)
    threshold = peak - PLATEAU_TOLERANCE
    plateau = next(i + 1 for i, value in enumerate(smoothed) if value >= threshold)
    total = min(
        DIAGNOSTIC_EPOCHS,
        EPOCH_ROUNDING * math.ceil(EPOCH_SAFETY_FACTOR * plateau / EPOCH_ROUNDING),
    )
    return {
        "rule": {
            "diagnostic_epochs": DIAGNOSTIC_EPOCHS,
            "diagnostic_seed": DIAGNOSTIC_SEED,
            "plateau_window": PLATEAU_WINDOW,
            "plateau_tolerance": PLATEAU_TOLERANCE,
            "safety_factor": EPOCH_SAFETY_FACTOR,
            "rounding": EPOCH_ROUNDING,
        },
        "smoothed_peak_accuracy": peak,
        "threshold": threshold,
        "e_plateau": plateau,
        "total_epochs": total,
    }


# --- CLI ----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--device", default="cuda", choices=("cuda", "cpu"))
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="執行 spec §1.3 的 epoch 決定規則：單一 seed、固定 600 epoch，不寫出模型。",
    )
    parser.add_argument("--diagnostic-output", type=Path, default=DEFAULT_DIAGNOSTIC)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    device = resolve_device(args.device)
    matrix, targets, names, unit_ids = load_dataset(args.features, args.labels)
    positives = int(targets.sum())
    print(
        f"\n訓練資料 {len(unit_ids)} 筆 × {len(names)} 維"
        f"（positive {positives}、negative {len(targets) - positives}、"
        f"{positives / len(targets):.1%}）；裝置 {device}"
    )

    if not args.diagnose:
        raise SystemExit("正式訓練需等 TOTAL_EPOCHS 凍結後實作，目前只支援 --diagnose。")

    import time

    started = time.perf_counter()
    _, history = train(matrix, targets, DIAGNOSTIC_EPOCHS, DIAGNOSTIC_SEED, device)
    elapsed = time.perf_counter() - started
    budget = epoch_budget(history)
    report = {
        "model_version": MODEL_VERSION,
        "mode": "epoch_budget_diagnostic",
        "gold_consulted": False,
        "units": len(unit_ids),
        "features": len(names),
        "positives": positives,
        "wall_clock_seconds": elapsed,
        "environment": environment_fingerprint(device),
        **budget,
        "history": history,
    }
    final = history[-1]
    print(
        f"\n跑完 {DIAGNOSTIC_EPOCHS} epoch，耗時 {elapsed:.1f} 秒"
        f"（{elapsed / DIAGNOSTIC_EPOCHS * 1000:.1f} ms／epoch）"
    )
    print(f"  最終訓練準確率 {final['accuracy']:.4f}、loss {final['loss']:.4f}")
    print(f"  平滑後峰值 {budget['smoothed_peak_accuracy']:.4f}、門檻 {budget['threshold']:.4f}")
    print(f"  E_plateau = {budget['e_plateau']}")
    print(f"  TOTAL_EPOCHS = min(600, 取50倍數(3 × {budget['e_plateau']})) = "
          f"**{budget['total_epochs']}**")
    print("\n  曲線取樣：")
    for epoch in (1, 5, 10, 20, 30, 50, 75, 100, 150, 200, 300, 450, 600):
        if epoch <= len(history):
            row = history[epoch - 1]
            print(f"    epoch {epoch:>3}  loss {row['loss']:.4f}  acc {row['accuracy']:.4f}")

    if args.dry_run:
        return 0
    args.diagnostic_output.parent.mkdir(parents=True, exist_ok=True)
    args.diagnostic_output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    LOGGER.info("已寫出 %s。", args.diagnostic_output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
