"""M2：vanilla MLP，在 I／S 弱標籤上訓練。設定見 `docs/slb_config_spec_v1.md`。

執行順序第 5c 項（ADR-0002）。M3（加 SLB）在 `app/tools/train_authz_slb.py`，沿用本模組的
架構、資料載入、loss、可重現性設定與全部 audit 寫出函式，唯一差別是 SLB 機制本身——
這是 M2／M3 差距能歸因於 SLB 的前提。

與 M1 的區隔：`app/ml/trainer.py` 與 `app/ml/encoder.py` 是 M1 的 Random Forest
洩漏基線，刻意包含 `exported`、`protected`、`permission`，**不得修改也不得與本模組混用**。

三條不變量：

1. **不讀 Gold。** 本模組在任何模式下都不載入 `gold_review_log.jsonl`，也不計算任何
   Gold 指標。Gold 評估集只載入 feature 與 `review_unit_id`，不載入標籤
   （`features_gold_eval.jsonl` 本身不含標籤欄位），輸出的是預測，評估是另一個獨立步驟。
   epoch 預算、threshold 與超參數一律不得由 Gold 決定（`authz_label_spec.md` §10）。
2. **不做 early stopping、不做 checkpoint selection。** 報告使用最後一個 epoch 的模型。
   兩者都需要一把訓練資料以外的尺，而此處沒有可用的尺（spec §1.1）。
3. **abstain 不進訓練。** `observed_authz_label` 為 `null` 的 268 筆依
   `authz_lf_spec_v1.md` §5 排除；它們會在推論階段單獨輸出作為研究發現，不參與 loss。

兩個模式：

- `--diagnose` 執行 spec §1.3 已凍結的規則，機械地算出 `TOTAL_EPOCHS`。規則在
  `517187e` 先 commit、之後才執行，順序見 git 歷史。
- `--train` 執行正式的 3 次 M2（seed 20260823／24／25），每次固定 `TOTAL_EPOCHS = 100`
  個 epoch，寫出 spec §5.3 指定的三個產物。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import os
import random
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

# deterministic cuBLAS matmul 的前提，必須在 import torch 之前設定（spec §1b.1）。
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")

import numpy as np
import torch
from torch import nn

MODEL_VERSION = "authz-mlp-m2-v1"

DEFAULT_FEATURES = Path("dataset/authz_v2/features_training.jsonl")
DEFAULT_LABELS = Path("dataset/authz_v2/observed_labels_training.jsonl")
DEFAULT_GOLD_FEATURES = Path("dataset/authz_v2/features_gold_eval.jsonl")
DEFAULT_OUTPUT_DIR = Path("dataset/authz_v2/models")
DEFAULT_EXPERIMENTS_DIR = Path("dataset/authz_v2/experiments")
DEFAULT_DIAGNOSTIC = DEFAULT_EXPERIMENTS_DIR / "epoch_budget_diagnostic.json"
CONFIG_SPEC = Path("docs/slb_config_spec_v1.md")

# --- spec §1b／§2.2 凍結的超參數，不得由任何搜尋決定 -------------------------
HIDDEN_SIZES = (128, 64)
DROPOUT = 0.3
LEARNING_RATE = 1e-3
BATCH_SIZE = 64
SEEDS = (20260823, 20260824, 20260825)
CB_BETA = 0.9999
WEIGHT_INIT = "xavier_uniform"

# --- spec §1.4 凍結的 epoch 預算 --------------------------------------------
TOTAL_EPOCHS = 100

# --- spec §1.3 凍結的 epoch 決定規則 ----------------------------------------
DIAGNOSTIC_EPOCHS = 600
DIAGNOSTIC_SEED = 20260823
PLATEAU_WINDOW = 5
PLATEAU_TOLERANCE = 0.01
EPOCH_SAFETY_FACTOR = 3
EPOCH_ROUNDING = 50

LABEL_INDEX = {"negative": 0, "positive": 1}
LABEL_NAMES = ("negative", "positive")

LOGGER = logging.getLogger(__name__)


# --- 資料 ---------------------------------------------------------------------


def _read_features(path: Path) -> dict[str, Mapping[str, int]]:
    features: dict[str, Mapping[str, int]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                features[row["review_unit_id"]] = row["features"]
    if not features:
        raise ValueError(f"{path} 沒有任何 feature。")
    return features


def load_dataset(
    features_path: Path, labels_path: Path
) -> tuple[np.ndarray, np.ndarray, list[str], list[str]]:
    """回傳 (X, y, feature_names, review_unit_ids)。只含有標籤的 unit。"""
    features = _read_features(features_path)
    labels: dict[str, str | None] = {}
    with labels_path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                labels[row["review_unit_id"]] = row["observed_authz_label"]
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


def load_features_only(
    features_path: Path, names: Sequence[str]
) -> tuple[np.ndarray, list[str]]:
    """載入 Gold 評估集的 feature。`names` 由訓練池決定，欄位順序必須完全一致。

    刻意不接受任何標籤參數：Gold 標籤在本模組的任何路徑上都讀不到（不變量 1）。
    """
    features = _read_features(features_path)
    unit_ids = sorted(features)
    for uid in unit_ids:
        if sorted(features[uid]) != sorted(names):
            raise ValueError(f"{uid} 的 feature 欄位與訓練池不一致，無法共用模型。")
    matrix = np.array(
        [[features[uid][name] for name in names] for uid in unit_ids], dtype=np.float32
    )
    return matrix, unit_ids


# --- 格子（相異 feature vector）----------------------------------------------


def cell_ids(matrix: np.ndarray) -> np.ndarray:
    """回傳每一列所屬的格子編號。31 維全為布林，相異 feature vector 即為一格。

    格子是 spec §1.2、§5.5 全部推論的基礎：模型對同一格必然輸出同一個機率。
    """
    _, inverse = np.unique(matrix, axis=0, return_inverse=True)
    return inverse.reshape(-1).astype(np.int64)


def cell_majority(cells: np.ndarray, targets: np.ndarray) -> np.ndarray:
    """每一列所屬格子的 observed 標籤多數決。平手一律判 negative。

    平手的 tie-break 規則在執行前凍結（spec §7.3）：訓練池 113 格中有 3 格平手、
    共 16 筆。此函式不接觸 Gold，`agreement_training_label_vs_cell_majority`（§5.5）
    因此可在訓練中即時計算。
    """
    majority = np.zeros(len(cells), dtype=np.int64)
    for cell in np.unique(cells):
        mask = cells == cell
        positives = int(targets[mask].sum())
        negatives = int(mask.sum()) - positives
        majority[mask] = 1 if positives > negatives else 0
    return majority


# --- Loss：Class-Balanced CrossEntropy（spec §4.3、論文 Eq. (6)(7)）----------


def cb_class_weights(counts: Sequence[int] | np.ndarray, beta: float = CB_BETA) -> torch.Tensor:
    """論文 Eq. (6)：每筆 loss 權重為 `1 / EN_c`，`EN_c = (1 - β^{n_c}) / (1 - β)`。

    依 Cui et al. 原實作將權重正規化為「總和等於出現的類別數」。
    `nn.CrossEntropyLoss(reduction="mean")` 計算的是**以權重加權的平均**
    （`Σ w_i l_i / Σ w_i`），對 `w` 的整體縮放不變，因此此正規化不改變 loss 與梯度，
    只讓寫進 audit log 的數值可讀（未正規化時 `1/EN` 約為 1e-3 量級）。

    某類別在當下的訓練集合中為 0 筆時權重給 0：該類別沒有樣本進 loss，權重無作用，
    但 `1/EN` 在 `n = 0` 時未定義，必須明確處理（M3 階段二的 `D_c` 可能缺類別）。
    """
    counts_array = np.asarray(counts, dtype=np.float64)
    if counts_array.shape != (len(LABEL_INDEX),):
        raise ValueError(f"counts 必須有 {len(LABEL_INDEX)} 個類別：{counts_array}")
    if (counts_array < 0).any():
        raise ValueError(f"counts 不得為負：{counts_array}")
    effective = (1.0 - beta**counts_array) / (1.0 - beta)
    weights = np.where(counts_array > 0, 1.0 / np.where(effective > 0, effective, 1.0), 0.0)
    total = weights.sum()
    if total > 0:
        weights = weights / total * float((counts_array > 0).sum())
    return torch.tensor(weights, dtype=torch.float32)


def label_counts(targets: np.ndarray) -> np.ndarray:
    return np.bincount(targets, minlength=len(LABEL_INDEX)).astype(np.int64)


def make_loss(targets: np.ndarray, device: torch.device) -> nn.CrossEntropyLoss:
    counts = label_counts(targets)
    if (counts == 0).any():
        LOGGER.warning("訓練集合缺少類別：%s（該類別權重設為 0）", counts.tolist())
    return nn.CrossEntropyLoss(weight=cb_class_weights(counts).to(device))


# --- 模型 ---------------------------------------------------------------------


def build_model(input_dim: int) -> nn.Module:
    """31 → 128 → 64 → 2。輸出 2 個神經元，SLB 的 EMA 與 pseudo-label 在 softmax 上運作。

    權重初始化為 Xavier uniform（spec §2.2，論文明載），bias 為 0。必須在
    `set_determinism` 之後呼叫，初始化本身才是可重現的。
    """
    layers: list[nn.Module] = []
    previous = input_dim
    for size in HIDDEN_SIZES:
        layers += [nn.Linear(previous, size), nn.ReLU(), nn.Dropout(DROPOUT)]
        previous = size
    layers.append(nn.Linear(previous, len(LABEL_INDEX)))
    model = nn.Sequential(*layers)
    for module in model:
        if isinstance(module, nn.Linear):
            nn.init.xavier_uniform_(module.weight)
            nn.init.zeros_(module.bias)
    return model


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
                "nvidia_driver": _nvidia_driver_version(),
            }
        )
    return fingerprint


def _nvidia_driver_version() -> str | None:
    """spec §1b.1 要求連同驅動版本記錄：換驅動可能改變數值結果。"""
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    return result.stdout.strip().splitlines()[0].strip() if result.stdout.strip() else None


# --- 訓練的最小單位 -----------------------------------------------------------


def train_one_epoch(
    model: nn.Module,
    optimiser: torch.optim.Optimizer,
    loss_fn: nn.Module,
    inputs: torch.Tensor,
    labels: torch.Tensor,
    indices: torch.Tensor,
    generator: torch.Generator,
) -> float:
    """在 `indices` 指定的子集上訓練一個 epoch，回傳加權平均 loss。

    M2 的 `indices` 恆為全部訓練池；M3 階段二只傳入當時的 `D_c`。兩者共用同一函式，
    使「唯一差別是 SLB 機制」在程式層面也成立。
    """
    if len(indices) == 0:
        raise ValueError("訓練子集為空，無法訓練一個 epoch。")
    model.train()
    permutation = torch.randperm(len(indices), generator=generator).to(indices.device)
    order = indices[permutation]
    total_loss = 0.0
    for start in range(0, len(order), BATCH_SIZE):
        batch = order[start : start + BATCH_SIZE]
        optimiser.zero_grad(set_to_none=True)
        loss = loss_fn(model(inputs[batch]), labels[batch])
        loss.backward()
        optimiser.step()
        total_loss += loss.item() * len(batch)
    return total_loss / len(order)


def predict(model: nn.Module, inputs: torch.Tensor) -> tuple[np.ndarray, np.ndarray]:
    """回傳 (硬預測, P(positive))。eval 模式，關掉 dropout。"""
    model.eval()
    with torch.no_grad():
        logits = model(inputs)
        probabilities = torch.softmax(logits, dim=1)
    return (
        logits.argmax(dim=1).detach().cpu().numpy().astype(np.int64),
        probabilities[:, LABEL_INDEX["positive"]].detach().cpu().numpy().astype(np.float64),
    )


def accuracy_on(predictions: np.ndarray, labels: np.ndarray, indices: np.ndarray) -> float:
    if len(indices) == 0:
        return float("nan")
    return float((predictions[indices] == labels[indices]).mean())


# --- spec §5.6 的 per-epoch 指標 ---------------------------------------------


def epoch_metrics(
    *,
    run_id: str,
    model_name: str,
    seed: int,
    stage: str,
    epoch: int,
    train_loss: float,
    train_accuracy: float,
    trained_indices: np.ndarray,
    training_labels: np.ndarray,
    observed_labels: np.ndarray,
    cells: np.ndarray,
    cell_majority_labels: np.ndarray,
    clean_set_size: int | None = None,
    noisy_set_size: int | None = None,
    promoted_count: int | None = None,
    demoted_count: int | None = None,
    flips_to_pseudo: int | None = None,
    flips_to_observed: int | None = None,
) -> dict[str, Any]:
    """spec §5.6 的一列。全部指標只用 feature 與 observed label，不需要 Gold。

    `agreement_*`、`distinct_training_labels_per_cell_mean` 與
    `positive_share_of_training_labels` 一律**只在該 epoch 實際進入 loss 的集合上**
    計算，與 `train_accuracy` 的母體一致（spec §7.3）。
    """
    subset = training_labels[trained_indices]
    subset_cells = cells[trained_indices]
    distinct = [
        len(np.unique(subset[subset_cells == cell])) for cell in np.unique(subset_cells)
    ]
    return {
        "run_id": run_id,
        "model": model_name,
        "seed": seed,
        "stage": stage,
        "epoch": epoch,
        "train_loss": train_loss,
        "train_accuracy": train_accuracy,
        "trained_on_units": int(len(trained_indices)),
        "clean_set_size": clean_set_size,
        "noisy_set_size": noisy_set_size,
        "promoted_count": promoted_count,
        "demoted_count": demoted_count,
        "flips_to_pseudo": flips_to_pseudo,
        "flips_to_observed": flips_to_observed,
        "agreement_revised_vs_observed": float(
            (subset == observed_labels[trained_indices]).mean()
        ),
        "agreement_training_label_vs_cell_majority": float(
            (subset == cell_majority_labels[trained_indices]).mean()
        ),
        "distinct_training_labels_per_cell_mean": float(np.mean(distinct)),
        "positive_share_of_training_labels": float((subset == 1).mean()),
    }


# --- 產物 ---------------------------------------------------------------------


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_commit_for(path: Path) -> dict[str, Any]:
    """spec §5.7 的 `config_spec_commit`：設定當時的 commit，使設定可回溯。

    一併記錄該檔是否有未 commit 的改動——若為 true，manifest 指到的 commit 並不是
    這次執行實際採用的設定，報告不得只引用 SHA。
    """

    def run(args: list[str]) -> str:
        return subprocess.run(
            args, capture_output=True, text=True, check=False, cwd=Path.cwd()
        ).stdout.strip()

    return {
        "commit": run(["git", "log", "-1", "--format=%H", "--", str(path)]) or None,
        "dirty": bool(run(["git", "status", "--porcelain", "--", str(path)])),
    }


def write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]], *, append: bool = False) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("a" if append else "w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def prediction_rows(
    *,
    run_id: str,
    model_name: str,
    seed: int,
    split: str,
    unit_ids: Sequence[str],
    hard: np.ndarray,
    probabilities: np.ndarray,
    observed_labels: np.ndarray | None,
) -> list[dict[str, Any]]:
    """spec §5.3 的 `predictions_<run>.jsonl`。Gold 評估集的 `observed_authz_label`
    必為 `None`——那份檔案沒有標籤，本模組也不得去別處取（不變量 1）。"""
    rows: list[dict[str, Any]] = []
    for index, unit_id in enumerate(unit_ids):
        rows.append(
            {
                "run_id": run_id,
                "model": model_name,
                "seed": seed,
                "split": split,
                "review_unit_id": unit_id,
                "prob_positive": float(probabilities[index]),
                "predicted_label": LABEL_NAMES[int(hard[index])],
                "observed_authz_label": (
                    None if observed_labels is None else LABEL_NAMES[int(observed_labels[index])]
                ),
            }
        )
    return rows


def run_manifest(
    *,
    run_id: str,
    model_name: str,
    seed: int,
    config: Mapping[str, Any],
    input_paths: Mapping[str, Path],
    device: torch.device,
    wall_clock_seconds: float,
    output_row_counts: Mapping[str, int],
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """spec §5.7。`gold_consulted` 固定為 false，明示此執行未讀取 Gold。"""
    manifest: dict[str, Any] = {
        "run_id": run_id,
        "model": model_name,
        "model_version": MODEL_VERSION,
        "seed": seed,
        "config": dict(config),
        "config_spec_commit": git_commit_for(CONFIG_SPEC),
        "input_files": {
            name: {"path": str(path), "sha256": sha256_of(path)}
            for name, path in input_paths.items()
        },
        "environment": environment_fingerprint(device),
        "wall_clock_seconds": wall_clock_seconds,
        "output_row_counts": dict(output_row_counts),
        "gold_consulted": False,
    }
    if extra:
        manifest.update(extra)
    return manifest


def frozen_config(**overrides: Any) -> dict[str, Any]:
    """spec §5.7 的 `config`：寫下實際生效的值，不是文件上的值。"""
    config: dict[str, Any] = {
        "architecture": [31, *HIDDEN_SIZES, len(LABEL_INDEX)],
        "weight_init": WEIGHT_INIT,
        "dropout": DROPOUT,
        "optimizer": "Adam",
        "learning_rate": LEARNING_RATE,
        "batch_size": BATCH_SIZE,
        "loss": "class_balanced_cross_entropy",
        "cb_beta": CB_BETA,
        "total_epochs": TOTAL_EPOCHS,
        "early_stopping": False,
        "checkpoint_selection": False,
        "data_split_epochs_e": None,
        "revision_warmup_m": None,
        "revision_total_T": None,
        "ema_alpha": None,
    }
    config.update(overrides)
    return config


# --- M2 的一次正式執行 --------------------------------------------------------


def run_m2(
    *,
    seed: int,
    matrix: np.ndarray,
    targets: np.ndarray,
    unit_ids: Sequence[str],
    gold_matrix: np.ndarray,
    gold_unit_ids: Sequence[str],
    device: torch.device,
    epochs: int = TOTAL_EPOCHS,
) -> tuple[nn.Module, list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """固定 epoch 數訓練，回傳 (模型, per-epoch 指標, 預測列, 摘要)。

    不做 early stopping、不做 checkpoint selection（spec §1.1）：回傳的模型與預測
    一律來自最後一個 epoch。
    """
    run_id = f"m2-seed{seed}"
    started = time.perf_counter()
    set_determinism(seed)
    model = build_model(matrix.shape[1]).to(device)
    loss_fn = make_loss(targets, device)
    optimiser = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    inputs = torch.from_numpy(matrix).to(device)
    labels = torch.from_numpy(targets).to(device)
    all_indices = torch.arange(len(targets), device=device)
    generator = torch.Generator().manual_seed(seed)

    cells = cell_ids(matrix)
    majority = cell_majority(cells, targets)
    trained_indices = np.arange(len(targets))

    metrics: list[dict[str, Any]] = []
    for epoch in range(1, epochs + 1):
        loss_value = train_one_epoch(
            model, optimiser, loss_fn, inputs, labels, all_indices, generator
        )
        hard, _ = predict(model, inputs)
        metrics.append(
            epoch_metrics(
                run_id=run_id,
                model_name="M2",
                seed=seed,
                # M2 沒有兩階段結構，stage 固定為 vanilla（spec §7.3）。
                stage="vanilla",
                epoch=epoch,
                train_loss=loss_value,
                train_accuracy=accuracy_on(hard, targets, trained_indices),
                trained_indices=trained_indices,
                # M2 不做標籤修正，training_label 恆等於 observed label。
                training_labels=targets,
                observed_labels=targets,
                cells=cells,
                cell_majority_labels=majority,
            )
        )

    hard_train, prob_train = predict(model, inputs)
    gold_inputs = torch.from_numpy(gold_matrix).to(device)
    hard_gold, prob_gold = predict(model, gold_inputs)
    predictions = prediction_rows(
        run_id=run_id,
        model_name="M2",
        seed=seed,
        split="training",
        unit_ids=unit_ids,
        hard=hard_train,
        probabilities=prob_train,
        observed_labels=targets,
    ) + prediction_rows(
        run_id=run_id,
        model_name="M2",
        seed=seed,
        split="gold_eval",
        unit_ids=gold_unit_ids,
        hard=hard_gold,
        probabilities=prob_gold,
        observed_labels=None,
    )
    summary = {
        "run_id": run_id,
        "wall_clock_seconds": time.perf_counter() - started,
        "final_train_accuracy": metrics[-1]["train_accuracy"],
        "final_train_loss": metrics[-1]["train_loss"],
        "cells": int(len(np.unique(cells))),
        "cell_majority_ceiling": float((targets == majority).mean()),
        "predicted_positive_share_training": float((hard_train == 1).mean()),
        "predicted_positive_share_gold_eval": float((hard_gold == 1).mean()),
    }
    return model, metrics, predictions, summary


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


def run_diagnostic(
    matrix: np.ndarray, targets: np.ndarray, device: torch.device
) -> tuple[dict[str, Any], list[dict[str, float]], float]:
    """§1.3 的診斷執行：單一 seed、固定 600 epoch、不寫出模型、不讀 Gold。"""
    started = time.perf_counter()
    set_determinism(DIAGNOSTIC_SEED)
    model = build_model(matrix.shape[1]).to(device)
    loss_fn = make_loss(targets, device)
    optimiser = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    inputs = torch.from_numpy(matrix).to(device)
    labels = torch.from_numpy(targets).to(device)
    all_indices = torch.arange(len(targets), device=device)
    generator = torch.Generator().manual_seed(DIAGNOSTIC_SEED)

    history: list[dict[str, float]] = []
    for epoch in range(1, DIAGNOSTIC_EPOCHS + 1):
        loss_value = train_one_epoch(
            model, optimiser, loss_fn, inputs, labels, all_indices, generator
        )
        hard, _ = predict(model, inputs)
        history.append(
            {
                "epoch": epoch,
                "loss": loss_value,
                "accuracy": float((hard == targets).mean()),
            }
        )
    return epoch_budget(history), history, time.perf_counter() - started


# --- CLI ----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--gold-features", type=Path, default=DEFAULT_GOLD_FEATURES)
    parser.add_argument("--device", default="cuda", choices=("cuda", "cpu"))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--diagnose",
        action="store_true",
        help="執行 spec §1.3 的 epoch 決定規則：單一 seed、固定 600 epoch，不寫出模型。",
    )
    mode.add_argument(
        "--train",
        action="store_true",
        help=f"正式執行 M2：3 個凍結 seed，各 {TOTAL_EPOCHS} epoch，寫出 spec §5.3 的產物。",
    )
    parser.add_argument("--seed", type=int, action="append", help="只跑指定的 seed，可重複。")
    parser.add_argument("--diagnostic-output", type=Path, default=DEFAULT_DIAGNOSTIC)
    parser.add_argument("--experiments-dir", type=Path, default=DEFAULT_EXPERIMENTS_DIR)
    parser.add_argument("--models-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def _print_header(unit_ids: Sequence[str], names: Sequence[str], targets: np.ndarray,
                  device: torch.device) -> None:
    positives = int(targets.sum())
    print(
        f"\n訓練資料 {len(unit_ids)} 筆 × {len(names)} 維"
        f"（positive {positives}、negative {len(targets) - positives}、"
        f"{positives / len(targets):.1%}）；裝置 {device}"
    )


def _diagnose(args: argparse.Namespace, device: torch.device, matrix: np.ndarray,
              targets: np.ndarray, names: Sequence[str], unit_ids: Sequence[str]) -> int:
    budget, history, elapsed = run_diagnostic(matrix, targets, device)
    report = {
        "model_version": MODEL_VERSION,
        "mode": "epoch_budget_diagnostic",
        "gold_consulted": False,
        "units": len(unit_ids),
        "features": len(names),
        "positives": int(targets.sum()),
        "config": frozen_config(),
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
    write_json(args.diagnostic_output, report)
    LOGGER.info("已寫出 %s。", args.diagnostic_output)
    return 0


def _train(args: argparse.Namespace, device: torch.device, matrix: np.ndarray,
           targets: np.ndarray, names: Sequence[str], unit_ids: Sequence[str]) -> int:
    gold_matrix, gold_unit_ids = load_features_only(args.gold_features, names)
    print(f"Gold 評估集 {len(gold_unit_ids)} 筆（只讀 feature 與 id，無標籤）")
    seeds = tuple(args.seed) if args.seed else SEEDS
    metrics_path = args.experiments_dir / "slb_epoch_metrics.jsonl"

    for seed in seeds:
        if seed not in SEEDS:
            raise SystemExit(f"seed {seed} 不在凍結清單 {SEEDS} 內。")
        model, metrics, predictions, summary = run_m2(
            seed=seed,
            matrix=matrix,
            targets=targets,
            unit_ids=unit_ids,
            gold_matrix=gold_matrix,
            gold_unit_ids=gold_unit_ids,
            device=device,
            epochs=TOTAL_EPOCHS,
        )
        run_id = summary["run_id"]
        print(
            f"\n{run_id}：{TOTAL_EPOCHS} epoch、{summary['wall_clock_seconds']:.1f} 秒"
            f"\n  最終訓練準確率 {summary['final_train_accuracy']:.4f}"
            f"（格子多數決上限 {summary['cell_majority_ceiling']:.4f}、"
            f"{summary['cells']} 格）"
            f"\n  預測 positive 比例：訓練池 {summary['predicted_positive_share_training']:.3f}、"
            f"Gold 評估集 {summary['predicted_positive_share_gold_eval']:.3f}"
        )
        if summary["final_train_accuracy"] > summary["cell_majority_ceiling"] + 1e-9:
            raise SystemExit(
                "訓練準確率超過格子多數決上限，spec §1.2 的 sanity check 失敗——"
                "必為程式錯誤或洩漏。"
            )
        if args.dry_run:
            continue

        predictions_path = args.experiments_dir / f"predictions_{run_id}.jsonl"
        counts = {
            "slb_epoch_metrics.jsonl": write_jsonl(metrics_path, metrics, append=True),
            f"predictions_{run_id}.jsonl": write_jsonl(predictions_path, predictions),
            "label_revision_audit": 0,  # M2 沒有標籤修正，按定義為空（spec §5.3）。
        }
        args.models_dir.mkdir(parents=True, exist_ok=True)
        torch.save(model.state_dict(), args.models_dir / f"{run_id}.pt")
        write_json(
            args.experiments_dir / f"slb_run_manifest_{run_id}.json",
            run_manifest(
                run_id=run_id,
                model_name="M2",
                seed=seed,
                config=frozen_config(),
                input_paths={"features": args.features, "observed_labels": args.labels,
                             "gold_eval_features": args.gold_features},
                device=device,
                wall_clock_seconds=summary["wall_clock_seconds"],
                output_row_counts=counts,
                extra={"summary": summary},
            ),
        )
        LOGGER.info("%s 的產物已寫出。", run_id)
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    device = resolve_device(args.device)
    matrix, targets, names, unit_ids = load_dataset(args.features, args.labels)
    _print_header(unit_ids, names, targets, device)
    if args.diagnose:
        return _diagnose(args, device, matrix, targets, names, unit_ids)
    return _train(args, device, matrix, targets, names, unit_ids)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
