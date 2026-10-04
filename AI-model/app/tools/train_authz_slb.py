"""M3：MLP + SLB（Selective Label Bootstrapping）。設定見 `docs/slb_config_spec_v1.md`。

執行順序第 5c 項（ADR-0002）。架構、資料載入、loss、可重現性設定與全部 audit 寫出函式
一律沿用 `app/tools/train_authz_mlp.py`（M2），**本模組唯一新增的是 SLB 機制本身**——
這是 M2／M3 的差距能歸因於 SLB 的前提。

依 Alotaibi et al.（CCS '25）Algorithm 1 與 Algorithm 2 實作，兩階段：

```
階段一 Data Split（Algorithm 1）
  用全部 1,417 筆觀測標籤訓練拋棄式模型 f^DS，跑 e = 20 個 epoch
  每個 epoch 記下硬預測 → P_i；r_i = |{ŷ ∈ P_i : ŷ = ỹ_i}| / e        Eq. (3)
  D_c = {r_i = 1}、D_n = {r_i < 1}                                     Eq. (4)
  D_n 的 pseudo-label y_i^maj = majority(P_i)                          Eq. (5)
  origin flag o_i ∈ {c, n} 自此固定，全程不更新

階段二 Continuous Revision（Algorithm 2）
  EMA 初值 p̄⁽⁰⁾ = 階段一 e 個 epoch 的 softmax 平均                   Eq. (8)
  訓練全新模型 f̂，共 T = 100 個 epoch（含前 m = 5 個 warm-up）
  每個 epoch 只用當時的 D_c 進 loss，但對全部 N 筆更新 EMA
  p̄⁽ᵗ⁾ = α·p⁽ᵗ⁾ + (1−α)·p̄⁽ᵗ⁻¹⁾、ŷ⁽ᵗ⁾ = argmax p̄⁽ᵗ⁾               Eq. (9)(11)
  epoch t ≥ m 結束後重組 → D_c^{t+1}：
      ŷ⁽ᵗ⁾ = ỹ_i                    → D_c，以 observed 訓練
      o_i = n ∧ ŷ⁽ᵗ⁾ = y_i^maj      → D_c，以 pseudo 訓練（翻標籤）
      其餘                           → D_n，不進 loss
  f̂ 才是最終模型
```

三處容易記錯、spec §7.1 已校正的地方，在此重述：

1. `α = 0.95` 乘在**新的** prediction 上，所以 EMA 幾乎跟隨當下 epoch，不是強平滑。
2. `o_i` 固定於階段一：**階段一判 clean 的樣本永遠只能以 observed 標籤進 `D_c`**，
   `label_source = pseudo` 只會出現在 `o_i = n` 的樣本上。這是 audit log 的不變量。
3. `T` 含 `m`（Algorithm 2 line 2 `for r = 1 to m`、line 21 `for t = m+1 to T`），
   因此最終模型訓練 100 個 epoch，與 M2 相同；階段一那 20 個 epoch 是 SLB 的額外成本。

不變量與 M2 相同，且額外一條：**`D_c` 變成空集合時中止執行並回報**，不退回用全部資料
（spec §7.3 第 6 項）。那是研究結果，不是待修的 bug。
"""
from __future__ import annotations

import argparse
import gzip
import json
import logging
import time
from pathlib import Path
from typing import Any, Iterator, Sequence

# 必須先 import 本模組：它在 import torch 之前設定 CUBLAS_WORKSPACE_CONFIG（spec §1b.1）。
from app.tools import train_authz_mlp as m2

import numpy as np
import torch
from torch import nn

MODEL_VERSION = "authz-mlp-slb-m3-v1"

# --- spec §2.2 凍結的三個 epoch 參數與 EMA 平滑 ------------------------------
DATA_SPLIT_EPOCHS = 20  # e
REVISION_WARMUP = 5  # m
REVISION_TOTAL = 100  # T，等於 M2 的 TOTAL_EPOCHS
EMA_ALPHA = 0.95  # α，乘在新的 prediction 上（spec §7.1 第 2 項）

OBSERVED, PSEUDO, NO_LABEL = "observed", "pseudo", None
_NOT_INCLUDED = -1

LOGGER = logging.getLogger(__name__)


# --- 階段一：Data Split（Algorithm 1）----------------------------------------


class DataSplit:
    """階段一的產物。`origin_noisy` 是 Algorithm 2 的 `o_i = n`，自此固定不變。"""

    def __init__(
        self,
        *,
        hard_history: np.ndarray,
        prob_history: np.ndarray,
        observed: np.ndarray,
        metrics: list[dict[str, Any]],
    ) -> None:
        self.hard_history = hard_history
        self.prob_history = prob_history
        self.metrics = metrics
        epochs = hard_history.shape[0]
        matches = hard_history == observed
        # Eq. (3)。clean 用 all() 而非 r_i == 1.0，避免浮點等號比較。
        self.consistency = matches.mean(axis=0)
        self.clean = matches.all(axis=0)
        self.origin_noisy = ~self.clean
        # Eq. (5)。平手取 observed（spec §7.3 第 1 項）。
        positive_votes = hard_history.sum(axis=0)
        negative_votes = epochs - positive_votes
        self.pseudo_ties = positive_votes == negative_votes
        self.pseudo = np.where(
            positive_votes > negative_votes,
            1,
            np.where(negative_votes > positive_votes, 0, observed),
        ).astype(np.int64)
        # Eq. (8)：e 個 epoch 的 softmax 平均，不是最後一個 epoch（spec §7.1 第 1 項）。
        self.ema_initial = prob_history.mean(axis=0)


def data_split(
    *,
    run_id: str,
    seed: int,
    matrix: np.ndarray,
    targets: np.ndarray,
    cells: np.ndarray,
    cell_majority_labels: np.ndarray,
    device: torch.device,
    epochs: int = DATA_SPLIT_EPOCHS,
) -> DataSplit:
    """Algorithm 1。`f^DS` 是拋棄式的，只為算出 `r_i`、`y^maj` 與 EMA 初值。

    這同時是一次完整的 vanilla 執行（全部資料、原始標籤），因此 spec §5.3 所說的
    「vanilla 的預測軌跡」可直接取自本階段，不需要 M2 另外記 per-unit 軌跡。
    """
    model = m2.build_model(matrix.shape[1]).to(device)
    loss_fn = m2.make_loss(targets, device)
    optimiser = torch.optim.Adam(model.parameters(), lr=m2.LEARNING_RATE)
    inputs = torch.from_numpy(matrix).to(device)
    labels = torch.from_numpy(targets).to(device)
    all_indices = torch.arange(len(targets), device=device)
    generator = torch.Generator().manual_seed(seed)
    trained_indices = np.arange(len(targets))

    hard_history = np.empty((epochs, len(targets)), dtype=np.int64)
    prob_history = np.empty((epochs, len(targets)), dtype=np.float64)
    metrics: list[dict[str, Any]] = []
    for epoch in range(1, epochs + 1):
        loss_value = m2.train_one_epoch(
            model, optimiser, loss_fn, inputs, labels, all_indices, generator
        )
        hard, probabilities = m2.predict(model, inputs)
        hard_history[epoch - 1] = hard
        prob_history[epoch - 1] = probabilities
        metrics.append(
            m2.epoch_metrics(
                run_id=run_id,
                model_name="M3",
                seed=seed,
                stage="data_split",
                epoch=epoch,
                train_loss=loss_value,
                train_accuracy=m2.accuracy_on(hard, targets, trained_indices),
                trained_indices=trained_indices,
                # 階段一全部以 observed 標籤訓練，沒有任何修正。
                training_labels=targets,
                observed_labels=targets,
                cells=cells,
                cell_majority_labels=cell_majority_labels,
                # clean／noisy 的切分在 e 個 epoch 跑完之後才存在，期間為 null。
            )
        )
    return DataSplit(
        hard_history=hard_history,
        prob_history=prob_history,
        observed=targets,
        metrics=metrics,
    )


# --- 階段二：Continuous Revision（Algorithm 2）-------------------------------


def reassemble(
    *,
    ema_label: np.ndarray,
    observed: np.ndarray,
    pseudo: np.ndarray,
    origin_noisy: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Algorithm 2 line 12–20／28–36。回傳 (included, training_label, label_source)。

    `label_source` 以 0 = observed、1 = pseudo、-1 = 不進 loss 編碼。
    `o_i = n` 的條件不可省：階段一判 clean 的樣本不得以 pseudo-label 進 `D_c`
    （spec §7.1 第 3 項）。
    """
    keeps_observed = ema_label == observed
    takes_pseudo = (~keeps_observed) & origin_noisy & (ema_label == pseudo)
    included = keeps_observed | takes_pseudo
    training_label = np.where(
        keeps_observed, observed, np.where(takes_pseudo, pseudo, _NOT_INCLUDED)
    ).astype(np.int64)
    label_source = np.where(
        keeps_observed, 0, np.where(takes_pseudo, 1, _NOT_INCLUDED)
    ).astype(np.int64)
    return included, training_label, label_source


def continuous_revision(
    *,
    run_id: str,
    seed: int,
    matrix: np.ndarray,
    targets: np.ndarray,
    split: DataSplit,
    cells: np.ndarray,
    cell_majority_labels: np.ndarray,
    device: torch.device,
    audit: "AuditLog",
    unit_ids: Sequence[str],
    total_epochs: int = REVISION_TOTAL,
    warmup: int = REVISION_WARMUP,
) -> tuple[nn.Module, list[dict[str, Any]], dict[str, Any]]:
    """Algorithm 2。回傳 (最終模型, per-epoch 指標, 摘要)。"""
    if warmup >= total_epochs:
        raise ValueError(f"Algorithm 2 要求 m < T，得到 m={warmup}、T={total_epochs}。")

    observed = targets
    ema = split.ema_initial.copy()
    # D_c^0：階段一的切分，warm-up 期間固定不變（Algorithm 2 line 3）。
    included = split.clean.copy()
    training_label = np.where(included, observed, _NOT_INCLUDED).astype(np.int64)
    label_source = np.where(included, 0, _NOT_INCLUDED).astype(np.int64)
    previous = (included.copy(), training_label.copy())
    # 每筆最近一次非 null 的 label_source，未進過 loss 的視為 observed（spec §7.3 第 9 項）。
    # 不可改用「前一個 epoch 的 label_source」：樣本由 D_n 帶著 pseudo-label 被提拔進
    # D_c 時，前一個 epoch 是 null，那樣會把實際發生的翻標籤記成 0。
    last_source = np.zeros(len(observed), dtype=np.int64)

    model = m2.build_model(matrix.shape[1]).to(device)
    optimiser = torch.optim.Adam(model.parameters(), lr=m2.LEARNING_RATE)
    inputs = torch.from_numpy(matrix).to(device)
    generator = torch.Generator().manual_seed(seed)

    metrics: list[dict[str, Any]] = []
    for epoch in range(1, total_epochs + 1):
        trained_indices = np.flatnonzero(included)
        if len(trained_indices) == 0:
            raise RuntimeError(
                f"{run_id} 階段二 epoch {epoch}：D_c 為空集合，依 spec §7.3 第 6 項中止。"
                "這是 revision collapse 的極端形式，應作為結果回報，不得退回用全部資料。"
            )
        # loss 權重由當時 D_c 的 training label 重算（spec §7.3 第 4 項）。
        loss_fn = m2.make_loss(training_label[trained_indices], device)
        labels_tensor = torch.from_numpy(np.where(included, training_label, 0)).to(device)
        loss_value = m2.train_one_epoch(
            model,
            optimiser,
            loss_fn,
            inputs,
            labels_tensor,
            torch.from_numpy(trained_indices).to(device),
            generator,
        )
        hard, probabilities = m2.predict(model, inputs)
        # Eq. (9)／(11)：對全部 N 筆更新，D_n 的樣本不進 loss 但仍更新 EMA。
        ema = EMA_ALPHA * probabilities + (1.0 - EMA_ALPHA) * ema
        ema_label = (ema >= 0.5).astype(np.int64)

        previous_included, previous_label = previous
        flipped_to_pseudo = included & (label_source == 1) & (last_source == 0)
        flipped_to_observed = included & (label_source == 0) & (last_source == 1)
        last_source = np.where(included, label_source, last_source)
        metrics.append(
            m2.epoch_metrics(
                run_id=run_id,
                model_name="M3",
                seed=seed,
                stage="revision",
                epoch=epoch,
                train_loss=loss_value,
                train_accuracy=m2.accuracy_on(hard, training_label, trained_indices),
                trained_indices=trained_indices,
                training_labels=training_label,
                observed_labels=observed,
                cells=cells,
                cell_majority_labels=cell_majority_labels,
                clean_set_size=int(included.sum()),
                noisy_set_size=int((~included).sum()),
                promoted_count=int((included & ~previous_included).sum()),
                demoted_count=int((~included & previous_included).sum()),
                flips_to_pseudo=int(flipped_to_pseudo.sum()),
                flips_to_observed=int(flipped_to_observed.sum()),
            )
        )
        audit.write(
            revision_audit_rows(
                run_id=run_id,
                seed=seed,
                epoch=epoch,
                unit_ids=unit_ids,
                observed=observed,
                split=split,
                ema=ema,
                ema_label=ema_label,
                included=included,
                training_label=training_label,
                label_source=label_source,
                previous_included=previous_included,
                previous_label=previous_label,
            )
        )

        previous = (included.copy(), training_label.copy())
        # Algorithm 2：epoch m 結束後首次重組，之後逐輪重組。最後一輪的重組會產生
        # D_c^{T+1}，它不再被訓練，且可由本列的 ema_label 還原（spec §7.5），故不計算。
        if warmup <= epoch < total_epochs:
            included, training_label, label_source = reassemble(
                ema_label=ema_label,
                observed=observed,
                pseudo=split.pseudo,
                origin_noisy=split.origin_noisy,
            )

    summary = {
        "final_clean_set_size": int(metrics[-1]["clean_set_size"]),
        "final_train_accuracy": metrics[-1]["train_accuracy"],
        "final_agreement_revised_vs_observed": metrics[-1]["agreement_revised_vs_observed"],
        "final_agreement_training_label_vs_cell_majority": metrics[-1][
            "agreement_training_label_vs_cell_majority"
        ],
        "total_flips_to_pseudo": int(sum(row["flips_to_pseudo"] for row in metrics)),
        "total_flips_to_observed": int(sum(row["flips_to_observed"] for row in metrics)),
        "epochs_with_reassembly": int(total_epochs - warmup),
    }
    return model, metrics, summary


# --- audit log（spec §5.4、§7.4）----------------------------------------------


class AuditLog:
    """`label_revision_audit_<run_id>.jsonl.gz`，逐 epoch 串流寫出。

    每個 (run, stage, epoch, unit) 一列，欄位完全依 §5.4，不增不減（§7.4）。
    `path` 為 None 時只計數不寫檔，供 `--dry-run` 使用。
    """

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.rows = 0
        self._handle = None

    def __enter__(self) -> "AuditLog":
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = gzip.open(self.path, "wt", encoding="utf-8", newline="\n")
        return self

    def __exit__(self, *exc: object) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def write(self, rows: Iterator[dict[str, Any]]) -> None:
        for row in rows:
            self.rows += 1
            if self._handle is not None:
                self._handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def data_split_audit_rows(
    *,
    run_id: str,
    seed: int,
    epoch: int,
    unit_ids: Sequence[str],
    observed: np.ndarray,
    split: DataSplit,
) -> Iterator[dict[str, Any]]:
    """階段一的一個 epoch。`consistency_ratio`、`pseudo_label`、`set_membership` 要等
    e 個 epoch 跑完才算得出來，因此逐列重複存最終值（§5.4 的反正規化）。

    `training_label` 與 `included_in_training` 在階段一填實值而非 null：階段一確實把
    全部 N 筆以 observed 標籤送進 loss，填實值使本檔跨兩個階段語意一致，也讓階段一
    可直接當成 vanilla 的預測軌跡使用。
    """
    hard = split.hard_history[epoch - 1]
    probabilities = split.prob_history[epoch - 1]
    for index, unit_id in enumerate(unit_ids):
        yield {
            "run_id": run_id,
            "model": "M3",
            "seed": seed,
            "stage": "data_split",
            "epoch": epoch,
            "review_unit_id": unit_id,
            "observed_authz_label": m2.LABEL_NAMES[int(observed[index])],
            "predicted_label": m2.LABEL_NAMES[int(hard[index])],
            "predicted_prob_positive": float(probabilities[index]),
            "consistency_ratio": float(split.consistency[index]),
            "pseudo_label": m2.LABEL_NAMES[int(split.pseudo[index])],
            "ema_prob_positive": None,
            "ema_label": None,
            "set_membership": "clean" if split.clean[index] else "noisy",
            "training_label": m2.LABEL_NAMES[int(observed[index])],
            "label_source": OBSERVED,
            "included_in_training": True,
            "membership_changed": False,
            "training_label_changed": False,
        }


def revision_audit_rows(
    *,
    run_id: str,
    seed: int,
    epoch: int,
    unit_ids: Sequence[str],
    observed: np.ndarray,
    split: DataSplit,
    ema: np.ndarray,
    ema_label: np.ndarray,
    included: np.ndarray,
    training_label: np.ndarray,
    label_source: np.ndarray,
    previous_included: np.ndarray,
    previous_label: np.ndarray,
) -> Iterator[dict[str, Any]]:
    """階段二的一個 epoch。

    `set_membership`、`training_label`、`label_source`、`included_in_training` 描述的是
    **這個 epoch 用來訓練的集合**（即 `D_c^t`）；`ema_prob_positive`、`ema_label` 是
    **本 epoch 更新後**的 EMA（§5.4）。兩者的時點不同是刻意的：前者是這一輪的輸入，
    後者是這一輪的輸出，也是下一輪重組的依據。
    """
    for index, unit_id in enumerate(unit_ids):
        is_included = bool(included[index])
        yield {
            "run_id": run_id,
            "model": "M3",
            "seed": seed,
            "stage": "revision",
            "epoch": epoch,
            "review_unit_id": unit_id,
            "observed_authz_label": m2.LABEL_NAMES[int(observed[index])],
            "predicted_label": None,
            "predicted_prob_positive": None,
            "consistency_ratio": float(split.consistency[index]),
            "pseudo_label": m2.LABEL_NAMES[int(split.pseudo[index])],
            "ema_prob_positive": float(ema[index]),
            "ema_label": m2.LABEL_NAMES[int(ema_label[index])],
            "set_membership": "clean" if is_included else "noisy",
            "training_label": (
                m2.LABEL_NAMES[int(training_label[index])] if is_included else None
            ),
            "label_source": (
                (OBSERVED if label_source[index] == 0 else PSEUDO) if is_included else NO_LABEL
            ),
            "included_in_training": is_included,
            "membership_changed": is_included != bool(previous_included[index]),
            "training_label_changed": int(training_label[index]) != int(previous_label[index]),
        }


# --- 一次完整的 M3 執行 -------------------------------------------------------


def split_summary(split: DataSplit, targets: np.ndarray, cells: np.ndarray) -> dict[str, Any]:
    """§4.4 預先登記的預測要對照的那些數字。只用 feature 與 observed label。"""
    clean = split.clean
    histogram: dict[str, int] = {}
    for value in np.round(split.consistency, 2):
        key = f"{value:.2f}"
        histogram[key] = histogram.get(key, 0) + 1
    whole_cells_noisy = 0
    for cell in np.unique(cells):
        mask = cells == cell
        if not clean[mask].any():
            whole_cells_noisy += 1
    return {
        "clean_set_size": int(clean.sum()),
        "noisy_set_size": int((~clean).sum()),
        "clean_share": float(clean.mean()),
        "clean_positive": int((clean & (targets == 1)).sum()),
        "clean_negative": int((clean & (targets == 0)).sum()),
        "consistency_ratio_mean": float(split.consistency.mean()),
        "consistency_ratio_histogram": dict(sorted(histogram.items())),
        "pseudo_differs_from_observed": int((split.pseudo != targets).sum()),
        "pseudo_majority_ties": int(split.pseudo_ties.sum()),
        "cells_entirely_noisy": whole_cells_noisy,
        "cells_total": int(len(np.unique(cells))),
    }


def run_m3(
    *,
    seed: int,
    matrix: np.ndarray,
    targets: np.ndarray,
    unit_ids: Sequence[str],
    gold_matrix: np.ndarray,
    gold_unit_ids: Sequence[str],
    device: torch.device,
    audit_path: Path | None,
    data_split_epochs: int = DATA_SPLIT_EPOCHS,
    revision_total: int = REVISION_TOTAL,
    revision_warmup: int = REVISION_WARMUP,
) -> tuple[nn.Module, list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], int]:
    """回傳 (最終模型, per-epoch 指標, 預測列, 摘要, audit 列數)。"""
    run_id = f"m3-seed{seed}"
    started = time.perf_counter()
    m2.set_determinism(seed)
    cells = m2.cell_ids(matrix)
    majority = m2.cell_majority(cells, targets)

    with AuditLog(audit_path) as audit:
        split = data_split(
            run_id=run_id,
            seed=seed,
            matrix=matrix,
            targets=targets,
            cells=cells,
            cell_majority_labels=majority,
            device=device,
            epochs=data_split_epochs,
        )
        for epoch in range(1, data_split_epochs + 1):
            audit.write(
                data_split_audit_rows(
                    run_id=run_id,
                    seed=seed,
                    epoch=epoch,
                    unit_ids=unit_ids,
                    observed=targets,
                    split=split,
                )
            )
        model, revision_metrics, revision = continuous_revision(
            run_id=run_id,
            seed=seed,
            matrix=matrix,
            targets=targets,
            split=split,
            cells=cells,
            cell_majority_labels=majority,
            device=device,
            audit=audit,
            unit_ids=unit_ids,
            total_epochs=revision_total,
            warmup=revision_warmup,
        )
        audit_rows = audit.rows

    inputs = torch.from_numpy(matrix).to(device)
    hard_train, prob_train = m2.predict(model, inputs)
    hard_gold, prob_gold = m2.predict(model, torch.from_numpy(gold_matrix).to(device))
    predictions = m2.prediction_rows(
        run_id=run_id,
        model_name="M3",
        seed=seed,
        split="training",
        unit_ids=unit_ids,
        hard=hard_train,
        probabilities=prob_train,
        observed_labels=targets,
    ) + m2.prediction_rows(
        run_id=run_id,
        model_name="M3",
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
        "cells": int(len(np.unique(cells))),
        "cell_majority_ceiling": float((targets == majority).mean()),
        "data_split": split_summary(split, targets, cells),
        "revision": revision,
        "predicted_positive_share_training": float((hard_train == 1).mean()),
        "predicted_positive_share_gold_eval": float((hard_gold == 1).mean()),
    }
    return model, split.metrics + revision_metrics, predictions, summary, audit_rows


# --- CLI ----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, default=m2.DEFAULT_FEATURES)
    parser.add_argument("--labels", type=Path, default=m2.DEFAULT_LABELS)
    parser.add_argument("--gold-features", type=Path, default=m2.DEFAULT_GOLD_FEATURES)
    parser.add_argument("--device", default="cuda", choices=("cuda", "cpu"))
    parser.add_argument("--seed", type=int, action="append", help="只跑指定的 seed，可重複。")
    parser.add_argument(
        "--data-split-only",
        action="store_true",
        help="只跑階段一並印出 §4.4 要對照的 r_i 分布與 |D_c|，不寫任何產物。",
    )
    parser.add_argument("--experiments-dir", type=Path, default=m2.DEFAULT_EXPERIMENTS_DIR)
    parser.add_argument("--audit-dir", type=Path, default=Path("dataset/authz_v2"))
    parser.add_argument("--models-dir", type=Path, default=m2.DEFAULT_OUTPUT_DIR)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def _print_split(seed: int, summary: dict[str, Any]) -> None:
    print(
        f"\n  階段一（e = {DATA_SPLIT_EPOCHS}）的切分："
        f"\n    |D_c| = {summary['clean_set_size']}"
        f"（{summary['clean_share']:.1%}；positive {summary['clean_positive']}、"
        f"negative {summary['clean_negative']}）"
        f"\n    |D_n| = {summary['noisy_set_size']}"
        f"\n    整格全部落入 D_n 的格子：{summary['cells_entirely_noisy']} / "
        f"{summary['cells_total']}"
        f"\n    pseudo_label ≠ observed：{summary['pseudo_differs_from_observed']} 筆"
        f"（其中 majority 平手 {summary['pseudo_majority_ties']} 筆取 observed）"
        f"\n    r_i 平均 {summary['consistency_ratio_mean']:.4f}"
    )


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    device = m2.resolve_device(args.device)
    matrix, targets, names, unit_ids = m2.load_dataset(args.features, args.labels)
    positives = int(targets.sum())
    print(
        f"\n訓練資料 {len(unit_ids)} 筆 × {len(names)} 維"
        f"（positive {positives}、negative {len(targets) - positives}、"
        f"{positives / len(targets):.1%}）；裝置 {device}"
    )
    seeds = tuple(args.seed) if args.seed else m2.SEEDS
    for seed in seeds:
        if seed not in m2.SEEDS:
            raise SystemExit(f"seed {seed} 不在凍結清單 {m2.SEEDS} 內。")

    if args.data_split_only:
        cells = m2.cell_ids(matrix)
        for seed in seeds:
            m2.set_determinism(seed)
            split = data_split(
                run_id=f"m3-seed{seed}",
                seed=seed,
                matrix=matrix,
                targets=targets,
                cells=cells,
                cell_majority_labels=m2.cell_majority(cells, targets),
                device=device,
            )
            summary = split_summary(split, targets, cells)
            print(f"\nseed {seed}")
            _print_split(seed, summary)
            print(f"    r_i 分布：{summary['consistency_ratio_histogram']}")
        return 0

    gold_matrix, gold_unit_ids = m2.load_features_only(args.gold_features, names)
    print(f"Gold 評估集 {len(gold_unit_ids)} 筆（只讀 feature 與 id，無標籤）")
    metrics_path = args.experiments_dir / "slb_epoch_metrics.jsonl"

    for seed in seeds:
        run_id = f"m3-seed{seed}"
        audit_name = f"label_revision_audit_{run_id}.jsonl.gz"
        audit_path = None if args.dry_run else args.audit_dir / audit_name
        model, metrics, predictions, summary, audit_rows = run_m3(
            seed=seed,
            matrix=matrix,
            targets=targets,
            unit_ids=unit_ids,
            gold_matrix=gold_matrix,
            gold_unit_ids=gold_unit_ids,
            device=device,
            audit_path=audit_path,
        )
        revision = summary["revision"]
        print(
            f"\n{run_id}：階段一 {DATA_SPLIT_EPOCHS} + 階段二 {REVISION_TOTAL} epoch、"
            f"{summary['wall_clock_seconds']:.1f} 秒"
        )
        _print_split(seed, summary["data_split"])
        print(
            f"  階段二（T = {REVISION_TOTAL}、m = {REVISION_WARMUP}、α = {EMA_ALPHA}）："
            f"\n    最終 |D_c| = {revision['final_clean_set_size']}、"
            f"訓練準確率 {revision['final_train_accuracy']:.4f}"
            f"\n    最終 revised 對 observed 一致率 "
            f"{revision['final_agreement_revised_vs_observed']:.4f}"
            f"\n    最終 training_label 對格內多數一致率 "
            f"{revision['final_agreement_training_label_vs_cell_majority']:.4f}"
            f"（§5.5 的線索；趨近 1.0 即為格內同質化）"
            f"\n    翻標籤累計：→pseudo {revision['total_flips_to_pseudo']}、"
            f"→observed {revision['total_flips_to_observed']}"
            f"\n  預測 positive 比例：訓練池 "
            f"{summary['predicted_positive_share_training']:.3f}、"
            f"Gold 評估集 {summary['predicted_positive_share_gold_eval']:.3f}"
            f"\n  audit log {audit_rows} 列"
        )
        if revision["final_train_accuracy"] > summary["cell_majority_ceiling"] + 1e-9:
            LOGGER.warning(
                "階段二的訓練準確率 %.4f 高於格子多數決上限 %.4f。這在 M3 不必然是洩漏——"
                "階段二只用 D_c 訓練且標籤已被修正，母體與 §1.2 的 1,417 筆不同——"
                "但必須在報告中說明。",
                revision["final_train_accuracy"],
                summary["cell_majority_ceiling"],
            )
        if args.dry_run:
            continue

        predictions_path = args.experiments_dir / f"predictions_{run_id}.jsonl"
        counts = {
            "slb_epoch_metrics.jsonl": m2.write_jsonl(metrics_path, metrics, append=True),
            f"predictions_{run_id}.jsonl": m2.write_jsonl(predictions_path, predictions),
            audit_name: audit_rows,
        }
        args.models_dir.mkdir(parents=True, exist_ok=True)
        torch.save(model.state_dict(), args.models_dir / f"{run_id}.pt")
        manifest = m2.run_manifest(
            run_id=run_id,
            model_name="M3",
            seed=seed,
            config=m2.frozen_config(
                data_split_epochs_e=DATA_SPLIT_EPOCHS,
                revision_warmup_m=REVISION_WARMUP,
                revision_total_T=REVISION_TOTAL,
                ema_alpha=EMA_ALPHA,
                total_epochs=REVISION_TOTAL,
            ),
            input_paths={
                "features": args.features,
                "observed_labels": args.labels,
                "gold_eval_features": args.gold_features,
            },
            device=device,
            wall_clock_seconds=summary["wall_clock_seconds"],
            output_row_counts=counts,
            extra={"model_version": MODEL_VERSION, "summary": summary},
        )
        manifest["output_files"] = {
            audit_name: {"sha256": m2.sha256_of(audit_path), "uncompressed_rows": audit_rows}
        }
        m2.write_json(args.experiments_dir / f"slb_run_manifest_{run_id}.json", manifest)
        LOGGER.info("%s 的產物已寫出。", run_id)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
