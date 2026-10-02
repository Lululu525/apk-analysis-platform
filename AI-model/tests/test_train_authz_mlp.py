import json

import numpy as np
import pytest

from app.tools import train_authz_mlp as mlp


def _write(tmp_path, features, labels):
    feature_path = tmp_path / "features.jsonl"
    label_path = tmp_path / "labels.jsonl"
    feature_path.write_text(
        "\n".join(
            json.dumps({"review_unit_id": uid, "features": vector})
            for uid, vector in features.items()
        )
        + "\n",
        encoding="utf-8",
    )
    label_path.write_text(
        "\n".join(
            json.dumps({"review_unit_id": uid, "observed_authz_label": label})
            for uid, label in labels.items()
        )
        + "\n",
        encoding="utf-8",
    )
    return feature_path, label_path


def test_abstained_units_are_excluded_from_training(tmp_path):
    """observed_authz_label 為 null 的 unit 不得進入 loss（authz_lf_spec §5）。"""
    features = {f"u{i}": {"a": i % 2, "b": 1 - i % 2} for i in range(4)}
    labels = {"u0": "positive", "u1": "negative", "u2": None, "u3": "positive"}

    matrix, targets, names, unit_ids = mlp.load_dataset(*_write(tmp_path, features, labels))

    assert unit_ids == ["u0", "u1", "u3"]
    assert matrix.shape == (3, 2)
    assert names == ["a", "b"]
    assert targets.tolist() == [1, 0, 1]


def test_feature_order_is_sorted_so_columns_are_stable(tmp_path):
    """欄位順序必須只由名稱決定，不得受 JSON 中的鍵序影響。"""
    features = {"u0": {"z": 1, "a": 0}, "u1": {"a": 1, "z": 0}}
    labels = {"u0": "positive", "u1": "negative"}

    matrix, _, names, _ = mlp.load_dataset(*_write(tmp_path, features, labels))

    assert names == ["a", "z"]
    assert matrix[0].tolist() == [0.0, 1.0]
    assert matrix[1].tolist() == [1.0, 0.0]


def test_label_without_feature_raises_instead_of_silently_dropping(tmp_path):
    features = {"u0": {"a": 1}}
    labels = {"u0": "positive", "u9": "negative"}

    with pytest.raises(ValueError, match="沒有 feature"):
        mlp.load_dataset(*_write(tmp_path, features, labels))


def test_class_weights_are_inverse_frequency():
    targets = np.array([0, 0, 0, 1], dtype=np.int64)

    weights = mlp.class_weights(targets)

    # negative 3 筆、positive 1 筆 → 權重比應為 1:3
    assert weights[1].item() == pytest.approx(3 * weights[0].item())


def test_class_weights_reject_a_missing_class():
    with pytest.raises(ValueError, match="不存在"):
        mlp.class_weights(np.zeros(5, dtype=np.int64))


def test_model_shape_matches_the_frozen_architecture():
    model = mlp.build_model(31)

    linears = [m for m in model if hasattr(m, "out_features")]
    assert [m.out_features for m in linears] == [128, 64, 2]
    assert linears[0].in_features == 31
    # 2 個神經元 + softmax 是 SLB 的 EMA 與 pseudo-label 的前提，不可換成單一 sigmoid。
    assert linears[-1].out_features == 2


def test_epoch_budget_applies_the_frozen_rule():
    """spec §1.3 的規則必須機械執行，不得有判斷空間。"""
    # 準確率在 epoch 10 之後完全持平，之前線性上升。
    history = [
        {"epoch": i + 1, "loss": 1.0, "accuracy": min(0.85, 0.5 + 0.035 * i)}
        for i in range(600)
    ]

    budget = mlp.epoch_budget(history)

    assert budget["smoothed_peak_accuracy"] == pytest.approx(0.85)
    assert budget["threshold"] == pytest.approx(0.84)
    # 準確率在 epoch 11 封頂，但 5-epoch 移動平均要到 epoch 14 才首次 >= 0.84
    # （epoch 13 的窗內仍含兩個上升期的值，平均 0.829）。平滑的用意正是如此。
    assert budget["e_plateau"] == 14
    assert budget["total_epochs"] == 50  # 取50倍數(3 × 14) = 50
    assert budget["rule"]["safety_factor"] == mlp.EPOCH_SAFETY_FACTOR


def test_epoch_budget_is_capped_at_the_diagnostic_length():
    """規則的上限不得被突破，否則正式執行會超出診斷觀察過的範圍。"""
    history = [{"epoch": i + 1, "loss": 1.0, "accuracy": i / 600} for i in range(600)]

    budget = mlp.epoch_budget(history)

    assert budget["total_epochs"] == mlp.DIAGNOSTIC_EPOCHS


def test_training_is_reproducible_under_a_fixed_seed():
    rng = np.random.default_rng(0)
    matrix = rng.random((64, 6)).astype(np.float32)
    targets = (rng.random(64) < 0.3).astype(np.int64)
    device = mlp.torch.device("cpu")

    _, first = mlp.train(matrix, targets, epochs=3, seed=20260823, device=device)
    _, second = mlp.train(matrix, targets, epochs=3, seed=20260823, device=device)

    assert [row["loss"] for row in first] == [row["loss"] for row in second]
    assert [row["accuracy"] for row in first] == [row["accuracy"] for row in second]


def test_different_seeds_give_different_trajectories():
    rng = np.random.default_rng(0)
    matrix = rng.random((64, 6)).astype(np.float32)
    targets = (rng.random(64) < 0.3).astype(np.int64)
    device = mlp.torch.device("cpu")

    _, first = mlp.train(matrix, targets, epochs=3, seed=20260823, device=device)
    _, second = mlp.train(matrix, targets, epochs=3, seed=20260824, device=device)

    assert [row["loss"] for row in first] != [row["loss"] for row in second]


def test_seeds_are_the_three_frozen_values():
    assert mlp.SEEDS == (20260823, 20260824, 20260825)


def test_cublas_workspace_is_configured_before_torch_use():
    """deterministic cuBLAS matmul 的前提，必須在 import torch 之前設好。"""
    import os

    assert os.environ["CUBLAS_WORKSPACE_CONFIG"] == ":4096:8"
