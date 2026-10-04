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


def test_cb_weights_follow_the_paper_effective_number():
    """論文 Eq. (6)：權重比必為 EN 的反比，與反比於頻率不同（spec §6.2）。"""
    counts = [1030, 387]
    beta = mlp.CB_BETA

    weights = mlp.cb_class_weights(counts, beta)

    effective = [(1 - beta**n) / (1 - beta) for n in counts]
    expected_ratio = effective[0] / effective[1]
    assert weights[1].item() / weights[0].item() == pytest.approx(expected_ratio, rel=1e-5)
    # 反比於頻率會得到 1030/387 ≈ 2.66，CB 的 β=0.9999 下明顯較小。
    assert weights[1].item() / weights[0].item() < 1030 / 387
    # 正規化為「總和等於出現的類別數」。
    assert weights.sum().item() == pytest.approx(2.0)


def test_cb_weight_normalisation_does_not_change_the_loss():
    """weighted mean reduction 對權重的整體縮放不變，正規化因此只影響可讀性。"""
    logits = mlp.torch.tensor([[2.0, -1.0], [0.5, 0.25], [-1.0, 3.0]])
    labels = mlp.torch.tensor([0, 1, 1])
    raw = mlp.torch.tensor([1.021e-3, 2.634e-3])

    scaled = mlp.nn.CrossEntropyLoss(weight=raw)(logits, labels)
    normalised = mlp.nn.CrossEntropyLoss(weight=raw / raw.sum() * 2)(logits, labels)

    assert scaled.item() == pytest.approx(normalised.item(), rel=1e-6)


def test_cb_weights_give_an_absent_class_zero_instead_of_dividing_by_zero():
    """M3 階段二的 D_c 可能缺類別，1/EN 在 n=0 時未定義，必須明確處理。"""
    weights = mlp.cb_class_weights([0, 50])

    assert weights[0].item() == 0.0
    assert weights[1].item() > 0.0


def test_cb_weights_reject_a_wrong_class_count():
    with pytest.raises(ValueError, match="必須有 2 個類別"):
        mlp.cb_class_weights([1, 2, 3])


def test_model_shape_matches_the_frozen_architecture():
    model = mlp.build_model(31)

    linears = [m for m in model if hasattr(m, "out_features")]
    assert [m.out_features for m in linears] == [128, 64, 2]
    assert linears[0].in_features == 31
    # 2 個神經元 + softmax 是 SLB 的 EMA 與 pseudo-label 的前提，不可換成單一 sigmoid。
    assert linears[-1].out_features == 2


def test_weights_are_xavier_initialised_and_biases_zero():
    """spec §2.2：論文明載 Xavier。PyTorch 預設的 Kaiming-uniform 界線不同。"""
    model = mlp.build_model(31)
    linears = [m for m in model if hasattr(m, "out_features")]

    for layer in linears:
        fan_in, fan_out = layer.in_features, layer.out_features
        bound = (6.0 / (fan_in + fan_out)) ** 0.5
        assert layer.weight.abs().max().item() <= bound + 1e-6
        # Xavier 用滿整個界線，Kaiming-uniform 的界線是 1/sqrt(fan_in)，兩者可分辨。
        assert layer.weight.abs().max().item() > 0.9 * bound
        assert layer.bias.abs().max().item() == 0.0


def test_cells_collapse_identical_feature_vectors():
    """格子是 spec §1.2、§5.5 全部推論的基礎。"""
    matrix = np.array([[0, 1], [1, 0], [0, 1], [1, 1]], dtype=np.float32)

    cells = mlp.cell_ids(matrix)

    assert cells[0] == cells[2]
    assert len({int(c) for c in cells}) == 3


def test_cell_majority_breaks_ties_towards_negative():
    """tie-break 規則在執行前凍結（spec §7.3）。"""
    matrix = np.array([[0], [0], [1], [1], [1]], dtype=np.float32)
    targets = np.array([0, 1, 1, 1, 0], dtype=np.int64)

    majority = mlp.cell_majority(mlp.cell_ids(matrix), targets)

    assert majority.tolist() == [0, 0, 1, 1, 1]


def test_epoch_metrics_only_cover_units_that_entered_the_loss():
    """spec §7.3：聚合指標的母體與 train_accuracy 一致，只含進 loss 的 unit。"""
    cells = np.array([0, 0, 1, 1], dtype=np.int64)
    row = mlp.epoch_metrics(
        run_id="r",
        model_name="M3",
        seed=1,
        stage="revision",
        epoch=7,
        train_loss=0.5,
        train_accuracy=0.75,
        trained_indices=np.array([0, 1, 2]),
        training_labels=np.array([1, 0, 1, 1], dtype=np.int64),
        observed_labels=np.array([0, 0, 1, 1], dtype=np.int64),
        cells=cells,
        cell_majority_labels=np.array([0, 0, 1, 1], dtype=np.int64),
        clean_set_size=3,
        noisy_set_size=1,
    )

    assert row["trained_on_units"] == 3
    assert row["agreement_revised_vs_observed"] == pytest.approx(2 / 3)
    assert row["agreement_training_label_vs_cell_majority"] == pytest.approx(2 / 3)
    assert row["positive_share_of_training_labels"] == pytest.approx(2 / 3)
    # 格 0 進 loss 的兩筆標籤相異（1 與 0）、格 1 只有一筆 → (2 + 1) / 2
    assert row["distinct_training_labels_per_cell_mean"] == pytest.approx(1.5)
    assert row["noisy_set_size"] == 1


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


def _toy_run(seed, epochs=3):
    """測試一律在 CPU 上跑：只驗邏輯，不產生任何可被報告引用的 artifact。

    正式執行的裝置由 spec §1b 凍結為 CUDA，§1.6 明載 CPU 只能作對照。
    """
    rng = np.random.default_rng(0)
    matrix = (rng.random((64, 6)) < 0.5).astype(np.float32)
    targets = (rng.random(64) < 0.3).astype(np.int64)
    return mlp.run_m2(
        seed=seed,
        matrix=matrix,
        targets=targets,
        unit_ids=[f"u{i}" for i in range(64)],
        gold_matrix=matrix[:4],
        gold_unit_ids=[f"g{i}" for i in range(4)],
        device=mlp.torch.device("cpu"),
        epochs=epochs,
    )


def test_training_is_reproducible_under_a_fixed_seed():
    _, first, first_predictions, _ = _toy_run(20260823)
    _, second, second_predictions, _ = _toy_run(20260823)

    assert [row["train_loss"] for row in first] == [row["train_loss"] for row in second]
    assert [row["train_accuracy"] for row in first] == [row["train_accuracy"] for row in second]
    assert first_predictions == second_predictions


def test_different_seeds_give_different_trajectories():
    _, first, _, _ = _toy_run(20260823)
    _, second, _, _ = _toy_run(20260824)

    assert [row["train_loss"] for row in first] != [row["train_loss"] for row in second]


def test_m2_predictions_cover_both_splits_and_carry_no_gold_label():
    """Gold 評估集一律輸出預測但不得帶標籤（不變量 1）。"""
    _, _, predictions, _ = _toy_run(20260823, epochs=1)

    gold = [row for row in predictions if row["split"] == "gold_eval"]
    training = [row for row in predictions if row["split"] == "training"]
    assert len(gold) == 4 and len(training) == 64
    assert all(row["observed_authz_label"] is None for row in gold)
    assert all(row["observed_authz_label"] is not None for row in training)


def test_m2_metrics_leave_the_slb_only_fields_null():
    """M2 沒有標籤修正，§5.6 的 SLB 欄位必須是 null 而不是假的 0。"""
    _, metrics, _, _ = _toy_run(20260823, epochs=1)

    row = metrics[0]
    assert row["stage"] == "vanilla"
    assert row["clean_set_size"] is None
    assert row["promoted_count"] is None
    assert row["flips_to_pseudo"] is None
    # training_label 恆等於 observed label。
    assert row["agreement_revised_vs_observed"] == 1.0


def test_gold_features_must_share_the_training_columns(tmp_path):
    path = tmp_path / "gold.jsonl"
    path.write_text(
        json.dumps({"review_unit_id": "g0", "features": {"a": 1}}) + "\n", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="feature 欄位與訓練池不一致"):
        mlp.load_features_only(path, ["a", "b"])


def test_seeds_are_the_three_frozen_values():
    assert mlp.SEEDS == (20260823, 20260824, 20260825)


def test_cublas_workspace_is_configured_before_torch_use():
    """deterministic cuBLAS matmul 的前提，必須在 import torch 之前設好。"""
    import os

    assert os.environ["CUBLAS_WORKSPACE_CONFIG"] == ":4096:8"
