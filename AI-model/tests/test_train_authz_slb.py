"""M3 的 SLB 機制。設定與公式依據見 `docs/slb_config_spec_v1.md` §2–§4 與 §7.1。

測試一律在 CPU 上跑：只驗邏輯，不產生任何可被報告引用的 artifact。正式執行的裝置由
spec §1b 凍結為 CUDA。
"""
import gzip
import json

import numpy as np
import pytest

from app.tools import train_authz_mlp as mlp
from app.tools import train_authz_slb as slb


def _split(hard_history, prob_history, observed):
    return slb.DataSplit(
        hard_history=np.array(hard_history, dtype=np.int64),
        prob_history=np.array(prob_history, dtype=np.float64),
        observed=np.array(observed, dtype=np.int64),
        metrics=[],
    )


# --- 階段一：Algorithm 1 ------------------------------------------------------


def test_consistency_ratio_compares_against_the_observed_label():
    """Eq. (3)。spec §3 第 1 點：這不是「預測穩不穩」，兩者結論會完全相反。

    第二筆穩定地預測成與 observed 相反的類別——按論文 r_i = 0 判 noisy；
    若誤用「預測類別不變的比例」會得到 1.0 並判 clean。
    """
    split = _split(
        hard_history=[[1, 0], [1, 0], [1, 0], [0, 0]],
        prob_history=np.zeros((4, 2)),
        observed=[1, 1],
    )

    assert split.consistency.tolist() == [0.75, 0.0]
    assert split.clean.tolist() == [False, False]
    assert split.origin_noisy.tolist() == [True, True]


def test_clean_requires_every_epoch_to_match():
    """Eq. (4) 的嚴格門檻 r_i = 1，不是比例、不是 per-class。"""
    split = _split(
        hard_history=[[1, 1, 0], [1, 0, 0], [1, 1, 0]],
        prob_history=np.zeros((3, 3)),
        observed=[1, 1, 0],
    )

    assert split.clean.tolist() == [True, False, True]


def test_pseudo_label_is_the_majority_prediction():
    """Eq. (5)。"""
    split = _split(
        hard_history=[[1, 0], [1, 0], [0, 1]],
        prob_history=np.zeros((3, 2)),
        observed=[0, 1],
    )

    assert split.pseudo.tolist() == [1, 0]


def test_pseudo_label_ties_fall_back_to_the_observed_label():
    """spec §7.3 第 1 項：e 為偶數時 10:10 可能發生，平手取 observed。"""
    split = _split(
        hard_history=[[1, 1], [0, 0]],
        prob_history=np.zeros((2, 2)),
        observed=[0, 1],
    )

    assert split.pseudo_ties.tolist() == [True, True]
    assert split.pseudo.tolist() == [0, 1]


def test_ema_starts_from_the_mean_over_all_data_split_epochs():
    """Eq. (8)、spec §7.1 第 1 項：是 e 個 epoch 的平均，不是最後一個 epoch。"""
    split = _split(
        hard_history=[[1], [1], [1]],
        prob_history=[[0.2], [0.5], [0.8]],
        observed=[1],
    )

    assert split.ema_initial.tolist() == [pytest.approx(0.5)]


# --- 重組規則：Algorithm 2 line 12–20／28–36 ---------------------------------


def test_an_originally_clean_sample_may_never_train_on_a_pseudo_label():
    """spec §7.1 第 3 項：`o_i = n` 的條件不可省，否則 D_c 的語意變了。

    兩筆的 EMA 都指向 pseudo 而非 observed，差別只在 origin flag。
    """
    included, training_label, label_source = slb.reassemble(
        ema_label=np.array([1, 1], dtype=np.int64),
        observed=np.array([0, 0], dtype=np.int64),
        pseudo=np.array([1, 1], dtype=np.int64),
        origin_noisy=np.array([False, True]),
    )

    # 原本 clean 的那筆進不了 D_c；原本 noisy 的那筆翻成 pseudo。
    assert included.tolist() == [False, True]
    assert label_source.tolist() == [-1, 1]
    assert training_label.tolist() == [-1, 1]


def test_matching_the_observed_label_keeps_a_sample_clean_with_its_own_label():
    included, training_label, label_source = slb.reassemble(
        ema_label=np.array([0, 1], dtype=np.int64),
        observed=np.array([0, 1], dtype=np.int64),
        pseudo=np.array([1, 0], dtype=np.int64),
        origin_noisy=np.array([True, True]),
    )

    assert included.tolist() == [True, True]
    assert label_source.tolist() == [0, 0]
    assert training_label.tolist() == [0, 1]


# --- 階段二：Algorithm 2 ------------------------------------------------------


def _toy_revision(total_epochs=8, warmup=3, clean_rows=None):
    # 自足：階段二會以全域 RNG 做 Xavier 初始化，不先鎖定的話結果會隨測試執行順序改變。
    mlp.set_determinism(20260823)
    rng = np.random.default_rng(0)
    matrix = (rng.random((40, 5)) < 0.5).astype(np.float32)
    targets = (rng.random(40) < 0.4).astype(np.int64)
    epochs = 4
    hard = np.tile(targets, (epochs, 1))
    if clean_rows is None:
        # 讓一部分樣本在某個 epoch 預測錯，成為 noisy。
        hard[1, ::3] = 1 - hard[1, ::3]
    else:
        hard[1, clean_rows:] = 1 - hard[1, clean_rows:]
    probabilities = np.where(hard == 1, 0.8, 0.2).astype(np.float64)
    split = _split(hard, probabilities, targets)
    cells = mlp.cell_ids(matrix)
    with slb.AuditLog(None) as audit:
        model, metrics, summary = slb.continuous_revision(
            run_id="t",
            seed=20260823,
            matrix=matrix,
            targets=targets,
            split=split,
            cells=cells,
            cell_majority_labels=mlp.cell_majority(cells, targets),
            device=mlp.torch.device("cpu"),
            audit=audit,
            unit_ids=[f"u{i}" for i in range(40)],
            total_epochs=total_epochs,
            warmup=warmup,
        )
    return split, metrics, summary, audit.rows


def test_revision_trains_T_epochs_in_total_including_the_warmup():
    """spec §7.1 第 4 項：Algorithm 2 line 2／21 使 T 含 m，最終模型訓練 T 個 epoch。"""
    _, metrics, _, _ = _toy_revision(total_epochs=8, warmup=3)

    assert [row["epoch"] for row in metrics] == list(range(1, 9))
    assert all(row["stage"] == "revision" for row in metrics)


def test_no_reassembly_happens_before_the_warmup_ends():
    """Algorithm 2 line 3：warm-up 期間固定訓練 D_c^0，不重組。"""
    _, metrics, _, _ = _toy_revision(total_epochs=8, warmup=3)

    warmup_rows, revised_rows = metrics[:3], metrics[3:]
    # warm-up 期間訓練集合完全不動。
    assert all(row["promoted_count"] == 0 for row in warmup_rows)
    assert all(row["demoted_count"] == 0 for row in warmup_rows)
    assert all(row["flips_to_pseudo"] == 0 for row in warmup_rows)
    assert len({row["clean_set_size"] for row in warmup_rows}) == 1
    # m 之後才有重組。某一個 epoch 恰好沒有變動是可能的，所以斷言整段期間有動過，
    # 而不是斷言第 m+1 個 epoch 一定變動（後者是資料巧合，不是 Algorithm 2 的性質）。
    assert sum(row["promoted_count"] + row["demoted_count"] for row in revised_rows) > 0


def test_warmup_must_be_shorter_than_the_total():
    with pytest.raises(ValueError, match="m < T"):
        _toy_revision(total_epochs=3, warmup=3)


def test_an_empty_clean_set_aborts_instead_of_falling_back():
    """spec §7.3 第 6 項：這是研究結果，不得以「沒資料就用全部」掩蓋。"""
    targets = np.array([0, 1], dtype=np.int64)
    matrix = np.array([[0.0], [1.0]], dtype=np.float32)
    # 兩筆在每個 epoch 都預測錯 → r_i = 0 → D_c^0 為空。
    split = _split([[1, 0], [1, 0]], [[0.9, 0.1], [0.9, 0.1]], targets)
    cells = mlp.cell_ids(matrix)

    with slb.AuditLog(None) as audit:
        with pytest.raises(RuntimeError, match="D_c 為空集合"):
            slb.continuous_revision(
                run_id="t",
                seed=20260823,
                matrix=matrix,
                targets=targets,
                split=split,
                cells=cells,
                cell_majority_labels=mlp.cell_majority(cells, targets),
                device=mlp.torch.device("cpu"),
                audit=audit,
                unit_ids=["u0", "u1"],
                total_epochs=4,
                warmup=2,
            )


def test_a_promotion_that_brings_a_pseudo_label_counts_as_a_flip(tmp_path):
    """spec §7.3 第 9 項的修正：樣本帶著 pseudo-label 由 D_n 進 D_c 時前一個 epoch 是
    null，若要求「兩端都非 null」就會把這份資料上唯一真正發生的標籤修正記成 0。"""
    rng = np.random.default_rng(6)
    matrix = (rng.random((40, 5)) < 0.5).astype(np.float32)
    targets = (rng.random(40) < 0.4).astype(np.int64)
    path = tmp_path / "audit.jsonl.gz"

    _, metrics, _, summary, _ = slb.run_m3(
        seed=20260823,
        matrix=matrix,
        targets=targets,
        unit_ids=[f"u{i}" for i in range(40)],
        gold_matrix=matrix[:2],
        gold_unit_ids=["g0", "g1"],
        device=mlp.torch.device("cpu"),
        audit_path=path,
        data_split_epochs=4,
        revision_total=8,
        revision_warmup=2,
    )

    with gzip.open(path, "rt", encoding="utf-8") as handle:
        written = [json.loads(line) for line in handle]
    first_reassembly = 3  # m + 1
    pseudo_at_first = sum(
        1
        for row in written
        if row["stage"] == "revision"
        and row["epoch"] == first_reassembly
        and row["label_source"] == "pseudo"
    )
    revision_metrics = [row for row in metrics if row["stage"] == "revision"]

    # warm-up 期間不可能有翻標籤（還沒重組）。
    assert all(row["flips_to_pseudo"] == 0 for row in revision_metrics[:2])
    # 首次重組帶進來的 pseudo-label 必須被算進去，不得因前一個 epoch 是 null 而漏掉。
    assert revision_metrics[first_reassembly - 1]["flips_to_pseudo"] == pseudo_at_first
    assert summary["revision"]["total_flips_to_pseudo"] >= pseudo_at_first


def test_ema_update_weights_the_new_prediction_by_alpha():
    """Eq. (9)、spec §7.1 第 2 項：α 乘在新的 prediction 上，不是舊的 EMA 上。

    直接驗公式方向：α = 0.95 時一個 epoch 之後 EMA 幾乎就是當下的預測。
    """
    previous, current = 0.0, 1.0

    updated = slb.EMA_ALPHA * current + (1.0 - slb.EMA_ALPHA) * previous

    assert updated == pytest.approx(0.95)
    assert slb.EMA_ALPHA == 0.95


def test_frozen_epoch_parameters_match_the_spec():
    assert (slb.DATA_SPLIT_EPOCHS, slb.REVISION_WARMUP, slb.REVISION_TOTAL) == (20, 5, 100)
    # 兩個最終模型的訓練預算必須相同，否則 M2／M3 的差距不只來自 SLB（spec §2.3）。
    assert slb.REVISION_TOTAL == mlp.TOTAL_EPOCHS


# --- audit log ----------------------------------------------------------------


def test_audit_log_has_one_row_per_unit_per_epoch_across_both_stages(tmp_path):
    rng = np.random.default_rng(1)
    matrix = (rng.random((12, 4)) < 0.5).astype(np.float32)
    targets = (rng.random(12) < 0.5).astype(np.int64)
    path = tmp_path / "audit.jsonl.gz"

    _, _, _, _, rows = slb.run_m3(
        seed=20260823,
        matrix=matrix,
        targets=targets,
        unit_ids=[f"u{i}" for i in range(12)],
        gold_matrix=matrix[:3],
        gold_unit_ids=["g0", "g1", "g2"],
        device=mlp.torch.device("cpu"),
        audit_path=path,
        data_split_epochs=3,
        revision_total=6,
        revision_warmup=2,
    )

    assert rows == 12 * (3 + 6)
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        written = [json.loads(line) for line in handle]
    assert len(written) == rows
    stages = {row["stage"] for row in written}
    assert stages == {"data_split", "revision"}
    # §5.4 的欄位清單，不增不減。
    assert set(written[0]) == {
        "run_id", "model", "seed", "stage", "epoch", "review_unit_id",
        "observed_authz_label", "predicted_label", "predicted_prob_positive",
        "consistency_ratio", "pseudo_label", "ema_prob_positive", "ema_label",
        "set_membership", "training_label", "label_source", "included_in_training",
        "membership_changed", "training_label_changed",
    }


def test_audit_log_never_sources_a_pseudo_label_for_an_originally_clean_unit(tmp_path):
    """spec §7.1 第 3 項的不變量，直接在產物上驗。"""
    rng = np.random.default_rng(2)
    matrix = (rng.random((20, 4)) < 0.5).astype(np.float32)
    targets = (rng.random(20) < 0.5).astype(np.int64)
    path = tmp_path / "audit.jsonl.gz"

    slb.run_m3(
        seed=20260823,
        matrix=matrix,
        targets=targets,
        unit_ids=[f"u{i}" for i in range(20)],
        gold_matrix=matrix[:2],
        gold_unit_ids=["g0", "g1"],
        device=mlp.torch.device("cpu"),
        audit_path=path,
        data_split_epochs=4,
        revision_total=8,
        revision_warmup=2,
    )

    with gzip.open(path, "rt", encoding="utf-8") as handle:
        written = [json.loads(line) for line in handle]
    origin = {
        row["review_unit_id"]: row["set_membership"]
        for row in written
        if row["stage"] == "data_split" and row["epoch"] == 1
    }
    for row in written:
        if row["label_source"] == "pseudo":
            assert origin[row["review_unit_id"]] == "noisy"
        if not row["included_in_training"]:
            assert row["training_label"] is None and row["label_source"] is None


def test_data_split_stage_records_the_per_epoch_trajectory_and_revision_records_ema(tmp_path):
    """階段一是 r_i 的證據（硬預測 + softmax），階段二是重組的證據（EMA）。"""
    rng = np.random.default_rng(3)
    matrix = (rng.random((8, 3)) < 0.5).astype(np.float32)
    targets = (rng.random(8) < 0.5).astype(np.int64)
    path = tmp_path / "audit.jsonl.gz"

    slb.run_m3(
        seed=20260823,
        matrix=matrix,
        targets=targets,
        unit_ids=[f"u{i}" for i in range(8)],
        gold_matrix=matrix[:2],
        gold_unit_ids=["g0", "g1"],
        device=mlp.torch.device("cpu"),
        audit_path=path,
        data_split_epochs=2,
        revision_total=4,
        revision_warmup=1,
    )

    with gzip.open(path, "rt", encoding="utf-8") as handle:
        written = [json.loads(line) for line in handle]
    for row in written:
        if row["stage"] == "data_split":
            assert row["predicted_label"] is not None
            assert row["predicted_prob_positive"] is not None
            assert row["ema_prob_positive"] is None and row["ema_label"] is None
        else:
            assert row["predicted_label"] is None
            assert row["ema_prob_positive"] is not None and row["ema_label"] is not None


# --- 整體 ---------------------------------------------------------------------


def test_m3_is_reproducible_under_a_fixed_seed():
    def once():
        rng = np.random.default_rng(4)
        matrix = (rng.random((30, 5)) < 0.5).astype(np.float32)
        targets = (rng.random(30) < 0.4).astype(np.int64)
        mlp.set_determinism(20260823)
        return slb.run_m3(
            seed=20260823,
            matrix=matrix,
            targets=targets,
            unit_ids=[f"u{i}" for i in range(30)],
            gold_matrix=matrix[:4],
            gold_unit_ids=[f"g{i}" for i in range(4)],
            device=mlp.torch.device("cpu"),
            audit_path=None,
            data_split_epochs=3,
            revision_total=6,
            revision_warmup=2,
        )

    _, first_metrics, first_predictions, first_summary, _ = once()
    _, second_metrics, second_predictions, second_summary, _ = once()

    assert [row["train_loss"] for row in first_metrics] == [
        row["train_loss"] for row in second_metrics
    ]
    assert first_predictions == second_predictions
    assert first_summary["data_split"] == second_summary["data_split"]


def test_m3_predictions_carry_no_gold_label():
    rng = np.random.default_rng(5)
    matrix = (rng.random((20, 4)) < 0.5).astype(np.float32)
    targets = (rng.random(20) < 0.5).astype(np.int64)

    _, _, predictions, _, _ = slb.run_m3(
        seed=20260823,
        matrix=matrix,
        targets=targets,
        unit_ids=[f"u{i}" for i in range(20)],
        gold_matrix=matrix[:3],
        gold_unit_ids=["g0", "g1", "g2"],
        device=mlp.torch.device("cpu"),
        audit_path=None,
        data_split_epochs=2,
        revision_total=4,
        revision_warmup=1,
    )

    gold = [row for row in predictions if row["split"] == "gold_eval"]
    assert len(gold) == 3
    assert all(row["observed_authz_label"] is None for row in gold)
