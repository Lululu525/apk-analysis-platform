"""評估協議的機械部分。協議見 `docs/authz_eval_protocol_v1.md`（執行前已凍結）。

這些測試守的是協議裡「不得挑數字」的那幾條：threshold 不搜尋、不取最佳 seed、
不做顯著性檢定、超過作弊上限要被標成洩漏跡象、錯誤分析的兩側必須並列。
"""
import json

import pytest

from app.tools import evaluate_authz_models as ev


def _run(macro_f1, recall=0.0, precision=0.0, balanced_accuracy=0.0):
    return {
        "classification": {
            "macro_f1": macro_f1,
            "recall": recall,
            "precision": precision,
            "balanced_accuracy": balanced_accuracy,
        }
    }


def test_runs_cover_both_models_and_all_three_frozen_seeds():
    assert ev.RUNS == (
        "m2-seed20260823",
        "m2-seed20260824",
        "m2-seed20260825",
        "m3-seed20260823",
        "m3-seed20260824",
        "m3-seed20260825",
    )


def test_aggregate_reports_the_spread_next_to_the_mean():
    """協議 §4：只報平均會隱藏 M3 已知的 seed 間分散度。"""
    per_seed = {20260823: _run(0.30), 20260824: _run(0.50), 20260825: _run(0.40)}

    aggregated = ev.aggregate(per_seed, "macro_f1")

    assert aggregated["mean"] == pytest.approx(0.40)
    assert (aggregated["min"], aggregated["max"]) == (0.30, 0.50)
    assert aggregated["spread"] == pytest.approx(0.20)
    # 三個 seed 全部列出，沒有被平均吃掉。
    assert set(aggregated["per_seed"]) == {"20260823", "20260824", "20260825"}


def test_paired_differences_flag_when_the_three_signs_disagree():
    """協議 §5：方向不一致即視為差距在 seed 噪音之內，不得只引用平均差的符號。"""
    m2 = {20260823: _run(0.30), 20260824: _run(0.40), 20260825: _run(0.50)}
    m3 = {20260823: _run(0.45), 20260824: _run(0.35), 20260825: _run(0.55)}

    difference = ev.paired_differences(m2, m3, "macro_f1")

    assert difference["per_seed"]["20260824"] == pytest.approx(-0.05)
    assert difference["mean_difference"] == pytest.approx(0.05)
    assert difference["directions_agree"] is False
    assert "噪音" in difference["note"]


def test_paired_differences_report_agreement_when_all_three_point_the_same_way():
    m2 = {20260823: _run(0.30), 20260824: _run(0.40), 20260825: _run(0.50)}
    m3 = {20260823: _run(0.35), 20260824: _run(0.45), 20260825: _run(0.55)}

    difference = ev.paired_differences(m2, m3, "macro_f1")

    assert difference["directions_agree"] is True


def test_exceeding_the_fitted_on_gold_ceiling_is_flagged_as_leakage():
    """協議 §3 判讀規則 1：超過 0.695 不是好消息。"""
    per_seed = {20260823: _run(0.70), 20260824: _run(0.60), 20260825: _run(0.50)}

    check = ev.leakage_check(per_seed)

    assert check["suspected"] is True
    assert check["seeds_exceeding"] == ["20260823"]
    assert check["threshold"] == 0.695


def test_scores_below_the_ceiling_are_not_flagged():
    per_seed = {seed: _run(0.69) for seed in ev.SEEDS}

    assert ev.leakage_check(per_seed)["suspected"] is False


def test_predictions_loader_keeps_only_the_gold_eval_split(tmp_path):
    """訓練池的預測不得混進 Gold 的評估母體。"""
    path = tmp_path / "predictions_m2-seed20260823.jsonl"
    path.write_text(
        "\n".join(
            json.dumps(row)
            for row in (
                {"split": "training", "review_unit_id": "t0", "prob_positive": 0.9,
                 "predicted_label": "positive"},
                {"split": "gold_eval", "review_unit_id": "g0", "prob_positive": 0.7,
                 "predicted_label": "positive"},
            )
        )
        + "\n",
        encoding="utf-8",
    )

    loaded = ev.load_predictions(tmp_path, "m2-seed20260823")

    assert set(loaded) == {"g0"}


def test_predictions_loader_rejects_a_file_without_gold_eval_rows(tmp_path):
    path = tmp_path / "predictions_m2-seed20260823.jsonl"
    path.write_text(
        json.dumps({"split": "training", "review_unit_id": "t0", "prob_positive": 0.1,
                    "predicted_label": "negative"}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="沒有任何 gold_eval"):
        ev.load_predictions(tmp_path, "m2-seed20260823")


def test_attach_run_takes_the_hard_label_from_the_artifact_not_a_new_threshold():
    """協議 §2：threshold 固定 0.5，直接採用訓練時已算好的硬預測，不重新切。"""
    rows = [{"review_unit_id": "g0", "sha256": "a", "label": "positive",
             "reachability": "confirmed"}]
    predictions = {"g0": {"prob_positive": 0.51, "predicted_label": "positive"}}

    attached = ev.attach_run(rows, predictions, "m2-seed20260823")

    assert attached[0]["predictions"]["m2-seed20260823"] is True
    assert attached[0]["scores"]["m2-seed20260823"] == pytest.approx(0.51)


def test_error_analysis_puts_the_cost_side_next_to_the_side_slb_wants_to_fix():
    """協議 §6：65 筆漏判的 recall 與 Gold negative 的 TN 必須並列。

    u0 是 LF 漏判的 positive（SLB 想修的）；u1 是 Gold negative（修正的代價）。
    M3 把兩筆都預測成 positive——救回了 u0，同時犧牲了 u1。兩個數字都必須出現。
    """
    rows = [
        {"review_unit_id": "u0", "sha256": "a", "label": "positive", "reachability": "confirmed"},
        {"review_unit_id": "u1", "sha256": "a", "label": "negative", "reachability": "confirmed"},
    ]
    observed = {"u0": "negative", "u1": "negative"}
    predictions_by_run = {
        run_id: {
            "u0": {"predicted_label": "positive" if run_id.startswith("m3") else "negative"},
            "u1": {"predicted_label": "positive" if run_id.startswith("m3") else "negative"},
        }
        for run_id in ev.RUNS
    }

    analysis = ev.lf_error_analysis(rows, observed, predictions_by_run)

    missed = analysis["lf_missed_positives"]
    negatives = analysis["gold_negatives"]
    assert missed["units"] == 1 and negatives["units"] == 1
    assert missed["metric"] == "predicted_positive"
    assert negatives["metric"] == "predicted_negative"
    # M2 兩邊都判 negative：漏判一筆也沒救回，但 Gold negative 全對。
    assert missed["by_run"]["m2-seed20260823"] == 0
    assert negatives["by_run"]["m2-seed20260823"] == 1
    # M3 救回了漏判，代價是 Gold negative 答錯。
    assert missed["by_run"]["m3-seed20260823"] == 1
    assert negatives["by_run"]["m3-seed20260823"] == 0


def test_error_analysis_separates_the_lf_abstentions():
    """LF abstain 的 4 筆既不是漏判也不是判對，必須自己一格。"""
    rows = [
        {"review_unit_id": "u0", "sha256": "a", "label": "positive", "reachability": "confirmed"}
    ]
    predictions_by_run = {
        run_id: {"u0": {"predicted_label": "positive"}} for run_id in ev.RUNS
    }

    analysis = ev.lf_error_analysis(rows, {"u0": None}, predictions_by_run)

    assert analysis["lf_abstained"]["units"] == 1
    assert analysis["lf_missed_positives"]["units"] == 0


def test_report_records_that_the_protocol_knobs_were_not_turned():
    """這些旗標是給讀者看的：協議 §0 列的五件事都沒做。"""
    rows = [
        {"review_unit_id": "g0", "sha256": "a", "label": "positive", "reachability": "confirmed"},
        {"review_unit_id": "g1", "sha256": "a", "label": "negative", "reachability": "refuted"},
    ]
    predictions_by_run = {
        run_id: {
            "g0": {"prob_positive": 0.8, "predicted_label": "positive"},
            "g1": {"prob_positive": 0.2, "predicted_label": "negative"},
        }
        for run_id in ev.RUNS
    }

    report = ev.evaluate(
        rows=rows,
        predictions_by_run=predictions_by_run,
        accounting={"gold_events": 2},
        observed_labels={},
    )

    assert report["threshold"] == 0.5
    assert report["threshold_searched"] is False
    assert report["best_seed_selected"] is False
    assert report["probability_ensemble"] is False
    assert report["significance_test"] is False
    # 兩層都在，不得只報好看的那一層。
    assert set(report["layers"]) == {"pipeline_all_binary", "reachable_subset"}
    assert report["layers"]["pipeline_all_binary"]["evaluated_units"] == 2
    assert report["layers"]["reachable_subset"]["evaluated_units"] == 1


def test_reference_lines_match_the_committed_artifacts():
    """參考線不得在此重算，必須與既有產物一致（協議 §3）。"""
    assert ev.REFERENCE_LINES["lf_observed_label"]["macro_f1"] == 0.331
    assert ev.REFERENCE_LINES["reachability_rule_all_positive"]["macro_f1"] == 0.439
    assert ev.REFERENCE_LINES["cross_apk_majority"]["macro_f1"] == 0.519
    assert ev.REFERENCE_LINES["fitted_on_gold_ceiling"]["macro_f1"] == 0.695
    assert ev.LEAKAGE_SUSPICION_THRESHOLD == 0.695
