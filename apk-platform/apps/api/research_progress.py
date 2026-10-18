"""Read-only research progress view derived from the audited claims manifest."""
from __future__ import annotations

import csv
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CLAIMS_PATH = (
    REPO_ROOT / "AI-model" / "dataset" / "authz_v2" / "research_claims_20261019.csv"
)

METRIC_LABELS = {
    "training_units": "Training units",
    "r_gate_macro_f1": "R gate macro F1",
    "coarse_cell_macro_f1": "Coarse-cell macro F1",
    "m2_mean_macro_f1": "M2 mean macro F1",
    "m3_mean_macro_f1": "M3 mean macro F1",
    "linkage_linked_units": "Linked units",
    "linkage_macro_f1": "Linkage macro F1",
}


def _boundary(row: dict[str, str]) -> str:
    if row["claim_scope"] == "static_possible_path":
        return "static_path_only"
    if row["evaluation_design"] == "same_batch_fit":
        return "descriptive_ceiling"
    if row["gold_role"] == "tuning_or_rule_design":
        return "design_informed"
    return "held_out_internal"


def load_research_progress(claims_path: Path = DEFAULT_CLAIMS_PATH) -> dict:
    with claims_path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError("research claims manifest is empty")

    claims = []
    population_map: dict[str, dict] = {}
    for row in rows:
        population_id = row["population_id"]
        units = int(row["unit_count"])
        apks = int(row["apk_count"])
        population_map.setdefault(
            population_id,
            {"population_id": population_id, "unit_count": units, "apk_count": apks},
        )
        claims.append({
            "claim_id": row["claim_id"],
            "population_id": population_id,
            "unit_count": units,
            "apk_count": apks,
            "metric_name": row["metric_name"],
            "metric_label": METRIC_LABELS.get(row["metric_name"], row["metric_name"]),
            "metric_value": float(row["metric_value"]),
            "evaluation_design": row["evaluation_design"],
            "gold_role": row["gold_role"],
            "claim_scope": row["claim_scope"],
            "boundary": _boundary(row),
            "notes": row.get("notes", ""),
            "source": {
                "artifact_path": row["artifact_path"],
                "artifact_sha256": row["artifact_sha256"],
                "json_pointer": row["json_pointer"],
            },
        })

    populations = sorted(population_map.values(), key=lambda item: (-item["unit_count"], item["population_id"]))
    return {
        "schema_version": "research-progress-v1",
        "report_date": "2026-10-19",
        "evidence_status": "bounded",
        "summary": {
            "claim_count": len(claims),
            "population_count": len(populations),
            "generalization_claim_count": sum(
                claim["claim_scope"] == "generalization" for claim in claims
            ),
            "static_path_claim_count": sum(
                claim["claim_scope"] == "static_possible_path" for claim in claims
            ),
        },
        "populations": populations,
        "claims": claims,
        "caveats": [
            "不同 population 的指標不可直接混算或排名。",
            "同批擬合結果只代表描述性上限，不是獨立測試。",
            "Linkage 只代表靜態控制流可能路徑，不證明資料流、runtime guard 或 exploit。",
            "目前沒有任何結果登錄為外部獨立測試的泛化主張。",
        ],
    }
