"""Entry-to-sink linkage：從 component 的 entry method 到 sink 所在 method 的可達性。

規格見 `docs/authz_linkage_spec_v1.md`（規則已於執行前 commit 凍結）。執行順序第 6 項。

**規格 §0 必讀**：本分析的三條規則是在接觸過 Gold 的 positive 側之後才定下來的，
與本專題其他每一份規格的順序相反。報告不得把它描述成「先凍結再量」。

回答的問題只有一個：沿著呼叫關係，component 的 entry method 到不到得了 sink 所在的 method。
不做 taint analysis、不處理反射與動態載入、不處理 native code、不產生 A 的證據。

兩條補充規則補的是靜態呼叫圖必然斷掉的地方（規格 §2.2、§2.3）：

- **規則 A** 建構者 → 回呼：`new Thread(r).start()` 不存在任何一行「呼叫 run()」，
  因此以「誰建構了這個物件，誰就可能使它的回呼執行」補邊。
- **規則 B** `<init>` 視為 entry：框架一定先建構 component 實例才呼叫生命週期方法。

兩者都是**過度近似**：不 sound（建構了不一定執行）也不 complete（反射的邊看不到），
會產生不存在的路徑。`used_callback_edge` 與 `used_init_as_entry` 逐列記錄，
使兩條近似各自的貢獻可事後稽核。

本模組**不讀 Gold**；`--evaluate` 才與 Gold join，且只讀標籤、不寫入。
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import logging
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

ANALYSIS_VERSION = "authz-linkage-v1"

DEFAULT_UNITS = Path("dataset/authz_v2/candidate_units_pilot300.jsonl")
DEFAULT_SAMPLES = Path(
    "output/canonical_pilot/pilot_300_six_strata_seed_20260823_v3/selected_samples.csv"
)
DEFAULT_OUTPUT = Path("dataset/authz_v2/entry_sink_linkage.jsonl")
DEFAULT_GOLD_LOG = Path("dataset/authz_v2/gold_review_log.jsonl")
DEFAULT_OBSERVED_LABELS = Path("dataset/authz_v2/observed_labels_gold_eval.jsonl")
DEFAULT_EVAL_OUTPUT = Path("dataset/authz_v2/experiments/linkage_eval.json")

# --- 規格 §2.2 凍結的規則參數，不得增減 -------------------------------------
CALLBACK_METHODS = frozenset(
    {
        "run",
        "doInBackground",
        "onPostExecute",
        "onPreExecute",
        "onProgressUpdate",
        "onClick",
        "onLongClick",
        "onItemClick",
        "handleMessage",
        "call",
        "onReceive",
    }
)
MAX_DEPTH = 8
CONSTRUCTOR = "<init>"

# 設計這些規則時實際看過的 APK（規格 §0 第 2 項、§4 第 2 組）。
DESIGN_APK_PREFIXES = ("9b2a8728", "9ed8ab7e")

LOGGER = logging.getLogger(__name__)


# --- 呼叫圖 -------------------------------------------------------------------


class CallGraph:
    """以 `(class_name, method_name)` 為節點的反向呼叫圖。

    節點刻意不含 descriptor（規格 §2.1）：同名多載被併成一個節點，屬過度近似。
    """

    def __init__(self) -> None:
        self.callers: dict[tuple[str, str], set[tuple[str, str]]] = collections.defaultdict(set)
        # 規則 A 補出的邊單獨存放，使「這條路徑用到了哪一條近似」可以如實記錄。
        self.callback_callers: dict[tuple[str, str], set[tuple[str, str]]] = (
            collections.defaultdict(set)
        )
        self.constructor_callers: dict[str, set[tuple[str, str]]] = collections.defaultdict(set)
        self.methods_by_class: dict[str, set[str]] = collections.defaultdict(set)
        self.callback_edges = 0

    def add_call(self, caller: tuple[str, str], callee: tuple[str, str]) -> None:
        self.callers[callee].add(caller)
        if callee[1] == CONSTRUCTOR:
            self.constructor_callers[callee[0]].add(caller)

    def apply_callback_rule(self) -> None:
        """規則 A：誰建構了這個物件，誰就可能使它的回呼執行。"""
        for class_name, methods in self.methods_by_class.items():
            for callback in methods & CALLBACK_METHODS:
                builders = self.constructor_callers.get(class_name)
                if not builders:
                    continue
                added = builders - self.callers.get((class_name, callback), set())
                self.callback_callers[(class_name, callback)].update(added)
                self.callback_edges += len(added)

    def _parents(
        self, node: tuple[str, str], use_callbacks: bool
    ) -> Iterable[tuple[str, str]]:
        if not use_callbacks:
            return self.callers.get(node, ())
        return self.callers.get(node, set()) | self.callback_callers.get(node, set())

    def reach_entry(
        self,
        class_name: str,
        method_name: str,
        entries: frozenset[str],
        *,
        use_callbacks: bool,
    ) -> int | None:
        """由 sink 所在 method 往回 BFS，回傳到達 entry method 的跳數。

        只接受**同一個 class** 的 entry method：unit 的身分是
        (component, caller_class, caller_method)，其他 class 的 entry 是另一條 unit 的事。
        中間節點可以是任何 class（例如匿名內部類別），只有終點受此限制。
        """
        start = (class_name, method_name)
        seen = {start}
        frontier: collections.deque[tuple[str, str, int]] = collections.deque([(*start, 0)])
        while frontier:
            current_class, current_method, depth = frontier.popleft()
            if (
                current_class == class_name
                and current_method in entries
                and (current_class, current_method) != start
            ):
                return depth
            if depth >= MAX_DEPTH:
                continue
            for parent in self._parents((current_class, current_method), use_callbacks):
                if parent not in seen:
                    seen.add(parent)
                    frontier.append((parent[0], parent[1], depth + 1))
        return None


def build_call_graph(apk_path: Path) -> CallGraph:
    """以 Androguard 的 XREF 建圖。import 放在函式內，使本模組在無 androguard 時仍可 import。"""
    from androguard.misc import AnalyzeAPK

    _, _, analysis = AnalyzeAPK(str(apk_path))
    graph = CallGraph()
    for method in analysis.get_methods():
        owner = method.get_method().get_class_name()
        graph.methods_by_class[owner].add(method.name)
        try:
            xrefs = method.get_xref_to()
        except Exception:  # pragma: no cover - Androguard 對少數 method 會丟例外
            continue
        for _, callee, _ in xrefs:
            graph.add_call((owner, method.name), (callee.get_class_name(), callee.name))
    graph.apply_callback_rule()
    return graph


# --- 逐 unit 判定 -------------------------------------------------------------


def entry_methods_for(component_type: str) -> frozenset[str]:
    """沿用 `build_observed_labels.ENTRY_METHODS`（已於 a7a8327 凍結），不另行定義。"""
    from .build_observed_labels import ENTRY_METHODS

    methods = ENTRY_METHODS.get(component_type)
    if methods is None:
        raise ValueError(f"未知的 component_type {component_type!r}")
    return frozenset(methods)


def judge_unit(unit: Mapping[str, Any], graph: CallGraph) -> dict[str, Any]:
    """單一 unit 的 linkage 判定。回傳規格 §5 的欄位（不含 run 層級的欄位）。"""
    component_type = str(unit["component_type"])
    entries = entry_methods_for(component_type)
    caller_class = str(unit["caller_class"])
    caller_method = str(unit["caller_method"])

    if caller_method in entries:
        # sink 就寫在 entry method 裡，與 LF 規則 1 的 positive 條件相同。
        return {
            "linkage_result": "linked",
            "linkage_reason": "sink_in_entry_method",
            "path_depth": 0,
            "used_callback_edge": False,
            "used_init_as_entry": False,
        }

    # 由最弱的假設往上試，使記錄下來的是「最少需要哪幾條近似」。
    with_init = entries | {CONSTRUCTOR}
    for use_callbacks, targets in (
        (False, entries),
        (False, with_init),
        (True, entries),
        (True, with_init),
    ):
        depth = graph.reach_entry(
            caller_class, caller_method, targets, use_callbacks=use_callbacks
        )
        if depth is not None:
            return {
                "linkage_result": "linked",
                "linkage_reason": "call_chain",
                "path_depth": depth,
                "used_callback_edge": use_callbacks,
                "used_init_as_entry": targets is with_init,
            }
    return {
        "linkage_result": "not_linked",
        "linkage_reason": "no_path",
        "path_depth": None,
        "used_callback_edge": False,
        "used_init_as_entry": False,
    }


def unavailable(reason: str) -> dict[str, Any]:
    return {
        "linkage_result": "error",
        "linkage_reason": reason,
        "path_depth": None,
        "used_callback_edge": False,
        "used_init_as_entry": False,
    }


# --- 資料載入 -----------------------------------------------------------------


def load_units(path: Path, unit_ids: set[str] | None = None) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            unit = json.loads(line)
            if unit_ids is None or unit["review_unit_id"] in unit_ids:
                units.append(unit)
    return units


def load_apk_paths(samples_csv: Path) -> dict[str, str]:
    paths: dict[str, str] = {}
    with samples_csv.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            paths[row["sha256"]] = row["source_path"]
    return paths


def analyse(
    units: Sequence[Mapping[str, Any]], apk_paths: Mapping[str, str]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """逐 APK 建一次圖，再判該 APK 的全部 unit。回傳 (rows, 執行摘要)。"""
    by_apk: dict[str, list[Mapping[str, Any]]] = collections.defaultdict(list)
    for unit in units:
        by_apk[str(unit["sha256"])].append(unit)

    rows: list[dict[str, Any]] = []
    stats = collections.Counter()
    callback_edges = 0
    started = time.perf_counter()
    for index, (sha256, group) in enumerate(sorted(by_apk.items()), 1):
        path = apk_paths.get(sha256)
        verdict: dict[str, Any] | None = None
        graph: CallGraph | None = None
        if path is None or not Path(path).exists():
            verdict = unavailable("apk_unavailable")
        else:
            try:
                graph = build_call_graph(Path(path))
                callback_edges += graph.callback_edges
            except Exception as exc:  # pragma: no cover - 解析失敗照實記錄，不當成 not_linked
                LOGGER.warning("%s 解析失敗：%s", sha256[:12], exc)
                verdict = unavailable("parse_failed")
        for unit in group:
            payload = verdict if verdict is not None else judge_unit(unit, graph)  # type: ignore[arg-type]
            stats[payload["linkage_result"]] += 1
            if payload["linkage_result"] == "linked":
                stats[f"reason:{payload['linkage_reason']}"] += 1
                if payload["used_callback_edge"]:
                    stats["needed_callback_edge"] += 1
                if payload["used_init_as_entry"]:
                    stats["needed_init_as_entry"] += 1
            rows.append(
                {
                    "review_unit_id": str(unit["review_unit_id"]),
                    "sha256": sha256,
                    "analysis_version": ANALYSIS_VERSION,
                    **payload,
                }
            )
        if index % 20 == 0:
            LOGGER.info("已處理 %d / %d 個 APK。", index, len(by_apk))
    summary = {
        "analysis_version": ANALYSIS_VERSION,
        "units": len(rows),
        "apks": len(by_apk),
        "wall_clock_seconds": time.perf_counter() - started,
        "synthetic_callback_edges": callback_edges,
        "max_depth": MAX_DEPTH,
        "callback_methods": sorted(CALLBACK_METHODS),
        "counts": dict(sorted(stats.items())),
        "gold_consulted": False,
    }
    return rows, summary


# --- 規格 §4 的量測 -----------------------------------------------------------


def evaluate(
    *,
    linkage: Mapping[str, Mapping[str, Any]],
    gold_log: Path,
    units_path: Path,
    samples_csv: Path,
    observed_labels_path: Path,
) -> dict[str, Any]:
    """與 Gold join，產生規格 §4 的四組數字。只讀 Gold，不寫入。"""
    from .gold_consistency import load_identities, load_latest_events
    from .r_gate import ManifestCache, judge_reachability
    from .rule_baselines import _classification, _ranking

    events = load_latest_events(gold_log)
    identities = load_identities(units_path, set(events))
    manifests = ManifestCache(samples_csv)
    observed: dict[str, str | None] = {}
    if observed_labels_path.exists():
        with observed_labels_path.open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    row = json.loads(line)
                    observed[str(row["review_unit_id"])] = row["observed_authz_label"]

    rows: list[dict[str, Any]] = []
    for unit_id, event in events.items():
        identity = identities.get(unit_id)
        if identity is None or unit_id not in linkage:
            continue
        label = event["gold_authz_label"]
        if label not in ("positive", "negative"):
            continue
        manifest = manifests.get(str(identity["sha256"]))
        reachability = judge_reachability(
            manifest, str(identity["component_name"]), str(identity["component_type"])
        )["result"]
        result = linkage[unit_id]["linkage_result"]
        rows.append(
            {
                "review_unit_id": unit_id,
                "sha256": str(identity["sha256"]),
                "label": label,
                "sink_group_id": identity.get("sink_group_id"),
                "reachability": reachability,
                "observed_authz_label": observed.get(unit_id),
                "linkage_result": result,
                # error 一律當成 not linked，並在 §6 的限制中揭露其筆數。
                "scores": {"linkage": 1.0 if result == "linked" else 0.0},
                "predictions": {"linkage": result == "linked"},
            }
        )

    reachable = [row for row in rows if row["reachability"] != "refuted"]
    held_out = [
        row for row in reachable if not row["sha256"].startswith(DESIGN_APK_PREFIXES)
    ]

    def layer(subset: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        return {
            "evaluated_units": len(subset),
            "positives": sum(1 for row in subset if row["label"] == "positive"),
            "negatives": sum(1 for row in subset if row["label"] == "negative"),
            "apks": len({row["sha256"] for row in subset}),
            "classification": _classification(subset, "linkage"),
            "ranking": _ranking(subset, "linkage", (10, 50)),
        }

    missed = [
        row
        for row in reachable
        if row["label"] == "positive" and row["observed_authz_label"] == "negative"
    ]
    gold_negatives = [row for row in reachable if row["label"] == "negative"]
    return {
        "analysis_version": ANALYSIS_VERSION,
        "spec": "docs/authz_linkage_spec_v1.md",
        "design_informed_by_gold_positives": True,
        "design_apk_prefixes": list(DESIGN_APK_PREFIXES),
        "errors_counted_as_not_linked": sum(
            1 for row in reachable if row["linkage_result"] == "error"
        ),
        "layers": {
            "reachable_subset": layer(reachable),
            "reachable_subset_excluding_design_apks": layer(held_out),
            "pipeline_all_binary": layer(rows),
        },
        "error_analysis": {
            "lf_missed_positives": {
                "units": len(missed),
                "linked": sum(1 for row in missed if row["linkage_result"] == "linked"),
            },
            "gold_negatives": {
                "units": len(gold_negatives),
                "not_linked": sum(
                    1 for row in gold_negatives if row["linkage_result"] != "linked"
                ),
            },
        },
        "reference_lines": {
            "lf_observed_label": 0.331,
            "reachability_rule_all_positive": 0.439,
            "cross_apk_majority": 0.519,
            "fitted_on_gold_ceiling": 0.695,
            "m2_mean": 0.400,
            "m3_mean": 0.207,
        },
    }


# --- 報表 ---------------------------------------------------------------------


LAYER_TITLES = {
    "reachable_subset": "外部可達子集（全部）",
    "reachable_subset_excluding_design_apks": "外部可達子集，排除設計時看過的 APK【主要數字】",
    "pipeline_all_binary": "Gold 全部二分類（被 R 主導，不可用於評價本分析）",
}


def print_summary(summary: Mapping[str, Any]) -> None:
    print(
        f"\n{summary['units']} 筆 unit × {summary['apks']} 個 APK，"
        f"耗時 {summary['wall_clock_seconds']:.0f} 秒"
        f"，補出的回呼邊 {summary['synthetic_callback_edges']}"
    )
    for key, value in summary["counts"].items():
        print(f"    {key:<34} {value:>6}")


def print_evaluation(report: Mapping[str, Any]) -> None:
    print("\n⚠ 規格 §0：本分析的規則是在接觸過 Gold 的 positive 側之後才定下來的，"
          "不是「先凍結再量」。主要數字為排除設計時看過的 APK 那一組。")
    for key, title in LAYER_TITLES.items():
        layer = report["layers"][key]
        c, r = layer["classification"], layer["ranking"]
        print(
            f"\n=== {title} ===\n"
            f"  {layer['evaluated_units']} 筆"
            f"（positive {layer['positives']}、negative {layer['negatives']}）、"
            f"{layer['apks']} 個 APK\n"
            f"  TP {c['tp']}  FP {c['fp']}  FN {c['fn']}  TN {c['tn']}\n"
            f"  precision {c['precision']:.3f}  recall {c['recall']:.3f}  "
            f"macro F1 {c['macro_f1']:.3f}  balanced acc {c['balanced_accuracy']:.3f}\n"
            f"  排序：P@10 {r['P@10']:.2f}  看到 80% positive 需 "
            f"{r['units_to_80pct_recall']} 筆（相異分數 {r['distinct_scores']}）"
        )
    analysis = report["error_analysis"]
    print(
        f"\n=== 想修的那一側 × 代價那一側 ===\n"
        f"  LF 漏判的 positive {analysis['lf_missed_positives']['units']} 筆："
        f"linkage 接起來 {analysis['lf_missed_positives']['linked']} 筆\n"
        f"  Gold negative {analysis['gold_negatives']['units']} 筆："
        f"linkage 未接起來 {analysis['gold_negatives']['not_linked']} 筆"
    )
    print("\n=== 參考線（macro F1）===")
    for name, value in report["reference_lines"].items():
        print(f"  {name:<34} {value:.3f}")
    if report["errors_counted_as_not_linked"]:
        print(f"\n  註：{report['errors_counted_as_not_linked']} 筆因 APK 無法分析被當成 "
              f"not linked，見規格 §6。")


# --- CLI ----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--units", type=Path, default=DEFAULT_UNITS)
    parser.add_argument("--samples", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--gold-log", type=Path, default=DEFAULT_GOLD_LOG)
    parser.add_argument("--observed-labels", type=Path, default=DEFAULT_OBSERVED_LABELS)
    parser.add_argument("--eval-output", type=Path, default=DEFAULT_EVAL_OUTPUT)
    parser.add_argument(
        "--gold-only",
        action="store_true",
        help="只分析 Gold 覆核過的 unit（21 個 APK，約 40 秒），不跑全部 300 顆。",
    )
    parser.add_argument(
        "--evaluate",
        action="store_true",
        help="與 Gold join，產生規格 §4 的四組數字。需要先有 linkage 產物或同時產生。",
    )
    parser.add_argument("--dry-run", action="store_true", help="只印報表，不寫檔。")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:  # Androguard 的 loguru 預設會印出數十萬行 DEBUG
        from loguru import logger

        logger.remove()
    except ImportError:  # pragma: no cover
        pass
    args = build_parser().parse_args(argv)

    unit_ids: set[str] | None = None
    if args.gold_only:
        from .gold_consistency import load_latest_events

        unit_ids = set(load_latest_events(args.gold_log))
    units = load_units(args.units, unit_ids)
    if not units:
        raise SystemExit("沒有任何 unit 可分析。")
    rows, summary = analyse(units, load_apk_paths(args.samples))
    print_summary(summary)

    if not args.dry_run:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        LOGGER.info("已寫出 %s。", args.output)

    if args.evaluate:
        report = evaluate(
            linkage={row["review_unit_id"]: row for row in rows},
            gold_log=args.gold_log,
            units_path=args.units,
            samples_csv=args.samples,
            observed_labels_path=args.observed_labels,
        )
        report["run_summary"] = summary
        print_evaluation(report)
        if not args.dry_run:
            args.eval_output.parent.mkdir(parents=True, exist_ok=True)
            args.eval_output.write_text(
                json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            LOGGER.info("已寫出 %s。", args.eval_output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
