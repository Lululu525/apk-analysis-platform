"""Gold 授權標籤的內部一致性檢查（唯讀）。

每個 review unit 取 append-only log 的最新 event，依三個層級比對 R/I/S/A：

- component（同 APK、同 component type 與名稱）：R 是 component 層級性質，必須一致。
- method（再加上同 caller class／method／descriptor）：A 的 runtime guard 位於同一段
  程式，應一致；I、S 可能因 sink 不同而合理不同，只列出供人工檢視，不計為矛盾。
- 明確的 `safe_group_id`：審查時已宣稱共用關鍵證據，R/I/S/A 與 label 任何差異都是矛盾。

另檢查每筆 label 是否可由 R/I/S/A 決策表唯一推導（受保護 writer 上線前的 legacy
event 未經此驗證）。本模組不寫入任何檔案；發現矛盾時須走
`docs/agents/golden-review-session.md` §5.1 的修訂流程並經人工核准。
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .golden_review_session import derive_label

DEFAULT_GOLD_LOG = Path("dataset/authz_v2/gold_review_log.jsonl")
DEFAULT_UNITS = Path("dataset/authz_v2/candidate_units_pilot300.jsonl")
PREDICATES = ("R", "I", "S", "A")


def load_latest_events(gold_log: Path) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    with gold_log.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                event = json.loads(line)
                latest[str(event["review_unit_id"])] = event
    return latest


def load_identities(units_path: Path, unit_ids: set[str]) -> dict[str, dict[str, Any]]:
    identities: dict[str, dict[str, Any]] = {}
    with units_path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                unit = json.loads(line)
                if unit["review_unit_id"] in unit_ids:
                    identities[str(unit["review_unit_id"])] = unit
    return identities


def _predicates(event: Mapping[str, Any]) -> dict[str, str]:
    return {name: str(event.get(f"{name}_predicate_result")) for name in PREDICATES}


def _group(
    events: Mapping[str, Mapping[str, Any]],
    identities: Mapping[str, Mapping[str, Any]],
    key_fields: Sequence[str],
) -> dict[tuple, list[str]]:
    groups: dict[tuple, list[str]] = defaultdict(list)
    for unit_id in events:
        identity = identities.get(unit_id)
        if identity is None:
            continue
        groups[tuple(identity.get(field) for field in key_fields)].append(unit_id)
    return {key: ids for key, ids in groups.items() if len(ids) > 1}


def _diverging(
    unit_ids: Iterable[str],
    events: Mapping[str, Mapping[str, Any]],
    predicates: Sequence[str],
    include_label: bool = False,
) -> list[str]:
    """回傳在此組內取值不一致的欄位名稱。"""
    unit_ids = list(unit_ids)
    fields = [f"{name}_predicate_result" for name in predicates]
    if include_label:
        fields.append("gold_authz_label")
    return [
        field
        for field in fields
        if len({str(events[unit_id].get(field)) for unit_id in unit_ids}) > 1
    ]


def check(
    events: Mapping[str, Mapping[str, Any]],
    identities: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    component_key = ("sha256", "component_type", "component_name")
    method_key = component_key + ("caller_class", "caller_method", "caller_descriptor")

    component_groups = _group(events, identities, component_key)
    method_groups = _group(events, identities, method_key)
    safe_groups: dict[str, list[str]] = defaultdict(list)
    for unit_id, event in events.items():
        group_id = event.get("safe_group_id")
        if group_id:
            safe_groups[str(group_id)].append(unit_id)
    safe_groups = {key: ids for key, ids in safe_groups.items() if len(ids) > 1}

    findings: list[dict[str, Any]] = []
    for key, ids in component_groups.items():
        diverging = _diverging(ids, events, ("R",))
        if diverging:
            findings.append({"level": "component", "severity": "contradiction", "key": key, "units": ids, "fields": diverging})
    for key, ids in method_groups.items():
        contradiction = _diverging(ids, events, ("A",))
        if contradiction:
            findings.append({"level": "method", "severity": "contradiction", "key": key, "units": ids, "fields": contradiction})
        review = _diverging(ids, events, ("I", "S"))
        if review:
            findings.append({"level": "method", "severity": "review", "key": key, "units": ids, "fields": review})
    for key, ids in safe_groups.items():
        diverging = _diverging(ids, events, PREDICATES, include_label=True)
        if diverging:
            findings.append({"level": "safe_group", "severity": "contradiction", "key": (key,), "units": ids, "fields": diverging})

    label_mismatches = []
    for unit_id, event in events.items():
        derived = derive_label({f"{name}_predicate_result": value for name, value in _predicates(event).items()})
        if derived != event.get("gold_authz_label"):
            label_mismatches.append({"unit": unit_id, "derived": derived, "recorded": event.get("gold_authz_label")})

    return {
        "units": len(events),
        "units_with_identity": sum(1 for unit_id in events if unit_id in identities),
        "component_groups": len(component_groups),
        "method_groups": len(method_groups),
        "safe_groups": len(safe_groups),
        "findings": findings,
        "label_mismatches": label_mismatches,
    }


def _print_report(report: Mapping[str, Any], events: Mapping[str, Mapping[str, Any]]) -> None:
    print(f"Gold units（最新 event）：{report['units']}，可對應 identity：{report['units_with_identity']}")
    print(
        f"多筆組數：component {report['component_groups']}、method {report['method_groups']}、"
        f"safe_group {report['safe_groups']}"
    )
    contradictions = [row for row in report["findings"] if row["severity"] == "contradiction"]
    reviews = [row for row in report["findings"] if row["severity"] == "review"]
    print(f"\n矛盾：{len(contradictions)} 組；需人工檢視（I/S 因 sink 不同可能合理）：{len(reviews)} 組")
    print(f"label 無法由 R/I/S/A 推導：{len(report['label_mismatches'])} 筆")
    for title, rows in (("矛盾", contradictions), ("需人工檢視", reviews)):
        if not rows:
            continue
        print(f"\n== {title} ==")
        for row in rows:
            key = row["key"]
            label = f"{str(key[0])[:8]} {key[2]}" if row["level"] != "safe_group" else key[0]
            if row["level"] == "method":
                label += f" :: {key[4]}{key[5]}"
            print(f"[{row['level']}] {label}  不一致欄位={row['fields']}")
            for unit_id in row["units"]:
                event = events[unit_id]
                risa = "/".join(str(event.get(f"{name}_predicate_result"))[:4] for name in PREDICATES)
                print(
                    f"    {unit_id[-12:]}  R/I/S/A={risa}  label={event.get('gold_authz_label')}"
                    f"  at={str(event.get('reviewed_at'))[:16]}"
                )
    for row in report["label_mismatches"]:
        print(f"  label 不符 {row['unit'][-12:]}：推導={row['derived']} 記錄={row['recorded']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold-log", type=Path, default=DEFAULT_GOLD_LOG)
    parser.add_argument("--units", type=Path, default=DEFAULT_UNITS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    events = load_latest_events(args.gold_log)
    identities = load_identities(args.units, set(events))
    report = check(events, identities)
    _print_report(report, events)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
