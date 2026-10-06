"""Entry-to-sink linkage 的規則。規格見 `docs/authz_linkage_spec_v1.md`。

測試守的是兩件事：三條凍結的規則各自做對了什麼，以及**每條路徑最少用到哪幾條近似**
必須被如實記錄——`used_callback_edge` 與 `used_init_as_entry` 是這個分析唯一的稽核手段
（規格 §5）。呼叫圖以手工建構，不需要 APK 或 Androguard。
"""
import pytest

from app.tools import entry_sink_linkage as linkage


def _graph(edges, classes=None):
    """edges: [(caller, callee)]，節點寫成 "Lcls;.method"。"""
    graph = linkage.CallGraph()
    for caller, callee in edges:
        graph.add_call(_node(caller), _node(callee))
    for name, methods in (classes or {}).items():
        graph.methods_by_class[name].update(methods)
    graph.apply_callback_rule()
    return graph


def _node(text):
    cls, method = text.rsplit(".", 1)
    return (cls, method)


def _unit(caller="Lcom/x/A;.helper", component_type="activity"):
    cls, method = caller.rsplit(".", 1)
    return {
        "review_unit_id": "u0",
        "sha256": "abc",
        "component_type": component_type,
        "caller_class": cls,
        "caller_method": method,
    }


# --- 凍結的參數 ---------------------------------------------------------------


def test_frozen_rule_parameters():
    """規格 §2.2 的清單與深度上限不得增減。"""
    assert linkage.MAX_DEPTH == 8
    assert linkage.CALLBACK_METHODS == frozenset(
        {"run", "doInBackground", "onPostExecute", "onPreExecute", "onProgressUpdate",
         "onClick", "onLongClick", "onItemClick", "handleMessage", "call", "onReceive"}
    )
    assert linkage.DESIGN_APK_PREFIXES == ("9b2a8728", "9ed8ab7e")


def test_entry_methods_come_from_the_already_frozen_lf():
    """不得另行定義 entry 集合，否則兩處會分歧（規格 §2.2）。"""
    from app.tools.build_observed_labels import ENTRY_METHODS

    for component_type, methods in ENTRY_METHODS.items():
        assert linkage.entry_methods_for(component_type) == frozenset(methods)


def test_unknown_component_type_raises():
    with pytest.raises(ValueError, match="未知的 component_type"):
        linkage.entry_methods_for("widget")


# --- 基礎呼叫邊 ---------------------------------------------------------------


def test_sink_written_inside_the_entry_method_needs_no_graph():
    """與 LF 規則 1 的 positive 條件相同，深度 0，不動用任何近似。"""
    verdict = linkage.judge_unit(_unit("Lcom/x/A;.onCreate"), _graph([]))

    assert verdict["linkage_result"] == "linked"
    assert verdict["linkage_reason"] == "sink_in_entry_method"
    assert verdict["path_depth"] == 0
    assert verdict["used_callback_edge"] is False
    assert verdict["used_init_as_entry"] is False


def test_a_plain_call_chain_is_found_without_any_approximation():
    """onCreate → helper，只用 Androguard 原本的邊。"""
    graph = _graph([("Lcom/x/A;.onCreate", "Lcom/x/A;.helper")])

    verdict = linkage.judge_unit(_unit("Lcom/x/A;.helper"), graph)

    assert verdict["linkage_reason"] == "call_chain"
    assert verdict["path_depth"] == 1
    assert verdict["used_callback_edge"] is False
    assert verdict["used_init_as_entry"] is False


def test_the_chain_may_pass_through_another_class_but_must_end_in_the_same_one():
    """中間節點可以是匿名內部類別，終點必須是該 unit 自己 class 的 entry method。"""
    graph = _graph([
        ("Lcom/x/A;.onCreate", "Lcom/x/A$1;.helper"),
        ("Lcom/x/A$1;.helper", "Lcom/x/A;.sinkHolder"),
    ])

    assert linkage.judge_unit(_unit("Lcom/x/A;.sinkHolder"), graph)["linkage_result"] == "linked"
    # 另一個 class 的 entry method 不算：那是另一條 unit 的事。
    other = _graph([("Lcom/y/B;.onCreate", "Lcom/x/A;.sinkHolder")])
    assert linkage.judge_unit(_unit("Lcom/x/A;.sinkHolder"), other)["linkage_result"] == "not_linked"


def test_no_path_is_reported_as_not_linked_with_a_null_depth():
    verdict = linkage.judge_unit(_unit("Lcom/x/A;.orphan"), _graph([]))

    assert verdict["linkage_result"] == "not_linked"
    assert verdict["linkage_reason"] == "no_path"
    assert verdict["path_depth"] is None


def test_the_depth_limit_stops_an_overlong_chain():
    """上限必須存在，否則大型 APK 的 BFS 會掃過整個呼叫圖。"""
    chain = [(f"Lcom/x/A;.m{i}", f"Lcom/x/A;.m{i + 1}") for i in range(12)]
    graph = _graph([("Lcom/x/A;.onCreate", "Lcom/x/A;.m0"), *chain])

    assert linkage.judge_unit(_unit("Lcom/x/A;.m12"), graph)["linkage_result"] == "not_linked"
    assert linkage.judge_unit(_unit("Lcom/x/A;.m7"), graph)["linkage_result"] == "linked"


# --- 規則 A：建構者 → 回呼 ---------------------------------------------------


def test_a_thread_callback_is_unreachable_without_rule_a():
    """`new Thread(r).start()` 不存在任何一行呼叫 run()，靜態呼叫圖必然在此斷掉。"""
    edges = [
        ("Lcom/x/A;.onCreate", "Lcom/x/A$1;.<init>"),
        ("Lcom/x/A$1;.run", "Lcom/x/A;.helper"),
    ]
    without_rule = linkage.CallGraph()
    for caller, callee in edges:
        without_rule.add_call(_node(caller), _node(callee))
    # 刻意不呼叫 apply_callback_rule()

    assert linkage.judge_unit(_unit("Lcom/x/A;.helper"), without_rule)["linkage_result"] == "not_linked"


def test_rule_a_bridges_the_callback_and_is_recorded_as_such():
    edges = [
        ("Lcom/x/A;.onCreate", "Lcom/x/A$1;.<init>"),
        ("Lcom/x/A$1;.run", "Lcom/x/A;.helper"),
    ]
    graph = _graph(edges, {"Lcom/x/A$1;": {"run", "<init>"}})

    verdict = linkage.judge_unit(_unit("Lcom/x/A;.helper"), graph)

    assert verdict["linkage_result"] == "linked"
    assert verdict["used_callback_edge"] is True
    assert verdict["used_init_as_entry"] is False


def test_rule_a_only_applies_to_the_frozen_callback_names():
    """回呼清單是凍結的；`doSomething` 不在清單內就不得補邊。"""
    edges = [
        ("Lcom/x/A;.onCreate", "Lcom/x/A$1;.<init>"),
        ("Lcom/x/A$1;.doSomething", "Lcom/x/A;.helper"),
    ]
    graph = _graph(edges, {"Lcom/x/A$1;": {"doSomething", "<init>"}})

    assert linkage.judge_unit(_unit("Lcom/x/A;.helper"), graph)["linkage_result"] == "not_linked"


# --- 規則 B：<init> 視為 entry ----------------------------------------------


def test_rule_b_covers_a_handler_built_in_a_field_initialiser():
    """欄位初始化會被編譯進 <init>，而框架一定先建構 component 才呼叫 onCreate。"""
    edges = [
        ("Lcom/x/A;.<init>", "Lcom/x/A$1;.<init>"),
        ("Lcom/x/A$1;.handleMessage", "Lcom/x/A;.helper"),
    ]
    graph = _graph(edges, {"Lcom/x/A$1;": {"handleMessage", "<init>"}})

    verdict = linkage.judge_unit(_unit("Lcom/x/A;.helper"), graph)

    assert verdict["linkage_result"] == "linked"
    assert verdict["used_callback_edge"] is True
    assert verdict["used_init_as_entry"] is True


def test_weaker_assumptions_are_preferred_so_the_record_is_the_minimum_needed():
    """同時存在兩條路徑時，記錄的必須是「最少需要哪幾條近似」（規格 §5）。"""
    edges = [
        ("Lcom/x/A;.onCreate", "Lcom/x/A;.helper"),       # 不需要任何近似
        ("Lcom/x/A;.<init>", "Lcom/x/A$1;.<init>"),        # 另一條需要兩條近似
        ("Lcom/x/A$1;.run", "Lcom/x/A;.helper"),
    ]
    graph = _graph(edges, {"Lcom/x/A$1;": {"run", "<init>"}})

    verdict = linkage.judge_unit(_unit("Lcom/x/A;.helper"), graph)

    assert verdict["used_callback_edge"] is False
    assert verdict["used_init_as_entry"] is False


# --- 執行層 -------------------------------------------------------------------


def test_a_missing_apk_is_an_error_not_a_negative_result():
    """APK 不在原路徑時不得當成 not_linked——那會把工具的限制說成 App 的性質。"""
    rows, summary = linkage.analyse([_unit()], {})

    assert rows[0]["linkage_result"] == "error"
    assert rows[0]["linkage_reason"] == "apk_unavailable"
    assert summary["counts"]["error"] == 1
    assert summary["gold_consulted"] is False


def test_rows_carry_the_join_key_and_the_analysis_version():
    rows, _ = linkage.analyse([_unit()], {})

    assert rows[0]["review_unit_id"] == "u0"
    assert rows[0]["sha256"] == "abc"
    assert rows[0]["analysis_version"] == "authz-linkage-v1"
