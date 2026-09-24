from app.tools import gold_consistency as consistency


def _event(unit_id, results, statuses, label, safe_group=None):
    event = {"review_unit_id": unit_id, "gold_authz_label": label, "safe_group_id": safe_group}
    for name, result, status in zip("RISA", results, statuses):
        event[f"{name}_predicate_result"] = result
        event[f"{name}_evidence_status"] = status
    return event


def _identity(unit_id, caller_method="run"):
    return {
        "review_unit_id": unit_id,
        "sha256": "a" * 64,
        "component_type": "receiver",
        "component_name": "com.example.R",
        "caller_class": "Lcom/example/R;",
        "caller_method": caller_method,
        "caller_descriptor": "()V",
    }


def test_not_analysed_predicates_are_not_contradictions():
    """審查深度不同（early-stop）不是矛盾，只有實際判定相左才是。"""
    events = {
        "u1": _event("u1", ["unknown"] * 4, ["observed_unresolved"] + ["not_analyzed_due_to_upstream_unknown"] * 3, "unknown"),
        "u2": _event("u2", ["unknown", "confirmed", "confirmed", "confirmed"], ["observed_unresolved"] + ["confirmed_present"] * 3, "unknown"),
    }
    identities = {unit_id: _identity(unit_id) for unit_id in events}

    report = consistency.check(events, identities)

    assert report["findings"] == []
    assert report["label_mismatches"] == []


def test_real_predicate_divergence_is_reported():
    events = {
        "u1": _event("u1", ["confirmed", "refuted", "unknown", "unknown"], ["confirmed_present", "confirmed_absent", "not_analyzed", "not_analyzed"], "negative"),
        "u2": _event("u2", ["refuted", "refuted", "unknown", "unknown"], ["confirmed_absent", "confirmed_absent", "not_analyzed", "not_analyzed"], "negative"),
    }
    identities = {unit_id: _identity(unit_id) for unit_id in events}

    report = consistency.check(events, identities)

    levels = {(row["level"], row["severity"]) for row in report["findings"]}
    assert ("component", "contradiction") in levels
    assert all("R_predicate_result" in row["fields"] for row in report["findings"])


def test_label_must_derive_from_predicates():
    events = {"u1": _event("u1", ["confirmed"] * 4, ["confirmed_present"] * 4, "negative")}
    report = consistency.check(events, {"u1": _identity("u1")})
    assert report["label_mismatches"] == [{"unit": "u1", "derived": "positive", "recorded": "negative"}]
