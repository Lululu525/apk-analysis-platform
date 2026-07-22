"""Unit tests for the filter-row feature encoder."""
from __future__ import annotations

import numpy as np
import pytest

from app.ml.encoder import (
    BOOLEAN_COLUMNS,
    CATEGORICAL_COLUMNS,
    MULTI_HOT_FIELDS,
    FilterRowEncoder,
)


def _record(
    component_type="service",
    permission=None,
    exported=True,
    protected=False,
    actions=None,
    categories=None,
    data_types=None,
):
    return {
        "features": {
            "component_type": component_type,
            "permission": permission,
            "exported": exported,
            "protected": protected,
            "actions": actions or [],
            "categories": categories or [],
            "data_types": data_types or [],
        }
    }


def test_missing_permission_encoded_as_none_sentinel():
    explicit_none = _record(permission=None)
    missing_key = _record(permission="will-be-removed")
    del missing_key["features"]["permission"]

    encoder = FilterRowEncoder()
    matrix = encoder.fit_transform([explicit_none, missing_key])

    assert "<NONE>" in encoder.onehot.categories_[1]
    permission_none_index = encoder.feature_names_.index("permission_<NONE>")
    assert matrix[:, permission_none_index].tolist() == [1.0, 1.0]


def test_unknown_categorical_value_in_transform_becomes_all_zero():
    encoder = FilterRowEncoder()
    encoder.fit_transform([_record(component_type="service")])

    matrix = encoder.transform([_record(component_type="activity")])

    component_indexes = [
        index
        for index, name in enumerate(encoder.feature_names_)
        if name.startswith("component_type_")
    ]
    assert component_indexes
    assert matrix[0, component_indexes].tolist() == [0.0] * len(component_indexes)


def test_unknown_multi_hot_label_filtered_not_raised():
    encoder = FilterRowEncoder()
    encoder.fit_transform(
        [_record(actions=["android.intent.action.VIEW"])]
    )

    matrix = encoder.transform(
        [_record(actions=["android.intent.action.UNKNOWN_NEW"])]
    )

    action_indexes = [
        index
        for index, name in enumerate(encoder.feature_names_)
        if name.startswith("has_action_")
    ]
    assert action_indexes
    assert matrix[0, action_indexes].tolist() == [0.0] * len(action_indexes)


def test_fit_transform_shape_matches_feature_names():
    records = [
        _record(
            actions=["A"],
            categories=["C"],
            data_types=["text/plain"],
        ),
        _record(component_type="activity", permission="P"),
    ]
    encoder = FilterRowEncoder()

    matrix = encoder.fit_transform(records)

    assert matrix.shape[1] == len(encoder.feature_names_)


def test_boolean_columns_encoded_as_0_1():
    missing_keys = _record()
    del missing_keys["features"]["exported"]
    del missing_keys["features"]["protected"]
    records = [
        _record(exported=True, protected=False),
        _record(exported=False, protected=True),
        missing_keys,
    ]
    encoder = FilterRowEncoder()

    matrix = encoder.fit_transform(records)

    exported_index = encoder.feature_names_.index("exported")
    protected_index = encoder.feature_names_.index("protected")
    assert matrix[:, exported_index].tolist() == [1.0, 0.0, 0.0]
    assert matrix[:, protected_index].tolist() == [0.0, 1.0, 0.0]


def test_multi_hot_field_captures_multiple_values():
    records = [
        _record(actions=["A", "B"]),
        _record(actions=["C"]),
    ]
    encoder = FilterRowEncoder()

    matrix = encoder.fit_transform(records)

    action_indexes = {
        name: index
        for index, name in enumerate(encoder.feature_names_)
        if name.startswith("has_action_")
    }
    assert matrix[0, action_indexes["has_action_A"]] == 1
    assert matrix[0, action_indexes["has_action_B"]] == 1
    assert matrix[0, action_indexes["has_action_C"]] == 0


def test_feature_names_order_consistent_with_columns():
    encoder = FilterRowEncoder()
    encoder.fit_transform(
        [
            _record(
                actions=["A"],
                categories=["C"],
                data_types=["text/plain"],
            )
        ]
    )

    expected = (
        list(encoder.onehot.get_feature_names_out(CATEGORICAL_COLUMNS))
        + BOOLEAN_COLUMNS
        + [
            f"{MULTI_HOT_FIELDS[field]}{label}"
            for field in MULTI_HOT_FIELDS
            for label in encoder.mlbs[field].classes_
        ]
    )
    assert encoder.feature_names_ == expected


def test_transform_before_fit_raises_runtime_error():
    encoder = FilterRowEncoder()

    with pytest.raises(RuntimeError, match="fit"):
        encoder.transform([_record()])


def test_save_load_round_trip(tmp_path):
    records = [
        _record(actions=["A"], categories=["C"]),
        _record(
            component_type="activity",
            permission="P",
            data_types=["text/plain"],
        ),
    ]
    encoder = FilterRowEncoder()
    encoder.fit_transform(records)
    path = tmp_path / "encoder.joblib"

    encoder.save(path)
    loaded = FilterRowEncoder.load(path)

    assert loaded.feature_names_ == encoder.feature_names_
    np.testing.assert_array_equal(
        loaded.transform(records),
        encoder.transform(records),
    )


def test_empty_multi_hot_field_defaults_to_empty_list():
    encoder = FilterRowEncoder()
    encoder.fit_transform(
        [
            _record(
                actions=["A"],
                categories=["C"],
                data_types=["text/plain"],
            )
        ]
    )
    missing_keys = _record()
    for field in MULTI_HOT_FIELDS:
        del missing_keys["features"][field]

    matrix = encoder.transform([missing_keys])

    multi_hot_indexes = [
        index
        for index, name in enumerate(encoder.feature_names_)
        if name.startswith(tuple(MULTI_HOT_FIELDS.values()))
    ]
    assert multi_hot_indexes
    assert matrix[0, multi_hot_indexes].tolist() == [0.0] * len(multi_hot_indexes)
