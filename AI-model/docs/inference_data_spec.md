# Inference Data Specification v1

This document defines the v1 inference input and output formats. Inference rows
are generated directly from `pipeline_apk.py` after it calls
`build_model_features()`.

## 1. Inference Input Format

Inference input records have no `label` and no `split`:

```json
{
  "schema_version": "1.0",
  "encoder_version": "1.0",
  "sample_id": "com.example.app__v1.0__abc123",
  "row_type": "filter",
  "features": {
    "component_type": "service",
    "permission": "<NONE>",
    "exported": true,
    "protected": false,
    "has_action_android_intent_action_view": true
  }
}
```

Top-level fields:

| Field | Type | Values | Description |
| --- | --- | --- | --- |
| `schema_version` | `str` | `1.0` | Matches `app/ml/feature_schema.json`. |
| `encoder_version` | `str` | `1.0` | Matches `encoder.joblib`; bump when the encoder is retrained incompatibly. |
| `sample_id` | `str` | `{package_name}__{version_name}__{apk_sha256[:8]}` | APK-level sample identifier. |
| `row_type` | `str` | `filter`, `resolution` | `resolution` is reserved for v2 activation. |
| `features` | `object` | Same as training features | Feature structure is identical to the training sample `features` object. |

`filter` and `resolution` feature definitions are identical to
`docs/training_data_spec.md`. Missing categorical values are filled with
`<NONE>`, and missing dynamic multi-hot fields are treated as `False`.

## 2. Model Output Format

Each row-level prediction is emitted as:

```json
{
  "row_id": "com.example.app__v1.0__abc123__filter__com.example.SyncService",
  "row_type": "filter",
  "risk_probability": 0.87,
  "predicted_label": 1,
  "top_features": [
    {"feature": "exported", "importance": 0.41},
    {"feature": "has_action_android_intent_action_view", "importance": 0.23},
    {"feature": "component_type_service", "importance": 0.18}
  ],
  "model_version": "rf_filter_v1"
}
```

Output fields:

| Field | Type | Description |
| --- | --- | --- |
| `row_id` | `str` | `{sample_id}__{row_type}__{component_name}`. |
| `row_type` | `str` | `filter` or future `resolution`. |
| `risk_probability` | `float` | Positive-class risk probability. |
| `predicted_label` | `int` | `0` or `1`, derived from the model threshold. |
| `top_features` | `array` | Top 5 entries from `feature_importances_`, each with `feature` and `importance`. |
| `model_version` | `str` | `rf_filter_v1` for filter rows; `lr_resolution_v1` for future v2 resolution rows. |

For `top_features`, feature names must refer to encoded model input names, such
as `exported`, `has_action_android_intent_action_view`, or
`component_type_service`.

## 3. App-level Risk Aggregation

Row-level predictions are aggregated to app-level risk with:

```python
app_risk_probability = max(filter_row.risk_probability for filter_row in apk_filter_rows)
```

Use `max` instead of `mean` because, in security analysis, one high-risk
component is enough for the whole app to be considered risky.
