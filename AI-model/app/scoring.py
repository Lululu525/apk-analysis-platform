from __future__ import annotations

from typing import Any


HIGH_RISK_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
}

MEDIUM_RISK_PERMISSIONS = {
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
}

LOW_RISK_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.WAKE_LOCK",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.POST_NOTIFICATIONS",
}

WEIGHTS = {
    "high": 30,
    "medium": 15,
    "low": 5,
}


def is_false_positive_permission(permission: str) -> bool:
    """
    Filter obvious non-platform or internal/test-like permission names.
    """
    return (
        permission.startswith("com.example")
        or "DYNAMIC_RECEIVER" in permission
        or permission.endswith("_PERMISSION")
    )


def classify_permission(permission: str) -> str | None:
    """
    Return permission risk class: high / medium / low / None.
    """
    if permission in HIGH_RISK_PERMISSIONS:
        return "high"

    if permission in MEDIUM_RISK_PERMISSIONS:
        return "medium"

    if permission in LOW_RISK_PERMISSIONS:
        return "low"

    return None


def score_to_level(score: int) -> str:
    """
    Map 0-100 score to risk level.
    """
    if score >= 71:
        return "High"
    if score >= 41:
        return "Medium"
    if score >= 21:
        return "Low"
    return "Info"


def build_rule_based_result(
    permissions: list[str],
) -> tuple[int, dict[str, int], list[dict[str, Any]], list[str]]:
    """
    Build rule-based score, counts, findings, and filtered permissions.
    """
    findings: list[dict[str, Any]] = []
    filtered_permissions: list[str] = []

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    score = 0

    for permission in permissions:
        if is_false_positive_permission(permission):
            filtered_permissions.append(permission)
            continue

        category = classify_permission(permission)
        if category is None:
            continue

        weight = WEIGHTS[category]
        score += weight
        counts[category] += 1

        findings.append(
            {
                "id": f"PERM-{permission.split('.')[-1]}",
                "severity": category,
                "title": f"{category.capitalize()}-risk permission detected",
                "description": permission,
                "remediation": (
                    "Review whether this permission is strictly necessary for "
                    "the app's core functionality."
                ),
                "evidence": permission,
                "score_weight": weight,
            }
        )

    return min(score, 100), counts, findings, filtered_permissions


def extract_features(
    permissions: list[str],
    counts: dict[str, int],
    rule_score: int,
    filtered_permissions: list[str],
) -> dict[str, Any]:
    """
    Convert current APK result into a feature dictionary.
    This is the placeholder feature interface for future ML integration.
    """
    clean_permissions = [
        permission
        for permission in permissions
        if not is_false_positive_permission(permission)
    ]

    return {
        "permission_count": len(clean_permissions),
        "high_risk_count": counts["high"],
        "medium_risk_count": counts["medium"],
        "low_risk_count": counts["low"],
        "filtered_count": len(filtered_permissions),
        "rule_score": rule_score,
    }


def mock_ml_adjust(features: dict[str, Any]) -> int:
    """
    Mock ML adjustment layer.

    Purpose:
    - keep an ML-like interface
    - slightly adjust the rule-based score
    - make future replacement with a real model easy
    """
    rule_score = int(features.get("rule_score", 0))
    high_count = int(features.get("high_risk_count", 0))
    medium_count = int(features.get("medium_risk_count", 0))
    low_count = int(features.get("low_risk_count", 0))

    adjusted = rule_score + high_count * 5 + medium_count * 2 + low_count * 1
    return min(adjusted, 100)


def score_permissions(
    permissions: list[str],
) -> tuple[int, str, dict[str, int], list[dict[str, Any]], list[str], dict[str, Any]]:
    """
    Main scoring entrypoint.

    Returns:
        risk_score,
        risk_level,
        counts,
        findings,
        filtered_permissions,
        features
    """
    rule_score, counts, findings, filtered_permissions = build_rule_based_result(
        permissions
    )

    features = extract_features(
        permissions=permissions,
        counts=counts,
        rule_score=rule_score,
        filtered_permissions=filtered_permissions,
    )

    final_score = mock_ml_adjust(features)
    risk_level = score_to_level(final_score)

    features["final_score"] = final_score
    features["formula"] = "final_score = mock_ml_adjust(rule_score, counts)"

    return final_score, risk_level, counts, findings, filtered_permissions, features