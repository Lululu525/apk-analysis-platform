from __future__ import annotations
from typing import List, Dict, Any
import re
from ..schemas import Finding

# 先用「strings 掃描」做實用的規則
SUSPICIOUS_PATTERNS = [
    ("HARDCODED_PASSWORD", r"(password\s*=\s*['\"][^'\"]+['\"])"),
    ("API_KEY", r"(api[_-]?key\s*=\s*['\"][^'\"]+['\"])"),
    ("PRIVATE_KEY", r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"),
    ("TELNET_ENABLED", r"\btelnetd\b"),
    ("DROPBEAR_SSH", r"\bdropbear\b"),
]

def scan_text_for_rules(text: str) -> List[Finding]:
    findings: List[Finding] = []
    for rule_id, pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            findings.append(
                Finding(
                    finding_id=rule_id,
                    title=f"Rule triggered: {rule_id}",
                    severity="medium" if rule_id not in ("PRIVATE_KEY",) else "high",
                    confidence=0.7,
                    category="rule_based",
                    evidence={"pattern": pattern, "hint": "Matched in extracted strings"},
                    remediation="Review and remove sensitive material; rebuild firmware."
                )
            )
    return findings