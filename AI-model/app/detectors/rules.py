"""
Rule-based static detector.

Each rule maps to:
  - CWE  (Common Weakness Enumeration)  — structural/design weakness
  - CVE examples                         — real-world known exploits of this pattern

Reference:
  https://cwe.mitre.org/
  https://nvd.nist.gov/
"""
from __future__ import annotations

import re
from typing import List

from ..schemas import Finding


# ── Rule table ─────────────────────────────────────────────────────────────────
# (rule_id, regex_pattern, severity, cwe_list, cve_examples, remediation)

_RULES: list[tuple[str, str, str, list[str], list[str], str]] = [
    # ── Credential & Secret Exposure ──────────────────────────────────────────
    (
        "HARDCODED_PASSWORD",
        r"password\s*=\s*['\"][^'\"]{1,64}['\"]",
        "high",
        ["CWE-259", "CWE-798"],
        ["CVE-2019-16920", "CVE-2021-27395"],
        "Remove hardcoded passwords; use device-unique secrets provisioned at manufacturing.",
    ),
    (
        "HARDCODED_API_KEY",
        r"api[_-]?key\s*=\s*['\"][^'\"]{8,}['\"]",
        "high",
        ["CWE-798"],
        [],
        "Rotate the API key and store it in a secure vault or TEE.",
    ),
    (
        "PRIVATE_KEY_PEM",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "critical",
        ["CWE-321", "CWE-798"],
        ["CVE-2022-27255", "CVE-2017-7921"],
        "Remove private keys from firmware; provision per-device keys at the factory.",
    ),
    (
        "AWS_ACCESS_KEY",
        r"AKIA[0-9A-Z]{16}",
        "critical",
        ["CWE-798"],
        [],
        "Revoke the AWS key immediately and rotate; use IAM roles instead.",
    ),
    (
        "GENERIC_SECRET_TOKEN",
        r"(?:secret|token|auth)[_-]?(?:key|token)?\s*=\s*['\"][A-Za-z0-9+/=_\-]{16,}['\"]",
        "high",
        ["CWE-798"],
        [],
        "Remove hardcoded secrets; load from secure storage at runtime.",
    ),

    # ── Dangerous Services ────────────────────────────────────────────────────
    (
        "TELNET_ENABLED",
        r"\btelnetd\b",
        "high",
        ["CWE-319", "CWE-306"],
        ["CVE-2019-12780"],
        "Disable telnetd; use SSH for remote administration.",
    ),
    (
        "DROPBEAR_SSH",
        r"\bdropbear\b",
        "info",
        [],
        ["CVE-2016-7406", "CVE-2018-15599"],
        "Keep Dropbear up-to-date; disable password auth and use key-based auth.",
    ),
    (
        "FTP_SERVICE",
        r"\b(?:vsftpd|ftpd|pure-ftpd)\b",
        "high",
        ["CWE-319"],
        [],
        "Disable FTP; migrate to SFTP.",
    ),

    # ── Command Injection / Shell ─────────────────────────────────────────────
    (
        "SYSTEM_CALL",
        r"\bsystem\s*\(['\"][^'\"]*(\$|`|;|&&|\|\|)",
        "high",
        ["CWE-78"],
        ["CVE-2021-20090", "CVE-2022-30525"],
        "Validate and sanitize all input before passing to system(); prefer execv family.",
    ),
    (
        "POPEN_CALL",
        r"\bpopen\s*\(",
        "medium",
        ["CWE-78"],
        [],
        "Audit popen() calls for unsanitised input.",
    ),

    # ── Memory Safety ─────────────────────────────────────────────────────────
    (
        "GETS_FUNCTION",
        r"\bgets\s*\(",
        "high",
        ["CWE-120", "CWE-121"],
        [],
        "Replace gets() with fgets(); gets() is removed from C11.",
    ),
    (
        "STRCPY_FUNCTION",
        r"\bstrcpy\s*\(",
        "medium",
        ["CWE-120"],
        [],
        "Replace strcpy() with strncpy() or strlcpy().",
    ),
    (
        "SPRINTF_FUNCTION",
        r"\bsprintf\s*\(",
        "low",
        ["CWE-134"],
        [],
        "Replace sprintf() with snprintf() to avoid format-string overflows.",
    ),

    # ── Network Exposure ──────────────────────────────────────────────────────
    (
        "BIND_ANY_INTERFACE",
        r'(?:bind|listen)\s*\([^)]*(?:0\.0\.0\.0|INADDR_ANY)',
        "medium",
        ["CWE-284"],
        [],
        "Bind only to required interfaces; avoid 0.0.0.0 on production devices.",
    ),

    # ── Crypto Weaknesses ─────────────────────────────────────────────────────
    (
        "WEAK_HASH_MD5",
        r"\bMD5\b|\bmd5sum\b|\bmd5crypt\b",
        "medium",
        ["CWE-328"],
        [],
        "Replace MD5 with SHA-256 or SHA-3 for integrity / hashing.",
    ),
    (
        "WEAK_HASH_SHA1",
        r"\bSHA1\b|\bsha1sum\b",
        "low",
        ["CWE-328"],
        [],
        "Replace SHA-1 with SHA-256 for security-sensitive operations.",
    ),
    (
        "HARDCODED_IV",
        r'(?:iv|IV|nonce)\s*=\s*[bB]?[\'"][0-9a-fA-F]{16,}[\'"]',
        "high",
        ["CWE-329"],
        [],
        "Generate IVs/nonces randomly; never hardcode them.",
    ),

    # ── Debug / Backdoor Indicators ───────────────────────────────────────────
    (
        "DEBUG_UART_SHELL",
        r"\b(?:uart|serial)\b.*\b(?:shell|console|bash|sh)\b",
        "medium",
        ["CWE-912"],
        [],
        "Disable debug UART shell in production builds.",
    ),
    (
        "HARDCODED_IP",
        r"\b(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
        "low",
        ["CWE-547"],
        [],
        "Avoid hardcoded IP addresses; use DNS or runtime configuration.",
    ),
]


# ── Scanner ────────────────────────────────────────────────────────────────────

def scan_text_for_rules(text: str) -> List[Finding]:
    """
    Apply all rules against a text blob (extracted strings or decompiled output).
    Each rule fires at most once per scan to avoid duplicate findings.
    """
    findings: List[Finding] = []
    seen: set[str] = set()

    for rule_id, pattern, severity, cwe, cve_examples, remediation in _RULES:
        if rule_id in seen:
            continue
        if re.search(pattern, text, flags=re.IGNORECASE):
            findings.append(Finding(
                finding_id=rule_id,
                title=_title(rule_id),
                severity=severity,
                confidence=0.75,
                category="rule_based",
                cwe=cwe,
                cve_examples=cve_examples,
                evidence={"pattern": pattern, "source": "strings_scan"},
                remediation=remediation,
            ))
            seen.add(rule_id)

    return findings


def _title(rule_id: str) -> str:
    return rule_id.replace("_", " ").title()
