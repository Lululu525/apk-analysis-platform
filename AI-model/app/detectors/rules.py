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

from dataclasses import dataclass
import re

from ..schemas import Finding, Severity


@dataclass(frozen=True)
class TextRule:
    """
    Structured text scanning rule.

    This replaces the old anonymous tuple format so each field has
    an explicit meaning and rule definitions are easier to maintain.
    """

    rule_id: str
    pattern: str
    severity: Severity
    cwe: list[str]
    cve_examples: list[str]
    remediation: str


# ── Rule table ─────────────────────────────────────────────────────────────────

_RULES: list[TextRule] = [
    # ── Credential & Secret Exposure ──────────────────────────────────────────
    TextRule(
        rule_id="HARDCODED_PASSWORD",
        pattern=r"password\s*=\s*['\"][^'\"]{1,64}['\"]",
        severity="high",
        cwe=["CWE-259", "CWE-798"],
        cve_examples=["CVE-2019-16920", "CVE-2021-27395"],
        remediation="Remove hardcoded passwords; use device-unique secrets provisioned at manufacturing.",
    ),
    TextRule(
        rule_id="HARDCODED_API_KEY",
        pattern=r"api[_-]?key\s*=\s*['\"][^'\"]{8,}['\"]",
        severity="high",
        cwe=["CWE-798"],
        cve_examples=[],
        remediation="Rotate the API key and store it in a secure vault or TEE.",
    ),
    TextRule(
        rule_id="PRIVATE_KEY_PEM",
        pattern=r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        severity="critical",
        cwe=["CWE-321", "CWE-798"],
        cve_examples=["CVE-2022-27255", "CVE-2017-7921"],
        remediation="Remove private keys from firmware; provision per-device keys at the factory.",
    ),
    TextRule(
        rule_id="AWS_ACCESS_KEY",
        pattern=r"AKIA[0-9A-Z]{16}",
        severity="critical",
        cwe=["CWE-798"],
        cve_examples=[],
        remediation="Revoke the AWS key immediately and rotate; use IAM roles instead.",
    ),
    TextRule(
        rule_id="GENERIC_SECRET_TOKEN",
        pattern=r"(?:secret|token|auth)[_-]?(?:key|token)?\s*=\s*['\"][A-Za-z0-9+/=_\-]{16,}['\"]",
        severity="high",
        cwe=["CWE-798"],
        cve_examples=[],
        remediation="Remove hardcoded secrets; load from secure storage at runtime.",
    ),

    # ── Dangerous Services ────────────────────────────────────────────────────
    TextRule(
        rule_id="TELNET_ENABLED",
        pattern=r"\btelnetd\b",
        severity="high",
        cwe=["CWE-319", "CWE-306"],
        cve_examples=["CVE-2019-12780"],
        remediation="Disable telnetd; use SSH for remote administration.",
    ),
    TextRule(
        rule_id="DROPBEAR_SSH",
        pattern=r"\bdropbear\b",
        severity="info",
        cwe=[],
        cve_examples=["CVE-2016-7406", "CVE-2018-15599"],
        remediation="Keep Dropbear up-to-date; disable password auth and use key-based auth.",
    ),
    TextRule(
        rule_id="FTP_SERVICE",
        pattern=r"\b(?:vsftpd|ftpd|pure-ftpd)\b",
        severity="high",
        cwe=["CWE-319"],
        cve_examples=[],
        remediation="Disable FTP; migrate to SFTP.",
    ),

    # ── Command Injection / Shell ─────────────────────────────────────────────
    TextRule(
        rule_id="SYSTEM_CALL",
        pattern=r"\bsystem\s*\(['\"][^'\"]*(\$|`|;|&&|\|\|)",
        severity="high",
        cwe=["CWE-78"],
        cve_examples=["CVE-2021-20090", "CVE-2022-30525"],
        remediation="Validate and sanitize all input before passing to system(); prefer execv family.",
    ),
    TextRule(
        rule_id="POPEN_CALL",
        pattern=r"\bpopen\s*\(",
        severity="medium",
        cwe=["CWE-78"],
        cve_examples=[],
        remediation="Audit popen() calls for unsanitised input.",
    ),

    # ── Memory Safety ─────────────────────────────────────────────────────────
    TextRule(
        rule_id="GETS_FUNCTION",
        pattern=r"\bgets\s*\(",
        severity="high",
        cwe=["CWE-120", "CWE-121"],
        cve_examples=[],
        remediation="Replace gets() with fgets(); gets() is removed from C11.",
    ),
    TextRule(
        rule_id="STRCPY_FUNCTION",
        pattern=r"\bstrcpy\s*\(",
        severity="medium",
        cwe=["CWE-120"],
        cve_examples=[],
        remediation="Replace strcpy() with strncpy() or strlcpy().",
    ),
    TextRule(
        rule_id="SPRINTF_FUNCTION",
        pattern=r"\bsprintf\s*\(",
        severity="low",
        cwe=["CWE-134"],
        cve_examples=[],
        remediation="Replace sprintf() with snprintf() to avoid format-string overflows.",
    ),

    # ── Network Exposure ──────────────────────────────────────────────────────
    TextRule(
        rule_id="BIND_ANY_INTERFACE",
        pattern=r'(?:bind|listen)\s*\([^)]*(?:0\.0\.0\.0|INADDR_ANY)',
        severity="medium",
        cwe=["CWE-284"],
        cve_examples=[],
        remediation="Bind only to required interfaces; avoid 0.0.0.0 on production devices.",
    ),

    # ── Crypto Weaknesses ─────────────────────────────────────────────────────
    TextRule(
        rule_id="WEAK_HASH_MD5",
        pattern=r"\bMD5\b|\bmd5sum\b|\bmd5crypt\b",
        severity="medium",
        cwe=["CWE-328"],
        cve_examples=[],
        remediation="Replace MD5 with SHA-256 or SHA-3 for integrity / hashing.",
    ),
    TextRule(
        rule_id="WEAK_HASH_SHA1",
        pattern=r"\bSHA1\b|\bsha1sum\b",
        severity="low",
        cwe=["CWE-328"],
        cve_examples=[],
        remediation="Replace SHA-1 with SHA-256 for security-sensitive operations.",
    ),
    TextRule(
        rule_id="HARDCODED_IV",
        pattern=r'(?:iv|IV|nonce)\s*=\s*[bB]?[\'"][0-9a-fA-F]{16,}[\'"]',
        severity="high",
        cwe=["CWE-329"],
        cve_examples=[],
        remediation="Generate IVs/nonces randomly; never hardcode them.",
    ),

    # ── Debug / Backdoor Indicators ───────────────────────────────────────────
    TextRule(
        rule_id="DEBUG_UART_SHELL",
        pattern=r"\b(?:uart|serial)\b.*\b(?:shell|console|bash|sh)\b",
        severity="medium",
        cwe=["CWE-912"],
        cve_examples=[],
        remediation="Disable debug UART shell in production builds.",
    ),
    TextRule(
        rule_id="HARDCODED_IP",
        pattern=r"\b(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
        severity="low",
        cwe=["CWE-547"],
        cve_examples=[],
        remediation="Avoid hardcoded IP addresses; use DNS or runtime configuration.",
    ),
]


# ── Scanner ────────────────────────────────────────────────────────────────────

def scan_text_for_rules(text: str) -> list[Finding]:
    """
    Apply all rules against a text blob, such as extracted strings or decompiled output.
    Each rule fires at most once per scan to avoid duplicate findings.
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    for rule in _RULES:
        if rule.rule_id in seen:
            continue

        if re.search(rule.pattern, text, flags=re.IGNORECASE):
            findings.append(Finding(
                id=rule.rule_id,
                title=_title(rule.rule_id),
                severity=rule.severity,
                confidence=0.75,
                category="rule_based",
                cwe=rule.cwe,
                cve_examples=rule.cve_examples,
                evidence={"pattern": rule.pattern, "source": "strings_scan"},
                remediation=rule.remediation,
            ))
            seen.add(rule.rule_id)

    return findings


def _title(rule_id: str) -> str:
    return rule_id.replace("_", " ").title()