"""
Embedded filesystem / configuration analysis.

Scans extracted firmware filesystem for:
  - /etc/passwd  : empty/default passwords, root shell access
  - /etc/shadow  : weak hashes (MD5/DES)
  - WiFi PSK     : wpa_supplicant.conf, nvram dumps
  - SSL/TLS keys : private keys stored in firmware
  - Default creds: admin/admin, root/root patterns in config files
  - World-writable sensitive files

CWE references:
  CWE-259  Use of Hard-coded Password
  CWE-798  Use of Hard-coded Credentials
  CWE-321  Use of Hard-coded Cryptographic Key
  CWE-732  Incorrect Permission Assignment for Critical Resource
  CWE-916  Use of Password Hash With Insufficient Computational Effort
"""
from __future__ import annotations

import re
import stat
from pathlib import Path

from ..schemas import Finding

# ── regex patterns ─────────────────────────────────────────────────────────────

_PASSWD_EMPTY_RE  = re.compile(r"^([^:]+)::[^:]*:[^:]*:", re.M)        # empty password field
_PASSWD_ROOT_SHELL = re.compile(r"^root:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:/bin/(?:sh|bash|ash)", re.M)
_SHADOW_WEAK_HASH = re.compile(r"^([^:]+):(\$1\$[^:]+|\$des\$[^:]+|[A-Za-z0-9./]{13}):", re.M)  # MD5 / DES

_WIFI_PSK_RE = re.compile(r'psk\s*=\s*["\']?(.{8,63})["\']?', re.I)
_WIFI_SSID_RE = re.compile(r'ssid\s*=\s*["\']?([^"\'\n]+)["\']?', re.I)

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)

_DEFAULT_CRED_RE = re.compile(
    r'(?:password|passwd|pwd|secret)\s*[=:]\s*["\']?'
    r'(admin|root|1234|12345|password|pass|default|guest|user)'
    r'["\']?\b',
    re.I,
)

_NVRAM_PSK_RE = re.compile(r'(?:wpa_psk|wl_wpa_psk|wifi_password)\s*=\s*(\S+)', re.I)

# ── file targeting ─────────────────────────────────────────────────────────────

_HIGH_VALUE_PATHS = {
    "etc/passwd",
    "etc/shadow",
    "etc/wpa_supplicant.conf",
    "etc/config/wireless",         # OpenWrt
    "tmp/nvram",
    "nvram",
    "etc/wireless",
    "etc/ppp/chap-secrets",
    "etc/ppp/pap-secrets",
    "etc/ipsec.secrets",
    "etc/strongswan.conf",
    "etc/ssl",
    "etc/certs",
    "usr/etc",
}

_CONFIG_EXTENSIONS = {".conf", ".cfg", ".ini", ".xml", ".json", ".txt", ".sh", ".key", ".pem", ".crt", ".cert", ""}


def _rel(path: Path, root: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")


def _read_safe(path: Path, max_bytes: int = 256_000) -> str:
    try:
        return path.read_bytes()[:max_bytes].decode("utf-8", errors="replace")
    except OSError:
        return ""


def _is_world_writable(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & stat.S_IWOTH)
    except OSError:
        return False


def _is_interesting(path: Path, root: Path) -> bool:
    rel = _rel(path, root).lower()
    for hint in _HIGH_VALUE_PATHS:
        if rel == hint or rel.startswith(hint + "/"):
            return True
    return path.suffix.lower() in _CONFIG_EXTENSIONS


# ── individual scanners ────────────────────────────────────────────────────────

def _scan_passwd(content: str, rel: str) -> list[Finding]:
    findings = []

    if _PASSWD_EMPTY_RE.search(content):
        m = _PASSWD_EMPTY_RE.findall(content)
        findings.append(Finding(
            finding_id="FS_PASSWD_EMPTY",
            title="Account with empty password found in /etc/passwd",
            severity="critical",
            confidence=0.95,
            category="embedded_config",
            cwe=["CWE-259", "CWE-798"],
            cve_examples=["CVE-2021-27395"],
            evidence={"file": rel, "accounts": m[:5]},
            remediation="Set a strong password or lock accounts that do not require login.",
        ))

    if _PASSWD_ROOT_SHELL.search(content):
        findings.append(Finding(
            finding_id="FS_ROOT_SHELL",
            title="root account has a login shell enabled",
            severity="high",
            confidence=0.9,
            category="embedded_config",
            cwe=["CWE-250"],
            evidence={"file": rel},
            remediation="Change root shell to /sbin/nologin or enforce key-based auth.",
        ))

    return findings


def _scan_shadow(content: str, rel: str) -> list[Finding]:
    findings = []
    weak = _SHADOW_WEAK_HASH.findall(content)
    if weak:
        accounts = [a for a, _ in weak[:5]]
        findings.append(Finding(
            finding_id="FS_SHADOW_WEAK_HASH",
            title="Weak password hash (MD5/DES) in /etc/shadow",
            severity="high",
            confidence=0.9,
            category="embedded_config",
            cwe=["CWE-916"],
            cve_examples=[],
            evidence={"file": rel, "accounts": accounts},
            remediation="Re-hash passwords using SHA-512 ($6$); disable MD5/DES in PAM.",
        ))
    return findings


def _scan_wifi(content: str, rel: str) -> list[Finding]:
    findings = []
    psk_matches = _WIFI_PSK_RE.findall(content)
    if psk_matches:
        findings.append(Finding(
            finding_id="FS_WIFI_PSK_HARDCODED",
            title="Hardcoded Wi-Fi PSK found in firmware",
            severity="high",
            confidence=0.85,
            category="embedded_config",
            cwe=["CWE-798"],
            cve_examples=[],
            evidence={"file": rel, "psk_count": len(psk_matches)},
            remediation="Remove hardcoded Wi-Fi credentials; use provisioning on first boot.",
        ))
    return findings


def _scan_private_key(content: str, rel: str) -> list[Finding]:
    if _PRIVATE_KEY_RE.search(content):
        return [Finding(
            finding_id="FS_PRIVATE_KEY_EMBEDDED",
            title="Private key material embedded in firmware",
            severity="critical",
            confidence=0.95,
            category="embedded_config",
            cwe=["CWE-321", "CWE-798"],
            cve_examples=["CVE-2022-27255"],
            evidence={"file": rel},
            remediation="Remove private keys from firmware; provision per-device keys at manufacturing.",
        )]
    return []


def _scan_default_creds(content: str, rel: str) -> list[Finding]:
    if _DEFAULT_CRED_RE.search(content) or _NVRAM_PSK_RE.search(content):
        return [Finding(
            finding_id="FS_DEFAULT_CREDENTIALS",
            title="Default or hardcoded credentials found in config",
            severity="high",
            confidence=0.8,
            category="embedded_config",
            cwe=["CWE-798", "CWE-259"],
            cve_examples=["CVE-2019-16920"],
            evidence={"file": rel},
            remediation="Replace hardcoded credentials with device-unique secrets.",
        )]
    return []


def _scan_world_writable(path: Path, rel: str) -> list[Finding]:
    if _is_world_writable(path):
        return [Finding(
            finding_id="FS_WORLD_WRITABLE_CONFIG",
            title="Sensitive config file is world-writable",
            severity="medium",
            confidence=0.85,
            category="embedded_config",
            cwe=["CWE-732"],
            evidence={"file": rel, "mode": oct(path.stat().st_mode)},
            remediation="Set file permissions to 600 or 640.",
        )]
    return []


# ── public API ─────────────────────────────────────────────────────────────────

def scan_filesystem(root: Path) -> list[Finding]:
    """
    Walk an extracted firmware filesystem and apply all embedded-config checks.
    """
    all_findings: list[Finding] = []
    seen_ids: set[str] = set()

    if not root.is_dir():
        return all_findings

    for fpath in sorted(root.rglob("*")):
        if not fpath.is_file():
            continue
        if not _is_interesting(fpath, root):
            continue

        rel = _rel(fpath, root)
        content = _read_safe(fpath)

        scanners = []
        lower_rel = rel.lower()

        if "passwd" in lower_rel and "shadow" not in lower_rel:
            scanners.append(_scan_passwd)
        if "shadow" in lower_rel:
            scanners.append(_scan_shadow)
        if "wpa_supplicant" in lower_rel or "wireless" in lower_rel or "nvram" in lower_rel:
            scanners.append(_scan_wifi)
        if "ssl" in lower_rel or "cert" in lower_rel or "key" in lower_rel or "pki" in lower_rel:
            scanners.append(_scan_private_key)

        # Run default-creds and private-key scan on all interesting files
        scanners += [_scan_default_creds, _scan_private_key]

        for scanner in set(scanners):  # dedup scanner list per file
            for f in scanner(content, rel):
                if f.finding_id not in seen_ids:
                    all_findings.append(f)
                    seen_ids.add(f.finding_id)

        # Permission check (independent of content)
        for f in _scan_world_writable(fpath, rel):
            if f.finding_id + rel not in seen_ids:
                all_findings.append(f)
                seen_ids.add(f.finding_id + rel)

    return all_findings
