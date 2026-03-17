"""
Network / service exposure detection for extracted firmware filesystems.

Scans for:
  - Enabled network daemons (telnet, ftp, tftp, http, ssh/dropbear)
  - inetd / xinetd service configurations
  - Hardcoded listening ports in config files
  - Unauthenticated / plaintext protocol indicators

CWE references:
  CWE-319  Cleartext Transmission of Sensitive Information
  CWE-306  Missing Authentication for Critical Function
  CWE-912  Hidden Functionality (undocumented services)
"""
from __future__ import annotations

import re
from pathlib import Path

from ..schemas import Finding

# ── service signature rules ───────────────────────────────────────────────────

_SERVICE_RULES: list[dict] = [
    {
        "id": "NET_TELNET_ENABLED",
        "title": "Telnet service may be enabled",
        "severity": "high",
        "cwe": ["CWE-319", "CWE-306"],
        "cve_examples": ["CVE-2019-12780"],
        "remediation": "Disable telnetd; replace with SSH.",
        "patterns": [
            re.compile(r"\btelnetd\b", re.I),
            re.compile(r"telnet\s+stream\s+tcp", re.I),  # inetd.conf style
        ],
        "file_hints": ["inetd.conf", "xinetd.d", "rcS", "init.d", "inittab", "rc.local"],
    },
    {
        "id": "NET_FTP_ENABLED",
        "title": "FTP service may be enabled (plaintext credentials)",
        "severity": "high",
        "cwe": ["CWE-319"],
        "cve_examples": [],
        "remediation": "Disable FTP; use SFTP/SCP instead.",
        "patterns": [
            re.compile(r"\bftpd\b", re.I),
            re.compile(r"\bvsftpd\b", re.I),
            re.compile(r"ftp\s+stream\s+tcp", re.I),
        ],
        "file_hints": ["inetd.conf", "vsftpd.conf", "rcS", "init.d"],
    },
    {
        "id": "NET_TFTP_ENABLED",
        "title": "TFTP service detected (unauthenticated file transfer)",
        "severity": "high",
        "cwe": ["CWE-306"],
        "cve_examples": [],
        "remediation": "Disable TFTP or restrict to trusted networks.",
        "patterns": [
            re.compile(r"\btftpd\b", re.I),
            re.compile(r"tftp\s+dgram\s+udp", re.I),
        ],
        "file_hints": ["inetd.conf", "rcS"],
    },
    {
        "id": "NET_HTTP_UNENCRYPTED",
        "title": "HTTP server (unencrypted) may be exposed",
        "severity": "medium",
        "cwe": ["CWE-319"],
        "cve_examples": [],
        "remediation": "Enforce HTTPS; disable plain HTTP on production devices.",
        "patterns": [
            re.compile(r"\bhttpd\b", re.I),
            re.compile(r"\blighttpd\b", re.I),
            re.compile(r"\bnginx\b", re.I),
            re.compile(r"\buhttpd\b", re.I),  # OpenWrt
        ],
        "file_hints": ["httpd.conf", "lighttpd.conf", "nginx.conf", "rcS", "init.d"],
    },
    {
        "id": "NET_DROPBEAR_SSH",
        "title": "Dropbear SSH server detected",
        "severity": "info",
        "cwe": [],
        "cve_examples": ["CVE-2016-7406"],
        "remediation": "Ensure Dropbear is up-to-date; disable root login if possible.",
        "patterns": [
            re.compile(r"\bdropbear\b", re.I),
        ],
        "file_hints": ["rcS", "init.d", "inittab"],
    },
    {
        "id": "NET_SNMP_ENABLED",
        "title": "SNMP service detected (potential info disclosure)",
        "severity": "medium",
        "cwe": ["CWE-200"],
        "cve_examples": [],
        "remediation": "Use SNMPv3 with auth/priv; change default community strings.",
        "patterns": [
            re.compile(r"\bsnmpd\b", re.I),
            re.compile(r"community\s+(public|private)\b", re.I),  # default community
        ],
        "file_hints": ["snmpd.conf", "rcS"],
    },
    {
        "id": "NET_UPNP_ENABLED",
        "title": "UPnP service detected (network exposure risk)",
        "severity": "medium",
        "cwe": ["CWE-912"],
        "cve_examples": ["CVE-2020-12695"],
        "remediation": "Disable UPnP on WAN interface; restrict to LAN only.",
        "patterns": [
            re.compile(r"\bupnpd\b", re.I),
            re.compile(r"\bminiupnpd\b", re.I),
        ],
        "file_hints": ["upnpd.conf", "rcS", "init.d"],
    },
]

# Files / directories worth scanning for network config
_INTERESTING_PATHS = {
    "etc/inetd.conf",
    "etc/xinetd.conf",
    "etc/init.d",
    "etc/rc.d",
    "etc/inittab",
    "etc/rc.local",
    "etc/rcS",
    "etc/config",       # OpenWrt UCI
    "etc/snmpd.conf",
    "etc/vsftpd.conf",
    "etc/lighttpd.conf",
    "etc/nginx",
    "etc/httpd.conf",
    "usr/sbin",         # daemon binaries
}

_HARDCODED_PORT_RE = re.compile(
    r"(?:port|listen|bind)[^=:]*[=:]\s*(\d{1,5})", re.I
)


def _should_scan(path: Path, root: Path) -> bool:
    rel = str(path.relative_to(root)).lower().replace("\\", "/")
    for hint in _INTERESTING_PATHS:
        if rel.startswith(hint) or hint in rel:
            return True
    # Also scan shell scripts
    if path.suffix in {".sh", ".conf", ""}:
        return True
    return False


def _read_safe(path: Path, max_bytes: int = 512_000) -> str:
    try:
        return path.read_bytes()[:max_bytes].decode("utf-8", errors="replace")
    except OSError:
        return ""


def scan_filesystem(root: Path) -> list[Finding]:
    """
    Walk an extracted firmware filesystem and detect enabled network services.
    """
    findings: list[Finding] = []
    triggered: set[str] = set()      # dedup by rule_id

    if not root.is_dir():
        return findings

    for fpath in sorted(root.rglob("*")):
        if not fpath.is_file():
            continue
        if not _should_scan(fpath, root):
            continue

        text = _read_safe(fpath)
        if not text:
            continue

        rel_str = str(fpath.relative_to(root))

        for rule in _SERVICE_RULES:
            rule_id: str = rule["id"]
            if rule_id in triggered:
                continue

            for pat in rule["patterns"]:
                if pat.search(text):
                    findings.append(Finding(
                        finding_id=rule_id,
                        title=rule["title"],
                        severity=rule["severity"],
                        confidence=0.75,
                        category="network_exposure",
                        cwe=rule["cwe"],
                        cve_examples=rule["cve_examples"],
                        evidence={
                            "matched_file": rel_str,
                            "pattern": pat.pattern,
                        },
                        remediation=rule["remediation"],
                    ))
                    triggered.add(rule_id)
                    break

    return findings


def scan_strings(strings_list: list[str]) -> list[Finding]:
    """
    Detect network service indicators from a flat list of extracted strings
    (used when filesystem extraction is unavailable).
    """
    text = "\n".join(strings_list)
    findings: list[Finding] = []
    triggered: set[str] = set()

    for rule in _SERVICE_RULES:
        rule_id: str = rule["id"]
        if rule_id in triggered:
            continue
        for pat in rule["patterns"]:
            if pat.search(text):
                findings.append(Finding(
                    finding_id=rule_id,
                    title=rule["title"],
                    severity=rule["severity"],
                    confidence=0.6,   # lower confidence without FS context
                    category="network_exposure",
                    cwe=rule["cwe"],
                    cve_examples=rule["cve_examples"],
                    evidence={"source": "strings_scan", "pattern": pat.pattern},
                    remediation=rule["remediation"],
                ))
                triggered.add(rule_id)
                break

    return findings
