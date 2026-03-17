"""
checksec integration — check binary protection features on ELF files.

Detects:
  - NX (No-eXecute / DEP)
  - Stack Canary
  - PIE (Position Independent Executable)
  - RELRO (Read-Only Relocations)
  - RPATH / RUNPATH (unsafe library search paths)

Falls back gracefully if checksec is not installed.
Install: brew install checksec  or  pip install checksec.py
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..schemas import Finding


@dataclass
class BinaryProtection:
    path: str
    nx: bool = False
    canary: bool = False
    pie: bool = False
    relro: str = "none"       # "none" | "partial" | "full"
    rpath: bool = False
    runpath: bool = False
    raw: dict = field(default_factory=dict)


def _run_checksec_json(elf_path: Path, timeout: int = 30) -> dict | None:
    """Try `checksec --output=json --file=<path>` and return parsed JSON."""
    try:
        r = subprocess.run(
            ["checksec", "--output=json", f"--file={elf_path}"],
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode != 0:
            return None
        return json.loads(r.stdout)
    except Exception:
        return None


def _parse_checksec_output(raw: dict, elf_path: Path) -> BinaryProtection | None:
    """Parse checksec JSON output into BinaryProtection."""
    # checksec JSON shape: {"<path>": {"nx": "yes", "canary": "yes", ...}}
    key = str(elf_path)
    data = raw.get(key) or (next(iter(raw.values())) if raw else None)
    if not data:
        return None

    def yn(val: str | None) -> bool:
        return str(val or "").lower() in ("yes", "enabled", "true", "1")

    relro_raw = str(data.get("relro", "none")).lower()
    if "full" in relro_raw:
        relro = "full"
    elif "partial" in relro_raw:
        relro = "partial"
    else:
        relro = "none"

    return BinaryProtection(
        path=str(elf_path),
        nx=yn(data.get("nx")),
        canary=yn(data.get("canary")),
        pie=yn(data.get("pie")),
        relro=relro,
        rpath=yn(data.get("rpath")),
        runpath=yn(data.get("runpath")),
        raw=data,
    )


def _protection_to_findings(bp: BinaryProtection) -> list[Finding]:
    findings: list[Finding] = []
    rel = bp.path  # use as evidence label

    if not bp.nx:
        findings.append(Finding(
            finding_id="CHECKSEC_NO_NX",
            title="Binary lacks NX/DEP protection",
            severity="high",
            confidence=0.9,
            category="binary_hardening",
            cwe=["CWE-119"],
            evidence={"file": rel, "nx": False},
            remediation="Compile with -z noexecstack and enable hardware NX support.",
        ))

    if not bp.canary:
        findings.append(Finding(
            finding_id="CHECKSEC_NO_CANARY",
            title="Binary lacks stack canary",
            severity="medium",
            confidence=0.9,
            category="binary_hardening",
            cwe=["CWE-121"],
            evidence={"file": rel, "canary": False},
            remediation="Compile with -fstack-protector-strong.",
        ))

    if not bp.pie:
        findings.append(Finding(
            finding_id="CHECKSEC_NO_PIE",
            title="Binary is not position-independent (no PIE/ASLR)",
            severity="medium",
            confidence=0.9,
            category="binary_hardening",
            cwe=["CWE-119"],
            evidence={"file": rel, "pie": False},
            remediation="Compile with -fPIE -pie.",
        ))

    if bp.relro == "none":
        findings.append(Finding(
            finding_id="CHECKSEC_NO_RELRO",
            title="Binary has no RELRO (GOT overwrite risk)",
            severity="medium",
            confidence=0.85,
            category="binary_hardening",
            cwe=["CWE-123"],
            evidence={"file": rel, "relro": "none"},
            remediation="Link with -Wl,-z,relro,-z,now for full RELRO.",
        ))
    elif bp.relro == "partial":
        findings.append(Finding(
            finding_id="CHECKSEC_PARTIAL_RELRO",
            title="Binary has only partial RELRO",
            severity="low",
            confidence=0.85,
            category="binary_hardening",
            cwe=["CWE-123"],
            evidence={"file": rel, "relro": "partial"},
            remediation="Link with -Wl,-z,now to achieve full RELRO.",
        ))

    if bp.rpath or bp.runpath:
        findings.append(Finding(
            finding_id="CHECKSEC_UNSAFE_RPATH",
            title="Binary has unsafe RPATH/RUNPATH",
            severity="medium",
            confidence=0.8,
            category="binary_hardening",
            cwe=["CWE-426"],
            evidence={"file": rel, "rpath": bp.rpath, "runpath": bp.runpath},
            remediation="Remove RPATH/RUNPATH or restrict to trusted paths.",
        ))

    return findings


def scan_elf(elf_path: Path) -> tuple[list[Finding], str]:
    """
    Scan a single ELF binary with checksec.

    Returns:
        (findings, status)
        status: "ok" | "tool_missing" | "parse_error" | "unsupported"
    """
    if not shutil.which("checksec"):
        return [], "tool_missing"

    raw = _run_checksec_json(elf_path)
    if raw is None:
        return [], "parse_error"

    bp = _parse_checksec_output(raw, elf_path)
    if bp is None:
        return [], "unsupported"

    return _protection_to_findings(bp), "ok"


def scan_directory(root: Path, file_limit: int = 30) -> tuple[list[Finding], bool]:
    """
    Find ELF binaries in an extracted filesystem and run checksec on each.

    Returns:
        (all_findings, tool_available)
    """
    if not shutil.which("checksec"):
        return [], False

    all_findings: list[Finding] = []
    count = 0

    for fpath in sorted(root.rglob("*")):
        if not fpath.is_file():
            continue
        try:
            with fpath.open("rb") as f:
                if f.read(4) != b"\x7fELF":
                    continue
        except OSError:
            continue

        findings, _ = scan_elf(fpath)
        all_findings.extend(findings)
        count += 1
        if count >= file_limit:
            break

    return all_findings, True