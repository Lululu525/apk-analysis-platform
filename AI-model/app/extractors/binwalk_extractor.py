"""
binwalk integration for firmware extraction.

binwalk -e -M  (extract + matryoshka recursive)
Falls back gracefully if binwalk is not installed.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class BinwalkResult:
    success: bool
    extracted_dir: Path | None = None
    signatures: list[str] = field(default_factory=list)   # human-readable hits
    errors: list[str] = field(default_factory=list)
    tool_missing: bool = False


def extract(firmware_path: Path, output_dir: Path) -> BinwalkResult:
    """
    Run `binwalk -e -M <firmware_path>` and return the extraction result.

    binwalk puts extracted content under:
        <output_dir>/_<firmware_filename>.extracted/
    """
    if not shutil.which("binwalk"):
        return BinwalkResult(
            success=False,
            tool_missing=True,
            errors=["binwalk not found. Install with: pip install binwalk  or  brew install binwalk"],
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "binwalk",
        "--extract",          # -e
        "--matryoshka",       # -M  recursive extraction
        "--directory", str(output_dir),
        "--quiet",
        str(firmware_path),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,      # 5 min cap
        )
    except subprocess.TimeoutExpired:
        return BinwalkResult(success=False, errors=["binwalk timed out after 300 s"])
    except Exception as e:
        return BinwalkResult(success=False, errors=[f"binwalk subprocess error: {e}"])

    # Parse signature hits from stdout (each non-empty line is a hit)
    signatures = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip() and not line.startswith("WARNING")
    ]

    errors: list[str] = []
    if result.returncode != 0:
        errors.append(f"binwalk exited {result.returncode}: {result.stderr.strip()[:200]}")

    # Locate the extraction directory binwalk created
    extracted_dir: Path | None = None
    candidate = output_dir / f"_{firmware_path.name}.extracted"
    if candidate.is_dir():
        extracted_dir = candidate
    else:
        # Some versions use slightly different naming; search for the first dir
        dirs = [d for d in output_dir.iterdir() if d.is_dir()]
        if dirs:
            extracted_dir = dirs[0]

    return BinwalkResult(
        success=extracted_dir is not None,
        extracted_dir=extracted_dir,
        signatures=signatures,
        errors=errors,
    )
