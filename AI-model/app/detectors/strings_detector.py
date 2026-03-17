"""
String extraction with disassembly-first strategy.

Priority order for each binary:
  1. ELF + objdump available  → dump .rodata section (clean, no garbage)
  2. Any file + system strings → system `strings` CLI (better than Python ASCII scan)
  3. Fallback                  → Python printable-ASCII scan

The disassembly-first approach drastically reduces noise in .bin firmware blobs
because we only look at the read-only data segment instead of the whole binary.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


# ── helpers ──────────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 60) -> str | None:
    """Run a command, return stdout as str or None on error."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None


def _is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


# ── strategy 1: objdump .rodata ──────────────────────────────────────────────

def _strings_via_rodata(path: Path, min_len: int = 4) -> list[str] | None:
    """
    Use `objdump -s -j .rodata` to dump the read-only data section,
    then extract printable strings from the hex dump.

    Returns None if objdump is unavailable or the section doesn't exist.
    """
    if not shutil.which("objdump"):
        return None
    if not _is_elf(path):
        return None

    output = _run(["objdump", "-s", "-j", ".rodata", str(path)])
    if not output:
        return None

    strings: list[str] = []
    buf: list[str] = []

    # objdump hex-dump format:  " aaaa bbbb  cccc dddd  <printable>"
    # The printable portion is after the second two-space gap (columns 9+)
    for line in output.splitlines():
        # Content lines start with a hex address like " 1234 "
        parts = line.split("  ")
        if len(parts) < 3:
            _flush(buf, strings, min_len)
            continue
        printable = parts[-1].rstrip()
        for ch in printable:
            if 32 <= ord(ch) <= 126:
                buf.append(ch)
            else:
                _flush(buf, strings, min_len)

    _flush(buf, strings, min_len)
    return strings if strings else None


def _flush(buf: list[str], out: list[str], min_len: int) -> None:
    if len(buf) >= min_len:
        out.append("".join(buf))
    buf.clear()


# ── strategy 2: system `strings` CLI ─────────────────────────────────────────

def _strings_via_system(path: Path, min_len: int = 6) -> list[str] | None:
    """
    Use the system `strings` tool.  Uses min_len=6 (default 4 creates too much noise
    for raw binary blobs).
    """
    if not shutil.which("strings"):
        return None

    output = _run(["strings", f"-n{min_len}", str(path)])
    if output is None:
        return None
    return [s for s in output.splitlines() if s.strip()]


# ── strategy 3: Python fallback ───────────────────────────────────────────────

def _strings_python(data: bytes, min_len: int = 6, limit: int = 5000) -> list[str]:
    out: list[str] = []
    buf: list[int] = []

    def flush():
        if len(buf) >= min_len:
            s = bytes(buf).decode("ascii", errors="ignore")
            if s:
                out.append(s)
        buf.clear()

    for b in data:
        if 32 <= b <= 126:
            buf.append(b)
        else:
            flush()
            if len(out) >= limit:
                break
    flush()
    return out[:limit]


# ── public API ────────────────────────────────────────────────────────────────

def extract_strings(path: Path, min_len: int = 6, limit: int = 5000) -> tuple[list[str], str]:
    """
    Extract meaningful strings from a binary file.

    Returns:
        (strings_list, method_used)
        method_used: "rodata" | "system_strings" | "python_fallback"
    """
    # Strategy 1: ELF rodata (cleanest)
    result = _strings_via_rodata(path, min_len=min_len)
    if result is not None:
        return result[:limit], "rodata"

    # Strategy 2: system strings CLI
    result = _strings_via_system(path, min_len=min_len)
    if result is not None:
        return result[:limit], "system_strings"

    # Strategy 3: Python ASCII scan (always available)
    try:
        data = path.read_bytes()[:4_000_000]  # 4 MB cap
    except OSError:
        return [], "python_fallback"

    return _strings_python(data, min_len=min_len, limit=limit), "python_fallback"


def extract_strings_from_dir(
    root: Path,
    min_len: int = 6,
    per_file_limit: int = 2000,
    file_limit: int = 50,
) -> dict[str, list[str]]:
    """
    Walk an extracted filesystem directory and extract strings from each binary.
    Skips known non-binary extensions and huge files (> 20 MB).

    Returns: {relative_path_str: [strings]}
    """
    _SKIP_SUFFIXES = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
        ".mp3", ".mp4", ".wav", ".ogg",
        ".pdf", ".zip", ".gz", ".xz", ".bz2",
        ".pyc", ".class",
    }
    _MAX_SIZE = 20 * 1024 * 1024  # 20 MB

    results: dict[str, list[str]] = {}
    count = 0

    for fpath in sorted(root.rglob("*")):
        if not fpath.is_file():
            continue
        if fpath.suffix.lower() in _SKIP_SUFFIXES:
            continue
        if fpath.stat().st_size > _MAX_SIZE:
            continue
        if count >= file_limit:
            break

        strings, _ = extract_strings(fpath, min_len=min_len, limit=per_file_limit)
        if strings:
            results[str(fpath.relative_to(root))] = strings
        count += 1

    return results
