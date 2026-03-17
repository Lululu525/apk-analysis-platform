"""
Detect whether a file is an APK, firmware blob, ELF, or unknown.
Routing decision is based on magic bytes first, then file extension.
"""
from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Literal

FileType = Literal["apk", "firmware", "elf", "unknown"]

# (magic_bytes, label) — checked in order against the file header
_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"PK\x03\x04",        "zip"),           # ZIP / APK / JAR / OTA
    (b"\x7fELF",           "elf"),            # ELF binary
    (b"hsqs",              "squashfs"),        # SquashFS LE
    (b"sqsh",              "squashfs"),        # SquashFS BE
    (b"qshs",              "squashfs"),        # SquashFS (alt)
    (b"shsq",              "squashfs"),        # SquashFS (alt)
    (b"\x1f\x8b",         "gzip"),            # gzip
    (b"BZh",               "bzip2"),           # bzip2
    (b"\xfd7zXZ\x00",     "xz"),              # xz
    (b"\x85\x19\x01\xe8", "cramfs"),          # CramFS LE
    (b"\xe8\x01\x19\x85", "cramfs"),          # CramFS BE
    (b"ANDROID!",          "android_boot"),   # Android boot image
    (b"\x27\x05\x19\x56", "uimage"),          # U-Boot legacy image
    (b"\x1b\x4c\x09\xce", "yaffs2"),         # YAFFS2
    (b"\x06\x05\x2d\x19", "jffs2"),          # JFFS2 LE
    (b"\x19\x2d\x05\x06", "jffs2"),          # JFFS2 BE
]

_FIRMWARE_EXTENSIONS = {".bin", ".img", ".fw", ".rom", ".hex", ".elf", ".trx", ".chk"}
_APK_EXTENSIONS     = {".apk"}


def _read_magic(path: Path, n: int = 16) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(n)
    except OSError:
        return b""


def _is_apk(path: Path) -> bool:
    """APK = ZIP archive that contains AndroidManifest.xml at root level."""
    try:
        with zipfile.ZipFile(path) as zf:
            return "AndroidManifest.xml" in zf.namelist()
    except Exception:
        return False


def detect(path: Path) -> FileType:
    magic = _read_magic(path)

    for sig, label in _MAGIC_SIGNATURES:
        if magic[: len(sig)] == sig:
            if label == "zip":
                return "apk" if _is_apk(path) else "firmware"
            if label == "elf":
                return "elf"
            return "firmware"

    # Fallback: extension hint
    suffix = path.suffix.lower()
    if suffix in _APK_EXTENSIONS:
        return "apk"
    if suffix in _FIRMWARE_EXTENSIONS:
        return "firmware"

    return "unknown"
