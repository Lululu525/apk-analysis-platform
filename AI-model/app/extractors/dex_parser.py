"""
Minimal DEX string table parser.

DEX format reference: https://source.android.com/docs/core/runtime/dex-format

String table layout:
  Header[0x38] = string_ids_size  (uint32 LE)
  Header[0x3C] = string_ids_off   (uint32 LE)

  string_ids[i] = uint32 offset → string_data_item
  string_data_item = ULEB128(utf16_length) + MUTF-8 bytes + \x00

We read all strings from the table and return those that look human-readable.
"""
from __future__ import annotations

import struct
from pathlib import Path

_DEX_MAGIC = b"dex\n"


def _read_uleb128(data: bytes, pos: int) -> tuple[int, int]:
    """Decode an unsigned LEB128 integer. Returns (value, new_pos)."""
    result = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            break
    return result, pos


def _is_readable(s: str, min_len: int) -> bool:
    if len(s) < min_len:
        return False
    # Reject strings that look like Java internal descriptors with no real words
    # (e.g. "Ljava/lang/Object;" is fine, "[B" is too short)
    printable = sum(32 <= ord(c) <= 126 for c in s)
    return printable / len(s) >= 0.80


def extract_strings_from_dex(path: Path, min_len: int = 6, limit: int = 5000) -> list[str]:
    """
    Parse the DEX string table and return all strings meeting min_len.
    Returns empty list if file is not a valid DEX or on any parse error.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return []

    if not data[:4] == _DEX_MAGIC:
        return []

    if len(data) < 0x70:  # minimum DEX header size
        return []

    try:
        string_ids_size = struct.unpack_from("<I", data, 0x38)[0]
        string_ids_off  = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return []

    strings: list[str] = []

    for i in range(string_ids_size):
        if len(strings) >= limit:
            break

        id_offset = string_ids_off + i * 4
        if id_offset + 4 > len(data):
            break

        try:
            data_offset = struct.unpack_from("<I", data, id_offset)[0]
            if data_offset >= len(data):
                continue

            _utf16_len, str_start = _read_uleb128(data, data_offset)

            # Read until null terminator
            null_pos = data.index(b"\x00", str_start)
            raw = data[str_start:null_pos]
            s = raw.decode("utf-8", errors="replace")

            if _is_readable(s, min_len):
                strings.append(s)
        except (ValueError, struct.error, UnicodeDecodeError):
            continue

    return strings
