#!/usr/bin/env python3

from pathlib import Path
import io
import mmap
import hashlib
import pickle
import math
import json
import queue
import re
import fnmatch
import struct
import sys
import threading
import tempfile
import subprocess
import shutil
import time
import wave
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import lz4.block

# Pillow is used only to display the RGBA image returned by dds_decoder.py.
# DDS/DX10 decoding is handled by the local universal decoder module.
try:
    from PIL import Image, ImageTk
except ImportError:
    Image = None
    ImageTk = None

_APP_DIR = Path(__file__).resolve().parent
_CONFIG_PATH = _APP_DIR / "control_resonant_asset_browser.json"
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

DDS_DECODER = None
DDS_DECODER_ERROR = None

# The decoder is a single local file next to this GUI.
# It bootstraps the established BCn codec into a private local cache when needed.
try:
    from dds_decoder import decode_dds as _decode_dds
    DDS_DECODER = _decode_dds
except Exception as _exc:
    DDS_DECODER_ERROR = _exc

# Also accept a local module/package named dds exposing the same API.
if DDS_DECODER is None:
    try:
        from dds import decode_dds as _decode_dds
        DDS_DECODER = _decode_dds
        DDS_DECODER_ERROR = None
    except Exception as _exc:
        if DDS_DECODER_ERROR is None:
            DDS_DECODER_ERROR = _exc


# ============================================================================
# RMD / PACK2 PARSER
# ============================================================================

DESCRIPTOR_SIZE = 0x10
ARCHIVE_SIZE = 0x18
PATH_SIZE = 0x1C
FILE_SIZE = 0x20
CHUNK_SIZE = 0x10


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def u40(buf, off):
    return int.from_bytes(buf[off:off + 5], "little")


def parse_header(toc):
    return {
        "table_off": u32(toc, 0x08),
        "table_size": u32(toc, 0x0C),
        "archives_off": u32(toc, 0x10),
        "archives_count": u32(toc, 0x14),
        "paths_off": u32(toc, 0x18),
        "paths_count": u32(toc, 0x1C),
        "files_off": u32(toc, 0x20),
        "files_count": u32(toc, 0x24),
        "strings_off": u32(toc, 0x28),
        "strings_size": u32(toc, 0x2C),
        "paths2_off": u32(toc, 0x30),
        "paths2_count": u32(toc, 0x34),
        "metadata_off": u32(toc, 0x38),
        "metadata_size": u32(toc, 0x3C),
        "chunks_off": u32(toc, 0x50),
        "chunks_size": u32(toc, 0x54),
    }


def check_table(full, h, name, off_key, count_key, record_size):
    off = h[off_key]
    count = h[count_key]
    end = off + count * record_size
    if end > len(full):
        raise RuntimeError(
            f"{name} table exceeds logical TOC: "
            f"off=0x{off:X}, count=0x{count:X}, "
            f"record_size=0x{record_size:X}, "
            f"end=0x{end:X}, TOC=0x{len(full):X}"
        )


def reconstruct_logical_toc(toc, h):
    table_size = h["table_size"]

    if table_size % DESCRIPTOR_SIZE:
        raise RuntimeError(
            "Descriptor table size is not divisible by "
            f"0x{DESCRIPTOR_SIZE:X}"
        )

    count = table_size // DESCRIPTOR_SIZE
    full = bytearray()

    for i in range(count):
        p = h["table_off"] + i * DESCRIPTOR_SIZE

        if p + DESCRIPTOR_SIZE > len(toc):
            raise RuntimeError(
                f"TOC descriptor {i} outside physical TOC: 0x{p:X}"
            )

        data_off = u40(toc, p + 0x03)
        decomp = u32(toc, p + 0x08)
        comp = u32(toc, p + 0x0C)
        stored_size = comp if comp else decomp
        data_end = data_off + stored_size

        if data_end > len(toc):
            raise RuntimeError(
                f"TOC descriptor {i}: data outside physical TOC: "
                f"off=0x{data_off:X}, size=0x{stored_size:X}, "
                f"end=0x{data_end:X}, TOC=0x{len(toc):X}"
            )

        raw = toc[data_off:data_end]

        if comp:
            raw = lz4.block.decompress(
                raw,
                uncompressed_size=decomp
            )

        if len(raw) != decomp:
            raise RuntimeError(
                f"TOC descriptor {i}: expected 0x{decomp:X}, "
                f"got 0x{len(raw):X}"
            )

        full += raw

    return full


def read_string(full, h, off, size):
    start = h["strings_off"] + off
    end = start + size
    strings_end = h["strings_off"] + h["strings_size"]

    if start < h["strings_off"] or end > strings_end:
        raise RuntimeError(
            f"String outside string table: off=0x{off:X}, size=0x{size:X}, "
            f"string_table=0x{strings_end:X}"
        )

    if end > len(full):
        raise RuntimeError(
            f"String outside logical TOC: start=0x{start:X}, "
            f"end=0x{end:X}, TOC=0x{len(full):X}"
        )

    return full[start:end].decode("utf-8", errors="replace")


def parse_paths(full, h):
    paths = {}
    base = h["paths_off"]
    strings = h["strings_off"]

    check_table(full, h, "Path", "paths_off", "paths_count", PATH_SIZE)

    for i in range(h["paths_count"]):
        p = base + i * PATH_SIZE
        string_off = u32(full, p + 0x14)
        string_len = u32(full, p + 0x18)

        start = strings + string_off
        end = start + string_len

        if start < strings or end > strings + h["strings_size"]:
            raise RuntimeError(
                f"Path {i} string outside string table: "
                f"off=0x{string_off:X}, size=0x{string_len:X}"
            )

        paths[i] = full[start:end].decode("utf-8", errors="replace")

    return paths


def parse_files(full, h, paths):
    files = []
    base = h["files_off"]

    check_table(full, h, "File", "files_off", "files_count", FILE_SIZE)

    for i in range(h["files_count"]):
        p = base + i * FILE_SIZE

        chunk_off = u32(full, p + 0x00)
        chunk_size = u32(full, p + 0x04)
        path_idx = u32(full, p + 0x08)
        string_off = u32(full, p + 0x0C)
        string_size = u32(full, p + 0x10)
        total_size = u32(full, p + 0x14)
        metadata_off = u32(full, p + 0x18)
        metadata_size = u32(full, p + 0x1C)

        name = read_string(full, h, string_off, string_size)
        path = paths.get(path_idx, f"<path_{path_idx}>")

        files.append({
            "index": i,
            "path_idx": path_idx,
            "path": path,
            "name": name,
            "full_path": f"{path}/{name}",
            "chunk_off": chunk_off,
            "chunk_size": chunk_size,
            "total_size": total_size,
            "metadata_off": metadata_off,
            "metadata_size": metadata_size,
        })

    return files


def parse_chunk(full, h, logical_off):
    p = h["chunks_off"] + logical_off

    if p + CHUNK_SIZE > len(full):
        raise RuntimeError(f"Chunk outside logical TOC: 0x{p:X}")

    flags = full[p + 0x00]
    archive = full[p + 0x01]
    blob_off = u40(full, p + 0x03)
    decomp = u32(full, p + 0x08)
    comp = u32(full, p + 0x0C)

    return {
        "toc_off": p,
        "flags": flags,
        "archive": archive,
        "blob_off": blob_off,
        "decomp": decomp,
        "comp": comp,
        "stored": comp if comp else decomp,
    }


def get_file_chunks(full, h, file_entry):
    chunk_off = file_entry["chunk_off"]
    chunk_size = file_entry["chunk_size"]

    if chunk_size % CHUNK_SIZE:
        raise RuntimeError(
            f"File {file_entry['index']} has invalid "
            f"chunk_size 0x{chunk_size:X}"
        )

    chunk_end = h["chunks_off"] + chunk_off + chunk_size

    if chunk_end > len(full):
        raise RuntimeError(
            f"File {file_entry['index']} chunk range outside logical TOC: "
            f"off=0x{chunk_off:X}, size=0x{chunk_size:X}"
        )

    chunks = []
    for i in range(chunk_size // CHUNK_SIZE):
        c = parse_chunk(full, h, chunk_off + i * CHUNK_SIZE)
        c["index"] = i
        chunks.append(c)

    return chunks


def extract_chunk(blob_fh, chunk):
    start = chunk["blob_off"]
    size = chunk["stored"]

    blob_fh.seek(start)
    raw = blob_fh.read(size)

    if len(raw) != size:
        raise RuntimeError(
            f"Chunk short read: wanted 0x{size:X}, got 0x{len(raw):X} "
            f"at blob offset 0x{start:X}"
        )

    if chunk["comp"]:
        raw = lz4.block.decompress(
            raw,
            uncompressed_size=chunk["decomp"]
        )

    if len(raw) != chunk["decomp"]:
        raise RuntimeError(
            f"Chunk decompression mismatch: expected "
            f"0x{chunk['decomp']:X}, got 0x{len(raw):X}"
        )

    return raw


def safe_output_path(root, asset_path):
    parts = []
    for part in Path(asset_path).parts:
        if part in ("", ".", ".."):
            continue
        parts.append(part)
    return root.joinpath(*parts)


def extract_file_bytes(full, h, file_entry, blob_handles):
    chunks = get_file_chunks(full, h, file_entry)
    output = bytearray()

    for chunk in chunks:
        blob_fh = blob_handles.get(chunk["archive"])
        if blob_fh is None:
            raise RuntimeError(
                f"Archive {chunk['archive']} has no known blob"
            )
        output += extract_chunk(blob_fh, chunk)

    expected = file_entry["total_size"]
    if len(output) != expected:
        raise RuntimeError(
            f"{file_entry['full_path']}: size mismatch: "
            f"expected 0x{expected:X}, got 0x{len(output):X}"
        )

    return bytes(output), chunks


# ============================================================================
# METADATA / TEXT VIEW HELPERS
# ============================================================================

def _read_u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def _read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def _printable_strings(data, min_len=4):
    """Return printable ASCII/UTF-8-ish strings with their byte offsets."""
    out = []
    for m in re.finditer(rb"[ -~]{%d,}" % min_len, data):
        raw = m.group(0)
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            value = raw.decode("latin-1", errors="replace")
        out.append((m.start(), value))
    return out


def decode_meta_container(data):
    """Decode the known PKMD/DMKP metadata envelope into readable text.

    The RMD extractor deliberately preserves this byte stream unchanged.
    This function is GUI-side presentation only.  The verified container
    begins with the little-endian uint32 magic 0x504B4D44 (ASCII 'DMKP'),
    followed by a uint32 record count.  The remainder is intentionally
    presented conservatively: known header fields, record-like uint16/uint32
    values, and embedded strings are shown without inventing semantics for
    fields that are not yet proven.
    """
    if len(data) < 16:
        return data.hex(" ")

    magic = data[:4]
    if magic not in (b"DMKP", b"PKMD"):
        return data.decode("utf-8", errors="replace")

    count = _read_u32(data, 4)
    lines = [
        "PKMD metadata container",
        "=" * 72,
        f"Magic:       {magic.decode('ascii', errors='replace')} (0x{int.from_bytes(magic, 'little'):08X})",
        f"Record count: {count}",
        f"Total size:   0x{len(data):X} ({len(data):,} bytes)",
        "",
        "Header / container fields",
        "-------------------------",
    ]

    # Preserve the unknown header bytes as explicit little-endian fields.
    # This is preferable to silently assigning incorrect names to them.
    for off in range(8, min(0x10, len(data)), 4):
        if off + 4 <= len(data):
            lines.append(f"+0x{off:04X}: u32 0x{_read_u32(data, off):08X} ({_read_u32(data, off)})")

    lines += [
        "",
        "Embedded strings",
        "-----------------",
    ]

    strings = _printable_strings(data)
    if strings:
        for off, value in strings:
            lines.append(f"+0x{off:04X}: {value}")
    else:
        lines.append("<no printable strings>")

    lines += [
        "",
        "Hex/structure information",
        "--------------------------",
        "Unknown fields are deliberately left unnamed; the raw metadata is preserved.",
    ]

    # Show the first 0xB8 bytes as grouped uint32 values.  This covers the
    # PKMD envelope and descriptors while remaining useful for reverse engineering.
    end = min(len(data), 0xB8)
    for off in range(0x10, end, 16):
        chunk = data[off:min(off + 16, end)]
        words = []
        for i in range(0, len(chunk), 4):
            part = chunk[i:i + 4]
            if len(part) == 4:
                words.append(f"0x{int.from_bytes(part, 'little'):08X}")
            else:
                words.append(part.hex())
        lines.append(f"+0x{off:04X}: " + "  ".join(words))

    return "\n".join(lines)


def format_css(css):
    """Make common minified CSS readable without changing its contents."""
    css = css.replace("\r\n", "\n").replace("\r", "\n")
    out = []
    indent = 0
    token = []
    in_string = None
    comment = False
    i = 0

    def emit(text):
        text = text.strip()
        if text:
            out.append("    " * indent + text)

    while i < len(css):
        c = css[i]
        n = css[i + 1] if i + 1 < len(css) else ""

        if comment:
            token.append(c)
            if c == "*" and n == "/":
                token.append(n)
                i += 2
                emit("".join(token))
                token = []
                comment = False
                continue
            i += 1
            continue

        if in_string:
            token.append(c)
            if c == "\\" and n:
                token.append(n)
                i += 2
                continue
            if c == in_string:
                in_string = None
            i += 1
            continue

        if c == "/" and n == "*":
            if token and "".join(token).strip():
                emit("".join(token))
                token = []
            token.extend([c, n])
            comment = True
            i += 2
            continue

        if c in "'\"":
            in_string = c
            token.append(c)
            i += 1
            continue

        if c == "{":
            head = "".join(token).strip()
            token = []
            if head:
                emit(head + " {")
            else:
                emit("{")
            indent += 1
            i += 1
            continue

        if c == ";":
            value = "".join(token).strip()
            token = []
            if value:
                emit(value + ";")
            i += 1
            continue

        if c == "}":
            value = "".join(token).strip()
            token = []
            if value:
                emit(value)
            indent = max(0, indent - 1)
            emit("}")
            i += 1
            continue

        token.append(c)
        i += 1

    tail = "".join(token).strip()
    if tail:
        emit(tail)
    return "\n".join(out)


def _material_value_text(type_code, payload):
    """Decode the material scalar/vector payloads used by the observed format."""
    if type_code == 12 and len(payload) == 1:
        return "true" if payload[0] else "false"

    float_counts = {0: 1, 1: 2, 2: 3, 3: 4, 6: 2}
    count = float_counts.get(type_code)
    if count is not None and len(payload) == count * 4:
        values = struct.unpack("<" + "f" * count, payload)
        return "(" + ", ".join(f"{v:.9g}" for v in values) + ")"

    if len(payload) == 4:
        value = int.from_bytes(payload, "little")
        return f"0x{value:08X} ({value})"

    if len(payload) % 4 == 0 and len(payload) <= 64:
        words = [
            int.from_bytes(payload[i:i + 4], "little")
            for i in range(0, len(payload), 4)
        ]
        return "raw32=[" + ", ".join(f"0x{x:08X}" for x in words) + "]"

    return payload.hex(" ")


def format_material(data):
    """Pretty-print the serialized .material property container.

    The observed container starts with version, flags and property count,
    followed by repeated: name length, UTF-8 name, type code, typed payload.
    The scalar/vector encodings used by the supplied material sample are
    decoded explicitly; unknown type codes are retained as raw bytes instead
    of being assigned invented semantics.
    """
    if len(data) < 12:
        return data.hex(" ")

    version, flags, property_count = struct.unpack_from("<III", data, 0)
    pos = 12
    lines = [
        "CONTROL Resonant Material",
        "=" * 78,
        f"Version:        {version}",
        f"Flags:          0x{flags:08X} ({flags})",
        f"Property count: {property_count}",
        "",
        "Properties",
        "----------",
    ]

    # Types observed in the supplied material sample.  Unknown types are not
    # guessed; the parser falls back to a structural boundary search.
    fixed_sizes = {
        0: 4,   # scalar float
        1: 8,   # float2/range
        2: 12,  # float3
        3: 16,  # float4/color
        4: 4,   # resource/index value
        5: 4,
        6: 8,
        7: 4,
        8: 4,
        9: 4,
        10: 4,
        11: 16,
        12: 1,  # bool
        13: 4,
        14: 4,
        15: 4,
        16: 4,
    }

    def next_property_boundary(start):
        # Structural fallback for a type not present in the known table.
        # A valid next property has a reasonable UTF-8/ASCII name and a type
        # code that can at least be represented as a u32. Prefer the earliest
        # such boundary that leaves enough room for the remaining properties.
        for candidate in range(start, len(data) - 8):
            if candidate % 1:
                continue
            if candidate + 8 > len(data):
                break
            n = int.from_bytes(data[candidate:candidate + 4], "little")
            if n <= 0 or n > 256:
                continue
            name_end = candidate + 4 + n
            if name_end + 4 > len(data):
                continue
            raw_name = data[candidate + 4:name_end]
            if not raw_name or any(c < 0x20 or c > 0x7E for c in raw_name):
                continue
            return candidate
        return len(data)

    parsed = 0
    while parsed < property_count and pos + 8 <= len(data):
        prop_offset = pos
        name_len = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if name_len > 4096 or pos + name_len + 4 > len(data):
            lines.append(f"[0x{prop_offset:04X}] Invalid property name length: {name_len}")
            break

        raw_name = data[pos:pos + name_len]
        pos += name_len
        name = raw_name.decode("utf-8", errors="replace")
        type_code = struct.unpack_from("<I", data, pos)[0]
        pos += 4

        payload_size = fixed_sizes.get(type_code)
        if payload_size is None or pos + payload_size > len(data):
            if parsed == property_count - 1:
                payload_size = len(data) - pos
            else:
                boundary = next_property_boundary(pos)
                payload_size = max(0, boundary - pos)

        payload = data[pos:pos + payload_size]
        pos += payload_size
        lines.append(
            f"[{parsed:02d}] {name}"
            f"\n      type: {type_code}"
            f"\n      value: {_material_value_text(type_code, payload)}"
        )
        parsed += 1

    if parsed != property_count:
        lines += ["", f"Parsed {parsed}/{property_count} properties."]
    if pos < len(data):
        lines += ["", f"Trailing bytes: 0x{len(data) - pos:X} ({len(data) - pos:,})", data[pos:].hex(" ")]

    return "\n".join(lines)


def format_binlua(data):
    """Render the readable string records embedded in Northlight BINLUA.

    The supplied Resonant files use records of:
        uint8 record/opcode, uint8 ASCII length, ASCII bytes
    followed eventually by opaque VM bytecode. The VM itself is not guessed
    or disassembled here; the useful human-readable string table is presented.
    """
    lines = [
        "Northlight BINLUA",
        "=" * 78,
        f"Size: {len(data):,} bytes (0x{len(data):X})",
    ]
    if len(data) < 4:
        return "\n".join(lines + ["\nFile is shorter than the BINLUA header."])

    lines += ["", "Header", "------", f"+0x0000: {data[:4].hex(' ')}"]
    pos = 4
    records = []
    while pos + 2 <= len(data):
        opcode = data[pos]
        length = data[pos + 1]
        if length == 0 or length > 0x7F or pos + 2 + length > len(data):
            break
        raw = data[pos + 2:pos + 2 + length]
        if not raw or any(b < 0x20 or b > 0x7E for b in raw):
            break
        records.append((pos, opcode, raw.decode("ascii")))
        pos += 2 + length

    lines += ["", "Readable string records", "------------------------"]
    if records:
        for index, (off, opcode, value) in enumerate(records, 1):
            lines.append(f"{index:05d}  +0x{off:04X}  [{opcode:02X}]  {value}")
    else:
        lines.append("No readable BINLUA string records were found.")

    lines += [
        "",
        "Remaining VM data",
        "------------------",
        f"Offset: +0x{pos:04X}",
        f"Size:   {len(data) - pos:,} bytes",
        "The remaining bytes are VM/instruction data and are intentionally not shown as a fake disassembly.",
    ]
    return "\n".join(lines)

def _decode_simple_string_table(data):
    """Decode the large Northlight string_table.bin variant.

    Layout verified against the supplied 4,593,048-byte sample:
      uint32 entry_count
      repeated: uint32 UTF-8 key length, key bytes,
                uint32 UTF-16LE code-unit count, UTF-16LE value
    """
    if len(data) < 4:
        return None
    count = struct.unpack_from("<I", data, 0)[0]
    if count == 0 or count > 5_000_000:
        return None
    pos = 4
    rows = []
    try:
        for _ in range(count):
            if pos + 4 > len(data):
                return None
            key_len = struct.unpack_from("<I", data, pos)[0]; pos += 4
            if key_len > 1_000_000 or pos + key_len > len(data):
                return None
            key = data[pos:pos + key_len].decode("utf-8", errors="replace"); pos += key_len
            if pos + 4 > len(data):
                return None
            value_len = struct.unpack_from("<I", data, pos)[0]; pos += 4
            if value_len > 1_000_000 or pos + value_len * 2 > len(data):
                return None
            value = data[pos:pos + value_len * 2].decode("utf-16le", errors="replace"); pos += value_len * 2
            rows.append((key, value))
    except (struct.error, UnicodeError):
        return None
    if pos != len(data):
        return None
    return rows


def _decode_rmdl_string_table(data):
    """
    Decode the compact RMDL sequence string-table variant used by
    *strings.bin assets.

    Verified layout:

        0x00  "RMDL"
        0x04  uint32 version
        0x0C  uint32 reserved/size field
        0x10  uint32 entry count
        0x18  variable record stream

    A dialogue record is identified by the little-endian marker
    0xD34DB33F (bytes 3F B3 4D D3), followed by:

        uint32 type       == 2
        uint32 size
        uint32 string_hash
        uint32 reserved
        uint32 value_len
        bytes  value
        uint32 speaker_len
        bytes  speaker
        [padding/record data]

    The record's payload length is size - 16.  The next record marker is
    therefore found immediately after that payload.

    Type 1 records are file/source references and are deliberately skipped;
    they are not dialogue strings.

    This is a structural parser, not a printable-string/offset heuristic.
    """
    if len(data) < 0x18 or data[:4] != b"RMDL":
        return None

    try:
        entry_count = struct.unpack_from("<I", data, 0x10)[0]
    except struct.error:
        return None

    if entry_count == 0 or entry_count > 100000:
        return None

    marker = b"\x3f\xb3\x4d\xd3"
    rows = []
    pos = 0x18

    # The sequence header contains some variable metadata before the first
    # marker. Find the first structurally valid marker rather than guessing
    # a fixed record-header size.
    def find_record(start):
        p = data.find(marker, start)
        while p >= 0:
            if p + 12 <= len(data):
                try:
                    record_type, size = struct.unpack_from("<II", data, p + 4)
                except struct.error:
                    return None
                payload_len = size - 16
                if (
                    record_type in (1, 2)
                    and size >= 16
                    and payload_len >= 0
                    and p + 12 + payload_len <= len(data)
                ):
                    return p
            p = data.find(marker, p + 1)
        return None

    pos = find_record(pos)
    if pos is None:
        return None

    # Every serialized entry carries the same marker immediately before its
    # type/size fields.  Some entries have variable metadata before the marker,
    # so parse every structurally valid marker rather than assuming a fixed
    # record stride.
    for match in re.finditer(re.escape(marker), data[pos:]):
        rec_pos = pos + match.start()
        if rec_pos + 12 > len(data):
            continue

        try:
            record_type, size = struct.unpack_from("<II", data, rec_pos + 4)
        except struct.error:
            continue

        payload_len = size - 16
        if (
            record_type not in (1, 2)
            or size < 16
            or payload_len < 0
            or rec_pos + 12 + payload_len > len(data)
        ):
            continue

        payload_start = rec_pos + 12
        payload_end = payload_start + payload_len
        payload = data[payload_start:payload_end]

        if record_type != 2 or len(payload) < 12:
            continue

        try:
            # hash + reserved + UTF-8 byte length
            _string_hash, _reserved, value_len = struct.unpack_from(
                "<III", payload, 0
            )
            value_start = 12
            value_end = value_start + value_len
            if value_end + 4 > len(payload):
                continue

            value_bytes = payload[value_start:value_end]
            speaker_len = struct.unpack_from("<I", payload, value_end)[0]
            speaker_start = value_end + 4
            speaker_end = speaker_start + speaker_len
            if speaker_end > len(payload):
                continue

            key = payload[speaker_start:speaker_end].decode(
                "utf-8", errors="replace"
            ).strip("\x00")
            value = value_bytes.decode(
                "utf-8", errors="replace"
            ).strip("\x00")

            if key or value:
                rows.append((key, value))
        except (struct.error, ValueError, UnicodeError):
            continue

    # A valid RMDL string table should produce at least one dialogue record.
    if not rows:
        return None

    return rows

def format_strings_bin(data):
    """Render string-table binaries as a human-readable key/value list."""
    rows = _decode_simple_string_table(data)
    variant = "Northlight STRING TABLE"
    if rows is None:
        rows = _decode_rmdl_string_table(data)
        variant = "Northlight RMDL STRING TABLE"
    if rows is None:
        return (
            "Northlight STRING TABLE\n"
            + "=" * 78 + "\n"
            + f"Size: {len(data):,} bytes (0x{len(data):X})\n\n"
            + "The file format could not be decoded as a supported string-table variant.\n"
        )

    lines = [
        variant,
        "=" * 78,
        f"Entries: {len(rows):,}",
        "",
        "KEY\tVALUE",
        "-" * 78,
    ]
    for key, value in rows:
        lines.append(f"{key}\t{value}")
    return "\n".join(lines)

def _is_string_table_binary(data):
    # Accept the two structurally decoded Northlight variants:
    # the large string_table.bin layout and the compact RMDL sequence tables.
    return (
        _decode_simple_string_table(data) is not None
        or _decode_rmdl_string_table(data) is not None
    )


def format_text_asset(data, suffix):
    if suffix == ".meta":
        return decode_meta_container(data)

    if suffix == ".material":
        return format_material(data)

    text = data.decode("utf-8", errors="replace")

    if suffix == ".json":
        try:
            obj = json.loads(text)
            return json.dumps(obj, indent=2, ensure_ascii=False)
        except json.JSONDecodeError as exc:
            return (
                "JSON parse error; showing original text.\n"
                f"Line {exc.lineno}, column {exc.colno}: {exc.msg}\n\n"
                + text
            )

    if suffix == ".css":
        return format_css(text)

    if suffix == ".binlua":
        return format_binlua(data)

    return text


# ============================================================================
# BINFBX DECODER
# ============================================================================

# Keep the complex BINFBX parser/converter as a separate module, exactly like
# dds_decoder.py.  The module must live next to this GUI as binfbx_decoder.py.
try:
    import binfbx_decoder
    BINFBX_DECODER_ERROR = None
except Exception as _exc:
    binfbx_decoder = None
    BINFBX_DECODER_ERROR = _exc


# ============================================================================
# GUI
# ============================================================================

TEXT_EXTENSIONS = {
    ".txt", ".xml", ".json", ".ini", ".cfg", ".config",
    ".css", ".html", ".htm", ".js", ".lua", ".shader",
    ".material", ".meta", ".binlua",
}

FILETYPE_FILTERS = {
    "All": None,
    "Images": {".tex"},
    "3D Models": {".binfbx"},
    "Text": TEXT_EXTENSIONS,
}


class ControlAssetBrowser(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("CONTROL Resonant Asset Prowser")
        self.geometry("1280x800")
        self.minsize(900, 600)

        self.install_dir = None

        # Persistent application settings live beside the GUI, never inside
        # the selected game installation.
        self.config_path = _CONFIG_PATH
        self.settings = self._load_config()
        self.theme_var = tk.StringVar(value=self.settings.get("theme", "light"))
        self.filetype_var = tk.StringVar(value=self.settings.get("filetype", "All"))
        self._theme_colors = {}
        self._preview_canvases = []
        self._preview_text_widgets = []
        self._search_placeholder = None
        self._apply_theme(self.theme_var.get())

        # Each .rmdtoc is an independent Pack2 container.  Keep the
        # parser data per container so archive indices can safely overlap.
        self.containers = []
        self.files = []

        # Search indexes are built once, when the TOC index is loaded.
        # They are never rebuilt while typing in the search box.
        self._search_suffix_index = {}
        self._search_token_index = {}
        self._search_ngram_index = {}
        self._search_entry_by_id = {}
        self._search_total = 0

        # Search/export presentation is separate from the permanent full tree.
        # The full tree is never detached/re-attached while searching.
        self._search_results_tree = None
        self._search_result_entries = {}
        self._search_result_build_job = None
        self._search_result_generation = 0
        self._export_marked_entries = set()

        self.tree_file_entries = {}
        self.tree_folder_paths = {}
        self.tree_synthetic_groups = {}
        self.export_checked = {}

        # The complete Treeview is built once after indexing. Search never
        # rebuilds it; it only detaches/reattaches already-created nodes.
        self._tree_built = False
        self._tree_root = None
        self._tree_node_parent = {}
        self._tree_node_order = {}
        self._tree_all_nodes = []
        self._tree_file_nodes = {}
        self._tree_filter_generation = 0
        self._tree_visible_nodes = set()
        self._tree_children = {}
        self._tree_node_depth = {}

        # Search filters the in-memory TOC index only.
        self.search_var = tk.StringVar()
        self._search_after_id = None
        self._search_generation = 0
        self._search_thread = None
        self._search_apply_job = None
        self._tree_filtering = False

        self.current_file = None
        self._viewer_generation = 0
        self.current_image = None
        self.current_image_source = None
        self._image_fit_job = None
        self._audio_process = None
        self._audio_temp_dir = None
        self._audio_wav = None

        self._load_queue = queue.Queue()
        self._load_thread = None
        self._load_generation = 0
        self._loading = False
        self._load_button = None

        self._build_menu()
        self._build_layout()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._restore_last_installation)

    # ------------------------------------------------------------------
    # Configuration / appearance
    # ------------------------------------------------------------------

    def _load_config(self):
        defaults = {
            "theme": "light",
            "filetype": "All",
            "last_game_path": "",
        }
        try:
            if self.config_path.is_file():
                with self.config_path.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    defaults.update(data)
        except Exception:
            pass

        if defaults.get("theme") not in ("light", "dark"):
            defaults["theme"] = "light"
        if defaults.get("filetype") not in FILETYPE_FILTERS:
            defaults["filetype"] = "All"
        if not isinstance(defaults.get("last_game_path"), str):
            defaults["last_game_path"] = ""
        return defaults

    def _save_config(self):
        self.settings["theme"] = self.theme_var.get()
        self.settings["filetype"] = self.filetype_var.get()
        self.settings["last_game_path"] = (
            str(self.install_dir) if self.install_dir is not None else self.settings.get("last_game_path", "")
        )
        temp = self.config_path.with_suffix(self.config_path.suffix + ".tmp")
        try:
            with temp.open("w", encoding="utf-8") as fh:
                json.dump(self.settings, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
            temp.replace(self.config_path)
        except Exception:
            try:
                temp.unlink()
            except Exception:
                pass

    def _apply_theme(self, theme):
        theme = theme if theme in ("light", "dark") else "light"
        self.theme_var.set(theme)
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        if theme == "dark":
            bg = "#202124"
            panel = "#292a2d"
            fg = "#eeeeee"
            muted = "#b8b8b8"
            select = "#3d6ea8"
            trough = "#17181a"
            border = "#4b4d52"
            entry_bg = "#18191b"
            preview_bg = "#18191b"
            preview_fg = "#eeeeee"
            mesh_fill = "#808080"
            mesh_outline = "#d0d0d0"
        else:
            bg = "#f0f0f0"
            panel = "#ffffff"
            fg = "#202020"
            muted = "#555555"
            select = "#c7ddf5"
            trough = "#d8d8d8"
            border = "#b8b8b8"
            entry_bg = "#ffffff"
            preview_bg = "#ffffff"
            preview_fg = "#202020"
            mesh_fill = "#b0b0b0"
            mesh_outline = "#404040"

        self._theme_colors = {
            "bg": bg, "panel": panel, "fg": fg, "muted": muted,
            "select": select, "trough": trough, "border": border,
            "entry_bg": entry_bg, "preview_bg": preview_bg,
            "preview_fg": preview_fg, "mesh_fill": mesh_fill,
            "mesh_outline": mesh_outline,
        }

        self.configure(background=bg)
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("TButton", background=panel, foreground=fg)
        style.map("TButton", background=[("active", select)])
        style.configure("TEntry", fieldbackground=entry_bg, foreground=fg, bordercolor=border)
        style.configure("TCombobox", fieldbackground=entry_bg, background=panel, foreground=fg, arrowcolor=fg)
        style.configure("Treeview", background=panel, fieldbackground=panel, foreground=fg,
                        bordercolor=border, rowheight=22)
        style.map("Treeview", background=[("selected", select)], foreground=[("selected", fg)])
        style.configure("TPanedwindow", background=bg)
        style.configure("TSeparator", background=border)
        style.configure("Horizontal.TProgressbar", troughcolor=trough, background=select)

        try:
            self.option_add("*TCombobox*Listbox.background", entry_bg)
            self.option_add("*TCombobox*Listbox.foreground", fg)
            self.option_add("*TCombobox*Listbox.selectBackground", select)
            self.option_add("*TCombobox*Listbox.selectForeground", fg)
        except tk.TclError:
            pass

        if hasattr(self, "tree_scrollbar"):
            try:
                self.tree_scrollbar.configure(
                    bg=panel, activebackground=select, troughcolor=trough,
                    highlightbackground=bg, highlightcolor=border, bd=0,
                )
            except tk.TclError:
                pass

        # Menu widgets are classic Tk widgets, so theme the actual existing
        # menus explicitly.  option_add() alone only reliably affects menus
        # created afterwards and therefore did not update the menu bar when
        # switching theme at runtime.
        try:
            self.option_add("*Menu.background", panel)
            self.option_add("*Menu.foreground", fg)
            self.option_add("*Menu.activeBackground", select)
            self.option_add("*Menu.activeForeground", fg)
            for menu in (
                getattr(self, "_menubar", None),
                getattr(self, "_file_menu", None),
                getattr(self, "_settings_menu", None),
                getattr(self, "_about_menu", None),
            ):
                if menu is not None:
                    menu.configure(
                        background=panel, foreground=fg,
                        activebackground=select, activeforeground=fg,
                        disabledforeground=muted, borderwidth=0,
                    )
        except tk.TclError:
            pass

        # Update the persistent search placeholder without ever putting its
        # text into search_var, so it can never become a real search term.
        try:
            if self._search_placeholder is not None:
                self._search_placeholder.configure(
                    background=entry_bg, foreground=muted,
                )
        except tk.TclError:
            pass

        # Preview canvases are classic Tk widgets and do not inherit ttk
        # styles. Keep their background synchronized with the selected theme.
        alive = []
        for canvas in getattr(self, "_preview_canvases", []):
            try:
                canvas.configure(background=preview_bg)
                alive.append(canvas)
            except tk.TclError:
                pass
        self._preview_canvases = alive

        # Classic Tk Text widgets do not inherit ttk theme colors. Keep every
        # currently visible text preview synchronized with the selected theme.
        alive_text = []
        for widget in getattr(self, "_preview_text_widgets", []):
            try:
                widget.configure(
                    background=preview_bg,
                    foreground=preview_fg,
                    insertbackground=preview_fg,
                    selectbackground=select,
                    selectforeground=fg,
                )
                alive_text.append(widget)
            except tk.TclError:
                pass
        self._preview_text_widgets = alive_text

    def _style_preview_text(self, widget):
        colors = self._theme_colors
        widget.configure(
            background=colors.get("preview_bg", "#ffffff"),
            foreground=colors.get("preview_fg", "#202020"),
            insertbackground=colors.get("preview_fg", "#202020"),
            selectbackground=colors.get("select", "#c7ddf5"),
            selectforeground=colors.get("fg", "#202020"),
        )
        self._preview_text_widgets.append(widget)
        return widget

    def _restore_last_installation(self):
        last = str(self.settings.get("last_game_path", "")).strip()
        if last:
            candidate = Path(last).expanduser()
            if candidate.is_dir() and any(candidate.rglob("*.rmdtoc")):
                self._load_installation(candidate)
                return
        self._choose_installation()

    def _entry_matches_filetype(self, entry):
        selected = self.filetype_var.get()
        suffixes = FILETYPE_FILTERS.get(selected)
        if suffixes is None:
            return True
        return Path(str(entry.get("name", ""))).suffix.casefold() in suffixes

    def _on_filetype_changed(self, *_args):
        self.settings["filetype"] = self.filetype_var.get()
        self._save_config()
        if not self._tree_built:
            return
        # Search results and the permanent tree both use the same filter.
        if self.search_var.get().strip():
            self._search_generation += 1
            self._start_search(self._search_generation)
        else:
            self._show_main_tree()
            self._filter_tree("")

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_menu(self):
        menubar = tk.Menu(self)
        self._menubar = menubar

        file_menu = tk.Menu(menubar, tearoff=False)
        self._file_menu = file_menu
        file_menu.add_command(
            label="Export selected folder",
            command=self._export_selected_folders,
        )
        file_menu.add_command(
            label="Export selected file(s)",
            command=self._export_selected_files,
        )
        file_menu.add_separator()
        file_menu.add_command(
            label="Exit",
            command=self._on_close,
        )
        menubar.add_cascade(label="File", menu=file_menu)

        settings_menu = tk.Menu(menubar, tearoff=False)
        self._settings_menu = settings_menu
        settings_menu.add_command(
            label="Settings",
            command=self._show_settings,
        )
        menubar.add_cascade(label="Settings", menu=settings_menu)

        about_menu = tk.Menu(menubar, tearoff=False)
        self._about_menu = about_menu
        about_menu.add_command(
            label="About",
            command=self._show_about,
        )
        menubar.add_cascade(label="About", menu=about_menu)

        self.configure(menu=menubar)
        self._apply_theme(self.theme_var.get())

    def _build_layout(self):
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(fill="both", expand=True)

        self.paned = ttk.Panedwindow(
            self.main_frame,
            orient="horizontal",
        )
        self.paned.pack(fill="both", expand=True)

        self.sidebar = ttk.Frame(self.paned)
        self.content = ttk.Frame(self.paned)

        self.paned.add(self.sidebar, weight=1)
        self.paned.add(self.content, weight=9)

        self._build_sidebar()

        # IMPORTANT: footer is built BEFORE content.
        # _build_content() calls _show_empty_view(), which uses these widgets.
        self._build_footer()
        self._build_content()

        self.after_idle(self._set_initial_sidebar_width)

    def _set_initial_sidebar_width(self):
        try:
            width = self.paned.winfo_width()
            if width > 1:
                self.paned.sashpos(0, max(180, int(width * 0.10)))
        except tk.TclError:
            pass

    def _build_sidebar(self):
        top = ttk.Frame(self.sidebar)
        top.pack(fill="x", padx=6, pady=6)

        self._load_button = ttk.Button(
            top,
            text="Open game folder",
            command=self._choose_installation,
        )
        self._load_button.pack(fill="x")

        search_frame = ttk.Frame(self.sidebar)
        search_frame.pack(fill="x", padx=6, pady=(0, 6))

        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side="left", fill="x", expand=True)

        # Website-style placeholder: it is a separate label, not the actual
        # Entry value, so "Search for..." can never participate in searches.
        self._search_placeholder = tk.Label(
            self.search_entry,
            text="Search for...",
            anchor="w",
            padx=4,
            bd=0,
            background=self._theme_colors.get("entry_bg", "#ffffff"),
            foreground=self._theme_colors.get("muted", "#555555"),
        )
        self._search_placeholder.place(relx=0, rely=0.5, anchor="w")
        self._search_placeholder.bind("<Button-1>", lambda _e: self.search_entry.focus_set())
        self.search_entry.bind("<FocusIn>", self._search_placeholder_focus_in)
        self.search_entry.bind("<FocusOut>", self._search_placeholder_focus_out)
        self.search_var.trace_add("write", self._update_search_placeholder)

        self.search_clear_button = ttk.Button(
            search_frame, text="×", width=3, command=self._clear_search
        )
        self.search_clear_button.pack(side="right", padx=(4, 0))
        self.search_var.trace_add("write", self._on_search_changed)

        self.location_label = ttk.Label(
            self.sidebar,
            text="No game folder selected",
            anchor="w",
        )
        self.location_label.pack(fill="x", padx=6, pady=(0, 6))

        tree_frame = ttk.Frame(self.sidebar)
        tree_frame.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.tree_frame = tree_frame

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("mark",),
            show="tree headings",
            selectmode="browse",
        )
        self.tree.heading("#0", text="Assets")
        self.tree.heading("mark", text="Export")
        self.tree.column("#0", width=300, stretch=True)
        self.tree.column(
            "mark",
            width=55,
            minwidth=55,
            stretch=False,
            anchor="center",
        )

        # Use the classic Tk scrollbar here rather than ttk::scrollbar.
        # On very large Treeviews this keeps thumb dragging responsive across
        # the different Tk/ttk builds used on Windows and Linux.
        yscroll = tk.Scrollbar(
            tree_frame,
            orient="vertical",
            command=self.tree.yview,
            takefocus=False,
        )
        self.tree_scrollbar = yscroll
        self.tree.configure(yscrollcommand=yscroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Double-1>", self._on_tree_double_click)
        self.tree.bind("<Return>", self._on_tree_return)
        self.tree.bind("<Button-1>", self._on_tree_click)

        self.search_tree = ttk.Treeview(
            tree_frame,
            columns=("mark",),
            show="tree headings",
            selectmode="browse",
        )
        self.search_tree.heading("#0", text="Search results")
        self.search_tree.heading("mark", text="Export")
        self.search_tree.column("#0", width=300, stretch=True)
        self.search_tree.column("mark", width=55, minwidth=55, stretch=False, anchor="center")
        self.search_tree.bind("<<TreeviewSelect>>", self._on_search_tree_select)
        self.search_tree.bind("<Button-1>", self._on_search_tree_click)
        self.search_tree.bind("<Double-1>", self._on_search_tree_double_click)
        self.search_tree.pack_forget()

    def _update_search_placeholder(self, *_args):
        try:
            if self.search_var.get():
                self._search_placeholder.place_forget()
            elif self.search_entry.focus_get() is not self.search_entry:
                self._search_placeholder.place(relx=0, rely=0.5, anchor="w")
            else:
                self._search_placeholder.place_forget()
        except tk.TclError:
            pass

    def _search_placeholder_focus_in(self, _event=None):
        try:
            self._search_placeholder.place_forget()
        except tk.TclError:
            pass

    def _search_placeholder_focus_out(self, _event=None):
        self._update_search_placeholder()

    def _activate_tree_scrollbar(self, tree):
        """Attach the one visible sidebar scrollbar to the active Treeview.

        The search results use a separate Treeview.  The scrollbar therefore
        must follow whichever Treeview is currently visible; otherwise the
        scrollbar thumb/arrows can still be connected to the hidden main tree
        and appear to work without actually scrolling the search results.
        """
        try:
            if tree is self.tree:
                self.search_tree.configure(yscrollcommand="")
            else:
                self.tree.configure(yscrollcommand="")
            tree.configure(yscrollcommand=self.tree_scrollbar.set)
            self.tree_scrollbar.configure(command=tree.yview)
            self.tree_scrollbar.set(*tree.yview())
        except tk.TclError:
            pass

        ttk.Label(
            self.sidebar,
            text="Search paths/names. Click Export to mark folders/files.",
            anchor="w",
        ).pack(fill="x", padx=6, pady=(0, 6))

    def _build_content(self):
        self.viewer = ttk.Frame(self.content)
        self.viewer.pack(fill="both", expand=True)
        self._show_empty_view()

    def _build_footer(self):
        footer = ttk.Frame(self.main_frame)
        footer.pack(side="bottom", fill="x")

        self.load_status_frame = ttk.Frame(footer)
        self.load_status_frame.pack(fill="x", padx=8, pady=(3, 0))

        self.load_status_label = ttk.Label(
            self.load_status_frame,
            text="",
            anchor="w",
        )
        self.load_status_label.pack(side="left", padx=(0, 8))

        self.load_progress = ttk.Progressbar(
            self.load_status_frame,
            orient="horizontal",
            mode="determinate",
            maximum=100,
            value=0,
        )
        self.load_progress.pack(side="left", fill="x", expand=True)

        self.load_percent_label = ttk.Label(
            self.load_status_frame,
            text="0%",
            width=5,
            anchor="e",
        )
        self.load_percent_label.pack(side="right", padx=(8, 0))

        self.load_status_frame.pack_forget()

        ttk.Separator(
            footer,
            orient="horizontal",
        ).pack(fill="x")

        row = ttk.Frame(footer)
        row.pack(fill="x", padx=8, pady=4)

        self.footer_path = ttk.Label(row, text="", anchor="w")
        self.footer_path.pack(
            side="left",
            fill="x",
            expand=True,
        )

        self.footer_size = ttk.Label(row, text="", anchor="e")
        self.footer_size.pack(side="left", padx=12)

        self.footer_type = ttk.Label(row, text="", anchor="e")
        self.footer_type.pack(side="right")

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _choose_installation(self):
        directory = filedialog.askdirectory(
            title="Select CONTROL Resonant installation folder"
        )
        if directory:
            self._load_installation(Path(directory))

    def _load_installation(self, directory):
        if self._loading:
            return

        self._close_blobs()

        self.install_dir = directory
        self.containers = []
        self.files = []
        self.tree_file_entries.clear()
        self.tree_folder_paths.clear()
        self.tree_synthetic_groups.clear()
        self.export_checked.clear()
        self._export_marked_entries.clear()
        self._tree_built = False
        self._tree_root = None
        self._tree_node_parent.clear()
        self._tree_node_order.clear()
        self._tree_all_nodes.clear()
        self._tree_file_nodes.clear()
        self._tree_visible_nodes.clear()
        self._tree_children.clear()
        self._tree_node_depth.clear()
        self.current_file = None
        self._stop_audio()
        self.search_var.set("")

        self.location_label.configure(text=str(directory))
        self.tree.delete(*self.tree.get_children())
        self._show_empty_view()

        self._loading = True
        self._load_generation += 1
        generation = self._load_generation
        self._load_queue = queue.Queue()

        self.load_status_frame.pack(fill="x", padx=8, pady=(3, 0))
        self.load_progress.configure(value=0)
        self.load_percent_label.configure(text="0%")
        self.load_status_label.configure(text="Scanning for .rmdtoc files…")
        if self._load_button is not None:
            self._load_button.configure(state="disabled")

        self._load_thread = threading.Thread(
            target=self._load_installation_worker,
            args=(directory, generation),
            daemon=True,
        )
        self._load_thread.start()
        self.after(50, self._poll_load_queue)

    @staticmethod
    def _cache_path(directory):
        return _APP_DIR / ".control_resonant_asset_index.cache"

    def _toc_manifest(self, directory, toc_candidates):
        # Cache validation is deliberately path/existence based.  TOC contents
        # are not hashed at startup: if the same relative .rmdtoc files exist,
        # the existing index is trusted.  Users can explicitly use Rebuild cache
        # when they know the installation/index has changed.
        manifest = []
        total = max(len(toc_candidates), 1)
        for index, path in enumerate(toc_candidates, 1):
            rel = path.relative_to(directory).as_posix()
            manifest.append(rel)
            self._load_queue.put((
                "progress", self._load_generation,
                1 + int(4 * index / total),
                f"Checking TOC {index}/{len(toc_candidates)}: {path.name}",
            ))
        return manifest

    def _load_index_cache(self, directory, toc_candidates, manifest):
        cache_path = self._cache_path(directory)
        if not cache_path.is_file():
            return None
        try:
            with cache_path.open("rb") as fh:
                payload = pickle.load(fh)
            if payload.get("version") != 3:
                return None
            if payload.get("manifest") != manifest:
                return None
            containers = payload["containers"]
            files = payload["files"]
            suffix_index = payload["suffix_index"]
            token_index = payload["token_index"]
            ngram_index = payload["ngram_index"]

            by_rel = {p.relative_to(directory).as_posix(): p for p in toc_candidates}
            for container in containers:
                rel = str(container["toc_path"])
                toc_path = by_rel.get(rel)
                if toc_path is None:
                    return None
                container["toc_path"] = toc_path
                container["blob_handles"] = {}
                container["blob_paths"] = {}
                self._resolve_blob_paths(container)
                for entry in container.get("files", []):
                    entry["_container"] = containers.index(container)
                for entry in container.get("meta_files", []):
                    entry["_container"] = containers.index(container)

            return containers, files, suffix_index, token_index, ngram_index
        except Exception:
            return None

    def _write_index_cache(self, directory, manifest, containers, files,
                           suffix_index, token_index, ngram_index):
        cache_path = self._cache_path(directory)
        temp_path = cache_path.with_suffix(cache_path.suffix + ".tmp")
        try:
            payload_containers = []
            for container in containers:
                c = dict(container)
                toc_path = Path(c["toc_path"])
                c["toc_path"] = toc_path.relative_to(directory).as_posix()
                c["blob_handles"] = {}
                # Blob paths are derived from the TOC and can be resolved again.
                c["blob_paths"] = {}
                payload_containers.append(c)
            payload = {
                "version": 3,
                "manifest": manifest,
                "containers": payload_containers,
                "files": files,
                "suffix_index": suffix_index,
                "token_index": token_index,
                "ngram_index": ngram_index,
            }
            with temp_path.open("wb") as fh:
                pickle.dump(payload, fh, protocol=pickle.HIGHEST_PROTOCOL)
            temp_path.replace(cache_path)
            return cache_path.is_file()
        except Exception:
            try:
                temp_path.unlink()
            except Exception:
                pass
            return False

    def _load_installation_worker(self, directory, generation):
        try:
            toc_candidates = sorted(
                directory.rglob("*.rmdtoc"),
                key=lambda p: str(p).lower(),
            )
            if not toc_candidates:
                raise RuntimeError("No .rmdtoc file was found below the selected folder.")

            self._load_queue.put(("progress", generation, 1,
                                  f"Found {len(toc_candidates):,} .rmdtoc file(s)."))
            manifest = self._toc_manifest(directory, toc_candidates)

            cached = self._load_index_cache(directory, toc_candidates, manifest)
            if cached is not None:
                containers, files, suffix_index, token_index, ngram_index = cached
                self._load_queue.put((
                    "done", generation, containers, files,
                    suffix_index, token_index, ngram_index, "hit",
                ))
                return

            total_toc_bytes = max(sum(path.stat().st_size for path in toc_candidates), 1)
            read_bytes = 0
            containers = []
            files = []

            for toc_index, toc_path in enumerate(toc_candidates):
                self._load_queue.put((
                    "progress", generation,
                    5 + int(55 * read_bytes / total_toc_bytes),
                    f"Reading {toc_index + 1}/{len(toc_candidates)}: {toc_path.name}",
                ))
                toc_size = toc_path.stat().st_size
                with toc_path.open("rb") as toc_fh:
                    if toc_size == 0:
                        raise RuntimeError(f"Empty TOC: {toc_path}")
                    toc = mmap.mmap(toc_fh.fileno(), 0, access=mmap.ACCESS_READ)
                    try:
                        header = parse_header(toc)
                        logical_toc = reconstruct_logical_toc(toc, header)
                    finally:
                        toc.close()
                read_bytes += toc_size

                container = {
                    "toc_path": toc_path,
                    "header": header,
                    "logical_toc": logical_toc,
                    "paths": {},
                    "files": [],
                    "blob_paths": {},
                    "blob_handles": {},
                }
                self._resolve_blob_paths(container)
                container["paths"] = parse_paths(logical_toc, header)
                container["files"] = parse_files(logical_toc, header, container["paths"])
                container_index = len(containers)
                for entry in container["files"]:
                    entry["_container"] = container_index

                meta_entries = []
                for source_entry in container["files"]:
                    if not source_entry["metadata_size"]:
                        continue
                    meta_entry = dict(source_entry)
                    meta_entry["_is_meta"] = True
                    meta_entry["_meta_source_index"] = source_entry["index"]
                    meta_entry["name"] = source_entry["name"] + ".meta"
                    meta_entry["full_path"] = source_entry["full_path"] + ".meta"
                    meta_entry["total_size"] = source_entry["metadata_size"]
                    meta_entries.append(meta_entry)
                container["meta_files"] = meta_entries
                for entry in meta_entries:
                    entry["_container"] = container_index

                containers.append(container)
                files.extend(container["files"])
                files.extend(meta_entries)
                self._load_queue.put((
                    "progress", generation,
                    60 + int(30 * (toc_index + 1) / len(toc_candidates)),
                    f"Parsed {toc_index + 1}/{len(toc_candidates)} containers — {len(files):,} assets.",
                ))

            for index, entry in enumerate(files):
                entry["_search_id"] = index
                entry["_cluster_name"] = self._asset_cluster_name(entry)
                entry["_search_text"] = " ".join((
                    str(entry.get("path", "")),
                    str(entry.get("name", "")),
                    str(Path(entry.get("name", "")).suffix),
                    str(entry.get("full_path", "")),
                )).casefold()

            suffix_index, token_index, ngram_index = self._make_search_indexes(files)
            self._load_queue.put((
                "progress", generation, 96,
                "Creating index cache — This may take a few minutes.",
            ))
            cache_created = self._write_index_cache(
                directory, manifest, containers, files,
                suffix_index, token_index, ngram_index,
            )
            cache_status = "created" if cache_created else "not_created"
            self._load_queue.put((
                "done", generation, containers, files,
                suffix_index, token_index, ngram_index, cache_status,
            ))
        except Exception as exc:
            self._load_queue.put(("error", generation, exc))

    def _poll_load_queue(self):
        try:
            while True:
                message = self._load_queue.get_nowait()
                kind = message[0]

                if kind == "progress":
                    _, generation, percent, text = message
                    if generation != self._load_generation:
                        continue
                    percent = max(0, min(100, percent))
                    self.load_progress.configure(value=percent)
                    self.load_percent_label.configure(text=f"{percent}%")
                    self.load_status_label.configure(text=text)

                elif kind == "done":
                    _, generation, containers, files, suffix_index, token_index, ngram_index, cache_status = message
                    if generation != self._load_generation:
                        continue

                    self.containers = containers
                    self.files = files
                    self._search_suffix_index = suffix_index
                    self._search_token_index = token_index
                    self._search_ngram_index = ngram_index
                    self._search_entry_by_id = {entry.get("_search_id", i): entry for i, entry in enumerate(files)}
                    self._search_total = len(files)
                    self._populate_tree()
                    self.load_progress.configure(value=100)
                    self.load_percent_label.configure(text="100%")
                    if cache_status == "hit":
                        load_message = (
                            f"Loaded {len(files):,} assets from {len(containers):,} container(s) — "
                            "index cache hit."
                        )
                    elif cache_status == "created":
                        load_message = (
                            f"Loaded {len(files):,} assets from {len(containers):,} container(s) — "
                            "Index cache created. This may take a few minutes."
                        )
                    else:
                        load_message = (
                            f"Loaded {len(files):,} assets from {len(containers):,} container(s)."
                        )
                    self.load_status_label.configure(text=load_message)
                    # Only remember a location after a successful complete load.
                    self.settings["last_game_path"] = str(self.install_dir)
                    self._save_config()
                    self.title(
                        f"CONTROL Resonant Asset Browser — "
                        f"{len(containers)} container(s), "
                        f"{len(files):,} asset(s)"
                    )
                    self._finish_loading()
                    return

                elif kind == "error":
                    _, generation, exc = message
                    if generation != self._load_generation:
                        continue

                    self._close_blobs()
                    self.containers = []
                    self.files = []
                    self.tree.delete(*self.tree.get_children())
                    self._show_empty_view()
                    self._finish_loading()
                    messagebox.showerror("Load error", str(exc))
                    return

        except queue.Empty:
            pass

        if self._loading:
            self.after(50, self._poll_load_queue)

    def _finish_loading(self):
        self._loading = False
        self._load_thread = None
        if self._load_button is not None:
            self._load_button.configure(state="normal")

    def _resolve_blob_paths(self, container):
        h = container["header"]
        full = container["logical_toc"]
        toc_dir = container["toc_path"].parent

        check_table(
            full,
            h,
            "Archive",
            "archives_off",
            "archives_count",
            ARCHIVE_SIZE,
        )

        aoff = h["archives_off"]
        soff = h["strings_off"]

        for i in range(h["archives_count"]):
            p = aoff + i * ARCHIVE_SIZE

            name_off = u32(full, p + 0x00)
            name_len = u32(full, p + 0x04)

            start = soff + name_off
            end = start + name_len

            if start < soff or end > soff + h["strings_size"]:
                raise RuntimeError(
                    f"Archive {i} name outside string table: "
                    f"off=0x{name_off:X}, size=0x{name_len:X}"
                )

            rel = full[start:end].split(b"\0", 1)[0].decode(
                "utf-8",
                "replace",
            )

            candidate = (toc_dir / rel).resolve()
            if not candidate.is_file():
                candidate = toc_dir / Path(rel).name

            if candidate.is_file():
                container["blob_paths"][i] = candidate

    # ------------------------------------------------------------------
    # Tree
    # ------------------------------------------------------------------

    @staticmethod
    def _asset_cluster_name(entry):
        """Return the presentation-only asset-cluster name for a file."""
        name = entry.get("name", "")
        if name.lower().endswith(".meta"):
            name = name[:-5]
        suffix = Path(name).suffix
        if suffix:
            name = name[:-len(suffix)]
        return name or entry.get("name", "")

    @staticmethod
    def _make_search_indexes(files):
        """Build immutable-ish inverted indexes from the already parsed TOC.

        The important part is the trigram index: arbitrary substring searches
        such as ``.wem``, ``loading``, ``psychic_boss`` or ``ranger khan`` can
        obtain a small candidate set without scanning every asset.  The final
        substring test still runs against the precomputed ``_search_text`` so
        the index never changes search semantics.
        """
        suffix_index = {}
        token_index = {}
        ngram_index = {}

        for index, entry in enumerate(files):
            entry_id = entry.get("_search_id", index)
            name = str(entry.get("name", "")).casefold()
            path = str(entry.get("path", "")).casefold()
            full_path = str(entry.get("full_path", "")).casefold()
            searchable = entry.get("_search_text")
            if not searchable:
                searchable = " ".join((path, name, full_path)).casefold()
                entry["_search_text"] = searchable

            suffix = Path(name).suffix.casefold()
            if suffix:
                suffix_index.setdefault(suffix, set()).add(entry_id)
                suffix_index.setdefault(suffix.lstrip("."), set()).add(entry_id)

            tokens = set(re.findall(r"[^\\/\s._-]+|\.[a-z0-9_]+", searchable))
            for token in tokens:
                token_index.setdefault(token, set()).add(entry_id)

            # Unique trigrams per entry keep the index compact.  This is an
            # inverted substring index, not a second copy of the asset data.
            if len(searchable) >= 3:
                grams = {searchable[i:i + 3] for i in range(len(searchable) - 2)}
                for gram in grams:
                    ngram_index.setdefault(gram, set()).add(entry_id)

        return suffix_index, token_index, ngram_index

    def _build_search_index(self, files):
        self._search_suffix_index, self._search_token_index, self._search_ngram_index = self._make_search_indexes(files)

    @staticmethod
    def _query_terms(query):
        """Split a search into AND terms while preserving glob operators.

        Search terms are intentionally simple and fast:

            board .tex        -> contains both "board" and ".tex"
            gap*.bin          -> glob against the filename/path
            bless *.wem       -> contains "bless" and any .wem filename
            foo?.tex           -> one-character wildcard

        A bare term is a case-insensitive substring search. ``*`` matches
        zero or more characters and ``?`` matches exactly one character.
        """
        return [term.casefold() for term in re.findall(r"\S+", query) if term]

    @staticmethod
    def _search_term_has_glob(term):
        return "*" in term or "?" in term

    @staticmethod
    def _search_glob_matches(term, entry):
        """Match a wildcard term against both filename and full path.

        Matching the basename as well as the full path is important for
        queries such as ``gap*.bin``: the directory prefix must not prevent
        a filename glob from matching.
        """
        name = str(entry.get("name", "")).casefold()
        full_path = str(entry.get("full_path", "")).casefold()
        path = str(entry.get("path", "")).casefold()
        return (fnmatch.fnmatchcase(name, term) or
                fnmatch.fnmatchcase(full_path, term) or
                fnmatch.fnmatchcase(path, term) or
                fnmatch.fnmatchcase(name, f"*{term}*"))

    def _search_matches(self, entry, query):
        searchable = entry.get("_search_text", "")
        for term in self._query_terms(query):
            if self._search_term_has_glob(term):
                if not self._search_glob_matches(term, entry):
                    return False
            elif term not in searchable:
                return False
        return True

    def _on_search_changed(self, *_args):
        if self._search_after_id is not None:
            try: self.after_cancel(self._search_after_id)
            except tk.TclError: pass
        if self._search_result_build_job is not None:
            try: self.after_cancel(self._search_result_build_job)
            except tk.TclError: pass
            self._search_result_build_job = None
        self._search_generation += 1
        generation = self._search_generation
        self._search_after_id = self.after(80, self._start_search, generation)

    def _start_search(self, generation):
        self._search_after_id = None
        if generation != self._search_generation or not self._tree_built:
            return
        query = self.search_var.get().strip()
        if not query:
            self._show_main_tree()
            self.load_status_label.configure(
                text=f"Showing {len(self.files):,} of {len(self.files):,} indexed assets."
            )
            return

        self.load_status_label.configure(text="Searching RAM index…")
        terms = [term.casefold() for term in query.split() if term]
        suffix_index = self._search_suffix_index
        token_index = self._search_token_index
        ngram_index = self._search_ngram_index
        entries = self._search_entry_by_id

        def worker():
            candidate_ids = None
            for term in terms:
                indexed = suffix_index.get(term)
                if indexed is None:
                    indexed = token_index.get(term)

                # Wildcards cannot be looked up as a literal token, but their
                # fixed text can still be used as an n-gram prefilter. This
                # keeps searches such as ``gap*.bin`` RAM-only and fast even
                # with hundreds of thousands of indexed assets.
                if indexed is None and self._search_term_has_glob(term):
                    literal_parts = [part for part in re.split(r"[*?]+", term) if len(part) >= 3]
                    if literal_parts:
                        postings = []
                        for part in literal_parts:
                            grams = {part[i:i + 3] for i in range(len(part) - 2)}
                            part_postings = [ngram_index.get(g) for g in grams]
                            if not part_postings or not all(part_postings):
                                postings = []
                                break
                            part_postings.sort(key=len)
                            part_ids = part_postings[0].copy()
                            for posting in part_postings[1:]:
                                part_ids.intersection_update(posting)
                                if not part_ids:
                                    break
                            postings.append(part_ids)
                        if postings:
                            indexed = postings[0].copy()
                            for posting in postings[1:]:
                                indexed.intersection_update(posting)
                                if not indexed:
                                    break

                if indexed is not None:
                    candidate_ids = set(indexed) if candidate_ids is None else candidate_ids & indexed
                    if not candidate_ids:
                        break

            if generation != self._search_generation: return
            if candidate_ids is None:
                candidates = entries.values()
            else:
                candidates = (entries[eid] for eid in candidate_ids if eid in entries)
            matches = []
            for entry in candidates:
                if generation != self._search_generation: return
                if not self._entry_matches_filetype(entry):
                    continue
                if self._search_matches(entry, query):
                    matches.append(entry)
            matches.sort(key=lambda e: str(e.get("full_path", "")).casefold())
            self.after(0, self._show_search_results, generation, matches, query)

        self._search_thread = threading.Thread(target=worker, daemon=True)
        self._search_thread.start()

    def _show_main_tree(self):
        self.search_tree.pack_forget()
        self.tree.pack(side="left", fill="both", expand=True)
        self._activate_tree_scrollbar(self.tree)
        self._search_result_entries.clear()

    def _show_search_results(self, generation, matches, query):
        if generation != self._search_generation: return
        self.tree.pack_forget()
        self.search_tree.pack(side="left", fill="both", expand=True)
        self._activate_tree_scrollbar(self.search_tree)
        self.search_tree.delete(*self.search_tree.get_children())
        self._search_result_entries.clear()
        self._search_result_generation = generation
        self.load_status_label.configure(
            text=f"Showing {len(matches):,} of {len(self.files):,} indexed assets."
        )

        # Only matching entries are inserted. The permanent full tree is left
        # untouched, so clearing the search is a single pack/unpack operation.
        batch_size = 750
        def insert_batch(pos=0):
            if generation != self._search_generation:
                self._search_result_build_job = None
                return
            end = min(pos + batch_size, len(matches))
            for entry in matches[pos:end]:
                mark = "☑" if id(entry) in self._export_marked_entries else "☐"
                node = self.search_tree.insert("", "end", text=entry.get("full_path", entry.get("name", "")), values=(mark,))
                self._search_result_entries[node] = entry
            if end < len(matches):
                self._search_result_build_job = self.after(1, insert_batch, end)
            else:
                self._search_result_build_job = None
        insert_batch(0)

    def _on_search_tree_click(self, event):
        item = self.search_tree.identify_row(event.y)
        column = self.search_tree.identify_column(event.x)
        if item and column == "#1":
            entry = self._search_result_entries.get(item)
            if entry is not None:
                marked = id(entry) in self._export_marked_entries
                if marked:
                    self._export_marked_entries.discard(id(entry))
                else:
                    self._export_marked_entries.add(id(entry))
                state = not marked
                self.search_tree.set(item, "mark", "☑" if state else "☐")
                main_node = self._tree_file_nodes.get(id(entry))
                if main_node:
                    try:
                        self.tree.set(main_node, "mark", "☑" if state else "☐")
                    except tk.TclError:
                        pass
            return "break"

    def _on_search_tree_select(self, _event=None):
        selection = self.search_tree.selection()
        if not selection:
            return
        entry = self._search_result_entries.get(selection[0])
        if entry is not None:
            self.current_file = entry
            self._show_file(entry)

    def _on_search_tree_double_click(self, _event=None):
        self._on_search_tree_select()
        return "break"

    def _apply_search(self):
        self._start_search(self._search_generation)

    def _clear_search(self):
        self.search_var.set("")
        self.search_entry.focus_set()

    def _tree_insert(self, parent, text, *, values=("☐",), open=False):
        node = self.tree.insert(parent, "end", text=text, values=values, open=open)
        self._tree_node_parent[node] = parent
        self._tree_node_order[node] = len(self._tree_all_nodes)
        if parent:
            self._tree_children.setdefault(parent, []).append(node)
            self._tree_node_depth[node] = self._tree_node_depth.get(parent, 0) + 1
        else:
            self._tree_children.setdefault("", []).append(node)
            self._tree_node_depth[node] = 0
        self._tree_all_nodes.append(node)
        return node

    def _build_full_tree(self):
        """Build the complete Treeview exactly once from the RAM-resident index."""
        self.tree.delete(*self.tree.get_children())
        self.tree_file_entries.clear()
        self.tree_folder_paths.clear()
        self.tree_synthetic_groups.clear()
        self._tree_node_parent.clear()
        self._tree_node_order.clear()
        self._tree_all_nodes.clear()
        self._tree_file_nodes.clear()
        self._tree_visible_nodes.clear()
        self._tree_children.clear()
        self._tree_node_depth.clear()

        root = self._tree_insert(
            "", self.install_dir.name, values=("☐",), open=True
        )
        self._tree_root = root
        self.tree_folder_paths[root] = ""

        folders = {"": root}
        entries_by_folder = {}
        for entry in self.files:
            folder = entry["path"].replace("\\", "/").strip("/")
            entries_by_folder.setdefault(folder, []).append(entry)

        real_folders = {""}
        for entry in self.files:
            folder = entry["path"].replace("\\", "/").strip("/")
            if folder:
                parts = [p for p in folder.split("/") if p]
                acc = []
                for part in parts:
                    acc.append(part)
                    real_folders.add("/".join(acc))

        for folder_path in sorted(real_folders, key=lambda x: (x.count("/"), x.casefold())):
            if not folder_path:
                continue
            parts = [p for p in folder_path.split("/") if p]
            parent = root
            acc = []
            for part in parts:
                acc.append(part)
                current = "/".join(acc)
                if current not in folders:
                    node = self._tree_insert(parent, part, values=("☐",), open=False)
                    folders[current] = node
                    self.tree_folder_paths[node] = current
                parent = folders[current]

        for folder_path, entries in sorted(entries_by_folder.items(), key=lambda kv: kv[0].casefold()):
            parent = folders.get(folder_path, root)
            clusters = {}
            for entry in entries:
                clusters.setdefault(entry.get("_cluster_name") or self._asset_cluster_name(entry), []).append(entry)

            if len(clusters) <= 1:
                for entry in sorted(entries, key=lambda f: f["name"].casefold()):
                    node = self._tree_insert(parent, entry["name"], values=("☑" if id(entry) in self._export_marked_entries else "☐",))
                    self.tree_file_entries[node] = entry
                    self._tree_file_nodes[id(entry)] = node
                continue

            for cluster_name in sorted(clusters, key=str.casefold):
                group_entries = sorted(clusters[cluster_name], key=lambda f: f["name"].casefold())
                group_node = self._tree_insert(parent, cluster_name, open=False)
                self.tree_synthetic_groups[group_node] = group_entries
                for entry in group_entries:
                    node = self._tree_insert(group_node, entry["name"], values=("☑" if id(entry) in self._export_marked_entries else "☐",))
                    self.tree_file_entries[node] = entry
                    self._tree_file_nodes[id(entry)] = node

        self._tree_built = True
        self._tree_filter_generation += 1
        self._tree_visible_nodes = set(self._tree_all_nodes)

    def _filter_tree(self, query):
        """Filter existing nodes; no Treeview reconstruction or TOC reads."""
        query = query.strip()
        visible = {self._tree_root}
        matches = 0
        if not query:
            for node, entry in self.tree_file_entries.items():
                if self._entry_matches_filetype(entry):
                    matches += 1
                    current = node
                    while current:
                        visible.add(current)
                        if current == self._tree_root:
                            break
                        current = self._tree_node_parent.get(current)
        else:
            for node, entry in self.tree_file_entries.items():
                if self._entry_matches_filetype(entry) and self._search_matches(entry, query):
                    matches += 1
                    current = node
                    while current:
                        visible.add(current)
                        if current == self._tree_root:
                            break
                        current = self._tree_node_parent.get(current)

        current_visible = self._tree_visible_nodes
        to_hide = current_visible - visible
        to_show = visible - current_visible

        # Hide only nodes whose state changed. This is substantially cheaper
        # than detaching/re-attaching the complete tree for every keystroke.
        for node in sorted(to_hide, key=self._tree_node_order.get, reverse=True):
            if node == self._tree_root:
                continue
            try:
                self.tree.detach(node)
            except tk.TclError:
                pass

        # Reattach changed nodes parent-by-parent. This avoids an O(N²)
        # sibling scan when a very large folder is restored after clearing a
        # search.
        show_by_parent = {}
        for node in to_show:
            if node == self._tree_root:
                continue
            parent = self._tree_node_parent[node]
            if parent in visible:
                show_by_parent.setdefault(parent, set()).add(node)

        parents = sorted(
            show_by_parent,
            key=lambda p: self._tree_node_depth.get(p, 0),
        )
        for parent in parents:
            wanted = show_by_parent[parent]
            visible_child_index = 0
            for child in self._tree_children.get(parent, ()):
                if child not in visible:
                    continue
                if child in wanted:
                    try:
                        self.tree.reattach(child, parent, visible_child_index)
                    except tk.TclError:
                        pass
                visible_child_index += 1

        self._tree_visible_nodes = visible
        self.load_status_label.configure(
            text=f"Showing {matches:,} of {len(self.files):,} indexed assets."
        )

    def _populate_tree(self, query=None):
        """Initial build only; subsequent searches are pure node filtering."""
        if not self._tree_built:
            self._build_full_tree()
        if query is None:
            query = self.search_var.get()
        self._filter_tree(query)

    def _on_tree_click(self, event):
        tree = event.widget
        item = tree.identify_row(event.y)
        column = tree.identify_column(event.x)

        if item and column == "#1":
            self._toggle_export_mark(item, tree)
            return "break"

    def _toggle_export_mark(self, item, tree=None):
        tree = tree or self.tree
        entry = self.tree_file_entries.get(item)
        if entry is not None:
            key = id(entry)
            state = key not in self._export_marked_entries
            if state: self._export_marked_entries.add(key)
            else: self._export_marked_entries.discard(key)
        else:
            state = not self.export_checked.get(item, False)
            self.export_checked[item] = state
        tree.set(item, "mark", "☑" if state else "☐")

    def _on_tree_double_click(self, event):
        # ttk::treeview has platform-dependent default double-click behaviour.
        # Handle folder expansion ourselves and stop the default binding from
        # interfering, so this works consistently on Windows and Linux.
        item = self.tree.identify_row(event.y)
        region = self.tree.identify("region", event.x, event.y)
        if (item in self.tree_folder_paths or item in self.tree_synthetic_groups) and region in ("tree", "cell"):
            self.tree.selection_set(item)
            self.tree.focus(item)
            self.tree.item(item, open=not bool(self.tree.item(item, "open")))
            return "break"

    def _on_tree_return(self, _event=None):
        selection=self.tree.selection()
        if selection and (selection[0] in self.tree_folder_paths or selection[0] in self.tree_synthetic_groups):
            item=selection[0]
            self.tree.item(item, open=not bool(self.tree.item(item,"open")))
            return "break"

    def _on_tree_select(self, _event=None):
        selection = self.tree.selection()

        if not selection:
            self.current_file = None
            self._show_empty_view()
            return

        entry = self.tree_file_entries.get(selection[0])

        if entry is None:
            self.current_file = None
            self._show_empty_view()
            return

        self.current_file = entry
        self._show_file(entry)

    # ------------------------------------------------------------------
    # Viewer
    # ------------------------------------------------------------------

    def _clear_viewer(self):
        # Invalidate every delayed callback belonging to the previous viewer.
        # WEM decoding can finish after the user has already selected another
        # asset; those callbacks must never touch destroyed Tk widgets.
        self._viewer_generation += 1
        self._stop_audio()
        if self._audio_temp_dir is not None:
            try:
                self._audio_temp_dir.cleanup()
            except Exception:
                pass
            self._audio_temp_dir = None
        self._audio_wav = None
        audio_progress_job = getattr(self, "_audio_progress_job", None)
        if audio_progress_job is not None:
            try:
                self.after_cancel(audio_progress_job)
            except tk.TclError:
                pass
        self._audio_progress_job = None
        for child in self.viewer.winfo_children():
            child.destroy()
        self._preview_canvases = []
        self._preview_text_widgets = []
        self.current_image = None
        self.current_image_source = None
        image_fit_job = getattr(self, "_image_fit_job", None)
        if image_fit_job is not None:
            try:
                self.after_cancel(image_fit_job)
            except tk.TclError:
                pass
        self._image_fit_job = None

    def _show_empty_view(self):
        self._clear_viewer()

        # Intentionally empty.
        ttk.Frame(self.viewer).pack(fill="both", expand=True)

        self.footer_path.configure(text="")
        self.footer_size.configure(text="")
        self.footer_type.configure(text="")

    def _show_file(self, entry):
        self._clear_viewer()

        try:
            data = self._read_file(entry)
        except Exception as exc:
            self._show_error_view(str(exc))
            return

        suffix = Path(entry["name"]).suffix.lower()

        self.footer_path.configure(text=entry["full_path"])
        self.footer_size.configure(text=self._format_size(len(data)))
        self.footer_type.configure(text=suffix or "<no extension>")

        if suffix in {".tex", ".dds"}:
            self._show_image_view(data)
        elif suffix == ".wem":
            self._show_wem_view(entry, data)
        elif suffix == ".binfbx":
            self._show_binfbx_view(entry, data)
        elif suffix == ".meta":
            self._show_meta_view(entry, data)
        elif suffix == ".bin" and (
            _is_string_table_binary(data)
            or "strings" in entry.get("name", "").casefold()
            or "string_table" in entry.get("name", "").casefold()
        ):
            self._show_strings_bin_view(entry, data)
        elif suffix in TEXT_EXTENSIONS:
            self._show_text_view(data, suffix, entry)
        else:
            self._show_generic_view(entry, data)

    def _find_meta_for_binfbx(self, entry):
        """Find the GUI-side metadata companion for a BINFBX entry."""
        container = self._get_container(entry)
        source_index = entry.get("index")
        for meta in container.get("meta_files", []):
            if meta.get("_meta_source_index") == source_index:
                return meta
        # Fallback for trees built from older data.
        target = entry.get("full_path", "") + ".meta"
        for meta in container.get("meta_files", []):
            if meta.get("full_path") == target:
                return meta
        return None

    def _decode_mesh_metadata_for_view(self, entry, binfbx_size):
        meta_entry = self._find_meta_for_binfbx(entry)
        if meta_entry is None:
            raise RuntimeError("No .meta sidecar is available for this BINFBX asset.")
        meta_data = self._read_file(meta_entry)
        with tempfile.TemporaryDirectory(prefix="control_meta_") as td:
            meta_path = Path(td) / "asset.binfbx.meta"
            meta_path.write_bytes(meta_data)
            meta = binfbx_decoder.parse_metadata(meta_path, binfbx_size)
        return meta, meta_data

    def _show_binfbx_view(self, entry, data):
        """Parse BINFBX + its MeshMetadata and display an interactive mesh."""
        frame = ttk.Frame(self.viewer)
        frame.pack(fill="both", expand=True)

        try:
            meta, meta_data = self._decode_mesh_metadata_for_view(entry, len(data))
            with tempfile.TemporaryDirectory(prefix="control_binfbx_") as td:
                bin_path = Path(td) / "asset.binfbx"
                bin_path.write_bytes(data)
                mesh = binfbx_decoder.parse_binfbx(bin_path, meta)

                # Decode only the first non-empty LOD for immediate display.
                lod = 0
                while lod < mesh["lod_count"]:
                    try:
                        geo = binfbx_decoder.collect_geometry(mesh, meta, lod, "default")
                        if geo["positions"]:
                            break
                    except Exception:
                        geo = None
                    lod += 1
                if geo is None or not geo.get("positions"):
                    raise RuntimeError("BINFBX parsed, but no renderable geometry was found.")

            self._build_3d_mesh_view(frame, entry, mesh, geo, meta)

        except Exception as exc:
            # Parsing failure is shown as a parser diagnostic, not as a generic
            # "unsupported file" message. This makes malformed/version-unknown
            # assets useful for reverse-engineering.
            for child in frame.winfo_children():
                child.destroy()
            top = ttk.Frame(frame)
            top.pack(fill="x", padx=8, pady=8)
            ttk.Label(top, text=entry["name"], font=("", 14, "bold")).pack(side="left")
            ttk.Label(
                top,
                text="BINFBX parser error — see details below",
            ).pack(side="right")
            text = tk.Text(frame, wrap="none")
            text.pack(fill="both", expand=True, padx=8, pady=(0, 8))
            text.insert("1.0", f"{type(exc).__name__}: {exc}\n\n")
            text.insert("end", "This asset was not decoded heuristically.\n")
            text.insert("end", "The embedded parser rejected the structure explicitly.\n")
            text.configure(state="disabled")

    def _build_3d_mesh_view(self, parent, entry, mesh, geo, meta):
        """Tkinter software 3D viewer: orbit, pan and zoom a reconstructed mesh."""
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill="x", padx=6, pady=6)

        info = (
            f"BINFBX v0x{mesh['version']:X}  |  "
            f"LOD 0  |  vertices {len(geo['positions']):,}  |  "
            f"triangles {sum(len(p['indices']) for p in geo['primitives']) // 3:,}  |  "
            f"materials {len(mesh['material_ids']):,}"
        )
        ttk.Label(toolbar, text=info).pack(side="left")

        canvas = tk.Canvas(
            parent,
            background=self._theme_colors.get("preview_bg", "#101010"),
            highlightthickness=0,
        )
        self._preview_canvases.append(canvas)
        canvas.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        positions = geo["positions"]
        triangles = []
        for primitive in geo["primitives"]:
            inds = primitive["indices"]
            for i in range(0, len(inds) - 2, 3):
                triangles.append((inds[i], inds[i + 1], inds[i + 2], primitive["material"]))

        if not positions or not triangles:
            ttk.Label(parent, text="No triangles available for 3D display.").pack()
            return

        cx = sum(p[0] for p in positions) / len(positions)
        cy = sum(p[1] for p in positions) / len(positions)
        cz = sum(p[2] for p in positions) / len(positions)
        centered = [(p[0]-cx, p[1]-cy, p[2]-cz) for p in positions]
        radius = max((x*x+y*y+z*z)**0.5 for x,y,z in centered) or 1.0

        state = {"yaw": 0.55, "pitch": 0.25, "zoom": 1.0, "panx": 0.0, "pany": 0.0,
                 "lastx": 0, "lasty": 0, "button": None}

        def project(p):
            x,y,z=p
            cyaw, syaw = math.cos(state["yaw"]), math.sin(state["yaw"])
            cp, sp = math.cos(state["pitch"]), math.sin(state["pitch"])
            x, z = x*cyaw - z*syaw, x*syaw + z*cyaw
            y, z = y*cp - z*sp, y*sp + z*cp
            w=max(canvas.winfo_width(), 2); h=max(canvas.winfo_height(), 2)
            scale=min(w,h)*0.42*state["zoom"]/radius
            return (w*0.5 + x*scale + state["panx"], h*0.5 - y*scale + state["pany"], z)

        def draw():
            canvas.delete("all")
            projected=[project(p) for p in centered]
            faces=[]
            for a,b,c,mat in triangles:
                pa,pb,pc=projected[a],projected[b],projected[c]
                depth=(pa[2]+pb[2]+pc[2])/3.0
                # Back-to-front painter's order. Fill is intentionally neutral;
                # the viewer is geometry-first, not a material renderer.
                faces.append((depth, pa, pb, pc))
            faces.sort(reverse=True, key=lambda x:x[0])
            for _,pa,pb,pc in faces:
                canvas.create_polygon(
                    pa[0],pa[1],pb[0],pb[1],pc[0],pc[1],
                    fill=self._theme_colors.get("mesh_fill", "#808080"),
                    outline=self._theme_colors.get("mesh_outline", "#303030"),
                    width=1,
                )

        def press(event):
            state["lastx"],state["lasty"]=event.x,event.y
            state["button"]="rotate" if event.num==1 else "pan"

        def drag(event):
            dx,dy=event.x-state["lastx"],event.y-state["lasty"]
            state["lastx"],state["lasty"]=event.x,event.y
            if state["button"]=="rotate":
                state["yaw"] += dx*0.01
                state["pitch"] = max(-1.5,min(1.5,state["pitch"]+dy*0.01))
            else:
                state["panx"] += dx
                state["pany"] += dy
            draw()

        def release(_event): state["button"]=None
        def wheel(event):
            delta=1.12 if event.delta>0 else 1/1.12
            state["zoom"]=max(0.05,min(30.0,state["zoom"]*delta))
            draw()
        def reset(_event=None):
            state.update(yaw=0.55,pitch=0.25,zoom=1.0,panx=0.0,pany=0.0)
            draw()

        canvas.bind("<ButtonPress-1>", press)
        canvas.bind("<B1-Motion>", drag)
        canvas.bind("<ButtonRelease-1>", release)
        canvas.bind("<ButtonPress-3>", press)
        canvas.bind("<B3-Motion>", drag)
        canvas.bind("<ButtonRelease-3>", release)
        canvas.bind("<MouseWheel>", wheel)
        canvas.bind("<Button-4>", lambda e: wheel(type("E", (), {"delta": 1})()))
        canvas.bind("<Button-5>", lambda e: wheel(type("E", (), {"delta": -1})()))
        canvas.bind("<Configure>", lambda _e: draw())
        canvas.bind("<Key-r>", reset)
        canvas.focus_set()
        draw()

    def _show_error_view(self, message):
        self._clear_viewer()

        frame = ttk.Frame(self.viewer)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        ttk.Label(
            frame,
            text="Unable to read asset",
            font=("", 14, "bold"),
        ).pack(pady=(0, 10))

        text = self._style_preview_text(tk.Text(frame, wrap="word"))
        text.pack(fill="both", expand=True)
        text.insert("1.0", message)
        text.configure(state="disabled")

    def _show_text_view(self, data, suffix, entry=None):
        frame = ttk.Frame(self.viewer)
        frame.pack(fill="both", expand=True)

        text = self._style_preview_text(tk.Text(frame, wrap="word", undo=False, padx=8, pady=8))
        yscroll = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=text.yview,
        )
        text.configure(yscrollcommand=yscroll.set)

        text.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")

        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        text.insert(
            "1.0",
            format_text_asset(data, suffix),
        )
        text.configure(state="disabled")

    def _show_meta_view(self, entry, data):
        """Show metadata according to the type of asset that owns the sidecar."""
        frame = ttk.Frame(self.viewer)
        frame.pack(fill="both", expand=True)
        text = self._style_preview_text(tk.Text(frame, wrap="none"))
        y = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        x = ttk.Scrollbar(frame, orient="horizontal", command=text.xview)
        text.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        text.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        source = entry.get("_meta_source_index")
        container = self._get_container(entry)
        source_entry = next(
            (e for e in container["files"] if e.get("index") == source),
            None,
        )
        source_name = source_entry.get("name", "") if source_entry else ""
        source_suffix = Path(source_name).suffix.lower()

        try:
            # Only BINFBX sidecars are MeshMetadata. Other .meta resources are
            # still valid metadata, but must not be forced through that grammar.
            if source_suffix == ".binfbx" and binfbx_decoder is not None:
                meta, _ = self._decode_mesh_metadata_for_view(
                    source_entry, source_entry["total_size"]
                )
                lines = [
                    "CONTROL Resonant MeshMetadata",
                    "=" * 78,
                    f"Metadata size:             {len(data):,} bytes",
                    f"MeshMetadata version:      {meta['version']}",
                    f"BINFBX CPU bytes:          0x{meta['cpu_num_bytes']:X}",
                    f"MeshCpuBytes:              0x{meta['mesh_cpu_bytes']:X}",
                    f"LOD count:                 {meta['lod_count']}",
                    f"Streamable layouts:        {max(0, len(meta['layouts']) - 1)}",
                    f"Has bones:                 {meta['has_bones']}",
                    f"Skeleton ID:               0x{meta['skeleton_id']:016X}",
                    f"Geometry transform shader: 0x{meta['geometry_transform_shader_id']:016X}",
                    "",
                    "Bounds",
                    "------",
                    f"min = {meta['bbox_min']}",
                    f"max = {meta['bbox_max']}",
                    f"sphere = {meta['bound_sphere']}",
                    "",
                    "MeshFileLayout",
                    "---------------",
                ]
                for i, (lv, fo, vb, pb, ib, istride, streamable) in enumerate(meta["layouts"]):
                    lines.append(
                        f"[{i}] version={lv} file_offset=0x{fo:X} "
                        f"vertex={vb:,} position_only={pb:,} index={ib:,} "
                        f"index_stride={istride} streamable={streamable}"
                    )
                lines += ["", "Material/Submesh resource IDs"]
                for i, rid in enumerate(meta["submesh_ids"]):
                    lines.append(f"[{i}] 0x{rid:016X}")
                text.insert("1.0", "\n".join(lines))
            else:
                text.insert("1.0", decode_meta_container(data))
        except Exception as exc:
            # A metadata sidecar must never become a generic runtime error in
            # the viewer. Preserve the parser diagnostic and still show the
            # actual container bytes in a readable structural form.
            text.insert(
                "1.0",
                f"Metadata decoder note: {type(exc).__name__}: {exc}\n\n"
                + decode_meta_container(data),
            )

        text.configure(state="disabled")

    def _show_strings_bin_view(self, entry, data):
        frame = ttk.Frame(self.viewer)
        frame.pack(fill="both", expand=True)
        text = self._style_preview_text(tk.Text(frame, wrap="none"))
        y = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        x = ttk.Scrollbar(frame, orient="horizontal", command=text.xview)
        text.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        text.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        rendered = format_strings_bin(data)
        if rendered.startswith("Northlight STRING TABLE\n") and "could not be decoded" in rendered:
            rendered = (
                "String-table candidate\n"
                + "=" * 78
                + "\n"
                + f"File: {entry.get('name', '')}\n"
                + f"Size: {len(data):,} bytes (0x{len(data):X})\n\n"
                + rendered
            )
        text.insert("1.0", rendered)
        text.configure(state="disabled")

    def _find_vgmstream(self):
        """Find a portable vgmstream-cli placed beside the GUI, never PATH."""
        candidates = []
        if sys.platform.startswith("win"):
            candidates += [
                _APP_DIR / "vgmstream-cli.exe",
                _APP_DIR / "vgmstream" / "vgmstream-cli.exe",
                _APP_DIR / "vgmstream" / "vgmstream-cli" / "vgmstream-cli.exe",
            ]
        elif sys.platform == "darwin":
            candidates += [
                _APP_DIR / "vgmstream-cli",
                _APP_DIR / "vgmstream" / "vgmstream-cli",
            ]
        else:
            candidates += [
                _APP_DIR / "vgmstream-cli",
                _APP_DIR / "vgmstream" / "vgmstream-cli",
            ]
        for candidate in candidates:
            candidate = Path(candidate)
            if candidate.is_file():
                return candidate
        return None

    def _show_wem_view(self, entry, data):
        viewer_generation = self._viewer_generation
        frame = ttk.Frame(self.viewer, padding=18)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text=entry["name"], font=("", 15, "bold")).pack(pady=(10, 6))
        status = ttk.Label(frame, text="Wwise WEM audio — ready")
        status.pack(pady=(0, 10))

        self._audio_duration = 0.0
        self._audio_position = 0.0
        self._audio_play_started = None
        self._audio_paused = False
        self._audio_progress_job = None
        self._audio_status_label = status

        controls = ttk.Frame(frame)
        controls.pack(pady=4)
        play_button = ttk.Button(controls, text="▶ Play")
        pause_button = ttk.Button(controls, text="Ⅱ Pause", state="disabled")
        stop_button = ttk.Button(controls, text="■ Stop", state="disabled")
        play_button.pack(side="left", padx=4)
        pause_button.pack(side="left", padx=4)
        stop_button.pack(side="left", padx=4)

        time_row = ttk.Frame(frame)
        time_row.pack(fill="x", pady=(16, 2))
        elapsed_label = ttk.Label(time_row, text="00:00")
        elapsed_label.pack(side="left")
        total_label = ttk.Label(time_row, text="00:00", anchor="e")
        total_label.pack(side="right")

        progress = ttk.Scale(frame, from_=0, to=1, orient="horizontal")
        progress.pack(fill="x", padx=2)

        info = ttk.Label(frame, text="")
        info.pack(pady=12)

        vgmstream = self._find_vgmstream()
        if vgmstream is None:
            status.configure(text="Portable vgmstream-cli was not found beside the GUI.")
            info.configure(text=(
                "Place vgmstream-cli.exe (Windows) or vgmstream-cli (Linux) "
                "beside this GUI. It is used directly; PATH is not required."
            ))
            return

        self._audio_temp_dir = tempfile.TemporaryDirectory(prefix="control_wem_")
        wem_path = Path(self._audio_temp_dir.name) / entry["name"].split("/")[-1]
        wav_path = Path(self._audio_temp_dir.name) / "decoded.wav"
        wem_path.write_bytes(data)
        self._audio_wav = wav_path
        info.configure(text=f"Decoder: {vgmstream.name}")

        def format_time(value):
            value = max(0.0, float(value))
            minutes = int(value // 60)
            seconds = int(value % 60)
            return f"{minutes:02d}:{seconds:02d}"

        def viewer_alive():
            if self.current_file is not entry or self._viewer_generation != viewer_generation:
                return False
            try:
                return bool(frame.winfo_exists())
            except tk.TclError:
                return False

        def update_ui():
            if not viewer_alive():
                self._audio_progress_job = None
                return
            pos = self._audio_position
            if self._audio_play_started is not None and not self._audio_paused:
                pos += time.monotonic() - self._audio_play_started
            try:
                if self._audio_duration > 0:
                    pos = min(pos, self._audio_duration)
                    progress.configure(value=pos)
                elapsed_label.configure(text=format_time(pos))
                total_label.configure(text=format_time(self._audio_duration))
                if self._audio_play_started is not None and not self._audio_paused:
                    if pos >= self._audio_duration - 0.05:
                        self._stop_audio()
                        self._audio_position = 0.0
                        progress.configure(value=0)
                        elapsed_label.configure(text="00:00")
                        status.configure(text="Finished")
                        pause_button.configure(state="disabled")
                        stop_button.configure(state="disabled")
                        play_button.configure(state="normal")
                        self._audio_progress_job = None
                        return
            except tk.TclError:
                self._audio_progress_job = None
                return
            self._audio_progress_job = self.after(100, update_ui)

        def decode():
            try:
                result = subprocess.run(
                    [str(vgmstream), "-o", str(wav_path), str(wem_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                    cwd=str(vgmstream.parent),
                )
                if result.returncode != 0 or not wav_path.is_file():
                    detail = (result.stderr or result.stdout or "unknown decoder error").strip()
                    def failed_decode():
                        if not viewer_alive():
                            return
                        try:
                            status.configure(text=f"vgmstream could not decode this WEM: {detail}")
                            play_button.configure(state="disabled")
                        except tk.TclError:
                            pass
                    self.after(0, failed_decode)
                    return
                with wave.open(str(wav_path), "rb") as wf:
                    frames = wf.getnframes()
                    rate = wf.getframerate()
                    duration = (frames / rate) if rate else 0.0
                def ready():
                    if not viewer_alive():
                        return
                    try:
                        self._audio_duration = duration
                        total_label.configure(text=format_time(duration))
                        status.configure(text="Ready — press Play")
                        play_button.configure(state="normal")
                    except tk.TclError:
                        pass
                self.after(0, ready)
            except Exception as exc:
                detail = f"{type(exc).__name__}: {exc}"
                def failed():
                    if not viewer_alive():
                        return
                    try:
                        status.configure(text=f"Audio decode error: {detail}")
                        play_button.configure(state="disabled")
                    except tk.TclError:
                        pass
                self.after(0, failed)

        play_button.configure(state="disabled")
        threading.Thread(target=decode, daemon=True).start()

        def play_from(position=None):
            if not wav_path.is_file():
                return
            if position is None:
                position = self._audio_position
            position = max(0.0, min(float(position), self._audio_duration or 0.0))
            self._stop_audio()
            ffplay = self._find_ffplay()
            if ffplay is None:
                status.configure(text="ffplay is required for Pause/Resume playback. Place ffplay beside the GUI.")
                return
            command = [str(ffplay), "-nodisp", "-autoexit", "-loglevel", "quiet", "-ss", str(position), str(wav_path)]
            try:
                self._audio_process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(ffplay.parent))
                self._audio_position = position
                self._audio_play_started = time.monotonic()
                self._audio_paused = False
                status.configure(text="Playing")
                play_button.configure(state="disabled")
                pause_button.configure(state="normal")
                stop_button.configure(state="normal")
            except Exception as exc:
                status.configure(text=f"Playback error: {type(exc).__name__}: {exc}")

        def play():
            play_from(self._audio_position)

        def pause():
            if self._audio_play_started is not None and not self._audio_paused:
                self._audio_position += time.monotonic() - self._audio_play_started
            self._stop_audio()
            self._audio_paused = True
            self._audio_play_started = None
            status.configure(text="Paused")
            pause_button.configure(state="disabled")
            play_button.configure(state="normal")
            stop_button.configure(state="normal")

        def stop():
            self._stop_audio()
            self._audio_position = 0.0
            self._audio_play_started = None
            self._audio_paused = False
            progress.configure(value=0)
            elapsed_label.configure(text="00:00")
            status.configure(text="Stopped")
            pause_button.configure(state="disabled")
            stop_button.configure(state="disabled")
            play_button.configure(state="normal")

        def seek(value):
            if not self._audio_duration:
                return
            new_pos = max(0.0, min(float(value), self._audio_duration))
            was_playing = self._audio_play_started is not None and not self._audio_paused
            self._audio_position = new_pos
            if was_playing:
                play_from(new_pos)
            else:
                elapsed_label.configure(text=format_time(new_pos))

        play_button.configure(command=play)
        pause_button.configure(command=pause)
        stop_button.configure(command=stop)
        progress.configure(command=seek)
        update_ui()

    def _find_ffplay(self):
        candidates = [_APP_DIR / "ffplay.exe", _APP_DIR / "ffplay"]
        for sub in ("ffmpeg", "tools"):
            candidates += [_APP_DIR / sub / "ffplay.exe", _APP_DIR / sub / "ffplay"]
        for candidate in candidates:
            candidate = Path(candidate)
            if candidate.is_file():
                return candidate
        found = shutil.which("ffplay")
        return Path(found) if found else None

    def _start_wav_playback(self, wav_path, status, stop_button):
        """Play decoded PCM with native OS facilities; vgmstream remains local."""
        if sys.platform.startswith("win"):
            import winsound
            winsound.PlaySound(str(wav_path), winsound.SND_FILENAME | winsound.SND_ASYNC)
            self._audio_process = ("winsound", winsound)
            return

        # Linux desktops commonly expose one of these already. We do not add
        # anything to PATH; the absolute system command is used only as the
        # final PCM playback backend after vgmstream has decoded the WEM.
        players = [
            ("pw-play", ["pw-play", str(wav_path)]),
            ("paplay", ["paplay", str(wav_path)]),
            ("aplay", ["aplay", str(wav_path)]),
            ("ffplay", ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet", str(wav_path)]),
        ]
        for name, command in players:
            executable = shutil.which(name)
            if executable:
                proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self._audio_process = proc
                return
        raise RuntimeError("No supported Linux PCM playback backend was found (pw-play, paplay, aplay or ffplay).")

    def _stop_audio(self):
        proc = getattr(self, "_audio_process", None)
        if proc is None:
            return
        try:
            if isinstance(proc, tuple) and proc[0] == "winsound":
                proc[1].PlaySound(None, proc[1].SND_PURGE)
            else:
                proc.terminate()
                try:
                    proc.wait(timeout=0.5)
                except Exception:
                    proc.kill()
        except Exception:
            pass
        self._audio_process = None

    def _show_image_view(self, data):
        frame = ttk.Frame(self.viewer)
        frame.pack(fill="both", expand=True)

        if Image is None or ImageTk is None:
            ttk.Label(
                frame,
                text="Pillow is required to display decoded DDS images.",
            ).pack(expand=True)
            return

        if DDS_DECODER is None:
            ttk.Label(
                frame,
                text=(
                    "No DDS decoder is available.\n\n"
                    "Place dds_decoder.py next to this GUI script.\n"
                    f"Decoder error: {DDS_DECODER_ERROR}"
                ),
                justify="center",
            ).pack(expand=True)
            return

        try:
            image = DDS_DECODER(data)
            if not isinstance(image, Image.Image):
                raise TypeError(
                    "DDS decoder returned an unsupported object: "
                    f"{type(image).__name__}. Expected PIL.Image.Image."
                )
            image.load()
            self.current_image_source = image.copy()

            canvas = tk.Canvas(
                frame,
                background=self._theme_colors.get("preview_bg", "#ffffff"),
                highlightthickness=0,
            )
            self._preview_canvases.append(canvas)
            canvas.pack(fill="both", expand=True)

            def fit_image(_event=None):
                if self.current_image_source is None:
                    return
                w = max(canvas.winfo_width(), 2)
                h = max(canvas.winfo_height(), 2)
                src = self.current_image_source
                scale = min(w / src.width, h / src.height)
                new_w = max(1, int(src.width * scale))
                new_h = max(1, int(src.height * scale))
                if new_w == src.width and new_h == src.height:
                    fitted = src
                else:
                    try:
                        resample = Image.Resampling.LANCZOS
                    except AttributeError:
                        resample = Image.LANCZOS
                    fitted = src.resize((new_w, new_h), resample)
                photo = ImageTk.PhotoImage(fitted)
                self.current_image = photo
                canvas.delete("all")
                canvas.create_image(
                    w // 2, h // 2, image=photo, anchor="center"
                )

            def schedule_fit(_event=None):
                image_fit_job = getattr(self, "_image_fit_job", None)
                if image_fit_job is not None:
                    try:
                        self.after_cancel(image_fit_job)
                    except tk.TclError:
                        pass
                self._image_fit_job = self.after_idle(fit_image)

            canvas.bind("<Configure>", schedule_fit)
            self.after_idle(fit_image)

        except Exception as exc:
            # Some Northlight .tex entries are actually Bink2/KB2j media
            # despite the .tex extension.  Try the local FFmpeg decoder as a
            # second-stage fallback and show the first frame as an image.
            if data[:4] == b"KB2j" or data[:3] == b"KB2":
                if self._show_bink2_tex_frame(frame, data):
                    return
            ttk.Label(
                frame,
                text=f"Could not decode image:\n\n{exc}",
                justify="center",
            ).pack(expand=True)

    def _find_binkconv(self):
        candidates = [
            _APP_DIR / "binkconv.exe", _APP_DIR / "binkconv",
            _APP_DIR / "radvideo64.exe", _APP_DIR / "radvideo64",
        ]
        for sub in ("bink", "radvideo", "RADVideo", "tools"):
            candidates += [
                _APP_DIR / sub / "binkconv.exe", _APP_DIR / sub / "binkconv",
                _APP_DIR / sub / "radvideo64.exe", _APP_DIR / sub / "radvideo64",
            ]
        for candidate in candidates:
            candidate = Path(candidate)
            if candidate.is_file():
                return candidate
        return None

    def _show_bink2_tex_frame(self, frame, data):
        decoder = self._find_binkconv()
        ffmpeg = self._find_ffmpeg()
        try:
            with tempfile.TemporaryDirectory(prefix="control_bink2_tex_") as td:
                td_path = Path(td)
                src = td_path / "asset.tex"
                src.write_bytes(data)
                generated = []
                decoder_error = None

                if decoder is not None:
                    if decoder.name.lower().startswith("radvideo"):
                        command = [str(decoder), "binkconv", str(src), str(td_path / "frame.png"), "/n-1", "/z1", "/#"]
                    else:
                        command = [str(decoder), str(src), str(td_path / "frame.png"), "/n-1", "/z1", "/#"]
                    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False, cwd=str(decoder.parent))
                    generated = [q for q in td_path.iterdir() if q.suffix.lower() in (".png", ".bmp", ".tga", ".jpg", ".jpeg")]
                    if not generated:
                        decoder_error = (result.stderr or result.stdout or "binkconv failed").strip()

                if not generated and ffmpeg is not None:
                    out = td_path / "frame.png"
                    result = subprocess.run([str(ffmpeg), "-hide_banner", "-loglevel", "error", "-i", str(src), "-frames:v", "1", "-y", str(out)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False, cwd=str(Path(ffmpeg).parent))
                    if result.returncode == 0 and out.is_file():
                        generated = [out]
                    else:
                        err = (result.stderr or result.stdout or "ffmpeg could not decode KB2j media").strip()
                        decoder_error = (decoder_error + "\n\nFFmpeg: " + err) if decoder_error else err

                if not generated:
                    raise RuntimeError(decoder_error or "No local Bink2 decoder found. Place binkconv.exe or radvideo64.exe beside the GUI.")

                image = Image.open(generated[0]).convert("RGBA")
                image.load()
                self.current_image_source = image.copy()

            canvas = tk.Canvas(
                frame,
                background=self._theme_colors.get("preview_bg", "#ffffff"),
                highlightthickness=0,
            )
            self._preview_canvases.append(canvas)
            canvas.pack(fill="both", expand=True)
            def fit_image(_event=None):
                if self.current_image_source is None:
                    return
                w = max(canvas.winfo_width(), 2); h = max(canvas.winfo_height(), 2)
                src = self.current_image_source
                scale = min(w / src.width, h / src.height)
                size = (max(1, int(src.width * scale)), max(1, int(src.height * scale)))
                if size == src.size:
                    fitted = src
                else:
                    try: resample = Image.Resampling.LANCZOS
                    except AttributeError: resample = Image.LANCZOS
                    fitted = src.resize(size, resample)
                self.current_image = ImageTk.PhotoImage(fitted)
                canvas.delete("all")
                canvas.create_image(w // 2, h // 2, image=self.current_image, anchor="center")
            canvas.bind("<Configure>", fit_image)
            self.after_idle(fit_image)
            return True
        except Exception as exc:
            ttk.Label(frame, text=f"KB2j/Bink2 preview failed:\n\n{exc}", justify="center").pack(expand=True)
            return True

    def _show_generic_view(self, entry, data):
        frame = ttk.Frame(self.viewer)
        frame.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=20,
        )

        ttk.Label(
            frame,
            text=entry["name"],
            font=("", 16, "bold"),
        ).pack(pady=(20, 10))

        ttk.Label(
            frame,
            text=(
                "No specialized viewer is currently "
                "registered for this asset type."
            ),
            justify="center",
        ).pack()

        ttk.Label(
            frame,
            text=(
                f"\nSize: {self._format_size(len(data))}"
                f"\nType: {Path(entry['name']).suffix or '<none>'}"
            ),
            justify="center",
        ).pack()

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------

    def _get_container(self, entry):
        index = entry["_container"]
        return self.containers[index]

    def _ensure_blob_handles(self, container):
        for archive, path in container["blob_paths"].items():
            if archive in container["blob_handles"]:
                continue

            if path.is_file():
                container["blob_handles"][archive] = open(path, "rb")

    def _read_file(self, entry):
        container = self._get_container(entry)

        if entry.get("_is_meta"):
            h = container["header"]
            full = container["logical_toc"]
            base = h["metadata_off"]
            start = base + entry["metadata_off"]
            end = start + entry["metadata_size"]
            limit = base + h["metadata_size"]

            if start < base or end > limit or end > len(full):
                raise RuntimeError(
                    f"{entry['full_path']}: metadata range outside logical TOC"
                )
            return bytes(full[start:end])

        self._ensure_blob_handles(container)

        data, _ = extract_file_bytes(
            container["logical_toc"],
            container["header"],
            entry,
            container["blob_handles"],
        )
        return data

    def _converted_export_path(self, destination, entry, data=None):
        rel = Path(entry["full_path"].replace("\\", "/"))
        name_lower = entry["name"].lower()
        if rel.suffix.lower() == ".tex":
            rel = rel.with_suffix(".png")
        elif rel.suffix.lower() == ".wem":
            rel = rel.with_suffix(".wav") # was .mp3
        elif rel.suffix.lower() == ".bin" and data is not None and _is_string_table_binary(data):
            # String-table binaries are exported as their human-readable .txt form.
            rel = rel.with_suffix(".txt")
        return safe_output_path(destination, str(rel).replace("\\", "/"))

    def _convert_for_export(self, entry, data, output_path):
        suffix = Path(entry["name"]).suffix.lower()
        name_lower = entry["name"].lower()
        if suffix == ".tex":
            if DDS_DECODER is None:
                raise RuntimeError(f"DDS decoder unavailable: {DDS_DECODER_ERROR}")
            image = DDS_DECODER(data)
            image.save(output_path, "PNG")
            return True
        if suffix == ".bin":
            rows = _decode_simple_string_table(data) or _decode_rmdl_string_table(data)
            if rows is not None:
                with open(output_path, "w", encoding="utf-8", newline="\n") as f:
                    for key, value in rows:
                        f.write(f"{key}\t{value}\n")
                return True
        if suffix == ".wem":
            vgmstream = self._find_vgmstream()
            if vgmstream is None:
                raise RuntimeError("Portable vgmstream-cli was not found beside the GUI.")
            with tempfile.TemporaryDirectory(prefix="control_wem_export_") as td:
                td = Path(td)
                wem = td / entry["name"].split("/")[-1]
                wem.write_bytes(data)
                r = subprocess.run(
                    [str(vgmstream), "-o", str(output_path), str(wem)],
                    cwd=str(vgmstream.parent),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if r.returncode != 0 or not output_path.is_file():
                    raise RuntimeError((r.stderr or r.stdout or "vgmstream failed").strip())
            return True
        return False

    def _find_ffmpeg(self):
        candidates = [_APP_DIR / "ffmpeg.exe", _APP_DIR / "ffmpeg"]
        for sub in ("ffmpeg", "tools"):
            candidates += [_APP_DIR / sub / "ffmpeg.exe", _APP_DIR / sub / "ffmpeg"]
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        found = shutil.which("ffmpeg")
        return Path(found) if found else None

    def _export_entries(self, entries):
        if not entries:
            messagebox.showinfo(
                "Export",
                "No files are marked for export.",
            )
            return

        destination = filedialog.askdirectory(
            title="Select export destination"
        )
        if not destination:
            return

        destination = Path(destination)

        try:
            exported = 0
            failed = []

            for entry in entries:
                try:
                    container = self._get_container(entry)

                    if entry.get("_is_meta"):
                        h = container["header"]
                        full = container["logical_toc"]
                        meta_base = h["metadata_off"]
                        meta_start = meta_base + entry["metadata_off"]
                        meta_end = meta_start + entry["metadata_size"]
                        meta_limit = meta_base + h["metadata_size"]
                        if meta_start < meta_base or meta_end > meta_limit or meta_end > len(full):
                            raise RuntimeError(
                                f"{entry['full_path']}: metadata range outside logical TOC"
                            )
                        data = bytes(full[meta_start:meta_end])
                    else:
                        self._ensure_blob_handles(container)
                        data, _ = extract_file_bytes(
                            container["logical_toc"],
                            container["header"],
                            entry,
                            container["blob_handles"],
                        )

                    output_path = self._converted_export_path(destination, entry, data)
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    converted = self._convert_for_export(entry, data, output_path)
                    if not converted:
                        output_path.write_bytes(data)

                    meta_size = entry["metadata_size"]
                    if meta_size and not entry.get("_is_meta"):
                        h = container["header"]
                        full = container["logical_toc"]
                        meta_base = h["metadata_off"]
                        meta_start = meta_base + entry["metadata_off"]
                        meta_end = meta_start + meta_size

                        if (
                            meta_start < meta_base
                            or meta_end > (
                                meta_base + h["metadata_size"]
                            )
                        ):
                            raise RuntimeError(
                                f"{entry['full_path']}: metadata range "
                                "outside metadata table"
                            )

                        if meta_end > len(full):
                            raise RuntimeError(
                                f"{entry['full_path']}: metadata range "
                                "outside logical TOC"
                            )

                        metadata = full[meta_start:meta_end]
                        Path(
                            str(output_path) + ".meta"
                        ).write_bytes(metadata)

                    exported += 1

                except Exception as exc:
                    failed.append(
                        f"{entry['full_path']}: {exc}"
                    )

            message = f"Exported {exported} file(s)."
            if failed:
                message += (
                    f"\n\nFailed: {len(failed)}\n\n"
                    + "\n".join(failed[:20])
                )

            messagebox.showinfo("Export", message)

        except Exception as exc:
            messagebox.showerror(
                "Export error",
                str(exc),
            )

    def _export_selected_files(self):
        entries = [entry for entry in self.files if id(entry) in self._export_marked_entries]
        self._export_entries(entries)

    def _export_selected_folders(self):
        real_folders = []
        synthetic_groups = []

        for item, checked in self.export_checked.items():
            if not checked:
                continue
            if item in self.tree_synthetic_groups:
                synthetic_groups.append(item)
            elif item in self.tree_folder_paths:
                real_folders.append(self.tree_folder_paths[item])

        if not real_folders and not synthetic_groups:
            messagebox.showinfo(
                "Export",
                "No folder is marked for export.",
            )
            return

        selected = []
        seen = set()

        def add_entry(entry):
            key = (entry.get("_container"), entry.get("index"), bool(entry.get("_is_meta")))
            if key not in seen:
                seen.add(key)
                selected.append(entry)

        for item in synthetic_groups:
            for entry in self.tree_synthetic_groups.get(item, []):
                add_entry(entry)

        for entry in self.files:
            path = entry["path"].replace("\\", "/").strip("/")
            for folder in real_folders:
                folder = folder.replace("\\", "/").strip("/")
                if not folder or path == folder or path.startswith(folder + "/"):
                    add_entry(entry)
                    break

        self._export_entries(selected)

    # ------------------------------------------------------------------
    # Menu dialogs
    # ------------------------------------------------------------------

    def _show_settings(self):
        win = tk.Toplevel(self)
        win.title("Settings")
        win.transient(self)
        win.resizable(False, False)
        win.grab_set()

        outer = ttk.Frame(win, padding=14)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="Theme").grid(row=0, column=0, sticky="w", padx=(0, 18), pady=(0, 10))
        theme_var = tk.StringVar(value=self.theme_var.get())
        theme_box = ttk.Combobox(outer, textvariable=theme_var, values=("light", "dark"), state="readonly", width=18)
        theme_box.grid(row=0, column=1, sticky="ew", pady=(0, 10))

        ttk.Label(outer, text="File type").grid(row=1, column=0, sticky="w", padx=(0, 18), pady=(0, 10))
        filetype_var = tk.StringVar(value=self.filetype_var.get())
        filetype_box = ttk.Combobox(
            outer, textvariable=filetype_var,
            values=("Images", "3D Models", "Text", "All"),
            state="readonly", width=18,
        )
        filetype_box.grid(row=1, column=1, sticky="ew", pady=(0, 10))

        ttk.Separator(outer, orient="horizontal").grid(row=2, column=0, columnspan=2, sticky="ew", pady=(2, 12))

        cache_label = ttk.Label(outer, text=self._cache_description(), justify="left", anchor="w")
        cache_label.grid(row=3, column=0, columnspan=2, sticky="w", pady=(0, 8))

        rebuild = ttk.Button(outer, text="Rebuild cache", command=lambda: self._confirm_rebuild_cache(win, cache_label))
        rebuild.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(0, 10))

        buttons = ttk.Frame(outer)
        buttons.grid(row=5, column=0, columnspan=2, sticky="e")
        ttk.Button(buttons, text="Close", command=win.destroy).pack(side="right")

        def apply_settings(*_args):
            self.theme_var.set(theme_var.get())
            self.filetype_var.set(filetype_var.get())
            self.settings["theme"] = self.theme_var.get()
            self.settings["filetype"] = self.filetype_var.get()
            self._apply_theme(self.theme_var.get())
            self._save_config()
            self._on_filetype_changed()
            cache_label.configure(text=self._cache_description())

        theme_box.bind("<<ComboboxSelected>>", apply_settings)
        filetype_box.bind("<<ComboboxSelected>>", apply_settings)
        win.protocol("WM_DELETE_WINDOW", win.destroy)
        win.update_idletasks()
        x = self.winfo_rootx() + max(0, (self.winfo_width() - win.winfo_width()) // 2)
        y = self.winfo_rooty() + max(0, (self.winfo_height() - win.winfo_height()) // 2)
        win.geometry(f"+{x}+{y}")

    def _cache_description(self):
        path = self._cache_path(self.install_dir) if self.install_dir is not None else _CONFIG_PATH.with_name(".control_resonant_asset_index.cache")
        if not path.is_file():
            return f"Cache file: {path.name}\nStatus: no cache file exists."
        try:
            stat = path.stat()
            age = max(0, time.time() - stat.st_mtime)
            if age < 60:
                age_text = f"{age:.0f} seconds ago"
            elif age < 3600:
                age_text = f"{age / 60:.1f} minutes ago"
            elif age < 86400:
                age_text = f"{age / 3600:.1f} hours ago"
            else:
                age_text = f"{age / 86400:.1f} days ago"
            return (
                f"Cache file: {path.name}\n"
                f"Size: {self._format_size(stat.st_size)}\n"
                f"Age: {age_text}"
            )
        except OSError:
            return f"Cache file: {path.name}\nStatus: unavailable."

    def _confirm_rebuild_cache(self, settings_window=None, cache_label=None):
        path = _APP_DIR / ".control_resonant_asset_index.cache"
        if path.is_file():
            try:
                stat = path.stat()
                age = max(0, time.time() - stat.st_mtime)
                if age < 3600:
                    age_text = f"{age / 60:.1f} minutes old"
                elif age < 86400:
                    age_text = f"{age / 3600:.1f} hours old"
                else:
                    age_text = f"{age / 86400:.1f} days old"
                details = (
                    f"{path.name}\n"
                    f"Size: {self._format_size(stat.st_size)}\n"
                    f"Age: {age_text}\n\n"
                    "Rebuilding the cache will delete this file and rescan/reindex "
                    "the selected game installation."
                )
            except OSError:
                details = f"{path.name}\n\nThe cache will be deleted and rebuilt."
        else:
            details = (
                f"{path.name}\n\n"
                "No cache file currently exists. A new cache will be built."
            )

        parent = settings_window if settings_window is not None else self
        answer = messagebox.askyesno("Rebuild cache", details, parent=parent)
        if not answer:
            return

        try:
            if path.is_file():
                path.unlink()
        except OSError as exc:
            messagebox.showerror("Rebuild cache", f"Could not delete {path.name}:\n{exc}", parent=parent)
            return

        if cache_label is not None:
            cache_label.configure(text=f"Cache file: {path.name}\nStatus: rebuilding…")

        target = self.install_dir
        if target is None or not target.is_dir() or not any(target.rglob("*.rmdtoc")):
            last = str(self.settings.get("last_game_path", "")).strip()
            candidate = Path(last).expanduser() if last else None
            if candidate is not None and candidate.is_dir() and any(candidate.rglob("*.rmdtoc")):
                target = candidate
        if target is not None and target.is_dir():
            if settings_window is not None:
                settings_window.grab_release()
                settings_window.destroy()
            self._load_installation(target)

    def _show_about(self):
        messagebox.showinfo("About", "0x52", parent=self)

    # ------------------------------------------------------------------
    # Utility / shutdown
    # ------------------------------------------------------------------

    @staticmethod
    def _format_size(size):
        if size < 1024:
            return f"{size} B"

        if size < 1024 * 1024:
            return f"{size / 1024:.1f} KiB"

        if size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MiB"

        return f"{size / (1024 * 1024 * 1024):.2f} GiB"

    def _close_blobs(self):
        for container in getattr(self, "containers", []):
            for fh in container.get("blob_handles", {}).values():
                try:
                    fh.close()
                except Exception:
                    pass
            container.get("blob_handles", {}).clear()

    def _on_close(self):
        self._load_generation += 1
        self._loading = False
        self._stop_audio()
        if self._audio_temp_dir is not None:
            try:
                self._audio_temp_dir.cleanup()
            except Exception:
                pass
            self._audio_temp_dir = None
        self._close_blobs()
        self.destroy()


def main():
    app = ControlAssetBrowser()
    app.mainloop()


if __name__ == "__main__":
    main()
