#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
import sys
import os
import tempfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

import lz4.block


DESCRIPTOR = 0x10
ARCHIVE = 0x18
PATH = 0x1C
FILE = 0x20
CHUNK = 0x10

MAGIC = b"COTR"
SUPPORTED_VERSION = 3


class SemanticError(Exception):
    pass


@dataclass
class CheckStats:
    total: int = 0
    passed: int = 0
    failed: int = 0
    groups: dict[str, dict[str, int]] = field(default_factory=dict)
    current_group: str = "Unclassified"

    def set_group(self, name: str):
        self.current_group = name
        self.groups.setdefault(name, {"total": 0, "passed": 0, "failed": 0})

    def ok(self, condition: bool, message: str = ""):
        group = self.groups.setdefault(
            self.current_group, {"total": 0, "passed": 0, "failed": 0}
        )
        self.total += 1
        group["total"] += 1
        if condition:
            self.passed += 1
            group["passed"] += 1
            return
        self.failed += 1
        group["failed"] += 1
        raise SemanticError(message or "semantic check failed")


def u32(b, p):
    return struct.unpack_from("<I", b, p)[0]


def u64(b, p):
    return struct.unpack_from("<Q", b, p)[0]


def u40(b, p):
    return int.from_bytes(b[p:p + 5], "little")


def span(b, p, n):
    if not (0 <= p <= len(b) and 0 <= n <= len(b) - p):
        raise SemanticError(f"out-of-range span: 0x{p:x}+0x{n:x}")
    return b[p:p + n]


def table(b, off, count, size):
    if off > len(b):
        raise SemanticError(f"table offset outside logical TOC: 0x{off:x}")
    end = off + count * size
    if end > len(b):
        raise SemanticError(
            f"table exceeds logical TOC: 0x{off:x}+0x{count * size:x}"
        )
    return end


def string(logical, strings_off, strings_size, off, size):
    if off > strings_size or size > strings_size - off:
        raise SemanticError(
            f"string range outside pool: off=0x{off:x} size=0x{size:x}"
        )
    raw = span(logical, strings_off + off, size)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise SemanticError(f"invalid UTF-8 in string pool: {e}") from e


def _merge(ranges):
    out = []
    for a, b in sorted(ranges):
        if not (0 <= a <= b):
            raise SemanticError(f"invalid range 0x{a:x}..0x{b:x}")
        if out and a <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def _assert_partition(intervals, begin, end, label):
    """Require sorted half-open intervals to partition [begin,end)."""
    pos = begin
    for a, b, what in sorted(intervals):
        if a != pos:
            raise SemanticError(
                f"{label} has gap/overlap before {what}: "
                f"expected 0x{pos:x}, got 0x{a:x}"
            )
        if b < a or b > end:
            raise SemanticError(
                f"{label} range outside [0x{begin:x},0x{end:x}): "
                f"{what}=0x{a:x}..0x{b:x}"
            )
        pos = b
    if pos != end:
        raise SemanticError(
            f"{label} does not cover through 0x{end:x}; stopped at 0x{pos:x}"
        )


def decode_toc(path: Path):
    toc = path.read_bytes()
    stats = CheckStats()

    stats.set_group("COTR header")
    stats.ok(len(toc) >= 0x58, "TOC shorter than 0x58-byte header")
    stats.ok(toc[0:4] == MAGIC, f"bad magic: {toc[0:4]!r}")

    version = u32(toc, 0x04)
    stats.ok(
        version == SUPPORTED_VERSION,
        f"unsupported COTR version {version}",
    )

    descriptor_off = u32(toc, 0x08)
    descriptor_size = u32(toc, 0x0C)
    logical_archive_off = u32(toc, 0x10)
    archive_count = u32(toc, 0x14)
    path_off = u32(toc, 0x18)
    path_count = u32(toc, 0x1C)
    file_off = u32(toc, 0x20)
    file_count = u32(toc, 0x24)
    strings_off = u32(toc, 0x28)
    strings_size = u32(toc, 0x2C)
    metadata_type_off = u32(toc, 0x30)
    metadata_type_count = u32(toc, 0x34)
    metadata_off = u32(toc, 0x38)
    metadata_size = u32(toc, 0x3C)
    chunk_off = u32(toc, 0x50)
    chunk_size = u32(toc, 0x54)

    stats.ok(descriptor_off == 0x58, "descriptor table does not start at 0x58")
    stats.ok(descriptor_size % DESCRIPTOR == 0, "descriptor size is not 0x10-aligned")
    stats.ok(descriptor_off + descriptor_size <= len(toc), "descriptor table exceeds physical TOC")
    stats.ok(logical_archive_off == 0, "logical archive table does not start at 0")
    stats.ok(
        all(x == 0 for x in toc[0x40:0x50]),
        "header reserved bytes 0x40..0x4f are not zero",
    )

    descriptors = descriptor_size // DESCRIPTOR
    logical = bytearray()
    descriptor_info = []

    stats.set_group("Descriptor reconstruction")
    physical_payload_ranges = []
    for i in range(descriptors):
        p = descriptor_off + i * DESCRIPTOR
        misc = span(toc, p, 3)
        data_off = u40(toc, p + 3)
        decomp = u32(toc, p + 8)
        comp = u32(toc, p + 0xC)
        stored = comp or decomp

        stats.ok(
            data_off >= descriptor_off + descriptor_size,
            f"descriptor {i}: payload starts inside descriptor table",
        )
        stats.ok(
            data_off + stored <= len(toc),
            f"descriptor {i}: physical payload exceeds TOC",
        )

        stats.ok(
            misc == b"\x10\x00\x00",
            f"descriptor {i}: unexpected 3-byte format field {misc.hex()}",
        )

        raw = span(toc, data_off, stored)
        if comp:
            raw = lz4.block.decompress(raw, uncompressed_size=decomp)

        stats.ok(
            len(raw) == decomp,
            f"descriptor {i}: decompressed size mismatch",
        )

        logical += raw
        physical_payload_ranges.append((data_off, data_off + stored))
        descriptor_info.append(
            {
                "misc": misc,
                "data_off": data_off,
                "decomp": decomp,
                "comp": comp,
                "stored": stored,
            }
        )

    # Descriptor payloads are independent physical regions.
    sorted_payloads = sorted(
        (a, b, i) for i, (a, b) in enumerate(physical_payload_ranges)
    )
    for left, right in zip(sorted_payloads, sorted_payloads[1:]):
        stats.ok(
            left[1] <= right[0],
            f"descriptor payloads overlap: {left[2]} and {right[2]}",
        )

    logical = bytes(logical)

    stats.set_group("Logical section layout")
    archive_end = table(logical, 0, archive_count, ARCHIVE)
    path_end = table(logical, path_off, path_count, PATH)
    file_end = table(logical, file_off, file_count, FILE)
    stats.ok(chunk_size % CHUNK == 0, "chunk_size is not 0x10-aligned")
    chunk_count = chunk_size // CHUNK
    chunk_end = table(logical, chunk_off, chunk_count, CHUNK)

    stats.ok(strings_off + strings_size <= len(logical), "string pool exceeds logical TOC")
    stats.ok(
        metadata_type_off + metadata_type_count * 8 <= len(logical),
        "metadata-type table exceeds logical TOC",
    )
    stats.ok(
        metadata_off + metadata_size <= len(logical),
        "metadata pool exceeds logical TOC",
    )

    # The logical sections form one ordered TOC layout, with only zero padding
    # allowed between sections. 
    sections = [
        ("archive", 0, archive_end),
        ("path", path_off, path_end),
        ("file", file_off, file_end),
        ("strings", strings_off, strings_off + strings_size),
        ("metadata_type", metadata_type_off,
         metadata_type_off + metadata_type_count * 8),
        ("metadata", metadata_off, metadata_off + metadata_size),
        ("chunk", chunk_off, chunk_end),
    ]
    for (n1, a1, b1), (n2, a2, b2) in zip(sections, sections[1:]):
        stats.ok(
            b1 <= a2,
            f"logical sections overlap: {n1} and {n2}",
        )
        if b1 < a2:
            gap = logical[b1:a2]
            stats.ok(
                not any(gap),
                f"non-zero logical alignment padding between {n1} and {n2}",
            )

    stats.ok(
        chunk_end == len(logical),
        f"chunk table does not terminate logical TOC: 0x{chunk_end:x} != 0x{len(logical):x}",
    )

    stats.set_group("Archive records")
    archives = []
    for i in range(archive_count):
        p = i * ARCHIVE
        name_off = u32(logical, p)
        name_size = u32(logical, p + 4)
        name = string(logical, strings_off, strings_size, name_off, name_size)
        identity = span(logical, p + 8, 8)
        blob_size = u64(logical, p + 0x10)

        stats.ok(blob_size >= 16, f"archive {i}: impossible BLOB size {blob_size}")
        archives.append((name, identity, blob_size))

    stats.set_group("Path records and tree")
    paths = []
    for i in range(path_count):
        p = path_off + i * PATH
        parent = u32(logical, p)
        first_child = u32(logical, p + 4)
        child_count = u32(logical, p + 8)
        first_file = u32(logical, p + 0xC)
        file_count_i = u32(logical, p + 0x10)
        name_off = u32(logical, p + 0x14)
        name_size = u32(logical, p + 0x18)
        name = string(logical, strings_off, strings_size, name_off, name_size)

        stats.ok(
            parent == 0xFFFFFFFF or parent < path_count,
            f"path {i}: invalid parent {parent}",
        )
        stats.ok(
            first_child + child_count <= path_count,
            f"path {i}: child range exceeds path table",
        )
        stats.ok(
            first_file + file_count_i <= file_count,
            f"path {i}: file range exceeds file table",
        )
        paths.append(
            (
                parent,
                first_child,
                child_count,
                first_file,
                file_count_i,
                name,
            )
        )

    # Exactly one root; all child ranges agree with parent links.
    roots = [i for i, p in enumerate(paths) if p[0] == 0xFFFFFFFF or p[0] == i]
    stats.ok(len(roots) == 1, f"expected one root path, found {len(roots)}")

    child_seen = [0] * path_count
    for i, p in enumerate(paths):
        first_child, child_count = p[1], p[2]
        for child in range(first_child, first_child + child_count):
            child_seen[child] += 1
            stats.ok(
                paths[child][0] == i,
                f"path {child}: parent field disagrees with child range of {i}",
            )

    for i, p in enumerate(paths):
        if i == roots[0]:
            continue
        stats.ok(
            child_seen[i] == 1,
            f"path {i}: expected exactly one parent range, got {child_seen[i]}",
        )

    stats.set_group("File records")
    files = []
    for i in range(file_count):
        p = file_off + i * FILE
        chunk_rel = u32(logical, p)
        chunk_bytes = u32(logical, p + 4)
        path_index = u32(logical, p + 8)
        name_off = u32(logical, p + 0xC)
        name_size = u32(logical, p + 0x10)
        total_size = u32(logical, p + 0x14)
        meta_rel = u32(logical, p + 0x18)
        meta_size = u32(logical, p + 0x1C)

        stats.ok(path_index < path_count, f"file {i}: invalid path index")
        stats.ok(chunk_bytes % CHUNK == 0, f"file {i}: chunk byte count not 0x10-aligned")
        stats.ok(
            chunk_rel + chunk_bytes <= chunk_size,
            f"file {i}: chunk range exceeds chunk table",
        )
        stats.ok(
            meta_rel <= metadata_size and meta_size <= metadata_size - meta_rel,
            f"file {i}: metadata range exceeds metadata pool",
        )

        name = string(logical, strings_off, strings_size, name_off, name_size)
        path_name = paths[path_index][5]
        full_name = f"{path_name}/{name}" if path_name else name

        files.append(
            {
                "index": i,
                "path_index": path_index,
                "path": path_name,
                "name": name,
                "full_name": full_name,
                "chunk_rel": chunk_rel,
                "chunk_bytes": chunk_bytes,
                "total_size": total_size,
                "meta_rel": meta_rel,
                "meta_size": meta_size,
            }
        )

    stats.set_group("Chunk-range partition")
    # File chunk ranges must partition the entire chunk table.
    chunk_ranges = []
    for f in files:
        chunk_ranges.append(
            (
                f["chunk_rel"],
                f["chunk_rel"] + f["chunk_bytes"],
                f"file {f['index']}",
            )
        )
    _assert_partition(chunk_ranges, 0, chunk_size, "file chunk ranges")
    stats.ok(True, "file chunk ranges partition the entire chunk table")

    stats.set_group("Path-range partition")
    # Path file ranges must partition the entire file table.
    file_ranges = [
        (
            p[3],
            p[3] + p[4],
            f"path {i}",
        )
        for i, p in enumerate(paths)
        if p[4]
    ]
    _assert_partition(file_ranges, 0, file_count, "path file ranges")
    stats.ok(True, "path file ranges partition the entire file table")

    stats.set_group("Path/file cross-reference")
    # Cross-check that every file record agrees with the path range that owns it.
    # This is still TOC-local validation: no BLOB reads or extraction required.
    for path_index, p in enumerate(paths):
        first_file, file_count_i = p[3], p[4]
        for file_index in range(first_file, first_file + file_count_i):
            stats.ok(
                files[file_index]["path_index"] == path_index,
                f"file {file_index}: path index {files[file_index]['path_index']} "
                f"disagrees with containing path {path_index}",
            )

    stats.set_group("Metadata-type table")
    # Metadata type entries: offsets are relative to metadata_type_off.
    # They address serialized type descriptions in logical TOC space.
    metadata_types = []
    for i in range(metadata_type_count):
        p = metadata_type_off + i * 8
        rel_off = u32(logical, p)
        size = u32(logical, p + 4)
        absolute = metadata_type_off + rel_off
        stats.ok(
            absolute + size <= len(logical),
            f"metadata type {i}: type-description range exceeds logical TOC",
        )
        stats.ok(size > 0, f"metadata type {i}: zero-sized type description")
        metadata_types.append((absolute, size))

    stats.set_group("DMKP metadata records")
    # Metadata instances: every metadata-bearing file has exactly one DMKP
    # record occupying its complete metadata range.
    metadata_magic_count = 0
    metadata_versions = {}
    for f in files:
        if not f["meta_size"]:
            continue

        metadata_magic_count += 1
        start = metadata_off + f["meta_rel"]
        raw = span(logical, start, f["meta_size"])

        stats.ok(
            raw[:4] == b"DMKP",
            f"file {f['index']} ({f['full_name']}): metadata is not DMKP",
        )

        version = u32(raw, 4)
        stats.ok(
            version in (3, 4),
            f"file {f['index']} ({f['full_name']}): unsupported DMKP version {version}",
        )
        metadata_versions[version] = metadata_versions.get(version, 0) + 1

    stats.set_group("Chunk semantics and file-size")
    # Chunk semantics and file-size invariant.
    chunk_count_by_file = 0
    compressed_chunks = 0
    stored_chunks = 0
    total_decomp = 0
    for f in files:
        base = chunk_off + f["chunk_rel"]
        count = f["chunk_bytes"] // CHUNK
        chunk_count_by_file += count

        file_sum = 0
        for j in range(count):
            p = base + j * CHUNK
            flags = logical[p]
            archive = logical[p + 1]
            reserved = logical[p + 2]
            blob_off = u40(logical, p + 3)
            decomp = u32(logical, p + 8)
            comp = u32(logical, p + 0xC)

            stats.ok(
                reserved == 0,
                f"file {f['index']}: chunk {j} reserved byte is non-zero",
            )
            stats.ok(
                archive < archive_count,
                f"file {f['index']}: chunk {j} archive index out of range",
            )
            stats.ok(
                (flags == 0x10) == (comp != 0),
                f"file {f['index']}: chunk {j} compression flag mismatch",
            )

            file_sum += decomp
            total_decomp += decomp
            if comp:
                compressed_chunks += 1
            else:
                stored_chunks += 1

            # The 40-bit offset is unsigned by construction; 
            _ = blob_off

        stats.ok(
            file_sum == f["total_size"],
            f"file {f['index']}: chunk decomp sum != total_size",
        )

    stats.ok(
        chunk_count_by_file == chunk_count,
        "file chunk ranges do not account for every chunk record",
    )

    return {
        "path": path,
        "toc": toc,
        "logical": logical,
        "archives": archives,
        "paths": paths,
        "files": files,
        "chunk_off": chunk_off,
        "chunk_size": chunk_size,
        "metadata_off": metadata_off,
        "metadata_size": metadata_size,
        "metadata_type_off": metadata_type_off,
        "metadata_type_count": metadata_type_count,
        "metadata_types": metadata_types,
        "physical_descriptor_count": descriptors,
        "physical_misc": [x["misc"] for x in descriptor_info],
        "descriptor_info": descriptor_info,
        "semantic_checks": stats,
        "semantic_groups": stats.groups,
        "metadata_magic_count": metadata_magic_count,
        "metadata_versions": metadata_versions,
        "compressed_chunks": compressed_chunks,
        "stored_chunks": stored_chunks,
        "chunk_count": chunk_count,
        "total_decomp": total_decomp,
    }


def extension(name):
    return ("." + name.rsplit(".", 1)[1].lower()) if "." in name else "<no extension>"


def discover(root):
    if root.is_file():
        if root.suffix.lower() != ".rmdtoc":
            raise ValueError(f"not an .rmdtoc file: {root}")
        return [root]
    if not root.is_dir():
        raise ValueError(f"not a file or directory: {root}")
    return sorted(root.rglob("*.rmdtoc"))


def locate_blob(toc_path: Path, archive_name: str) -> Path | None:
    candidate = (toc_path.parent / archive_name).resolve()
    return candidate if candidate.is_file() else None


def resolve_blobs(model):
    handles = {}

    for i, (rel, identity, expected_size) in enumerate(model["archives"]):
        blob = locate_blob(model["path"], rel)
        if blob is None:
            raise SemanticError(f"archive {i}: missing blob {rel}")
        if blob.stat().st_size != expected_size:
            raise SemanticError(
                f"archive {i}: BLOB size {blob.stat().st_size} != {expected_size}"
            )

        with blob.open("rb") as f:
            header = f.read(16)
        if len(header) != 16:
            raise SemanticError(f"archive {i}: BLOB header shorter than 16 bytes")
        if header[8:16] != identity:
            raise SemanticError(f"archive {i}: BLOB identity mismatch")
        handles[i] = blob

    return handles


def chunks(model, f):
    base = model["chunk_off"] + f["chunk_rel"]
    count = f["chunk_bytes"] // CHUNK

    for i in range(count):
        p = base + i * CHUNK
        flags = model["logical"][p]
        archive = model["logical"][p + 1]
        reserved = model["logical"][p + 2]
        blob_off = u40(model["logical"], p + 3)
        decomp = u32(model["logical"], p + 8)
        comp = u32(model["logical"], p + 0xC)
        stored = comp or decomp

        if reserved != 0:
            raise SemanticError("chunk reserved byte is non-zero")
        if archive >= len(model["archives"]):
            raise SemanticError("chunk archive index out of range")
        if (flags == 0x10) != (comp != 0):
            raise SemanticError("chunk compression flag mismatch")

        yield archive, blob_off, stored, decomp, comp


def metadata_root_crc32(model, f):
    """Return (resource size, CRC32); CRC32 is None when the file has no metadata."""
    expected_size = f["total_size"]
    if not f["meta_size"]:
        # Empty metadata ranges are valid in this corpus. These resources have
        # no DMKP root, so size can be checked but a metadata CRC cannot.
        return expected_size, None

    meta = span(
        model["logical"],
        model["metadata_off"] + f["meta_rel"],
        f["meta_size"],
    )
    needle = struct.pack("<III", 1, expected_size, 0)
    hits = []
    pos = 0
    while True:
        pos = meta.find(needle, pos)
        if pos < 0:
            break
        if pos + 16 <= len(meta):
            hits.append(u32(meta, pos + 12))
        pos += 1

    if len(hits) != 1:
        raise SemanticError(
            f"file {f['index']} ({f['full_name']}): expected exactly one DMKP "
            f"root header for size {expected_size}, found {len(hits)}"
        )

    return expected_size, hits[0]


def extract_file(model, f, blobs, output):
    output.parent.mkdir(parents=True, exist_ok=True)

    expected_size, expected_crc32 = metadata_root_crc32(model, f)
    tmp_path = None
    written = 0
    crc32 = 0

    try:
        # Never publish a file before its size and any available metadata CRC32 pass.
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=output.parent, prefix=f".{output.name}.", suffix=".tmp", delete=False
        ) as out:
            tmp_path = Path(out.name)

            for archive, blob_off, stored, decomp, comp in chunks(model, f):
                blob = blobs[archive]

                with blob.open("rb") as src:
                    src.seek(blob_off)
                    raw = src.read(stored)

                if len(raw) != stored:
                    raise SemanticError(
                        f"short BLOB read at 0x{blob_off:x}: "
                        f"{len(raw)} != {stored}"
                    )

                if comp:
                    raw = lz4.block.decompress(raw, uncompressed_size=decomp)

                if len(raw) != decomp:
                    raise SemanticError("decompressed chunk size mismatch")

                out.write(raw)
                written += len(raw)
                crc32 = zlib.crc32(raw, crc32) & 0xFFFFFFFF

            out.flush()
            os.fsync(out.fileno())

        if written != expected_size:
            raise SemanticError(
                f"extracted size {written} != expected size {expected_size}"
            )

        if expected_crc32 is not None and crc32 != expected_crc32:
            raise SemanticError(
                f"CRC32 mismatch for {f['full_name']}: "
                f"expected 0x{expected_crc32:08x}, got 0x{crc32:08x}"
            )

        # Re-open the exact file that will be published and validate it again.
        # This verifies the staged on-disk artifact, not just the streaming state.
        with tmp_path.open("rb") as check:
            actual_size = 0
            actual_crc32 = 0
            while True:
                block = check.read(1024 * 1024)
                if not block:
                    break
                actual_size += len(block)
                actual_crc32 = zlib.crc32(block, actual_crc32) & 0xFFFFFFFF

        if actual_size != expected_size:
            raise SemanticError(
                f"final extracted size {actual_size} != expected size {expected_size}"
            )
        if expected_crc32 is not None and actual_crc32 != expected_crc32:
            raise SemanticError(
                f"final extracted CRC32 mismatch for {f['full_name']}: "
                f"expected 0x{expected_crc32:08x}, got 0x{actual_crc32:08x}"
            )

        os.replace(tmp_path, output)
        tmp_path = None

        if f["meta_size"]:
            meta = span(
                model["logical"],
                model["metadata_off"] + f["meta_rel"],
                f["meta_size"],
            )
            output.with_name(output.name + ".meta").write_bytes(meta)

    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass


def safe_output(root, name):
    p = Path(name)
    if p.is_absolute() or ".." in p.parts or any(part in ("", ".") for part in p.parts):
        raise ValueError(f"unsafe output path: {name}")
    return root.joinpath(*p.parts)


def physical_byte_accounting(model):
    """
    Account for every physical .rmdtoc byte.

    Categories:
      structural  = header + descriptor records + descriptor payloads
      zero_gap    = unreferenced zero bytes
      nonzero_gap = unreferenced non-zero physical bytes

    The latter are physical storage gaps/padding. They are NOT silently
    called semantic TOC data.
    """
    toc = model["toc"]
    ranges = [(0, 0x58)]

    for i, d in enumerate(model["descriptor_info"]):
        p = 0x58 + i * DESCRIPTOR
        ranges.append((p, p + DESCRIPTOR))
        ranges.append((d["data_off"], d["data_off"] + d["stored"]))

    merged = _merge(ranges)
    structural = sum(b - a for a, b in merged)

    zero_gap = 0
    nonzero_gap = 0
    pos = 0
    for a, b in merged:
        if pos < a:
            gap = toc[pos:a]
            zero_gap += gap.count(0)
            nonzero_gap += len(gap) - gap.count(0)
        pos = max(pos, b)
    if pos < len(toc):
        gap = toc[pos:]
        zero_gap += gap.count(0)
        nonzero_gap += len(gap) - gap.count(0)

    total = len(toc)
    accounted = structural + zero_gap + nonzero_gap
    if accounted != total:
        raise SemanticError(
            f"physical byte accounting failed: "
            f"{accounted} != {total}"
        )

    return {
        "total": total,
        "structural": structural,
        "zero_gap": zero_gap,
        "nonzero_gap": nonzero_gap,
    }


def logical_byte_accounting(model):
    """
    Account every logical TOC byte as one of the semantic sections or
    zero alignment padding between sections.
    """
    logical = model["logical"]
    toc = model["toc"]
    ranges = [
        ("archive", 0, u32(toc, 0x14) * ARCHIVE),
        ("path", u32(toc, 0x18), u32(toc, 0x18) + u32(toc, 0x1C) * PATH),
        ("file", u32(toc, 0x20), u32(toc, 0x20) + u32(toc, 0x24) * FILE),
        ("strings", u32(toc, 0x28), u32(toc, 0x28) + u32(toc, 0x2C)),
        ("metadata_type", u32(toc, 0x30),
         u32(toc, 0x30) + u32(toc, 0x34) * 8),
        ("metadata", u32(toc, 0x38),
         u32(toc, 0x38) + u32(toc, 0x3C)),
        ("chunk", u32(toc, 0x50),
         u32(toc, 0x50) + u32(toc, 0x54)),
    ]

    known = 0
    zero_padding = 0
    for _, a, z in ranges:
        known += z - a
    for (_, _, z1), (_, a2, _) in zip(ranges, ranges[1:]):
        if z1 < a2:
            gap = logical[z1:a2]
            zero_padding += len(gap)
            if any(gap):
                raise SemanticError("non-zero logical section padding")

    total = len(logical)
    accounted = known + zero_padding
    if accounted != total:
        raise SemanticError(
            f"logical byte accounting failed: {accounted} != {total}"
        )

    return total, known, zero_padding


def summarize(models):
    total_logical = sum(len(m["logical"]) for m in models)
    total_files = sum(len(m["files"]) for m in models)
    total_paths = sum(len(m["paths"]) for m in models)
    total_archives = sum(len(m["archives"]) for m in models)
    total_chunks = sum(m["chunk_count"] for m in models)
    total_types = sum(m["metadata_type_count"] for m in models)
    total_metadata = sum(m["metadata_size"] for m in models)

    type_counts = {}
    for m in models:
        for f in m["files"]:
            t = extension(f["name"])
            type_counts[t] = type_counts.get(t, 0) + 1

    physical = [physical_byte_accounting(m) for m in models]
    logical = [logical_byte_accounting(m) for m in models]

    semantic_total = sum(m["semantic_checks"].total for m in models)
    semantic_failed = sum(m["semantic_checks"].failed for m in models)
    semantic_passed = semantic_total - semantic_failed

    print("=" * 72)
    print("CONTROL RESONANT RMDTOC")
    print("=" * 72)
    print(f"TOC files     : {len(models):,}")
    print(f"Archives      : {total_archives:,}")
    print(f"Paths         : {total_paths:,}")
    print(f"Files         : {total_files:,}")
    print(f"Chunks        : {total_chunks:,}")
    print(f"Metadata types: {total_types:,}")
    print(f"Metadata      : {total_metadata:,} bytes")
    print(f"Logical data  : {total_logical:,} bytes")
    print()

    physical_total = sum(x["total"] for x in physical)
    physical_accounted = sum(
        x["structural"] + x["zero_gap"] + x["nonzero_gap"]
        for x in physical
    )
    physical_nonzero_gap = sum(x["nonzero_gap"] for x in physical)

    logical_total = sum(x[0] for x in logical)
    logical_accounted = sum(x[1] + x[2] for x in logical)

    print("BYTE ACCOUNTING")
    print(f"  Physical TOC : {100.0 * physical_accounted / physical_total:.6f}%")
    print(f"  Logical TOC  : {100.0 * logical_accounted / logical_total:.6f}%")
    print(f"  Physical gap : {physical_nonzero_gap:,} non-zero bytes")
    print(f"  Unaccounted  : {physical_total - physical_accounted:,} bytes")
    print()

    print("SEMANTIC CHECK")
    semantic_pct = (
        100.0 * semantic_passed / semantic_total
        if semantic_total else 100.0
    )
    print(f"  Checks       : {semantic_passed:,}/{semantic_total:,}")
    print(f"  Coverage     : {semantic_pct:.6f}%")
    print(f"  Failures     : {semantic_failed:,}")
    print()

    print("VALIDATION GROUPS")
    group_names = []
    for model in models:
        for name in model["semantic_groups"]:
            if name not in group_names:
                group_names.append(name)
    for name in group_names:
        total = sum(m["semantic_groups"].get(name, {}).get("total", 0) for m in models)
        passed = sum(m["semantic_groups"].get(name, {}).get("passed", 0) for m in models)
        failed = sum(m["semantic_groups"].get(name, {}).get("failed", 0) for m in models)
        print(f"  {name:32s}: {passed:,}/{total:,} passed; failures={failed:,}")
    print()

    print("METADATA")
    versions = {}
    for m in models:
        for version, count in m["metadata_versions"].items():
            versions[version] = versions.get(version, 0) + count
    print(f"  DMKP records : {sum(m['metadata_magic_count'] for m in models):,}")
    print(
        "  Versions     : "
        + ", ".join(f"v{k}={v:,}" for k, v in sorted(versions.items()))
    )

    print()
    print("CHUNKS")
    compressed = sum(m["compressed_chunks"] for m in models)
    stored = sum(m["stored_chunks"] for m in models)
    print(f"  LZ4          : {compressed:,}")
    print(f"  Stored/raw   : {stored:,}")

    print()
    print("FILE TYPES")
    for t, n in sorted(type_counts.items(), key=lambda x: (-x[1], x[0])):
        print(f"  {t:18s} {n:,}")

    if semantic_failed:
        print()
        print("STATUS       : FAIL")
    else:
        print()
        print("STATUS       : PASS")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Strict Control Resonant .rmdtoc/.rmdblob parser, semantic "
            "validator and unpacker."
        ),
        epilog="""examples:
  python3 script.py /path/to/CONTROLresonant
      Validate all .rmdtoc files and print byte/semantic statistics.

  python3 script.py --filetype wem,tex /path/to/CONTROLresonant
      Validate first, then extract selected files.

  python3 script.py --filetype all /path/to/CONTROLresonant
      Validate first, then extract every referenced file.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--filetype",
        help="Comma-separated types to extract, e.g. wem,tex; use all for everything.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="Output directory (default: <script directory>/output).",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Do not return exit code 1 when semantic validation fails.",
    )
    parser.add_argument("path", nargs="?", type=Path)

    args = parser.parse_args()

    if args.path is None:
        parser.print_help()
        return 0

    toc_paths = discover(args.path)
    if not toc_paths:
        raise SystemExit(f"no .rmdtoc files found under {args.path}")

    models = []
    failures = []

    for toc_path in toc_paths:
        try:
            models.append(decode_toc(toc_path))
        except (SemanticError, AssertionError, struct.error, lz4.block.LZ4BlockError) as e:
            failures.append((toc_path, str(e)))

    if failures:
        print("=" * 72)
        print("SEMANTIC VALIDATION FAILURES")
        print("=" * 72)
        for path, error in failures:
            print(f"{path}: {error}")
        if not args.no_fail:
            return 1

    if models:
        summarize(models)

    if failures and not args.no_fail:
        return 1

    if args.filetype is None:
        return 0

    requested = {x.strip().lower() for x in args.filetype.split(",") if x.strip()}
    if not requested:
        raise SystemExit("--filetype is empty")

    extract_all = "all" in requested
    if extract_all:
        requested = set()

    out_root = (
        args.out
        if args.out is not None
        else Path(__file__).resolve().parent / "output"
    )

    requested_extensions = {"." + x.lstrip(".") for x in requested}
    total_to_extract = sum(
        1
        for model in models
        for f in model["files"]
        if extract_all or extension(f["name"]) in requested_extensions
    )

    extracted = 0
    for model in models:
        blobs = resolve_blobs(model)
        for f in model["files"]:
            if not extract_all and extension(f["name"]) not in requested_extensions:
                continue

            output = safe_output(out_root, f["full_name"])
            extract_file(model, f, blobs, output)

            extracted += 1
            pct = extracted / total_to_extract * 100 if total_to_extract else 100.0
            print(
                f"\rExtracted {extracted}/{total_to_extract} ({pct:.0f}%)",
                end="",
                flush=True,
            )

    print()
    print(f"Extracted {extracted:,} files to {out_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
