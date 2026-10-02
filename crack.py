#!/usr/bin/env python3

from pathlib import Path
import struct
import argparse
import lz4.block
import re


def u8(buf, off):
    return buf[off]


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def u40(buf, off):
    return int.from_bytes(buf[off:off + 5], "little")


def parse_header(toc):
    return {
        "table_off":      u32(toc, 0x08),
        "table_size":     u32(toc, 0x0C),

        "archives_off":   u32(toc, 0x10),
        "archives_count": u32(toc, 0x14),

        "paths_off":      u32(toc, 0x18),
        "paths_count":    u32(toc, 0x1C),

        "files_off":      u32(toc, 0x20),
        "files_count":    u32(toc, 0x24),

        "strings_off":    u32(toc, 0x28),
        "strings_size":   u32(toc, 0x2C),

        "paths2_off":     u32(toc, 0x30),
        "paths2_count":   u32(toc, 0x34),

        "metadata_off":   u32(toc, 0x38),
        "metadata_size":  u32(toc, 0x3C),

        "chunks_off":     u32(toc, 0x50),
        "chunks_size":    u32(toc, 0x54),
    }


def reconstruct_logical_toc(toc, h):
    if h["table_size"] % 0x10:
        raise RuntimeError("Descriptor table size is not divisible by 0x10")

    full = bytearray()

    count = h["table_size"] // 0x10

    for i in range(count):
        p = h["table_off"] + i * 0x10

        data_off = u40(toc, p + 0x03)
        decomp   = u32(toc, p + 0x08)
        comp     = u32(toc, p + 0x0C)

        stored = comp if comp else decomp

        raw = toc[data_off:data_off + stored]

        if comp:
            raw = lz4.block.decompress(
                raw,
                uncompressed_size=decomp
            )

        if len(raw) != decomp:
            raise RuntimeError(
                f"TOC descriptor {i}: "
                f"expected 0x{decomp:X}, got 0x{len(raw):X}"
            )

        full += raw

    return full


def parse_paths(full, h):
    paths = {}

    base = h["paths_off"]
    count = h["paths_count"]
    strings = h["strings_off"]

    record_size = 0x1C

    if base + count * record_size > h["files_off"]:
        raise RuntimeError("Path table exceeds files section")

    for i in range(count):
        p = base + i * record_size

        string_off = u32(full, p + 0x14)
        string_len = u32(full, p + 0x18)

        raw = full[
            strings + string_off:
            strings + string_off + string_len
        ]

        paths[i] = raw.decode("utf-8", errors="replace")

    return paths


def read_string(full, h, off, size):
    start = h["strings_off"] + off
    end = start + size

    return full[start:end].decode(
        "utf-8",
        errors="replace"
    )


def parse_files(full, h, paths):
    files = []

    base = h["files_off"]
    count = h["files_count"]

    for i in range(count):
        p = base + i * 0x20

        (
            chunk_off,
            chunk_size,
            path_idx,
            string_off,
            string_size,
            total_size,
            metadata_off,
            metadata_size,
        ) = struct.unpack_from("<8I", full, p)

        name = read_string(
            full,
            h,
            string_off,
            string_size
        )

        path = paths.get(
            path_idx,
            f"<path_{path_idx}>"
        )

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

    if p + 0x10 > len(full):
        raise RuntimeError(
            f"Chunk outside logical TOC: 0x{p:X}"
        )

    flags = u8(full, p + 0x00)
    archive = u8(full, p + 0x01)
    blob_off = u40(full, p + 0x03)
    decomp = u32(full, p + 0x08)
    comp = u32(full, p + 0x0C)

    stored = comp if comp else decomp

    return {
        "toc_off": p,
        "flags": flags,
        "archive": archive,
        "blob_off": blob_off,
        "decomp": decomp,
        "comp": comp,
        "stored": stored,
    }


def get_file_chunks(full, h, file_entry):
    chunk_off = file_entry["chunk_off"]
    chunk_size = file_entry["chunk_size"]

    if chunk_size % 0x10:
        raise RuntimeError(
            f"File {file_entry['index']} has invalid "
            f"chunk_size 0x{chunk_size:X}"
        )

    chunks = []

    count = chunk_size // 0x10

    for i in range(count):
        c = parse_chunk(
            full,
            h,
            chunk_off + i * 0x10
        )

        c["index"] = i

        chunks.append(c)

    return chunks


def extract_chunk(blob_fh, chunk):
    """Read only the needed range from an open blob file handle."""
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
            f"Chunk decompression mismatch: "
            f"expected 0x{chunk['decomp']:X}, "
            f"got 0x{len(raw):X}"
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
    """Assemble file data in memory from open blob handles. Does not write to disk."""
    chunks = get_file_chunks(full, h, file_entry)
    output = bytearray()

    for chunk in chunks:
        archive = chunk["archive"]
        blob_fh = blob_handles.get(archive)

        if blob_fh is None:
            raise RuntimeError(
                f"Archive {archive} has no known blob"
            )

        output += extract_chunk(blob_fh, chunk)

    expected = file_entry["total_size"]

    if len(output) != expected:
        raise RuntimeError(
            f"{file_entry['full_path']}: "
            f"size mismatch: "
            f"expected 0x{expected:X}, "
            f"got 0x{len(output):X}"
        )

    return bytes(output), chunks


def main():
    parser = argparse.ArgumentParser(
        description="Extract selected file types from Northlight .rmdtoc/.rmdblob"
    )

    parser.add_argument(
        "--filetype",
        type=str,
        default=None,
        help="Comma-separated file types to extract, e.g. tex,wem,css",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Limit number of selected assets to extract (default: all)",
    )

    parser.add_argument(
        "toc",
        type=Path,
        help="Path to .rmdtoc file",
    )

    args = parser.parse_args()

    toc_dir = args.toc.parent
    out_dir = args.toc.parent / "extracted"

    print("=" * 100)
    print("CONTROL RESONANT ASSET EXTRACTION KIT")
    print("=" * 100)

    print(f"TOC = {args.toc}")
    print(f"OUT = {out_dir}")

    toc = args.toc.read_bytes()

    h = parse_header(toc)
    full = reconstruct_logical_toc(toc, h)

    print(f"logical TOC = {len(full):,} (0x{len(full):X})")

    # ------------------------------------------------------------------
    # Build BLOBS from archives table (handles ../pc/ and ../generic/)
    # ------------------------------------------------------------------
    BLOBS = {}
    aoff = h["archives_off"]
    acnt = h["archives_count"]
    soff = h["strings_off"]

    for i in range(acnt):
        p = aoff + i * 0x18
        name_off = u32(full, p)
        name_len = u32(full, p + 4)
        raw = full[soff + name_off : soff + name_off + name_len]
        rel = raw.split(b"\0")[0].decode("utf-8", "replace")

        candidate = (toc_dir / rel).resolve()
        if not candidate.is_file():
            candidate = toc_dir / Path(rel).name

        if candidate.is_file():
            BLOBS[i] = candidate
            print(f"  archive {i} -> {candidate}  ({candidate.stat().st_size:,} bytes)")
        else:
            print(f"WARNING: archive {i} → {rel} not found")

    paths = parse_paths(full, h)
    print(f"paths = {len(paths):,}")

    files = parse_files(full, h, paths)

    # ------------------------------------------------------------------
    # FILE TYPE INVENTORY
    # ------------------------------------------------------------------
    type_counts = {}

    for f in files:
        filename = f["name"]

        if "." in filename:
            file_type = "." + filename.rsplit(".", 1)[1].lower()
        else:
            file_type = "<no extension>"

        type_counts[file_type] = type_counts.get(file_type, 0) + 1

    print()
    print("=" * 100)
    print("AVAILABLE FILE TYPES")
    print("=" * 100)

    for file_type, count in sorted(
        type_counts.items(),
        key=lambda item: (-item[1], item[0]),
    ):
        print(f"{file_type:20s} {count:,}")

    # ------------------------------------------------------------------
    # SELECT FILE TYPES
    # ------------------------------------------------------------------
    selected_types = set()

    if args.filetype:
        for value in args.filetype.split(","):
            value = value.strip().lower()

            if not value:
                continue

            if value != "<no extension>" and not value.startswith("."):
                value = "." + value

            selected_types.add(value)

    if not selected_types:
        print()
        print("No file type selected.")
        print("Use --filetype to select one or more types, for example:")
        print("  python3 script.py --filetype=tex base-generic.rmdtoc")
        print("  python3 script.py --filetype=wem base-generic.rmdtoc")
        print("  python3 script.py --filetype=tex,wem,css --count 10 base-generic.rmdtoc")
        return

    selected = [
        f
        for f in files
        if (
            (
                "." + f["name"].rsplit(".", 1)[1].lower()
            )
            if "." in f["name"]
            else "<no extension>"
        ) in selected_types
    ]

    if args.count is not None:
        if args.count < 0:
            parser.error("--count must be >= 0")
        selected = selected[:args.count]

    print()
    print("=" * 100)
    print("SELECTED FILE TYPES")
    print("=" * 100)

    for file_type in sorted(selected_types):
        print(f"{file_type:20s} {type_counts.get(file_type, 0):,}")

    print(f"selected = {len(selected):,}")

    needed_archives = set()
    for f in selected:
        chunks = get_file_chunks(full, h, f)
        for c in chunks:
            needed_archives.add(c["archive"])

    # Open blob files as handles — do NOT load entire blobs into RAM
    blob_handles = {}

    for archive in sorted(needed_archives):
        path = BLOBS.get(archive)

        if path is None:
            print(f"WARNING: archive {archive} has no known blob")
            continue

        if not path.exists():
            print(f"WARNING: blob missing for archive {archive}: {path}")
            continue

        print(f"archive {archive} -> {path}")
        blob_handles[archive] = open(path, "rb")

    print()
    print("=" * 100)
    print(f"EXTRACTING {len(selected)} ASSETS")
    print("=" * 100)

    ok = 0

    try:
        for n, f in enumerate(selected):
            print()
            print(f"[{n:03d}] {f['full_path']}")
            print(f"      size = 0x{f['total_size']:X} ({f['total_size']:,})")

            try:
                file_data, chunks = extract_file_bytes(
                    full, h, f, blob_handles
                )

                print(f"      chunks = {len(chunks)}")

                for c in chunks:
                    print(
                        f"        archive={c['archive']} "
                        f"blob=0x{c['blob_off']:X} "
                        f"stored=0x{c['stored']:X} "
                        f"decomp=0x{c['decomp']:X} "
                        f"comp=0x{c['comp']:X}"
                    )

                ok += 1

                output_path = safe_output_path(
                    out_dir,
                    f["full_path"],
                )
                output_path.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )
                output_path.write_bytes(file_data)

                print(f"      FILE -> {output_path}")

            except Exception as e:
                print(f"      ERROR: {e}")

    finally:
        for fh in blob_handles.values():
            fh.close()

    print()
    print("=" * 100)
    print("RESULT")
    print("=" * 100)
    print(f"selected = {len(selected)}")
    print(f"extracted = {ok}")
    print(f"failed = {len(selected) - ok}")

    print()
    print("=" * 100)
    print("DONE")
    print("=" * 100)


if __name__ == "__main__":
    main()
