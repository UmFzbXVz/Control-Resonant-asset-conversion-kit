#!/usr/bin/env python3

from pathlib import Path
import struct
import argparse
import lz4.block
import math
import re

from PIL import Image


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


# ----------------------------------------------------------------------
# TEX → PNG CONVERSION
# ----------------------------------------------------------------------

def rgb565(c):
    r = ((c >> 11) & 0x1F) * 255 // 31
    g = ((c >> 5) & 0x3F) * 255 // 63
    b = (c & 0x1F) * 255 // 31
    return r, g, b


def decode_bc1_block(data, offset):
    """Decode one BC1/DXT1 8-byte block → 16 RGBA tuples."""
    color0, color1, indices = struct.unpack_from("<HHI", data, offset)

    c0 = rgb565(color0)
    c1 = rgb565(color1)

    colors = [None] * 4
    colors[0] = (*c0, 255)
    colors[1] = (*c1, 255)

    if color0 > color1:
        colors[2] = (
            (2 * c0[0] + c1[0]) // 3,
            (2 * c0[1] + c1[1]) // 3,
            (2 * c0[2] + c1[2]) // 3,
            255,
        )
        colors[3] = (
            (c0[0] + 2 * c1[0]) // 3,
            (c0[1] + 2 * c1[1]) // 3,
            (c0[2] + 2 * c1[2]) // 3,
            255,
        )
    else:
        colors[2] = (
            (c0[0] + c1[0]) // 2,
            (c0[1] + c1[1]) // 2,
            (c0[2] + c1[2]) // 2,
            255,
        )
        colors[3] = (0, 0, 0, 0)

    pixels = []
    for i in range(16):
        idx = (indices >> (2 * i)) & 3
        pixels.append(colors[idx])
    return pixels


def decode_bc1(data, width, height):
    output = bytearray(width * height * 4)
    blocks_x = (width + 3) // 4
    blocks_y = (height + 3) // 4
    offset = 0

    for by in range(blocks_y):
        for bx in range(blocks_x):
            if offset + 8 > len(data):
                raise ValueError(f"Unexpected end of BC1 data at block ({bx}, {by})")
            pixels = decode_bc1_block(data, offset)
            offset += 8

            for py in range(4):
                for px in range(4):
                    x = bx * 4 + px
                    y = by * 4 + py
                    if x >= width or y >= height:
                        continue
                    color = pixels[py * 4 + px]
                    dst = (y * width + x) * 4
                    output[dst:dst + 4] = bytes(color)

    return bytes(output)


def decode_alpha_block(data, offset):
    """Decode BC3/BC4-style 8-byte alpha/endpoint block → 16 values 0-255."""
    a0 = data[offset]
    a1 = data[offset + 1]
    bits = int.from_bytes(data[offset + 2:offset + 8], "little")

    alphas = [0] * 8
    alphas[0] = a0
    alphas[1] = a1

    if a0 > a1:
        for i in range(1, 7):
            alphas[i + 1] = ((7 - i) * a0 + i * a1) // 7
    else:
        for i in range(1, 5):
            alphas[i + 1] = ((5 - i) * a0 + i * a1) // 5
        alphas[6] = 0
        alphas[7] = 255

    values = []
    for i in range(16):
        idx = (bits >> (3 * i)) & 7
        values.append(alphas[idx])
    return values


def decode_bc3(data, width, height):
    """BC3 / DXT5 — 16 bytes per block (alpha + color)."""
    output = bytearray(width * height * 4)
    blocks_x = (width + 3) // 4
    blocks_y = (height + 3) // 4
    offset = 0

    for by in range(blocks_y):
        for bx in range(blocks_x):
            if offset + 16 > len(data):
                raise ValueError(f"Unexpected end of BC3 data at block ({bx}, {by})")

            alphas = decode_alpha_block(data, offset)
            offset += 8
            colors = decode_bc1_block(data, offset)
            offset += 8

            for py in range(4):
                for px in range(4):
                    x = bx * 4 + px
                    y = by * 4 + py
                    if x >= width or y >= height:
                        continue
                    r, g, b, _ = colors[py * 4 + px]
                    a = alphas[py * 4 + px]
                    dst = (y * width + x) * 4
                    output[dst:dst + 4] = bytes((r, g, b, a))

    return bytes(output)


def decode_bc4(data, width, height):
    """BC4 — single channel, 8 bytes per block. Stored as grayscale RGBA."""
    output = bytearray(width * height * 4)
    blocks_x = (width + 3) // 4
    blocks_y = (height + 3) // 4
    offset = 0

    for by in range(blocks_y):
        for bx in range(blocks_x):
            if offset + 8 > len(data):
                raise ValueError(f"Unexpected end of BC4 data at block ({bx}, {by})")

            values = decode_alpha_block(data, offset)
            offset += 8

            for py in range(4):
                for px in range(4):
                    x = bx * 4 + px
                    y = by * 4 + py
                    if x >= width or y >= height:
                        continue
                    v = values[py * 4 + px]
                    dst = (y * width + x) * 4
                    output[dst:dst + 4] = bytes((v, v, v, 255))

    return bytes(output)


def decode_bc5(data, width, height):
    """BC5 — two channels (R+G), 16 bytes per block. Common for normal maps.
    Reconstructs approximate B from R/G for visualization (RG → normal).
    """
    output = bytearray(width * height * 4)
    blocks_x = (width + 3) // 4
    blocks_y = (height + 3) // 4
    offset = 0

    for by in range(blocks_y):
        for bx in range(blocks_x):
            if offset + 16 > len(data):
                raise ValueError(f"Unexpected end of BC5 data at block ({bx}, {by})")

            reds = decode_alpha_block(data, offset)
            offset += 8
            greens = decode_alpha_block(data, offset)
            offset += 8

            for py in range(4):
                for px in range(4):
                    x = bx * 4 + px
                    y = by * 4 + py
                    if x >= width or y >= height:
                        continue
                    r = reds[py * 4 + px]
                    g = greens[py * 4 + px]

                    # Reconstruct approximate blue for normal-map visualization
                    nx = (r / 255.0) * 2.0 - 1.0
                    ny = (g / 255.0) * 2.0 - 1.0
                    nz_sq = 1.0 - nx * nx - ny * ny
                    nz = math.sqrt(nz_sq) if nz_sq > 0 else 0.0
                    b = int(max(0, min(255, (nz * 0.5 + 0.5) * 255)))

                    dst = (y * width + x) * 4
                    output[dst:dst + 4] = bytes((r, g, b, 255))

    return bytes(output)


def half_to_float(h):
    """Convert IEEE 754 half-precision to float."""
    s = (h >> 15) & 1
    e = (h >> 10) & 0x1F
    m = h & 0x3FF

    if e == 0:
        if m == 0:
            return -0.0 if s else 0.0
        # subnormal
        return ((-1) ** s) * (m / 1024.0) * (2 ** -14)
    if e == 31:
        if m == 0:
            return float("-inf") if s else float("inf")
        return float("nan")

    return ((-1) ** s) * (1.0 + m / 1024.0) * (2 ** (e - 15))


def decode_r16g16b16a16_float(data, width, height):
    """R16G16B16A16_FLOAT — 8 bytes per pixel. Tone-map to 8-bit for PNG."""
    expected = width * height * 8
    if len(data) < expected:
        raise ValueError(
            f"Not enough R16G16B16A16_FLOAT data: need {expected}, have {len(data)}"
        )

    output = bytearray(width * height * 4)
    offset = 0

    for i in range(width * height):
        r_h, g_h, b_h, a_h = struct.unpack_from("<4H", data, offset)
        offset += 8

        r = half_to_float(r_h)
        g = half_to_float(g_h)
        b = half_to_float(b_h)
        a = half_to_float(a_h)

        def to_u8(v):
            if math.isnan(v) or math.isinf(v):
                return 0
            return int(max(0.0, min(255.0, v * 255.0)))

        dst = i * 4
        output[dst:dst + 4] = bytes((
            to_u8(r),
            to_u8(g),
            to_u8(b),
            to_u8(a),
        ))

    return bytes(output)


def decode_bgra8(data, width, height):
    """B8G8R8A8_UNORM / SRGB — 4 bytes per pixel, BGRA order."""
    expected = width * height * 4
    if len(data) < expected:
        raise ValueError(
            f"Not enough BGRA8 data: need {expected}, have {len(data)}"
        )

    output = bytearray(width * height * 4)
    for i in range(width * height):
        b, g, r, a = data[i * 4:i * 4 + 4]
        dst = i * 4
        output[dst:dst + 4] = bytes((r, g, b, a))

    return bytes(output)


def parse_dds(data):
    """Parse DDS texture from bytes (no disk I/O)."""
    if data[:4] != b"DDS ":
        raise ValueError("File does not start with a DDS header")

    header_size = struct.unpack_from("<I", data, 4)[0]
    if header_size != 124:
        raise ValueError(f"Unexpected DDS header size: {header_size}")

    height = struct.unpack_from("<I", data, 12)[0]
    width = struct.unpack_from("<I", data, 16)[0]

    pf_size = struct.unpack_from("<I", data, 76)[0]
    fourcc = data[84:88]

    if pf_size != 32:
        raise ValueError("Invalid DDS pixel format")

    format_id = None
    pixel_data_offset = 128
    block_size = None
    bytes_per_pixel = None

    if fourcc == b"DX10":
        dxgi_format = struct.unpack_from("<I", data, 128)[0]
        format_id = dxgi_format
        pixel_data_offset = 148

        if dxgi_format in (71, 72):
            block_size = 8
        elif dxgi_format in (77, 78):
            block_size = 16
        elif dxgi_format in (80, 81):
            block_size = 8
        elif dxgi_format in (83, 84):
            block_size = 16
        elif dxgi_format == 10:
            bytes_per_pixel = 8
        elif dxgi_format in (87, 91):
            bytes_per_pixel = 4
        else:
            raise NotImplementedError(
                f"Unsupported DXGI format {dxgi_format}"
            )

    elif fourcc in (b"DXT1", b"BC1 "):
        format_id = 71
        block_size = 8
        pixel_data_offset = 128

    elif fourcc in (b"DXT3", b"BC2 "):
        format_id = 74
        block_size = 16
        pixel_data_offset = 128
        raise NotImplementedError("BC2/DXT3 not yet implemented")

    elif fourcc in (b"DXT5", b"BC3 "):
        format_id = 77
        block_size = 16
        pixel_data_offset = 128

    elif fourcc in (b"BC4U", b"ATI1", b"BC4 "):
        format_id = 80
        block_size = 8
        pixel_data_offset = 128

    elif fourcc in (b"BC5U", b"ATI2", b"BC5 "):
        format_id = 83
        block_size = 16
        pixel_data_offset = 128

    else:
        raise NotImplementedError(
            f"Unsupported DDS format: {fourcc!r}"
        )

    if block_size is not None:
        blocks_x = (width + 3) // 4
        blocks_y = (height + 3) // 4
        required = blocks_x * blocks_y * block_size
    else:
        required = width * height * bytes_per_pixel

    available = len(data) - pixel_data_offset
    if available < required:
        raise ValueError(
            f"Not enough texture data: need {required} bytes, have {available}"
        )

    texture_data = data[pixel_data_offset:pixel_data_offset + required]

    return width, height, texture_data, format_id


def tex_bytes_to_png(tex_data, output_file):
    """Convert in-memory .tex (DDS) data to a PNG file on disk."""
    width, height, texture_data, format_id = parse_dds(tex_data)

    if format_id in (71, 72):
        rgba = decode_bc1(texture_data, width, height)
    elif format_id in (77, 78):
        rgba = decode_bc3(texture_data, width, height)
    elif format_id in (80, 81):
        rgba = decode_bc4(texture_data, width, height)
    elif format_id in (83, 84):
        rgba = decode_bc5(texture_data, width, height)
    elif format_id == 10:
        rgba = decode_r16g16b16a16_float(texture_data, width, height)
    elif format_id in (87, 91):
        rgba = decode_bgra8(texture_data, width, height)
    else:
        raise NotImplementedError(f"No decoder for format {format_id}")

    image = Image.frombytes("RGBA", (width, height), rgba)
    image.save(output_file, "PNG")

    return output_file


def main():
    parser = argparse.ArgumentParser(
        description="Extract .tex textures from Northlight .rmdtoc/.rmdblob and convert to PNG"
    )

    parser.add_argument(
        "toc",
        type=Path,
        help="Path to .rmdtoc file",
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output directory (default: tex_extracted next to the toc)",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Limit number of .tex assets to extract (default: all)",
    )

    args = parser.parse_args()

    toc_dir = args.toc.parent
    name = args.toc.name.replace(".rmdtoc", "")

    found = {}
    for path in toc_dir.glob(f"{name}*.rmdblob"):
        m = re.search(r"-(\d+)\.rmdblob$", path.name)
        if m:
            found[int(m.group(1))] = path

    # Same archive → file-number mapping as the original working script
    BLOBS = {
        0: found.get(0),
        1: found.get(5),
        2: None,
        3: found.get(1),
        4: found.get(2),
        5: found.get(3),
        6: found.get(4),
    }

    out_dir = args.out if args.out is not None else toc_dir / "tex_extracted"

    print("=" * 100)
    print("CONTROL RESONANT ASSET CONVERSION KIT")
    print("=" * 100)

    print(f"TOC = {args.toc}")
    print(f"OUT = {out_dir}")

    toc = args.toc.read_bytes()

    h = parse_header(toc)

    full = reconstruct_logical_toc(toc, h)

    print(f"logical TOC = {len(full):,} (0x{len(full):X})")

    paths = parse_paths(full, h)
    print(f"paths = {len(paths):,}")

    files = parse_files(full, h, paths)

    tex = [
        f for f in files
        if f["name"].lower().endswith(".tex")
    ]

    print(f"files = {len(files):,}")
    print(f"TEX assets = {len(tex):,}")

    selected = tex if args.count is None else tex[:args.count]

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

        print(f"archive {archive} -> {path.name}")
        blob_handles[archive] = open(path, "rb")

    print()
    print("=" * 100)
    print(f"EXTRACTING {len(selected)} TEX ASSETS")
    print("=" * 100)

    ok = 0
    converted = 0
    convert_failed = 0

    try:
        for n, f in enumerate(selected):
            print()
            print(f"[{n:03d}] {f['full_path']}")
            print(f"      size = 0x{f['total_size']:X} ({f['total_size']:,})")

            try:
                tex_data, chunks = extract_file_bytes(
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

                out_base = safe_output_path(out_dir, f["full_path"])
                out_base.parent.mkdir(parents=True, exist_ok=True)

                png_path = out_base.with_suffix(".png")
                tex_path = out_base  # already ends with .tex

                try:
                    tex_bytes_to_png(tex_data, png_path)
                    print(f"      PNG  -> {png_path}")
                    converted += 1
                except Exception as conv_err:
                    # Conversion failed — keep .tex as backup
                    tex_path.write_bytes(tex_data)
                    print(f"      CONVERT ERROR: {conv_err}")
                    print(f"      TEX  -> {tex_path}  (backup)")
                    convert_failed += 1

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
    print(f"converted to PNG = {converted}")
    print(f"convert failed (kept .tex) = {convert_failed}")

    print()
    print("=" * 100)
    print("DONE")
    print("=" * 100)


if __name__ == "__main__":
    main()
