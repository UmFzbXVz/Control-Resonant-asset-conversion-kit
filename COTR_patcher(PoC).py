#!/usr/bin/env python3
"""
Control (Northlight) MAIN_MENU patcher

  python3 control_patcher.py /path/to/rmdtoc_rmdblob/ 

"""

from __future__ import annotations

import argparse
import struct
import sys
import zlib
from pathlib import Path

# ---------------------------------------------------------------------------
# LZ4 block
# ---------------------------------------------------------------------------

def lz4_decompress(src: bytes, dsz: int) -> bytes:
    try:
        import lz4.block
        return lz4.block.decompress(src, uncompressed_size=dsz)
    except ImportError:
        pass
    out = bytearray()
    i = 0
    n = len(src)
    while i < n:
        t = src[i]
        i += 1
        ll = t >> 4
        if ll == 15:
            while True:
                x = src[i]
                i += 1
                ll += x
                if x != 255:
                    break
        out += src[i : i + ll]
        i += ll
        if i >= n:
            break
        off = src[i] | (src[i + 1] << 8)
        i += 2
        ml = t & 15
        if ml == 15:
            while True:
                x = src[i]
                i += 1
                ml += x
                if x != 255:
                    break
        ml += 4
        st = len(out) - off
        if off >= ml:
            out += out[st : st + ml]
        else:
            for k in range(ml):
                out.append(out[st + k])
    if len(out) != dsz:
        raise ValueError(f"LZ4 size mismatch: got {len(out)}, expected {dsz}")
    return bytes(out)


def lz4_compress(data: bytes, level: int = 12) -> bytes:
    """LZ4 block compress. Prefer HC (matches original game compression)."""
    if not data:
        return b""
    # Try python-lz4 HC
    try:
        import lz4.block
        return lz4.block.compress(data, mode="high_compression", compression=level, store_size=False)
    except Exception:
        pass
    # ctypes liblz4 HC
    import ctypes
    lib = ctypes.CDLL("liblz4.so.1")
    lib.LZ4_compressBound.argtypes = [ctypes.c_int]
    lib.LZ4_compressBound.restype = ctypes.c_int
    lib.LZ4_compress_HC.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int
    ]
    lib.LZ4_compress_HC.restype = ctypes.c_int
    bound = lib.LZ4_compressBound(len(data))
    dst = ctypes.create_string_buffer(bound)
    n = lib.LZ4_compress_HC(data, dst, len(data), bound, level)
    if n <= 0:
        # fallback default
        lib.LZ4_compress_default.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int
        ]
        lib.LZ4_compress_default.restype = ctypes.c_int
        n = lib.LZ4_compress_default(data, dst, len(data), bound)
    if n <= 0:
        raise RuntimeError("LZ4 compress failed")
    return dst.raw[:n]







CHUNK_MAX = 0x100000  # 1 MiB logical chunks as used by the TOC

# Default multi-patch for the main-menu message
DEFAULT_PATCHES = [
    (b"MAIN_MENU_RECAP",     "The game"),
    (b"MAIN_MENU_CONTINUE",  "is now"),
    (b"MAIN_MENU_LOAD_GAME", "<MODIFIABLE / OPEN FOR BUSINESS / CONTROLLED>"),
    (b"MAIN_MENU_NEW_GAME",  ""),
    (b"MAIN_MENU_OPTIONS",   ""),
    (b"MAIN_MENU_CREDITS",   ""),
    (b"MAIN_MENU_EXIT",      "/r/ControlResonant"),
]


# ---------------------------------------------------------------------------
# RMDTOC
# ---------------------------------------------------------------------------

class Toc:
    def __init__(self, path: Path):
        self.path = path
        self.raw = path.read_bytes()
        b = self.raw
        if b[:4] != b"COTR":
            raise ValueError(f"not COTR: {path}")
        H = dict(
            table_off=struct.unpack_from("<I", b, 8)[0],
            table_size=struct.unpack_from("<I", b, 0xC)[0],
            archives_off=struct.unpack_from("<I", b, 0x10)[0],
            archives_count=struct.unpack_from("<I", b, 0x14)[0],
            paths_off=struct.unpack_from("<I", b, 0x18)[0],
            paths_count=struct.unpack_from("<I", b, 0x1C)[0],
            files_off=struct.unpack_from("<I", b, 0x20)[0],
            files_count=struct.unpack_from("<I", b, 0x24)[0],
            strings_off=struct.unpack_from("<I", b, 0x28)[0],
            strings_size=struct.unpack_from("<I", b, 0x2C)[0],
            metadata_off=struct.unpack_from("<I", b, 0x38)[0],
            metadata_size=struct.unpack_from("<I", b, 0x3C)[0],
            chunks_off=struct.unpack_from("<I", b, 0x50)[0],
            chunks_size=struct.unpack_from("<I", b, 0x54)[0],
        )
        self.H = H

        # Build logical image from descriptor table
        L = bytearray()
        self.descriptors = []
        for i in range(H["table_size"] // 16):
            e = H["table_off"] + i * 16
            flags = b[e]
            off = int.from_bytes(b[e + 3 : e + 8], "little")
            ds = struct.unpack_from("<I", b, e + 8)[0]
            cs = struct.unpack_from("<I", b, e + 12)[0]
            raw = b[off : off + (cs or ds)]
            if cs:
                raw = lz4_decompress(raw, ds)
            self.descriptors.append(
                dict(flags=flags, data_off=off, decomp=ds, comp=cs, index=i)
            )
            L += raw
        self.L = bytes(L)

        def S(o, s):
            return self.L[H["strings_off"] + o : H["strings_off"] + o + s].decode(
                "utf8", "replace"
            )

        # Archives
        self.archives = []
        for i in range(H["archives_count"]):
            p = H["archives_off"] + i * 0x18
            no, ns = struct.unpack_from("<II", self.L, p)
            self.archives.append(S(no, ns))

        # Paths
        paths = []
        for i in range(H["paths_count"]):
            p = H["paths_off"] + i * 0x1C
            parent = struct.unpack_from("<I", self.L, p)[0]
            no, ns = struct.unpack_from("<II", self.L, p + 0x14)
            paths.append((parent, S(no, ns) if ns else ""))
        self.paths = paths

        def full_path(i):
            parts = []
            seen = set()
            cur = i
            while cur not in seen:
                seen.add(cur)
                nm = paths[cur][1]
                if nm and not nm.endswith(".rmdblob"):
                    parts.append(nm)
                par = paths[cur][0]
                if par == cur or par >= len(paths):
                    break
                cur = par
            return "/".join(reversed(parts))

        # Files
        self.files = {}
        for i in range(H["files_count"]):
            p = H["files_off"] + i * 0x20
            cr, cb, pi, no, ns, ts, mr, ms = struct.unpack_from("<8I", self.L, p)
            name = full_path(pi) + "/" + S(no, ns)
            self.files[name] = dict(
                chunk_rel=cr,
                chunk_bytes=cb,
                path_index=pi,
                total_size=ts,
                meta_rel=mr,
                meta_size=ms,
                file_rec_off=p,  # offset into L
            )

    def read_file(self, name: str, blob_path: Path) -> bytes:
        rec = self.files[name]
        blob = blob_path.read_bytes()
        out = bytearray()
        nchunks = rec["chunk_bytes"] // 16
        for j in range(nchunks):
            p = self.H["chunks_off"] + rec["chunk_rel"] + j * 16
            flags = self.L[p]
            arch = self.L[p + 1]
            blob_off = int.from_bytes(self.L[p + 3 : p + 8], "little")
            dec = struct.unpack_from("<I", self.L, p + 8)[0]
            comp = struct.unpack_from("<I", self.L, p + 12)[0]
            raw = blob[blob_off : blob_off + (comp or dec)]
            if comp:
                raw = lz4_decompress(raw, dec)
            if len(raw) != dec:
                raise ValueError(f"chunk {j} size {len(raw)} != {dec}")
            out += raw
        if len(out) != rec["total_size"]:
            raise ValueError(f"file size {len(out)} != {rec['total_size']}")
        return bytes(out)

    def get_chunks(self, name: str):
        rec = self.files[name]
        chunks = []
        nchunks = rec["chunk_bytes"] // 16
        for j in range(nchunks):
            p = self.H["chunks_off"] + rec["chunk_rel"] + j * 16
            chunks.append(
                dict(
                    L_off=p,
                    flags=self.L[p],
                    arch=self.L[p + 1],
                    blob_off=int.from_bytes(self.L[p + 3 : p + 8], "little"),
                    decomp=struct.unpack_from("<I", self.L, p + 8)[0],
                    comp=struct.unpack_from("<I", self.L, p + 12)[0],
                )
            )
        return chunks







def patch_string_table(data: bytes, patches: list[tuple[bytes, str]]) -> tuple[bytes, dict]:
    """
    Apply multiple key→value patches to a string_table.bin.
    patches: list of (key_bytes, new_value_str)
    """
    wanted = {k: v for k, v in patches}
    n = struct.unpack_from("<I", data, 0)[0]
    q = 4
    # Collect all entries as (start, end, key, old_val_bytes)
    entries = []
    for i in range(n):
        start = q
        kl = struct.unpack_from("<I", data, q)[0]
        q += 4
        key = data[q : q + kl]
        q += kl
        tl = struct.unpack_from("<I", data, q)[0]
        val_off = q + 4
        q += 4 + 2 * tl
        entries.append((start, q, key, data[val_off : val_off + 2 * tl]))

    missing = [k for k in wanted if not any(e[2] == k for e in entries)]
    if missing:
        raise RuntimeError(f"keys not found: {missing}")

    # Rebuild: walk entries in order, substitute patched values
    out = bytearray()
    out += data[:4]  # record count
    changes = []
    for start, end, key, old_val_bytes in entries:
        if key in wanted:
            new_val = wanted[key]
            new_bytes = new_val.encode("utf-16le")
            old_val = old_val_bytes.decode("utf-16le")
            # write: key_len | key | val_chars | val
            out += struct.pack("<I", len(key))
            out += key
            out += struct.pack("<I", len(new_val))
            out += new_bytes
            changes.append((key.decode("utf-8", "replace"), old_val, new_val))
        else:
            out += data[start:end]

    info = dict(
        changes=changes,
        old_size=len(data),
        new_size=len(out),
        size_delta=len(out) - len(data),
        old_crc=zlib.crc32(data) & 0xFFFFFFFF,
        new_crc=zlib.crc32(bytes(out)) & 0xFFFFFFFF,
    )
    return bytes(out), info






def rechunk(data: bytes, header_size: int = 16) -> tuple[bytes, list]:
    """
    Split data into 1MiB logical chunks, LZ4-compress each.
    Returns (blob_bytes with header_size zero-pad prefix, chunk_list).
    chunk_list entries: {blob_off, decomp, comp}
    """
    chunks = []
    payload = bytearray()
    pos = 0
    while pos < len(data):
        piece = data[pos : pos + CHUNK_MAX]
        comp = lz4_compress(piece)
        chunks.append(
            dict(blob_off=header_size + len(payload), decomp=len(piece), comp=len(comp))
        )
        payload += comp
        pos += len(piece)
    # Preserve space for archive header (blBR + version + hash)
    blob = bytearray(header_size) + payload
    return bytes(blob), chunks


def patch_logical_image(
    L: bytes,
    H: dict,
    file_rec: dict,
    old_chunks: list,
    new_size: int,
    new_crc: int,
    new_chunk_info: list,
    old_size: int,
    old_crc: int,
    old_blob_size: int | None = None,
    new_blob_size: int | None = None,
) -> bytes:
    """Update size, CRC, and chunk records inside the logical image."""
    Lp = bytearray(L)

    # Update file record total_size
    # file_rec_off points into L; total_size is at +20 within the 0x20 record
    fro = file_rec["file_rec_off"]
    struct.pack_into("<I", Lp, fro + 20, new_size)

    # Update archive blob size (offset +0x10 within 0x18 archive record)
    if old_blob_size is not None and new_blob_size is not None:
        for i in range(H["archives_count"]):
            p = H["archives_off"] + i * 0x18
            cur = struct.unpack_from("<I", Lp, p + 0x10)[0]
            if cur == old_blob_size:
                struct.pack_into("<I", Lp, p + 0x10, new_blob_size)

    # Update chunk records
    for j, (old_c, new_c) in enumerate(zip(old_chunks, new_chunk_info)):
        p = old_c["L_off"]
        # flags, arch, pad already set; write blob_off (u40), decomp, comp
        off_bytes = new_c["blob_off"].to_bytes(5, "little")
        Lp[p + 3 : p + 8] = off_bytes
        struct.pack_into("<I", Lp, p + 8, new_c["decomp"])
        struct.pack_into("<I", Lp, p + 12, new_c["comp"])

    # If fewer new chunks (shouldn't happen for -4 bytes), zero the rest
    if len(new_chunk_info) < len(old_chunks):
        for old_c in old_chunks[len(new_chunk_info) :]:
            p = old_c["L_off"]
            Lp[p : p + 16] = b"\x00" * 16
        # update chunk_bytes in file record
        struct.pack_into("<I", Lp, fro + 4, len(new_chunk_info) * 16)

    # FileInfoMetadata in DMKP: {u32 1, u32 size, u32 0, u32 CRC}
    # Replace old size and CRC wherever they appear as the known pair
    # Safer: find the DMKP FileInfoMetadata pattern
    dmkp = Lp.find(b"DMKP")
    if dmkp >= 0:
        nsec = struct.unpack_from("<I", Lp, dmkp + 4)[0]
        body = dmkp + 8 + 8 * nsec
        for i in range(nsec):
            kind = struct.unpack_from("<I", Lp, dmkp + 8 + 8 * i)[0]
            s, e = struct.unpack_from("<HH", Lp, dmkp + 8 + 8 * i + 4)
            if kind == 0 and e - s >= 16:
                # FileInfoMetadata
                off = body + s
                a, b, c, d = struct.unpack_from("<4I", Lp, off)
                if a == 1 and b == old_size and c == 0 and d == old_crc:
                    struct.pack_into("<I", Lp, off + 4, new_size)
                    struct.pack_into("<I", Lp, off + 12, new_crc)

    return bytes(Lp)





def main():
    ap = argparse.ArgumentParser(description="Patch main-menu strings in Control locale package (rmdtoc+rmdblob only)")
    ap.add_argument("directory", help="Directory with base-en.rmdtoc + base-en-000.rmdblob")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    root = Path(args.directory)

    # Find TOC
    toc_path = root / "base-en.rmdtoc"
    if not toc_path.is_file():
        cands = list(root.glob("**/*en*.rmdtoc")) + list(root.glob("**/*.rmdtoc"))
        if not cands:
            sys.exit(f"No .rmdtoc under {root}")
        toc_path = cands[0]

    toc = Toc(toc_path)
    print(f"TOC:  {toc_path} ({len(toc.raw)} bytes)")
    print(f"  logical image: {len(toc.L)} bytes")
    print(f"  archives: {toc.archives}")
    print(f"  files: {list(toc.files.keys())}")

    # Find string table
    st_name = None
    for name in toc.files:
        if name.endswith("string_table.bin") and "/en/" in name.replace("\\", "/"):
            st_name = name
            break
    if st_name is None:
        for name in toc.files:
            if "string_table" in name:
                st_name = name
                break
    if st_name is None:
        sys.exit(f"No string_table in TOC files: {list(toc.files)}")

    rec = toc.files[st_name]
    print(f"Target: {st_name}")
    print(f"  size={rec['total_size']} chunks={rec['chunk_bytes']//16}")

    # Resolve blob path
    arch_name = toc.archives[0] if toc.archives else None
    # archives store relative path like ../pc/base-en-000.rmdblob
    blob_path = None
    if arch_name:
        # try relative to toc parent, and flattened
        candidates = [
            toc_path.parent / Path(arch_name).name,
            toc_path.parent / arch_name,
            root / Path(arch_name).name,
            root / arch_name,
        ]
        # also any *en*.rmdblob
        candidates += list(root.glob("**/*en*.rmdblob"))
        candidates += list(root.glob("**/*.rmdblob"))
        for c in candidates:
            if c.is_file():
                blob_path = c
                break
    if blob_path is None:
        sys.exit("Could not find rmdblob")

    print(f"BLOB: {blob_path} ({blob_path.stat().st_size} bytes)")

    # Read string table through chunk table
    st_data = toc.read_file(st_name, blob_path)
    crc = zlib.crc32(st_data) & 0xFFFFFFFF
    print(f"Extracted string_table: {len(st_data)} bytes CRC={crc:#010x}")

    # Build patch list
    if args.value is not None:
        patches = [(b"MAIN_MENU_RECAP", args.value)]
    else:
        patches = list(DEFAULT_PATCHES)

    # Patch
    patched, info = patch_string_table(st_data, patches)
    print(f"Patched {len(info['changes'])} string(s):")
    for key, old, new in info["changes"]:
        print(f"  {key}: {old!r} → {new!r}")
    print(f"  size {info['old_size']} → {info['new_size']} (delta {info['size_delta']:+d})")
    print(f"  CRC  {info['old_crc']:#010x} → {info['new_crc']:#010x}")

    if args.dry_run:
        print("Dry-run — no files written")
        return

    # Determine archive header size from first chunk offset
    old_chunks = toc.get_chunks(st_name)
    header_size = old_chunks[0]["blob_off"] if old_chunks else 16
    print(f"Archive header size: {header_size}")

    # Preserve original header bytes
    orig_blob = blob_path.read_bytes()
    header = orig_blob[:header_size]

    # Re-chunk: reuse original compressed bytes for chunks that are
    # byte-identical to the original decompressed data; only recompress
    # from the first modified chunk onward (LZ4 HC level 12).
    n_old = len(old_chunks)
    # Find first chunk index that differs
    first_dirty = n_old
    pos = 0
    for j, oc in enumerate(old_chunks):
        orig_piece = st_data[pos : pos + oc["decomp"]]
        new_piece = patched[pos : pos + oc["decomp"]] if j < n_old - 1 else patched[pos:]
        # For non-last chunks compare exact 1MiB; for last compare remainder
        if j < n_old - 1:
            if orig_piece != patched[pos : pos + CHUNK_MAX]:
                first_dirty = j
                break
            pos += CHUNK_MAX
        else:
            if orig_piece != patched[pos:]:
                first_dirty = j
            break
    print(f"First modified chunk: {first_dirty} / {n_old}")

    new_payload_chunks = []
    payload = bytearray()
    pos = 0
    for j, oc in enumerate(old_chunks):
        if j < n_old - 1:
            piece = patched[pos : pos + CHUNK_MAX]
            piece_len = CHUNK_MAX
        else:
            piece = patched[pos:]
            piece_len = len(piece)

        if j < first_dirty:
            # Reuse original compressed data
            orig_comp = orig_blob[oc["blob_off"] : oc["blob_off"] + oc["comp"]]
            new_payload_chunks.append(
                dict(
                    blob_off=header_size + len(payload),
                    decomp=oc["decomp"],
                    comp=len(orig_comp),
                )
            )
            payload += orig_comp
            pos += oc["decomp"]
            print(f"  chunk[{j}] REUSED off={new_payload_chunks[-1]['blob_off']:#x} "
                  f"decomp={oc['decomp']} comp={len(orig_comp)}")
        else:
            comp = lz4_compress(piece)
            new_payload_chunks.append(
                dict(
                    blob_off=header_size + len(payload),
                    decomp=len(piece),
                    comp=len(comp),
                )
            )
            payload += comp
            pos += len(piece)
            print(f"  chunk[{j}] RECOMPRESSED off={new_payload_chunks[-1]['blob_off']:#x} "
                  f"decomp={len(piece)} comp={len(comp)}")

    if pos != len(patched):
        raise RuntimeError(f"rechunk failed: covered {pos} of {len(patched)}")

    new_blob = header + bytes(payload)
    print(f"New blob: {len(new_blob)} bytes (original {len(orig_blob)})")

    # Update logical image
    new_L = patch_logical_image(
        toc.L,
        toc.H,
        rec,
        old_chunks,
        info["new_size"],
        info["new_crc"],
        new_payload_chunks,
        info["old_size"],
        info["old_crc"],
        old_blob_size=len(orig_blob),
        new_blob_size=len(new_blob),
    )

    # Rebuild TOC file: compress new_L back into the descriptor section
    # base-en has one descriptor covering the entire logical image
    desc = toc.descriptors[0]
    new_comp = lz4_compress(new_L)
    new_toc = bytearray(toc.raw[: desc["data_off"]])
    new_toc += new_comp
    # update descriptor decomp/comp sizes
    table_off = toc.H["table_off"]
    struct.pack_into("<I", new_toc, table_off + 8, len(new_L))
    struct.pack_into("<I", new_toc, table_off + 12, len(new_comp))

    # Write
    blob_bak = blob_path.with_suffix(blob_path.suffix + ".bak")
    if not blob_bak.exists():
        blob_bak.write_bytes(orig_blob)
        print(f"BLOB backup: {blob_bak}")
    blob_path.write_bytes(new_blob)
    print(f"BLOB wrote:  {blob_path} ({len(new_blob)} bytes)")

    toc_bak = toc_path.with_suffix(toc_path.suffix + ".bak")
    if not toc_bak.exists():
        toc_bak.write_bytes(toc.raw)
        print(f"TOC  backup: {toc_bak}")
    toc_path.write_bytes(bytes(new_toc))
    print(f"TOC  wrote:  {toc_path} ({len(new_toc)} bytes)")

    # Verify roundtrip
    toc2 = Toc(toc_path)
    st2 = toc2.read_file(st_name, blob_path)
    assert len(st2) == info["new_size"], (len(st2), info["new_size"])
    assert (zlib.crc32(st2) & 0xFFFFFFFF) == info["new_crc"]
    for key, _old, new in info["changes"]:
        kb = key.encode("utf-8")
        idx = st2.find(kb)
        assert idx >= 0, key
        tl = struct.unpack_from("<I", st2, idx + len(kb))[0]
        val = st2[idx + len(kb) + 4 : idx + len(kb) + 4 + tl * 2].decode("utf-16le")
        assert val == new, (key, val, new)
        print(f"  roundtrip {key} = {val!r}")
    print("Roundtrip OK")
    print("Done.")


if __name__ == "__main__":
    main()
