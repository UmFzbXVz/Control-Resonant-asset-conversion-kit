#!/usr/bin/env python3
import sys
import struct
import json
import argparse
from pathlib import Path
import lz4.block

def read_u40(data, offset):
    return int.from_bytes(data[offset:offset + 5], "little")

def parse_toc(toc_path):
    toc_path = Path(toc_path)
    data = toc_path.read_bytes()
    assert data[0:4] == b"COTR"
    version = struct.unpack_from("<I", data, 4)[0]
    assert version == 3
    table_off = struct.unpack_from("<I", data, 8)[0]
    table_size = struct.unpack_from("<I", data, 12)[0]
    archives_off = struct.unpack_from("<I", data, 16)[0]
    archives_count = struct.unpack_from("<I", data, 20)[0]
    paths_off = struct.unpack_from("<I", data, 24)[0]
    paths_count = struct.unpack_from("<I", data, 28)[0]
    files_off = struct.unpack_from("<I", data, 32)[0]
    files_count = struct.unpack_from("<I", data, 36)[0]
    strings_off = struct.unpack_from("<I", data, 40)[0]
    strings_size = struct.unpack_from("<I", data, 44)[0]
    types_off = struct.unpack_from("<I", data, 48)[0]
    types_count = struct.unpack_from("<I", data, 52)[0]
    metadata_off = struct.unpack_from("<I", data, 56)[0]
    metadata_size = struct.unpack_from("<I", data, 60)[0]
    chunks_off = struct.unpack_from("<I", data, 80)[0]
    chunks_size = struct.unpack_from("<I", data, 84)[0]

    num_desc = table_size // 16
    logical_parts = []
    for i in range(num_desc):
        d = data[table_off + 16 * i : table_off + 16 * (i + 1)]
        data_off = read_u40(d, 3)
        decomp = struct.unpack_from("<I", d, 8)[0]
        comp = struct.unpack_from("<I", d, 12)[0]
        raw = data[data_off : data_off + (comp if comp else decomp)]
        if comp:
            part = lz4.block.decompress(raw, uncompressed_size=decomp)
        else:
            part = raw
        assert len(part) == decomp
        logical_parts.append(part)
    logical = b"".join(logical_parts)

    strings = logical[strings_off : strings_off + strings_size]

    archives = []
    for i in range(archives_count):
        rec = logical[archives_off + 24 * i : archives_off + 24 * (i + 1)]
        name_off, name_len = struct.unpack_from("<II", rec, 0)
        h = struct.unpack_from("<Q", rec, 8)[0]
        blob_size = struct.unpack_from("<Q", rec, 16)[0]
        name = strings[name_off : name_off + name_len].decode("utf-8")
        archives.append({"name": name, "hash": h, "blob_size": blob_size})

    path_recs = []
    for i in range(paths_count):
        rec = logical[paths_off + 28 * i : paths_off + 28 * (i + 1)]
        parent = struct.unpack_from("<I", rec, 0)[0]
        name_off = struct.unpack_from("<I", rec, 0x14)[0]
        name_len = struct.unpack_from("<I", rec, 0x18)[0]
        name = strings[name_off : name_off + name_len].decode("utf-8")
        path_recs.append({"parent": parent, "name": name})

    def full_path(idx):
        comps = []
        seen = set()
        while idx not in seen:
            seen.add(idx)
            p = path_recs[idx]
            if not p["name"].endswith(".rmdblob"):
                comps.append(p["name"])
            parent = p["parent"]
            if parent == idx:
                break
            idx = parent
        return "/".join(reversed(comps))

    types = []
    for i in range(types_count):
        rec = logical[types_off + 8 * i : types_off + 8 * (i + 1)]
        rel_off, size = struct.unpack_from("<II", rec)
        name = strings[rel_off : rel_off + size].decode("utf-8")
        types.append(name)

    files = []
    total_chunks = 0
    for i in range(files_count):
        rec = logical[files_off + 32 * i : files_off + 32 * (i + 1)]
        chunk_rel, chunk_bytes, path_idx, name_off, name_len, total_size, meta_rel, meta_size = struct.unpack_from("<IIIIIIII", rec)
        name = strings[name_off : name_off + name_len].decode("utf-8")
        path = full_path(path_idx)
        fullname = f"{path}/{name}" if path else name
        nchunks = chunk_bytes // 16
        total_chunks += nchunks

        chunks = []
        chunk_sum = 0
        for j in range(nchunks):
            crec = logical[chunks_off + chunk_rel + 16 * j : chunks_off + chunk_rel + 16 * (j + 1)]
            flags = crec[0]
            archive = crec[1]
            blob_off = read_u40(crec, 3)
            decomp = struct.unpack_from("<I", crec, 8)[0]
            comp = struct.unpack_from("<I", crec, 12)[0]
            chunk_sum += decomp
            assert (flags == 0x10 and comp != 0) or (flags == 0x00 and comp == 0)
            assert crec[2] == 0
            chunks.append({
                "flags": flags,
                "archive": archive,
                "blob_off": blob_off,
                "decomp": decomp,
                "comp": comp,
            })
        assert chunk_sum == total_size

        primary_id = None
        crc32 = None
        deps = []
        sections = []
        if meta_size > 0:
            meta = logical[metadata_off + meta_rel : metadata_off + meta_rel + meta_size]
            assert meta[0:4] == b"DMKP"
            nsec = struct.unpack_from("<I", meta, 4)[0]
            body = meta[8 + 8 * nsec :]
            for k in range(nsec):
                type_index, start, end = struct.unpack_from("<IHH", meta, 8 + 8 * k)
                tname = types[type_index]
                sec = body[start:end]
                sections.append({"type": tname, "start": start, "end": end})
                if tname == "r::FileInfoMetadata":
                    # u32 1 | u32 size | u32 0 | u32 crc32
                    _1, _size, _0, crc32 = struct.unpack_from("<IIII", sec)
                elif tname == "r::ResourceMetadata":
                    # u32 3 | u32 1 | u64 primaryId | u32 N | N × { u32 1, u64 depId }
                    _3, _1, primary_id = struct.unpack_from("<IIQ", sec)
                    N = struct.unpack_from("<I", sec, 16)[0]
                    for d in range(N):
                        _1b, dep_id = struct.unpack_from("<IQ", sec, 20 + 12 * d)
                        deps.append(dep_id)

        files.append({
            "fullname": fullname,
            "total_size": total_size,
            "nchunks": nchunks,
            "chunks": chunks,
            "primary_id": primary_id,
            "crc32": crc32,
            "deps": deps,
            "sections": [s["type"] for s in sections],
        })

    return {
        "toc": toc_path.name,
        "toc_path": str(toc_path),
        "archives": archives,
        "paths_count": paths_count,
        "files": files,
        "types": types,
        "total_chunks": total_chunks,
        "logical_size": len(logical),
    }

def extract_file(toc_dir, archives, file_rec, out_root):
    out_path = out_root / file_rec["fullname"]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    parts = []
    for ch in file_rec["chunks"]:
        arch = archives[ch["archive"]]
        blob_path = (toc_dir / arch["name"]).resolve()
        with open(blob_path, "rb") as f:
            f.seek(ch["blob_off"])
            raw = f.read(ch["comp"] if ch["comp"] else ch["decomp"])
        if ch["comp"]:
            part = lz4.block.decompress(raw, uncompressed_size=ch["decomp"])
        else:
            part = raw
        assert len(part) == ch["decomp"]
        parts.append(part)
    data = b"".join(parts)
    assert len(data) == file_rec["total_size"]
    out_path.write_bytes(data)
    return out_path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", help="path to directory containing .rmdtoc (and .rmdblob)")
    ap.add_argument("--archives", action="store_true", help="print archive names")
    ap.add_argument("--types", action="store_true", help="print type names")
    ap.add_argument("--files", action="store_true", help="print every file (path, size, primary_id, crc32)")
    ap.add_argument("--json", action="store_true", help="emit full structured JSON on stdout")
    ap.add_argument("--extract", metavar="DIR", help="extract all files into DIR (respects paths/names)")
    args = ap.parse_args()

    root = Path(args.root)
    tocs = sorted(root.glob("*.rmdtoc"))
    results = []
    total_files = 0
    total_chunks = 0
    total_archives = 0
    all_types = set()

    for toc in tocs:
        T = parse_toc(toc)
        results.append(T)
        total_files += len(T["files"])
        total_chunks += T["total_chunks"]
        total_archives += len(T["archives"])
        all_types.update(T["types"])

        if not args.json:
            print(f"{toc.name}: files={len(T['files'])} chunks={T['total_chunks']} archives={len(T['archives'])} types={len(T['types'])}")
            if args.archives:
                print(f"  archives: {[a['name'] for a in T['archives']]}")
            if args.types:
                print(f"  types: {T['types']}")
            if args.files:
                for f in T["files"]:
                    pid = f"{f['primary_id']:016x}" if f["primary_id"] is not None else "-"
                    crc = f"{f['crc32']:08x}" if f["crc32"] is not None else "-"
                    print(f"  {f['fullname']}  size={f['total_size']}  primary_id={pid}  crc32={crc}")

        if args.extract:
            out_root = Path(args.extract)
            toc_dir = toc.parent
            for f in T["files"]:
                extract_file(toc_dir, T["archives"], f, out_root)

    if not args.json:
        print(f"TOTAL: {len(tocs)} tocs, {total_files} files, {total_chunks} chunks, {total_archives} archives, {len(all_types)} unique types")

    if args.json:
        out = []
        for T in results:
            out.append({
                "toc": T["toc"],
                "archives": T["archives"],
                "types": T["types"],
                "files": [
                    {
                        "fullname": f["fullname"],
                        "total_size": f["total_size"],
                        "primary_id": f["primary_id"],
                        "crc32": f["crc32"],
                        "nchunks": f["nchunks"],
                        "sections": f["sections"],
                    }
                    for f in T["files"]
                ],
            })
        json.dump({"tocs": out, "total_files": total_files, "total_chunks": total_chunks, "total_archives": total_archives, "unique_types": sorted(all_types)}, sys.stdout, indent=2)
        print()

if __name__ == "__main__":
    main()
