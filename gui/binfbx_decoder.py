#!/usr/bin/env python3

from pathlib import Path
import argparse
import json
import math
import struct
import sys


ATTRIBUTE_SIZES = [4, 8, 12, 16, 4, 4, 4, 4, 8, 4, 8, 16, 8, 8, 1, 4, 2]
PKMD = 0x504B4D44


def u8(buf, off): return buf[off]
def i8(buf, off): return struct.unpack_from("<b", buf, off)[0]
def u16(buf, off): return struct.unpack_from("<H", buf, off)[0]
def i16(buf, off): return struct.unpack_from("<h", buf, off)[0]
def u32(buf, off): return struct.unpack_from("<I", buf, off)[0]
def i32(buf, off): return struct.unpack_from("<i", buf, off)[0]
def u64(buf, off): return struct.unpack_from("<Q", buf, off)[0]
def i64(buf, off): return struct.unpack_from("<q", buf, off)[0]
def f32(buf, off): return struct.unpack_from("<f", buf, off)[0]


class Reader:
    def __init__(self, data, pos=0):
        self.data = data
        self.pos = pos

    def need(self, size):
        if self.pos < 0 or self.pos + size > len(self.data):
            raise RuntimeError(f"read outside BINFBX at 0x{self.pos:X}, size 0x{size:X}")

    def bytes(self, size):
        self.need(size)
        out = self.data[self.pos:self.pos + size]
        self.pos += size
        return out

    def u8(self): self.need(1); x = self.data[self.pos]; self.pos += 1; return x
    def i32(self): self.need(4); x = i32(self.data, self.pos); self.pos += 4; return x
    def u32(self): self.need(4); x = u32(self.data, self.pos); self.pos += 4; return x
    def i64(self): self.need(8); x = i64(self.data, self.pos); self.pos += 8; return x
    def u64(self): self.need(8); x = u64(self.data, self.pos); self.pos += 8; return x
    def f32(self): self.need(4); x = f32(self.data, self.pos); self.pos += 4; return x
    def vec3(self): return (self.f32(), self.f32(), self.f32())
    def vec4(self): return (self.f32(), self.f32(), self.f32(), self.f32())


def parse_mesh_metadata_payload(buf, bin_size):
    r = Reader(buf)
    version = r.i32()
    r.i32()
    bbox_min = r.vec3()
    bbox_max = r.vec3()
    r.i32()
    bound_sphere = r.vec3()
    r.f32()
    has_bones = r.u8() == 1
    r.u8(); r.u8()
    r.i32()
    skeleton_id = r.u64()

    if version < 38:
        n = r.i32()
        if n < 0: raise RuntimeError("negative metadata string length")
        r.bytes(n)

    r.i32()
    n = r.i32()
    if n < 0: raise RuntimeError("negative LOD template path length")
    r.bytes(n)
    r.i32(); r.i32(); r.i32()
    if version >= 38:
        r.i32()

    lod_count = r.i32()
    r.i32(); r.i32()
    layout_version = r.i32()
    cpu_num_bytes = r.i32()
    mesh_cpu_bytes = r.i32()
    streamable_count = r.i32()

    if not 0 < lod_count <= 64:
        raise RuntimeError(f"invalid MeshMetadata LOD count {lod_count}")
    if not 0 <= streamable_count <= lod_count:
        raise RuntimeError(f"invalid MeshMetadata streamable count {streamable_count}")
    if cpu_num_bytes <= 0 or mesh_cpu_bytes < 0 or cpu_num_bytes > bin_size:
        raise RuntimeError("invalid MeshMetadata CPU byte range")
    if mesh_cpu_bytes >= bin_size:
        raise RuntimeError("MeshMetadata MeshCpuBytes outside BINFBX")

    layouts = []
    for i in range(streamable_count + 1):
        lv = r.i32()
        file_offset = r.i32()
        vertex_bytes = r.i32()
        position_bytes = r.i32()
        index_bytes = r.i32()
        r.i32(); r.i32()
        if lv >= 5:
            r.i32(); r.i32()
        r.i32(); r.i32(); r.i32()
        index_stride = r.i32()
        r.i32()
        if min(file_offset, vertex_bytes, position_bytes, index_bytes) < 0:
            raise RuntimeError("negative MeshFileLayout field")
        if file_offset + vertex_bytes + position_bytes + index_bytes > bin_size:
            raise RuntimeError("MeshFileLayout exceeds BINFBX")
        layouts.append((lv, file_offset, vertex_bytes, position_bytes, index_bytes, index_stride, i < streamable_count))

    r.u8()
    submesh_count = r.i32()
    if submesh_count < 0 or submesh_count > 100000:
        raise RuntimeError("invalid submesh count")
    submesh_ids = []
    for _ in range(submesh_count):
        r.i32(); submesh_ids.append(r.u64())

    if version >= 38:
        r.i32()
    r.i32(); geometry_transform_shader_id = r.u64()
    if version >= 38:
        r.i32()

    return {
        "version": version,
        "bbox_min": bbox_min,
        "bbox_max": bbox_max,
        "bound_sphere": bound_sphere,
        "has_bones": has_bones,
        "skeleton_id": skeleton_id,
        "lod_count": lod_count,
        "cpu_num_bytes": cpu_num_bytes,
        "mesh_cpu_bytes": mesh_cpu_bytes,
        "layouts": layouts,
        "layout_version": layout_version,
        "geometry_transform_shader_id": geometry_transform_shader_id,
        "submesh_ids": submesh_ids,
    }


def parse_metadata(path, bin_size):
    # A sidecar may be either the metadata payload itself or a PKMD container.
    # PKMD records use relative uint16 ranges into one shared payload area, so
    # each candidate must be structurally parsed before it can be selected.
    buf = path.read_bytes()
    if len(buf) < 4:
        raise RuntimeError(f"{path}: metadata is too small")

    if u32(buf, 0) != PKMD:
        return parse_mesh_metadata_payload(buf, bin_size)

    if len(buf) < 8:
        raise RuntimeError(f"{path}: truncated PKMD")
    count = i32(buf, 4)
    if count <= 0 or 8 + count * 8 > len(buf):
        raise RuntimeError(f"{path}: invalid PKMD record count {count}")

    data_start = 8 + count * 8
    candidates = []
    for i in range(count):
        type_index = i32(buf, 8 + i * 8)
        start = data_start + u16(buf, 12 + i * 8)
        end = data_start + u16(buf, 14 + i * 8)
        if start < data_start or end < start or end > len(buf):
            continue
        try:
            meta = parse_mesh_metadata_payload(buf[start:end], bin_size)
        except Exception:
            continue
        score = 0
        if meta["version"] >= 30: score += 2
        if meta["lod_count"] > 0: score += 2
        if meta["cpu_num_bytes"] > meta["mesh_cpu_bytes"]: score += 2
        if meta["layouts"][-1][5] in (2, 4): score += 1
        if meta["skeleton_id"] or not meta["has_bones"]: score += 1
        candidates.append((score, i, type_index, meta))

    if not candidates:
        raise RuntimeError(f"{path}: no PKMD record parses as rend::MeshMetadata")
    candidates.sort(key=lambda x: x[0], reverse=True)
    if len(candidates) > 1 and candidates[0][0] == candidates[1][0]:
        raise RuntimeError(f"{path}: ambiguous PKMD MeshMetadata records")
    return candidates[0][3]


def layout_for_lod(meta, lod):
    layouts = meta["layouts"]
    streamable = sum(1 for x in layouts if x[6])
    return layouts[lod] if lod < streamable else layouts[-1]


def parse_binfbx(path, meta):
    # The BINFBX CPU header begins at the byte offset declared by MeshMetadata.
    # The remainder of the file contains the physical vertex/index regions.
    buf = path.read_bytes()
    r = Reader(buf, meta["mesh_cpu_bytes"])
    version = r.u32()
    if version != 0x4E and not 0x57 <= version <= 0x5C:
        raise RuntimeError(f"unsupported Resonant BINFBX version 0x{version:X}")
    lod_count = r.i32()
    skeleton_lod_count = r.i32()
    bone_set_count = r.i32()
    if lod_count <= 0 or lod_count > 64: raise RuntimeError("invalid BINFBX LOD count")
    if bone_set_count < 0 or bone_set_count > 10000: raise RuntimeError("invalid bone set count")

    bone_set_counts = [r.i32() for _ in range(bone_set_count)]
    if any(x < 0 for x in bone_set_counts): raise RuntimeError("negative bone-set count")
    bone_count = sum(bone_set_counts)

    if version == 0x4E:
        for count in bone_set_counts:
            for _ in range(count):
                n = r.i32()
                if n < 0: raise RuntimeError("negative bone name length")
                r.bytes(n + 68)
        geometry_shader_id = 0
    else:
        r.bytes(4 * bone_set_count)
        name_buffer_size = r.i32()
        if name_buffer_size < 0: raise RuntimeError("negative bone name buffer")
        if bone_set_count: r.bytes(name_buffer_size)
        r.bytes(72 * bone_count)
        r.u64()
        geometry_shader_id = r.u64()
        r.u64()

    # The first palette maps mesh-local bone indices to skeleton bone indices.
    # Later palettes belong to other LODs and are not needed for vertex decoding.
    bone_map = []
    if skeleton_lod_count > 0:
        for _ in range(skeleton_lod_count):
            count = r.i32(); r.i32()
            if count < 0: raise RuntimeError("negative skeleton LOD count")
            r.bytes(48 * count)
            r.bytes(4 * count); r.bytes(4 * count); r.bytes(4 * count)
            r.bytes(8 * ((count + 63) // 64))
            count0 = r.i64()
            if count0 < 0: raise RuntimeError("negative skeleton table count")
            r.bytes(4 * count0)
        for lod in range(lod_count):
            n = r.i32()
            if n < 0: raise RuntimeError("negative palette count")
            palette = [r.i32() for _ in range(n)]
            inv_n = r.i32()
            if inv_n < 0: raise RuntimeError("negative inverse palette count")
            r.bytes(4 * inv_n)
            if lod == 0: bone_map = palette
        extra = r.i32()
        if extra < 0: raise RuntimeError("negative skeleton extra size")
        if extra: r.i32(); r.bytes(extra)

    r.f32()
    distance_count = r.i32()
    if distance_count < 0 or distance_count > 64: raise RuntimeError("invalid LOD distance count")
    distances = [r.f32() for _ in range(distance_count)]
    r.f32()
    sphere = r.vec4()
    bounds_min = r.vec3()
    bounds_max = r.vec3()
    lod_spheres = [r.vec4() for _ in range(lod_count)]

    if skeleton_lod_count > 0 and geometry_shader_id not in (0, 1, 0xFFFFFFFFFFFFFFFF):
        r.bytes(40)

    # Material indices stored by primitives refer to entries in the material ID table.
    material_count = r.i32()
    if material_count < 0 or material_count > 100000: raise RuntimeError("invalid material count")
    material_ids = [r.u64() for _ in range(material_count)]
    material_index_count = r.i32()
    if material_index_count < 0 or material_index_count > 100000: raise RuntimeError("invalid material index count")
    primary_materials = [r.i32() for _ in range(material_index_count)]

    variants = [("default", primary_materials)]
    variant_count = r.i32()
    if variant_count < 0 or variant_count > 10000: raise RuntimeError("invalid variant count")
    for _ in range(variant_count):
        n = r.i32()
        if n < 0 or n > 1_000_000: raise RuntimeError("invalid variant name length")
        name = r.bytes(n).decode("utf-8", "replace").rstrip("\0")
        variants.append((name, [r.i32() for _ in range(material_index_count)]))

    if version >= 0x58:
        n = r.i32()
        if n < 0: raise RuntimeError("negative v58 table count")
        r.bytes(4 * n)
    if version >= 0x54: r.u8()
    if version >= 0x59: r.u8()
    if version >= 0x5B:
        n = r.i32()
        if n < 0: raise RuntimeError("negative v5B table count")
        r.bytes(n * (20 if version >= 0x5C else 16))

    primitive_count = r.i32()
    if primitive_count < 0 or primitive_count > 1_000_000: raise RuntimeError("invalid primitive count")
    # Attribute offsets are built from the declarations rather than assuming a
    # fixed vertex stride; position-only and regular vertex streams are separate.
    primitives = []
    for i in range(primitive_count):
        lod = r.i32(); vertex_count = r.i32(); face_count = r.i32()
        r.i32(); r.i32()
        face_index_size = r.i32(); face_offset = r.i32(); influence_count = r.i32()
        ps = r.vec4(); pmin = r.vec3(); pmax = r.vec3()
        r.i32()
        attr_count = r.u8()
        attrs = []
        vpos = 0; vsize = 0
        for _ in range(attr_count):
            position_attribute = r.u8() == 0
            data_type = r.u8(); usage = r.u8(); r.u8()
            if data_type >= len(ATTRIBUTE_SIZES): raise RuntimeError(f"unknown attribute datatype {data_type}")
            size = ATTRIBUTE_SIZES[data_type]
            offset = vpos if position_attribute else vsize
            attrs.append({"position": position_attribute, "type": data_type, "usage": usage, "offset": offset, "size": size})
            if position_attribute: vpos += size
            else: vsize += size
        r.i32(); r.f32(); r.u8(); r.i32(); r.i32(); r.i32()
        if version == 0x4E:
            r.i32(); r.i32(); r.i32(); r.i32()
        else:
            if version >= 0x5A: r.i32()
            r.i32()
        r.u8()
        opacity_count = r.i32()
        if opacity_count < 0: raise RuntimeError("negative opacity micromap count")
        r.bytes((40 if version == 0x4E else 36) * opacity_count)
        primitives.append({
            "index": i, "lod": lod, "vertex_count": vertex_count, "face_count": face_count,
            "face_index_size": face_index_size, "face_offset": face_offset,
            "influence_count": influence_count, "sphere": ps, "min": pmin, "max": pmax,
            "vpos": vpos, "vsize": vsize, "attrs": attrs,
        })

    trailer = r.u32()
    if r.pos != meta["cpu_num_bytes"]:
        raise RuntimeError(f"BINFBX CPU header ends at 0x{r.pos:X}, metadata says 0x{meta['cpu_num_bytes']:X}")

    return {
        "data": buf, "version": version, "lod_count": lod_count,
        "skeleton_lod_count": skeleton_lod_count, "bone_map": bone_map,
        "sphere": sphere, "bounds_min": bounds_min, "bounds_max": bounds_max,
        "lod_spheres": lod_spheres, "material_ids": material_ids,
        "primary_materials": primary_materials, "variants": variants,
        "primitives": primitives, "trailer": trailer,
    }


def assign_lod_offsets(mesh, meta):
    # Multiple LODs can share one physical buffer region.  Within such a region
    # their vertex records are packed from the highest LOD number downward.
    lod_prims = [[] for _ in range(mesh["lod_count"])]
    for p in mesh["primitives"]:
        if not 0 <= p["lod"] < mesh["lod_count"]:
            raise RuntimeError(f"primitive {p['index']} has invalid LOD {p['lod']}")
        lod_prims[p["lod"]].append(p)

    layouts = [layout_for_lod(meta, i) for i in range(mesh["lod_count"])]
    groups = {}
    for lod, layout in enumerate(layouts):
        groups.setdefault(layout[1], []).append(lod)

    for group in groups.values():
        vertex_offset = 0
        position_offset = 0
        for lod in sorted(group, reverse=True):
            for p in lod_prims[lod]:
                p["vertex_offset"] = vertex_offset
                p["position_offset"] = position_offset
            if lod_prims[lod]:
                vertex_offset += lod_prims[lod][0]["vertex_count"] * lod_prims[lod][0]["vsize"]
                position_offset += lod_prims[lod][0]["vertex_count"] * lod_prims[lod][0]["vpos"]
    return lod_prims, layouts


def attr_for(p, usage):
    for a in p["attrs"]:
        if a["usage"] == usage:
            return a
    return None


def attr_value(data, base, stride, a, vertex, component=0):
    off = base + vertex * stride + a["offset"]
    dt = a["type"]
    if dt in (0, 1, 2, 3): return f32(data, off + component * 4)
    if dt == 4: return data[off + component] / 255.0
    if dt == 5: return data[off + component]
    if dt in (7, 8): return i16(data, off + component * 2)
    if dt == 13: return u16(data, off + component * 2)
    if dt == 15: return u32(data, off)
    raise RuntimeError(f"unsupported attribute datatype {dt} (usage {a['usage']})")


def oct_decode(x, y):
    z = 1.0 - abs(x) - abs(y)
    if z < 0:
        x, y = ((1 - abs(y)) * (1 if x >= 0 else -1),
                (1 - abs(x)) * (1 if y >= 0 else -1))
    n = math.sqrt(x*x + y*y + z*z)
    return (x/n, y/n, z/n) if n > 1e-12 else (0, 0, 1)


def decode_vertex(mesh, p, vertex_index, vertex_bytes, position_bytes):
    # Positions are quantized int16 values around the LOD sphere; the fourth
    # component is reused as one component of the octahedrally encoded normal.
    pos = attr_for(p, 0)
    if pos is None: raise RuntimeError(f"primitive {p['index']} has no POSITION")
    pos_data = position_bytes if pos["position"] else vertex_bytes
    pos_base = p["position_offset"] if pos["position"] else p["vertex_offset"]
    pos_stride = p["vpos"] if pos["position"] else p["vsize"]
    if pos["type"] != 8 or pos["size"] < 8:
        raise RuntimeError(f"primitive {p['index']}: unsupported POSITION datatype {pos['type']}")
    q = [attr_value(pos_data, pos_base, pos_stride, pos, vertex_index, i) / 32767.0 for i in range(4)]
    s = mesh["lod_spheres"][p["lod"]]
    position = ((q[0]*s[3]+s[0])*100.0, (q[1]*s[3]+s[1])*100.0, (q[2]*s[3]+s[2])*100.0)

    uv_a = attr_for(p, 2)
    uv = (0.0, 0.0)
    if uv_a:
        uv_data = position_bytes if uv_a["position"] else vertex_bytes
        uv_base = p["position_offset"] if uv_a["position"] else p["vertex_offset"]
        uv_stride = p["vpos"] if uv_a["position"] else p["vsize"]
        if uv_a["type"] == 7:
            uv = (attr_value(uv_data, uv_base, uv_stride, uv_a, vertex_index, 0) * 0.000244200258748606,
                  attr_value(uv_data, uv_base, uv_stride, uv_a, vertex_index, 1) * 0.000244200258748606)
        elif uv_a["type"] in (0, 1, 2, 3):
            uv = (attr_value(uv_data, uv_base, uv_stride, uv_a, vertex_index, 0),
                  attr_value(uv_data, uv_base, uv_stride, uv_a, vertex_index, 1))
        else:
            raise RuntimeError(f"primitive {p['index']}: unsupported TEXCOORD datatype {uv_a['type']}")

    normal = (0.0, 0.0, 1.0)
    normal_a = attr_for(p, 1)
    if normal_a:
        # The packed normal stores one octahedral component in the vertex stream;
        # the second component comes from the fourth quantized position value.
        if normal_a["type"] != 15: raise RuntimeError("unsupported NORMAL datatype")
        packed = attr_value(vertex_bytes, p["vertex_offset"], p["vsize"], normal_a, vertex_index)
        ny = (packed & 0x3FF) / 1023.0 * 2.0 - 1.0
        normal = oct_decode(q[3], ny)
    return position, normal, uv


def decode_skin(mesh, p, vertex_index, vertex_bytes, position_bytes):
    # Each BLENDINDICES declaration supplies a four-influence group.  A rigid
    # declaration stores one packed index and implicitly gives it full weight.
    index_attrs = [a for a in p["attrs"] if a["usage"] == 5]
    weight_attrs = [a for a in p["attrs"] if a["usage"] == 6]
    if not index_attrs: return [], []
    joints = []; weights = []
    for group, a in enumerate(index_attrs):
        data = position_bytes if a["position"] else vertex_bytes
        base = p["position_offset"] if a["position"] else p["vertex_offset"]
        stride = p["vpos"] if a["position"] else p["vsize"]
        off = base + vertex_index * stride + a["offset"]
        rigid = a["type"] == 15
        if rigid:
            vals = [u32(data, off), 0, 0, 0]
            ws = [1.0, 0.0, 0.0, 0.0]
        elif a["type"] == 5:
            vals = [data[off+i] for i in range(4)]
            if group < len(weight_attrs):
                w = weight_attrs[group]
                wd = position_bytes if w["position"] else vertex_bytes
                wb = p["position_offset"] if w["position"] else p["vertex_offset"]
                wsx = p["vpos"] if w["position"] else p["vsize"]
                wo = wb + vertex_index * wsx + w["offset"]
                ws = [wd[wo+i] / 255.0 for i in range(4)]
            else:
                ws = [0.0]*4
        else:
            raise RuntimeError(f"unsupported BLENDINDICES datatype {a['type']}")
        joints.extend(vals); weights.extend(ws)
    bone_map = mesh["bone_map"]
    if bone_map:
        joints = [bone_map[x] if 0 <= x < len(bone_map) else x for x in joints]
    # This exporter uses glTF's first four joint/weight channels.  If the
    # source contains more influences, keep the strongest source order here
    # and renormalize the retained weights so the vertex remains valid.
    joints = joints[:4] + [0]*max(0, 4-len(joints))
    weights = weights[:4] + [0.0]*max(0, 4-len(weights))
    total = sum(weights)
    if total > 1e-12: weights = [w/total for w in weights]
    return joints, weights


def parse_skeleton(path):
    # Skeleton tables are referenced through an offset table.  Bind-pose
    # transforms are converted to the same centimetre-scale convention used
    # by the mesh positions before being written to glTF.
    b = path.read_bytes(); r = Reader(b)
    r.pos = (r.pos + 19) & ~15
    literal_start = r.pos
    start = literal_start + r.u32(); end = start + r.i32(); offset_count = r.i32()
    offsets = [r.u32() for _ in range(offset_count)]
    real_offsets = []
    for x in offsets:
        r.pos = start + x
        real_offsets.append(start + r.i64())
    if len(real_offsets) < 3: raise RuntimeError("BINSKELETON missing required tables")
    r.pos = start
    bone_count = r.i32(); r.f32()
    bones = []
    r.pos = real_offsets[0]
    for i in range(bone_count):
        q = r.vec4(); p = r.vec4()
        bones.append({"name": f"bone_{i}", "parent": -1, "rotation": q, "translation": (p[0]*100, p[1]*100, p[2]*100)})
    r.pos = real_offsets[1]
    parents = [i16(b, r.pos + 2*i) for i in range(bone_count)]
    r.pos = real_offsets[2]
    for i in range(bone_count):
        bones[i]["name"] = f"bone_{r.u32()}"
    ext = (end + 15) & ~15
    r.pos = ext
    r.pos = ext + r.u32()
    names_start = r.pos
    name_table_offset = r.i64(); name_count = r.i32()
    pointers = [i64(b, r.pos + 8*i) for i in range(name_count)]
    for i in range(min(name_count, bone_count)):
        q = names_start + pointers[i]
        z = b.find(b"\0", q)
        if z >= 0: bones[i]["name"] = b[q:z].decode("utf-8", "replace")
    for i, parent in enumerate(parents): bones[i]["parent"] = parent
    return bones


def quat_matrix(q):
    x,y,z,w=q
    return [[1-2*y*y-2*z*z, 2*x*y-2*z*w, 2*x*z+2*y*w, 0],
            [2*x*y+2*z*w, 1-2*x*x-2*z*z, 2*y*z-2*x*w, 0],
            [2*x*z-2*y*w, 2*y*z+2*x*w, 1-2*x*x-2*y*y, 0],
            [0,0,0,1]]


def mat_mul(a,b):
    return [[sum(a[i][k]*b[k][j] for k in range(4)) for j in range(4)] for i in range(4)]


def mat_inverse(m):
    a=[row[:] for row in m]; inv=[[1 if i==j else 0 for j in range(4)] for i in range(4)]
    for c in range(4):
        pivot=max(range(c,4),key=lambda r:abs(a[r][c]))
        if abs(a[pivot][c]) < 1e-12: raise RuntimeError("singular skeleton bind matrix")
        a[c],a[pivot]=a[pivot],a[c]; inv[c],inv[pivot]=inv[pivot],inv[c]
        d=a[c][c]
        for j in range(4): a[c][j]/=d; inv[c][j]/=d
        for r in range(4):
            if r==c: continue
            d=a[r][c]
            for j in range(4): a[r][j]-=d*a[c][j]; inv[r][j]-=d*inv[c][j]
    return inv


def skeleton_matrices(bones):
    # glTF wants inverse bind matrices in global space, so first accumulate the
    # local bone transforms through the parent hierarchy and then invert them.
    local=[]; world=[]
    for b in bones:
        m=quat_matrix(b["rotation"])
        m[3][0],m[3][1],m[3][2]=b["translation"]
        local.append(m)
    for i,b in enumerate(bones):
        world.append(mat_mul(local[b["parent"]], world[b["parent"]]) if b["parent"] >= 0 else local[i])
    return [mat_inverse(m) for m in world]


def f32_bytes(values): return struct.pack("<%sf" % len(values), *values)
def u16_bytes(values): return struct.pack("<%sH" % len(values), *values)
def u32_bytes(values): return struct.pack("<%sI" % len(values), *values)


def collect_geometry(mesh, meta, lod, variant_name):
    lod_prims, layouts = assign_lod_offsets(mesh, meta)
    if lod < 0 or lod >= mesh["lod_count"]: raise RuntimeError("LOD outside range")
    selected = lod_prims[lod]
    if not selected: raise RuntimeError(f"LOD {lod} has no primitives")
    mapping = dict(mesh["variants"])[variant_name]
    layout = layouts[lod]
    _, file_offset, vertex_bytes_n, position_bytes_n, index_bytes_n, index_stride, _ = layout
    data = mesh["data"]
    a=file_offset; b=a+vertex_bytes_n; c=b+position_bytes_n; d=c+index_bytes_n
    if d > len(data): raise RuntimeError("LOD buffer region outside BINFBX")
    vertex_bytes=data[a:b]; position_bytes=data[b:c]; index_bytes=data[c:d]

    positions=[]; normals=[]; uvs=[]; joints=[]; weights=[]; primitives=[]
    for p in selected:
        if p["face_index_size"] not in (2,4): raise RuntimeError("unsupported face index size")
        end=p["face_offset"]*p["face_index_size"]+p["face_count"]*3*p["face_index_size"]
        if end > len(index_bytes): raise RuntimeError(f"primitive {p['index']} index range outside LOD")
        local={}; indices=[]
        for tri in range(p["face_count"]):
            face=[]
            off=p["face_offset"]*p["face_index_size"]+tri*3*p["face_index_size"]
            for j in range(3):
                o=off+j*p["face_index_size"]
                gi=u16(index_bytes,o) if p["face_index_size"]==2 else i32(index_bytes,o)
                if not 0 <= gi < p["vertex_count"]: raise RuntimeError(f"primitive {p['index']} index {gi} outside vertex_count")
                if gi not in local:
                    pos,n,uv=decode_vertex(mesh,p,gi,vertex_bytes,position_bytes)
                    local[gi]=len(positions); positions.append(pos); normals.append(n); uvs.append(uv)
                    jn,ww=decode_skin(mesh,p,gi,vertex_bytes,position_bytes); joints.append(jn); weights.append(ww)
                face.append(local[gi])
            indices.extend(face)
        material_slot=mapping[p["index"]] if p["index"] < len(mapping) else 0
        primitives.append({"indices":indices,"material":material_slot,"source":p["index"]})
    return {"positions":positions,"normals":normals,"uvs":uvs,"joints":joints,"weights":weights,"primitives":primitives}


def pad4(buf):
    while len(buf)%4: buf.append(0)


def make_glb(path, meshes, materials, bones=None):
    # Build a self-contained binary glTF: JSON describes the scene while one
    # BIN chunk stores every accessor payload with four-byte alignment.
    blob=bytearray(); views=[]; accessors=[]
    def add(data,target=None):
        pad4(blob); off=len(blob); blob.extend(data)
        v={"buffer":0,"byteOffset":off,"byteLength":len(data)}
        if target is not None: v["target"]=target
        views.append(v); return len(views)-1
    def accessor(view, comp, count, typ, minimum=None, maximum=None, normalized=False):
        x={"bufferView":view,"componentType":comp,"count":count,"type":typ}
        if minimum is not None:x["min"]=list(minimum)
        if maximum is not None:x["max"]=list(maximum)
        if normalized:x["normalized"]=True
        accessors.append(x); return len(accessors)-1

    # Material resource contents are intentionally not resolved here; stable
    # material slots are emitted so geometry keeps its source material identity.
    gltf_materials=[]
    for name in materials:
        gltf_materials.append({"name":name,"pbrMetallicRoughness":{"baseColorFactor":[0.8,0.8,0.8,1.0],"metallicFactor":0.0,"roughnessFactor":1.0}})

    gltf_meshes=[]; nodes=[]
    for mi,mesh in enumerate(meshes):
        pos=mesh["positions"]; nor=mesh["normals"]; uv=mesh["uvs"]
        pa=accessor(add(f32_bytes([v for p in pos for v in p]),34962),5126,len(pos),"VEC3",
                     [min(p[i] for p in pos) for i in range(3)],[max(p[i] for p in pos) for i in range(3)])
        na=accessor(add(f32_bytes([v for p in nor for v in p]),34962),5126,len(nor),"VEC3")
        ua=accessor(add(f32_bytes([v for p in uv for v in p]),34962),5126,len(uv),"VEC2")
        attrs={"POSITION":pa,"NORMAL":na,"TEXCOORD_0":ua}
        skin_index=None
        # Skin attributes are emitted only when decoded joint data is present.
        if bones is not None and any(mesh["joints"]):
            jb=[x for j in mesh["joints"] for x in (j[:4]+[0]*max(0,4-len(j)))]
            wb=[x for w in mesh["weights"] for x in (w[:4]+[0.0]*max(0,4-len(w)))]
            attrs["JOINTS_0"]=accessor(add(bytes(jb),34962),5121,len(mesh["joints"]),"VEC4")
            attrs["WEIGHTS_0"]=accessor(add(f32_bytes(wb),34962),5126,len(mesh["weights"]),"VEC4")
        gltf_prims=[]
        for p in mesh["primitives"]:
            inds=p["indices"]
            ia=accessor(add(u32_bytes(inds),34963),5125,len(inds),"SCALAR")
            gltf_prims.append({"attributes":attrs,"indices":ia,"material":p["material"],"mode":4})
        gltf_meshes.append({"name":mesh["name"],"primitives":gltf_prims})

    skin=None
    if bones is not None:
        inv=skeleton_matrices(bones)
        flat=[]
        for m in inv:
            flat.extend(m[r][c] for c in range(4) for r in range(4))
        ia=accessor(add(f32_bytes(flat)),5126,len(bones),"MAT4")
        skin={"joints":list(range(len(bones))),"inverseBindMatrices":ia,"skeleton":0}
        for i,b in enumerate(bones):
            n={"name":b["name"],"translation":list(b["translation"]),"rotation":list(b["rotation"]),"scale":[1,1,1]}
            nodes.append(n)
        for i,b in enumerate(bones):
            if b["parent"]>=0:nodes[b["parent"]].setdefault("children",[]).append(i)

    mesh_nodes=[]
    for i,m in enumerate(gltf_meshes):
        node={"name":m["name"],"mesh":i}
        if skin is not None: node["skin"]=0
        nodes.append(node); mesh_nodes.append(len(nodes)-1)

    scene_roots=[]
    if bones:
        scene_roots.extend(i for i,b in enumerate(bones) if b["parent"]<0)
    scene_roots.extend(mesh_nodes)
    gltf={"asset":{"version":"2.0","generator":"CONTROL Resonant BINFBX parser"},
          "buffers":[{"byteLength":len(blob)}],"bufferViews":views,"accessors":accessors,
          "materials":gltf_materials,"meshes":gltf_meshes,"nodes":nodes,
          "scenes":[{"nodes":scene_roots}],"scene":0}
    if skin is not None:gltf["skins"]=[skin]

    # The GLB container requires both JSON and BIN chunks to start on four-byte
    # boundaries; padding is not part of the logical accessor data.
    json_bytes=json.dumps(gltf,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    while len(json_bytes)%4: json_bytes += b" "
    pad4(blob)
    json_chunk=struct.pack("<I4s",len(json_bytes),b"JSON")+json_bytes
    bin_chunk=struct.pack("<I4s",len(blob),b"BIN ")+bytes(blob)
    total=12+len(json_chunk)+len(bin_chunk)
    header=struct.pack("<III",0x46546C67,2,total)
    path.write_bytes(header+json_chunk+bin_chunk)


def main():
    ap=argparse.ArgumentParser(description="CONTROL Resonant 2026 BINFBX parser + Blender GLB converter")
    ap.add_argument("binfbx",type=Path,help="Resonant .binfbx")
    ap.add_argument("--meta",type=Path,default=None,help="metadata sidecar; default: <file>.binfbx.meta")
    ap.add_argument("--skeleton",type=Path,default=None,help="optional .binskeleton for skinned export")
    ap.add_argument("--lod",type=int,default=0,help="LOD to export")
    ap.add_argument("--all-lods",action="store_true",help="put all non-empty LODs into one GLB")
    ap.add_argument("--variant",default="default",help="material variant")
    ap.add_argument("--all-variants",action="store_true",help="export all material variants into one GLB")
    ap.add_argument("--output",type=Path,default=None,help="output .glb; default next to input")
    args=ap.parse_args()

    if not args.binfbx.is_file(): ap.error(f"file not found: {args.binfbx}")
    meta_path=args.meta
    if meta_path is None:
        for p in (Path(str(args.binfbx)+".meta"),args.binfbx.with_suffix(".meta")):
            if p.is_file(): meta_path=p; break
    if meta_path is None: ap.error("no .meta sidecar found; extract it with 1_with_metadata.py")

    meta=parse_metadata(meta_path,args.binfbx.stat().st_size)
    mesh=parse_binfbx(args.binfbx,meta)
    if args.variant not in dict(mesh["variants"]) and not args.all_variants: ap.error(f"unknown variant: {args.variant}")

    skeleton=None
    if args.skeleton:
        skeleton=parse_skeleton(args.skeleton)
    elif meta["has_bones"] or meta["skeleton_id"]:
        hits=list(args.binfbx.parent.rglob("*.binskeleton"))
        if len(hits)==1:
            skeleton=parse_skeleton(hits[0])
        elif hits:
            print("WARNING: multiple .binskeleton files found; use --skeleton to select one",file=sys.stderr)

    lods=list(range(mesh["lod_count"])) if args.all_lods else [args.lod]
    variants=[name for name,_ in mesh["variants"]] if args.all_variants else [args.variant]
    meshes=[]; material_names=[]
    for variant in variants:
        for lod in lods:
            geo=collect_geometry(mesh,meta,lod,variant)
            geo["name"]=f"{args.binfbx.stem}_{variant}_lod{lod}"
            meshes.append(geo)
            for p in geo["primitives"]:
                slot=p["material"]
                rid=mesh["material_ids"][slot] if 0<=slot<len(mesh["material_ids"]) else 0
                name=f"material_{slot}_{rid:016X}"
                p["material"]=len(material_names) if name not in material_names else material_names.index(name)
                if name not in material_names: material_names.append(name)

    output=args.output or args.binfbx.with_suffix(".glb")
    make_glb(output,meshes,material_names,skeleton)
    print("="*100)
    print("CONTROL RESONANT BINFBX -> BLENDER GLB")
    print("="*100)
    print(f"BINFBX = {args.binfbx}")
    print(f"VERSION = 0x{mesh['version']:X}")
    print(f"LODs    = {len(lods)}")
    print(f"VARIANTS= {len(variants)}")
    print(f"MESHES  = {len(meshes)}")
    print(f"MATERIALS = {len(material_names)}")
    print(f"SKELETON = {len(skeleton) if skeleton else 0} bones")
    print(f"OUTPUT  = {output}")


if __name__ == "__main__":
    main()

