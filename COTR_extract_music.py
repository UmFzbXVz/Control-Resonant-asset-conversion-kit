#!/usr/bin/env python3
"""
extract_music_audio.py - extract Control's music / ambience / stinger / bed audio (NOT sfx, footsteps, gunfire or dialogue)

  python3 extract_music_audio.py <folder with .rmdtoc/.rmdblob> --out music_out
  python3 extract_music_audio.py <folder> --list                       # only print what would be extracted (counts, sizes)
  python3 extract_music_audio.py <folder> --categories music,ambience  # strict
  Categories: music, stingers, ambience, beds, environment   (default: all five)

Data model (all verified on the TOC metadata): Wwise media are data_pc/audio/media/<mediaID>.wem; each .bnk lists the media it needs as
DMKP dependencies; each .sndevent (a 0-byte file) lists its bank. So  event --> bank --> wem  needs no HIRC parsing.
Classification of an event/bank (a wem can belong to several; it is written once, under the strongest category):
  music        event/bank name has a 'mus'/'music' token, OR the bank's HIRC contains Music Segment/Track/Switch/Playlist objects (types 10-13)
  stingers     name has 'stinger'/'sting' (music stings; written under stingers/)
  ambience     token amb / ambience / ambient / atmos / atmosphere   (long beds, zone ambience)
  beds         token bed / drone
  environment  token env  (environment emitters, e.g. aircon hum)       -- disable with --categories or --strict
  Excluded unless music: dialogue/radio/foley/footstep/impact/damage/explosion/weapon/projectile/ui/menu tokens.
Every written file is listed in manifest.csv (category, event, bank, mediaID, bytes, path, best-effort duration). .wem is Wwise: use vgmstream/ww2ogg to convert.
"""
import argparse, collections, csv, os, re, sys
# ====== embedded library (RMDTOC/RMDBLOB reader) ======
import collections, glob, json, os, re, struct, sys, zlib

U32 = lambda b, p: struct.unpack_from('<I', b, p)[0]
U64 = lambda b, p: struct.unpack_from('<Q', b, p)[0]
NONE_RID = 0xFFFFFFFFFFFFFFFF
MARKER = b'\x3f\xb3\x4d\xd3'

# ------------------------------------------------------------------------------------------------ LZ4 (block)
try:
    import lz4.block as _lz4block                      
    def lz4_block(src, dsz):
        return _lz4block.decompress(src, uncompressed_size=dsz)
except Exception:
    def lz4_block(src, dsz):
        out = bytearray(); i = 0; n = len(src)
        while i < n:
            t = src[i]; i += 1
            ll = t >> 4
            if ll == 15:
                while True:
                    x = src[i]; i += 1; ll += x
                    if x != 255: break
            out += src[i:i + ll]; i += ll
            if i >= n: break
            off = src[i] | (src[i + 1] << 8); i += 2
            ml = t & 15
            if ml == 15:
                while True:
                    x = src[i]; i += 1; ml += x
                    if x != 255: break
            ml += 4; st = len(out) - off
            if off >= ml: out += out[st:st + ml]
            else:
                for k in range(ml): out.append(out[st + k])
        if len(out) != dsz: raise ValueError('LZ4: got %d bytes, expected %d' % (len(out), dsz))
        return bytes(out)

# ------------------------------------------------------------------------------------------------ RMDTOC
class Toc:
    """COTR v3: header -> LZ4 segment table -> logical image -> archives/paths/files/chunks/types/metadata."""
    def __init__(self, path):
        self.path = path
        b = open(path, 'rb').read()
        if b[:4] != b'COTR': raise ValueError('%s: not an RMDTOC (no COTR magic)' % path)
        H = dict(table_off=U32(b, 8), table_size=U32(b, 0xC), archives_off=U32(b, 0x10), archives_count=U32(b, 0x14),
                 paths_off=U32(b, 0x18), paths_count=U32(b, 0x1C), files_off=U32(b, 0x20), files_count=U32(b, 0x24),
                 strings_off=U32(b, 0x28), strings_size=U32(b, 0x2C), types_off=U32(b, 0x30), types_count=U32(b, 0x34),
                 metadata_off=U32(b, 0x38), metadata_size=U32(b, 0x3C), chunks_off=U32(b, 0x50), chunks_size=U32(b, 0x54))
        self.H = H
        L = bytearray()
        for i in range(H['table_size'] // 16):                 # descriptor: u40 off @+3, u32 decomp @+8, u32 comp @+12
            e = H['table_off'] + i * 16
            off = int.from_bytes(b[e + 3:e + 8], 'little'); ds = U32(b, e + 8); cs = U32(b, e + 12)
            raw = b[off:off + (cs or ds)]
            L += lz4_block(raw, ds) if cs else raw
        self.L = bytes(L)
        S = lambda o, s: self.L[H['strings_off'] + o:H['strings_off'] + o + s].decode('utf8', 'replace')
        self.types = [S(U32(self.L, H['types_off'] + 8 * i), U32(self.L, H['types_off'] + 8 * i + 4)) for i in range(H['types_count'])]
        self.archives = [S(U32(self.L, H['archives_off'] + i * 0x18), U32(self.L, H['archives_off'] + i * 0x18 + 4)) for i in range(H['archives_count'])]
        paths = []
        for i in range(H['paths_count']):
            p = H['paths_off'] + i * 0x1C
            paths.append((U32(self.L, p), S(U32(self.L, p + 0x14), U32(self.L, p + 0x18))))
        cache = {}
        def full(i):
            if i in cache: return cache[i]
            parts = []; seen = set(); cur = i
            while cur not in seen:
                seen.add(cur); nm = paths[cur][1]
                if nm and not nm.endswith('.rmdblob'): parts.append(nm)
                par = paths[cur][0]
                if par == cur or par >= len(paths): break
                cur = par
            cache[i] = '/'.join(reversed(parts)); return cache[i]
        self.files = {}
        for i in range(H['files_count']):
            p = H['files_off'] + i * 0x20
            cr, cb, pi, no, ns, ts, mr, ms = struct.unpack_from('<8I', self.L, p)
            self.files[full(pi) + '/' + S(no, ns)] = dict(chunk_rel=cr, chunk_bytes=cb, size=ts, meta_rel=mr, meta_size=ms)

    def meta_sections(self, name):
        """yield (className, bytes) for every DMKP section of a file."""
        rec = self.files[name]
        if rec['meta_size'] < 8: return
        raw = self.L[self.H['metadata_off'] + rec['meta_rel']:self.H['metadata_off'] + rec['meta_rel'] + rec['meta_size']]
        if raw[:4] != b'DMKP': return
        n = U32(raw, 4); body = 8 + 8 * n
        for i in range(n):
            k = U32(raw, 8 + 8 * i); s, e = struct.unpack_from('<HH', raw, 8 + 8 * i + 4)
            yield (self.types[k] if k < len(self.types) else '?%d' % k), raw[body + s:body + e]

    def chunks(self, name):
        rec = self.files[name]; H = self.H; out = []
        for j in range(rec['chunk_bytes'] // 16):
            q = H['chunks_off'] + rec['chunk_rel'] + 16 * j
            out.append((self.L[q], self.L[q + 1], int.from_bytes(self.L[q + 3:q + 8], 'little'), U32(self.L, q + 8), U32(self.L, q + 12)))
        return out                                                # (flags, archive, blob_off, decomp, comp)


class Pack:
    """All TOCs below `root` + their .rmdblob files. Pass the folder that holds the .rmdtoc/.rmdblob files."""
    def __init__(self, root, include_dev=False, verbose=True, need_deps=('.bnk', '.sndevent', '.bintimeline'), index_exts=None):
        self.root = os.path.abspath(root); self._fh = {}; self._blobs = None
        tocs = sorted(set(glob.glob(os.path.join(root, '*.rmdtoc')) + glob.glob(os.path.join(root, '**', '*.rmdtoc'), recursive=True)))
        if not include_dev:
            normal = {t for t in tocs if not t.endswith('-development.rmdtoc')}
            tocs = [t for t in tocs if t in normal or t.replace('-development.rmdtoc', '.rmdtoc') not in normal]
        if not tocs: raise SystemExit('no .rmdtoc files found below %s' % root)
        self.tocs = []; self.where = {}; self.ids = {}; self.deps = {}; self.tex = {}; self.size = {}
        for p in tocs:
            if verbose: print('reading', os.path.basename(p), file=sys.stderr)
            T = Toc(p); self.tocs.append(T)
            for name, rec in T.files.items():
                self.where.setdefault(name, T); self.size[name] = rec['size']
                ext = os.path.splitext(name)[1]
                if index_exts is not None and ext not in index_exts: continue
                for cls, sec in T.meta_sections(name):
                    if cls == 'r::ResourceMetadata' and len(sec) >= 20 and U32(sec, 0) == 3 and U32(sec, 4) == 1:
                        self.ids[U64(sec, 8)] = name
                        if ext in need_deps:
                            N = U32(sec, 16)
                            if 20 + 12 * N == len(sec): self.deps[name] = [U64(sec, 24 + 12 * j) for j in range(N)]
                    elif cls == 'rend::TextureMetadata' and len(sec) >= 44:
                        n = U32(sec, 20)
                        self.tex[name] = dict(flags=struct.unpack_from('<H', sec, 8)[0], width=struct.unpack_from('<H', sec, 10)[0],
                                              height=struct.unpack_from('<H', sec, 12)[0], depth=struct.unpack_from('<H', sec, 14)[0],
                                              mips=sec[16], fmt=sec[18], rows=n)
        if verbose: print('%d TOCs, %d files, %d resource ids' % (len(self.tocs), len(self.where), len(self.ids)), file=sys.stderr)

    # -- blobs --------------------------------------------------------------------------------------------------
    def _blob_path(self, toc, arch):
        d = os.path.dirname(toc.path)
        for c in (os.path.normpath(os.path.join(d, arch)), os.path.join(d, os.path.basename(arch)), os.path.join(self.root, os.path.basename(arch))):
            if os.path.exists(c): return c
        if self._blobs is None:
            self._blobs = {}
            for r, _, fs in os.walk(os.path.dirname(self.root) if os.path.basename(self.root) in ('pc', 'generic') else self.root):
                for f in fs:
                    if f.endswith('.rmdblob'): self._blobs.setdefault(f, os.path.join(r, f))
        if os.path.basename(arch) in self._blobs: return self._blobs[os.path.basename(arch)]
        raise FileNotFoundError('blob %s (needed by %s) not found below %s' % (arch, os.path.basename(toc.path), self.root))

    def _read_chunk(self, toc, ch):
        flags, arch, off, dec, comp = ch
        p = self._blob_path(toc, toc.archives[arch])
        fh = self._fh.get(p)
        if fh is None:
            if len(self._fh) > 24: [f.close() for f in self._fh.values()]; self._fh.clear()
            fh = self._fh[p] = open(p, 'rb')
        fh.seek(off); raw = fh.read(comp or dec)
        if len(raw) != (comp or dec): raise IOError('short read in %s at %d' % (p, off))
        return lz4_block(raw, dec) if comp else raw

    def read(self, name, verify=True):
        T = self.where[name]; out = bytearray()
        for ch in T.chunks(name): out += self._read_chunk(T, ch)
        if len(out) != T.files[name]['size']: raise IOError('%s: size %d != TOC %d' % (name, len(out), T.files[name]['size']))
        if verify:
            for cls, sec in T.meta_sections(name):
                if cls == 'r::FileInfoMetadata' and len(sec) == 16 and (zlib.crc32(bytes(out)) & 0xffffffff) != U32(sec, 12):
                    print('WARNING: CRC32 mismatch for %s' % name, file=sys.stderr)
        return bytes(out)

    def read_prefix(self, name, n):
        T = self.where[name]; out = bytearray()
        for ch in T.chunks(name):
            out += self._read_chunk(T, ch)
            if len(out) >= n: break
        return bytes(out[:n])

    def path_of(self, rid):
        return self.ids.get(rid)

# ------------------------------------------------------------------------------------------------ marker-object streams (RMDL, bintimeline, ...)
def rmdl_objs(b, a, e):
    """object = MARKER | u32 type(1|2) | u32 size(total incl. 16 B header + trailing MARKER) | u32 key | payload | MARKER"""
    out = []; q = a
    while q < e:
        q = b.find(MARKER, q, e)
        if q < 0: break
        if q + 16 <= e:
            t, sz, k = struct.unpack_from('<III', b, q + 4)
            if t in (1, 2) and 20 <= sz <= e - q and b[q + sz - 4:q + sz] == MARKER:
                out.append(dict(p=q, size=sz, key=k, pay=(q + 16, q + sz - 4))); q += sz; continue
        q += 1
    return out

K_RID = 0x1BFC72D5
K_VIDEO_EVENT = 0xC26E1FD3; K_SOUND_EVENT = 0x5823FB20; K_DIALOGUE_EVENT = 0xAAB3C695
REF_TEXTURE = 0x383FCF03; REF_SNDEVENT = 0x38ABEE66; REF_EXTSRC = 0x7378CA33

def timeline_refs(b):
    """-> dict(video=[tex ids], sound=[sndevent ids], dialogue_wem=[wem ids]) from a .bintimeline"""
    res = dict(video=[], sound=[], dialogue_wem=[])
    def rid_in(o, ref):
        for c in rmdl_objs(b, o['pay'][0], o['pay'][1]):
            if c['key'] == ref:
                for r in rmdl_objs(b, c['pay'][0], c['pay'][1]):
                    if r['key'] == K_RID:
                        v = U64(b, r['pay'][0] + 4)
                        if v != NONE_RID: yield v
    def walk(a, e):
        for o in rmdl_objs(b, a, e):
            k = o['key']
            if k == K_VIDEO_EVENT: res['video'] += list(rid_in(o, REF_TEXTURE))
            elif k == K_SOUND_EVENT: res['sound'] += list(rid_in(o, REF_SNDEVENT))
            elif k == K_DIALOGUE_EVENT: res['dialogue_wem'] += list(rid_in(o, REF_EXTSRC))
            else: walk(o['pay'][0], o['pay'][1])
    walk(0, len(b)); return res

# ------------------------------------------------------------------------------------------------ Wwise bank (BKHD / HIRC)
def bnk_info(data):
    """-> dict(version, bank_id, hirc_types{type:count}) ; HIRC object = u8 type | u32 length | (u32 id ...)"""
    info = dict(version=None, bank_id=None, hirc_types=collections.Counter()); pos = 0
    while pos + 8 <= len(data):
        tag = data[pos:pos + 4]; size = U32(data, pos + 4)
        if tag == b'BKHD' and size >= 8: info['version'] = U32(data, pos + 8); info['bank_id'] = U32(data, pos + 12)
        elif tag == b'HIRC' and size >= 4:
            n = U32(data, pos + 8); p = pos + 12
            for _ in range(n):
                if p + 5 > len(data): break
                info['hirc_types'][data[p]] += 1; p += 5 + U32(data, p + 1)
        pos += 8 + size
    return info

def wem_info(data):
    """best-effort RIFF/Wwise header summary (duration only when derivable)"""
    out = dict(size=len(data))
    if data[:4] not in (b'RIFF', b'RIFX'): return out
    p = 12; ch = {}
    while p + 8 <= len(data):
        t = data[p:p + 4]; s = U32(data, p + 4); ch[t] = (p + 8, s); p += 8 + s + (s & 1)
    if b'fmt ' in ch:
        o, s = ch[b'fmt ']
        out['codec_tag'] = struct.unpack_from('<H', data, o)[0]; out['channels'] = struct.unpack_from('<H', data, o + 2)[0]
        out['sample_rate'] = U32(data, o + 4); avg = U32(data, o + 8)
        if b'vorb' in ch and out['sample_rate']:
            vo, vs = ch[b'vorb']; out['duration_s_estimate'] = round(U32(data, vo) / out['sample_rate'], 3)
        elif avg and b'data' in ch: out['duration_s_estimate'] = round(ch[b'data'][1] / avg, 3)
    return out

# ------------------------------------------------------------------------------------------------ misc
def safe(s):
    return re.sub(r'[^A-Za-z0-9._\-]+', '_', s).strip('_') or 'x'

def dds_kind(h):
    """classify a .tex that starts with 'DDS ' (DDS_HEADER 124 B + DX10 header 20 B)"""
    if len(h) < 148 or h[:4] != b'DDS ': return None
    dxgi, dim, misc, arr, _ = struct.unpack_from('<IIIII', h, 128)
    depth = U32(h, 24)
    if misc & 4: return 'cube'
    if dim == 4: return '3d'
    if dim == 2: return '1d'
    if arr > 1: return 'array'
    return '2d'

def bink_header(h):
    """Bink 2 ('KB2' + revision letter): size-8, frames, largest frame, frames, width, height, fps num/den, flags, audio tracks"""
    if len(h) < 48 or h[:3] != b'KB2': return None
    v = struct.unpack_from('<10I', h, 4)
    fps = v[6] / v[7] if v[7] else 0
    return dict(revision=chr(h[3]), frames=v[1], width=v[4], height=v[5], fps=round(fps, 4), fps_num=v[6], fps_den=v[7],
                duration_s=round(v[1] / fps, 3) if fps else None, audio_tracks=v[9])

# ====== end library ======

CATS = ['music', 'stingers', 'ambience', 'beds', 'environment']
PRIORITY = {c: i for i, c in enumerate(CATS)}
EXCLUDE = {'dlg', 'vox', 'vo', 'dialogue', 'dialog', 'radio', 'foley', 'footstep', 'footsteps', 'step', 'steps', 'impact', 'damage', 'explosion',
           'gunshot', 'shot', 'melee', 'weapon', 'proj', 'projectile', 'hit', 'pain', 'death', 'ui', 'menu', 'haptics', 'reverb', 'aux'}
MUSIC_HIRC = {10, 11, 12, 13}

def classify(name, hirc=None):
    toks = set(re.split(r'[_\W]+', name.lower())); cats = []
    music = bool(toks & {'mus', 'music'}) or bool(hirc and set(hirc) & MUSIC_HIRC)
    if music: cats.append('music')
    if toks & {'stinger', 'sting'} and (music or not (toks & EXCLUDE)): cats.append('stingers')
    if not (toks & EXCLUDE):
        if toks & {'amb', 'ambience', 'ambient', 'atmos', 'atmosphere'}: cats.append('ambience')
        if toks & {'bed', 'drone'}: cats.append('beds')
        if 'env' in toks: cats.append('environment')
    return cats

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('root'); ap.add_argument('--out', default='music_out'); ap.add_argument('--categories', default=','.join(CATS))
    ap.add_argument('--strict', action='store_true', help='same as --categories music,stingers,ambience')
    ap.add_argument('--list', action='store_true'); ap.add_argument('--no-hirc', action='store_true', help='classify by names only (do not read the .bnk files)')
    ap.add_argument('--min-size', type=int, default=0, help='skip media smaller than N bytes'); ap.add_argument('--skip-empty', action='store_true', default=True)
    a = ap.parse_args()
    want = ['music', 'stingers', 'ambience'] if a.strict else [c.strip() for c in a.categories.split(',') if c.strip()]
    bad = [c for c in want if c not in CATS]
    if bad: raise SystemExit('unknown category: %s' % bad)

    pack = Pack(a.root, index_exts=('.wem', '.bnk', '.sndevent'), need_deps=('.bnk', '.sndevent'))
    banks = {os.path.basename(n)[:-4]: n for n in pack.where if n.endswith('.bnk')}
    events = {os.path.basename(n)[:-9]: n for n in pack.where if n.endswith('.sndevent')}

    hirc = {}
    if not a.no_hirc and not a.list:
        for i, (b, n) in enumerate(sorted(banks.items())):
            try: hirc[b] = bnk_info(pack.read(n, verify=False))['hirc_types']
            except FileNotFoundError: raise
            except Exception as e: print('bank %s: %s' % (b, e), file=sys.stderr)

    def media_of(bank_path, depth=0):
        out = []
        for d in pack.deps.get(bank_path, []):
            p = pack.path_of(d)
            if not p: continue
            if p.endswith('.wem'): out.append(p)
            elif p.endswith('.bnk') and depth < 1 and os.path.basename(p) != 'init.bnk': out += media_of(p, depth + 1)
        return out

    # (media path) -> best (category, label, bank)
    pick = {}; seen_by = collections.defaultdict(set)
    def consider(label, bank_name, cats):
        for c in cats:
            if c not in want: continue
            for w in media_of(banks[bank_name]) if bank_name in banks else []:
                if pack.size.get(w, 0) <= max(a.min_size, 0) and a.skip_empty: continue
                seen_by[w].add(label)
                if w not in pick or PRIORITY[c] < PRIORITY[pick[w][0]]: pick[w] = (c, label, bank_name)
    for ev, p in events.items():
        for d in pack.deps.get(p, []):
            bp = pack.path_of(d)
            if bp and bp.endswith('.bnk'):
                bn = os.path.basename(bp)[:-4]
                consider(ev, bn, classify(ev, hirc.get(bn)) or classify(bn, hirc.get(bn)))
    for bn in banks:                                              # banks without events, and music-by-HIRC banks
        if bn not in events or (hirc.get(bn) and set(hirc[bn]) & MUSIC_HIRC):
            if bn != 'init': consider(bn, bn, classify(bn, hirc.get(bn)))

    tot = collections.Counter(); sz = collections.Counter()
    for w, (c, lab, bn) in pick.items(): tot[c] += 1; sz[c] += pack.size[w]
    print('selected media by category:', file=sys.stderr)
    for c in CATS:
        if tot[c]: print('  %-12s %6d files  %8.2f GB' % (c, tot[c], sz[c] / 1e9), file=sys.stderr)
    print('  TOTAL        %6d files  %8.2f GB' % (sum(tot.values()), sum(sz.values()) / 1e9), file=sys.stderr)
    os.makedirs(a.out, exist_ok=True)
    rows = []
    for w, (c, lab, bn) in sorted(pick.items(), key=lambda x: (PRIORITY[x[1][0]], x[1][1], x[0])):
        dst = os.path.join(a.out, c, safe(lab), os.path.basename(w))
        info = {}
        if not a.list:
            os.makedirs(os.path.dirname(dst), exist_ok=True); data = pack.read(w); open(dst, 'wb').write(data); info = wem_info(data)
        rows.append([c, lab, bn, os.path.basename(w)[:-4], pack.size[w], os.path.relpath(dst, a.out), info.get('duration_s_estimate', ''), ';'.join(sorted(seen_by[w] - {lab}))[:300]])
    with open(os.path.join(a.out, 'manifest.csv'), 'w', newline='') as fo:
        wr = csv.writer(fo); wr.writerow(['category', 'event_or_bank', 'bank', 'media_id', 'bytes', 'path', 'duration_s_estimate', 'also_used_by']); wr.writerows(rows)
    print('manifest:', os.path.join(a.out, 'manifest.csv'), file=sys.stderr)

if __name__ == '__main__': main()
