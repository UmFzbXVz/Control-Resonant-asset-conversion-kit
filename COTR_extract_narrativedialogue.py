#!/usr/bin/env python3
"""
extract_dialogues.py - extract EVERY dialogue of Control (conversations + systemic barks) with audio, subtitles and structure,
grouped per quest where the data says so, everything else per conversation.

  python3 COTR_extract_narrativedialogue.py <folder with .rmdtoc/.rmdblob> --out dialogues_out [--lang en] [--no-audio] [--only REGEX]

Output
  quests/<quest>/<conversation>/conversation.json      graph(s) (nodes, pins, choice options, facts), sequences, lines
                                 audio/<wem files>      voice lines (original Wwise .wem, named as in the game data)
                                 sequence_<N>.srt       subtitles (timeline frames @30 fps; [a-b] segments of the string_table text)
  quests/<quest>/quest.json                             conversations + how the quest was derived
  loose/<family>/<conversation>/...                     conversations with no quest in their id / entity path / facts
  systemic/<sys_dialogue file>/lines.json + audio/      systemic barks (RMDL line files without graph/timeline)
  systemic/sets.json                                    DialogueSet -> ordered DialogueSetPlaylistItem -> line (by id) -> text/wem
  index.json                                            every conversation, its quest and counts

Structural joins (no name guessing):
  line <-> text        LINE.dialogueStringId == sidecar header id (exact u64)           (text = sidecar, subtitle = string_table[LINE.name])
  line <-> audio       LINE.wem RID (TOC primary id) ; the same RID is in DialogueTimelineEvent.sound_external_source
  line <-> time        the DialogueTimelineEvent carrying that wem RID: start/duration frames (30 per second)
  line <-> type        LINE.dialogueTypeId -> dialoguetypes.bin (play_dlg_* event, priority)
  sequence <-> graph   graph sequence-node record (41-byte, TOC id of the .bintimeline) -> DialogueTimelineEvent.dialogue RID (sequence.bin)
  quest                1 entity path segment (mq_/dq_/wq_/sq_..., or the folder after quests/mini_quests) consistent with the conversation-id
                         grammar <quest>_sNNNN_gNNN_<name>;  2 the grammar itself;  3 majority of 'quests/<q>/' facts in the graph
  set <-> line         Set.n item ids = the next n PlaylistItem objects in file order (sum(n) == #items, 6,311); item.lineId == LINE id (tag 0x1a)
Blob reading follows the reverse-engineered RMDBLOB spec and checks size + CRC32.
"""
import argparse, collections, json, os, re, struct, sys, glob
# ====== embedded RMDTOC/RMDBLOB reader ======
import collections, glob, json, os, re, struct, sys, zlib

U32 = lambda b, p: struct.unpack_from('<I', b, p)[0]
U64 = lambda b, p: struct.unpack_from('<Q', b, p)[0]
NONE_RID = 0xFFFFFFFFFFFFFFFF
MARKER = b'\x3f\xb3\x4d\xd3'

# ------------------------------------------------------------------------------------------------ LZ4 (block)
try:
    import lz4.block as _lz4block                      # optional speed-up: pip install lz4
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
    def __init__(self, root, include_dev=False, verbose=True, need_deps=('.bnk', '.sndevent', '.bintimeline'), index_exts=None, local=None):
        self.root = os.path.abspath(root); self._fh = {}; self._blobs = None; self.local = local
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

    def _local(self, name):
        if self.local:
            for pre in ('data/', 'data_pc/'):
                if name.startswith(pre):
                    q = os.path.join(self.local, name[len(pre):])
                    if os.path.isfile(q): return q
        return None

    def read(self, name, verify=True):
        q = self._local(name)
        if q: return open(q, 'rb').read()
        T = self.where[name]; out = bytearray()
        for ch in T.chunks(name): out += self._read_chunk(T, ch)
        if len(out) != T.files[name]['size']: raise IOError('%s: size %d != TOC %d' % (name, len(out), T.files[name]['size']))
        if verify:
            for cls, sec in T.meta_sections(name):
                if cls == 'r::FileInfoMetadata' and len(sec) == 16 and (zlib.crc32(bytes(out)) & 0xffffffff) != U32(sec, 12):
                    print('WARNING: CRC32 mismatch for %s' % name, file=sys.stderr)
        return bytes(out)

    def read_range(self, name, off, n):
        """bytes [off, off+n) of a file, decoding only the chunks that overlap"""
        q = self._local(name)
        if q:
            with open(q, 'rb') as fh: fh.seek(off); return fh.read(n)
        T = self.where[name]; pos = 0; out = bytearray()
        for ch in T.chunks(name):
            dec = ch[3]
            if pos + dec > off and pos < off + n:
                data = self._read_chunk(T, ch); a = max(off - pos, 0); out += data[a:a + (off + n - pos - a)]
            pos += dec
            if pos >= off + n: break
        return bytes(out)

    def read_prefix(self, name, n):
        q = self._local(name)
        if q:
            with open(q, 'rb') as fh: return fh.read(n)
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

# ====== embedded dialogue / timeline / graph formats ======
# ================================================================== dialogue / timeline / graph formats
K_LINE = 0x58FE2733; K_SIDE = 0x4135DAB6; K_DTYPE = 0x0534C4EC; K_TL_EVENT = 0xDBFF2F1F
REF_NAMES = {0x7378CA33: 'sound_external_source', 0xBA32F39E: 'animation_clip', 0x6DD154FF: 'dialogue', 0xF24361E4: 'dialogue_string_table',
             0x383FCF03: 'texture', 0x38ABEE66: 'sound_event'}
FPS = 30.0                                   # timeline ticks are frames @30 (DialogueTimelineEvent.duration / wem seconds = 30.0, median over 9,773 events)
EVENT_KEYS = {
    0x09620C06: 'CinematicsControlTimelineEvent',
    0x1013486D: 'TimelineTimelineEvent',
    0x27787B1A: 'GfxGraphVariableTimelineEvent',
    0x4FE77CB5: 'GfxGraphTimelineEvent',
    0x503B4D17: 'TransformTimelineEvent',
    0x5823FB20: 'SoundTimelineEvent',
    0x5CA65AF2: 'AnimationSourceTimelineEvent',
    0x71EBC4E8: 'ParameterCurveTimelineEvent',
    0x7A47B05E: 'ScriptClipTimelineEvent',
    0x8BF11083: 'HideTimelineEvent',
    0x8FA120F1: 'AnimationTimelineEvent',
    0x9C756F3D: 'AnimationMovementTimelineEvent',
    0x9CEA7162: 'ScriptTimelineEvent',
    0xA6863A68: 'ParticleTimelineEvent',
    0xAAB3C695: 'DialogueTimelineEvent',
    0xB61ABB1B: 'CameraTimelineEvent',
    0xBA780DF9: 'ParticleCommandTimelineEvent',
    0xC26E1FD3: 'VideoTimelineEvent',
    0xC81CB61E: 'AnimationParameterTimelineEvent',
    0xDBFF2F1F: 'TimelineEvent',
    0xDE56F6EA: 'CinematicLightTimelineEvent',
    0xED76B1FA: 'EarlyExitTimelineEvent',
}

EVENT_KEYS.pop(K_TL_EVENT, None)
SEGMENT_RX = re.compile(r'\[(\d+(?:\.\d+)?)-(\d+(?:\.\d+)?)\]')

def parse_string_table(b):
    n = U32(b, 0); q = 4; d = {}
    for _ in range(n):
        kl = U32(b, q); k = b[q + 4:q + 4 + kl].decode('utf8', 'replace'); q += 4 + kl
        tl = U32(b, q); d[k] = b[q + 4:q + 4 + 2 * tl].decode('utf-16le', 'replace'); q += 4 + 2 * tl
    return d

def parse_sequence(b):
    """RMDL line file. @0x20 u32 lineCount | @0x28 lineCount x u64 LINE object ids (tag 0x1a) | LINE objects.
    LINE: u32 0x13 | u32 nameLen | name | u64 dialogueStringId (tag 0x4f, same upper 56 bits as the LINE id) | u64 dialogueTypeId (tag 0x1e) |
          6 flag bytes (byte 4 = 1 on caption lines such as <sigh>) | RID(sound .wem) | RID(animation clip) | u8 | f32 (0.0/0.2/0.4) | u8"""
    cnt = U32(b, 0x20); ids = [U64(b, 0x28 + 8 * i) for i in range(cnt)]; lines = []
    for o in rmdl_objs(b, 0x28 + 8 * cnt, len(b)):
        if o['key'] != K_LINE: continue
        s, e = o['pay']; nl = U32(b, s + 4); q = s + 8 + nl
        ch = [c for c in rmdl_objs(b, q + 22, e) if c['key'] == K_RID]
        rids = [U64(b, c['pay'][0] + 4) for c in ch]
        post = b[ch[-1]['p'] + ch[-1]['size']:e] if ch else b''
        lines.append(dict(string_key=b[s + 8:s + 8 + nl].decode('utf8', 'replace'), string_id=U64(b, q), type_id=U64(b, q + 8), flags=list(b[q + 16:q + 22]),
                          wem_rid=rids[0] if rids else None, anim_rid=rids[1] if len(rids) > 1 else None,
                          post=dict(u8_a=post[0], f32=struct.unpack_from('<f', post, 1)[0], u8_b=post[5]) if len(post) >= 6 else None))
    return dict(ids=ids, lines=lines)

def parse_sidecar(b):
    """RMDL strings file. @0x10 u32 count | @0x18 count x u64 DialogueString ids (tag 0x4f) | objects (key 0x4135DAB6): u32 0 | u32 len | text | u32 len | speaker"""
    cnt = U32(b, 0x10); ids = [U64(b, 0x18 + 8 * i) for i in range(cnt)]; objs = []
    for o in rmdl_objs(b, 0x18 + 8 * cnt, len(b)):
        if o['key'] != K_SIDE: continue
        s, e = o['pay']; tl = U32(b, s + 4); sl = U32(b, s + 8 + tl)
        objs.append(dict(text=b[s + 8:s + 8 + tl].decode('utf8', 'replace'), speaker=b[s + 12 + tl:s + 12 + tl + sl].decode('utf8', 'replace')))
    return dict(ids=ids, objs=objs)

def parse_dialogue_types(b):
    """dialoguetypes.bin: @0x10 u32 count | @0x18 ids (tag 0x1e) | DialogueType objects: u32 4 | u32 priority | u32 0 | u32 nameLen | name | ..."""
    cnt = U32(b, 0x10); ids = [U64(b, 0x18 + 8 * i) for i in range(cnt)]; out = {}
    objs = [o for o in rmdl_objs(b, 0x18 + 8 * cnt, len(b)) if o['key'] == K_DTYPE]
    for i, o in enumerate(objs):
        s, e = o['pay']; nl = U32(b, s + 12)
        if i < len(ids): out[ids[i]] = dict(name=b[s + 16:s + 16 + nl].decode('utf8', 'replace'), priority=U32(b, s + 4))
    return out

def join_lines(seq, side, strings):
    """line <-> DialogueString by id (exact u64), text from sidecar, subtitle text (with [start-end] markup) from string_table"""
    pos = {i: k for k, i in enumerate(side['ids'])} if side else {}
    out = []
    for i, ln in enumerate(seq['lines']):
        d = dict(ln); j = pos.get(ln['string_id'])
        so = side['objs'][j] if side and j is not None and j < len(side['objs']) else None
        d['line_id'] = seq['ids'][i] if i < len(seq['ids']) else None
        d['text'] = so['text'] if so else None; d['speaker'] = so['speaker'] if so else None
        d['subtitle'] = strings.get(ln['string_key'])
        d['sidecar_joined_by'] = 'id' if so else None
        out.append(d)
    return out

def timeline_events(b):
    """all events of a .bintimeline. base (0xDBFF2F1F): u32 9 | u32 nameLen | name | i32 classCode | i32 startFrame | i32 x | u32 durationFrames | u8 | u32 36 | GUID[36]"""
    evs = []
    def walk(a, e, track):
        for o in rmdl_objs(b, a, e):
            k = o['key']
            if k in EVENT_KEYS:
                kids = rmdl_objs(b, o['pay'][0], o['pay'][1]); ev = dict(cls=EVENT_KEYS[k], refs={}, track=track)
                for c in kids:
                    if c['key'] == K_TL_EVENT:
                        s, e2 = c['pay']; ver, nl = struct.unpack_from('<II', b, s); q = s + 8 + nl
                        cc, st, x3, du = struct.unpack_from('<iiiI', b, q); gl = U32(b, q + 17)
                        ev.update(name=b[s + 8:s + 8 + nl].decode('utf8', 'replace'), class_code=cc, start=st, duration=du, guid=b[q + 21:q + 21 + gl].decode('ascii', 'replace'))
                    else:
                        for r in rmdl_objs(b, c['pay'][0], c['pay'][1]):
                            if r['key'] == K_RID:
                                v = U64(b, r['pay'][0] + 4)
                                if v != NONE_RID: ev['refs'].setdefault(REF_NAMES.get(c['key'], '0x%08X' % c['key']), []).append(v)
                if 'start' in ev: evs.append(ev)
            else: walk(o['pay'][0], o['pay'][1], track + 1 if k == 0x36B2DD1E else track)
    walk(0, len(b), 0); return evs

def srt_time(t):
    t = max(t, 0.0); ms = int(round(t * 1000)); h, ms = divmod(ms, 3600000); m, ms = divmod(ms, 60000); s, ms = divmod(ms, 1000)
    return '%02d:%02d:%02d,%03d' % (h, m, s, ms)

def subtitle_cues(line, start_s, dur_s):
    """cue list [(start, end, text)] in seconds. string_table text may carry [a-b] segments = seconds relative to the line's audio start (last end ~ audio duration)."""
    t = line.get('subtitle') or line.get('text') or ''
    segs = list(SEGMENT_RX.finditer(t))
    if segs:
        cues = []
        for i, m in enumerate(segs):
            nxt = segs[i + 1].start() if i + 1 < len(segs) else len(t)
            txt = t[m.end():nxt].strip()
            if txt: cues.append((start_s + float(m.group(1)), start_s + float(m.group(2)), txt))
        return cues
    return [(start_s, start_s + max(dur_s, 0.5), t.strip())] if t.strip() else []

def write_srt(path, cues):
    cues = sorted(cues)
    with open(path, 'w', encoding='utf-8') as fo:
        for i, (a, b2, t) in enumerate(cues, 1): fo.write('%d\n%s --> %s\n%s\n\n' % (i, srt_time(a), srt_time(b2), t))

# ------------------------------------------------------------------ BNDL / ECS / conversation graph (read through Pack.read_range)
T_GRAPH = 0x56283CF2; T_DEBUGNAME = 0x74C736B4; T_LUA = 0xE3E6E41B
def fnv1a32(b):
    h = 0x811C9DC5
    for c in b: h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
    return h
DECL = struct.pack('<I', 17) + b'declare variables' + struct.pack('<I', fnv1a32(b'declare variables')); PREAMBLE = 0x34
NODE_TYPES = {0x40: 'dialogue_sequence', 0x2: 'choice'}

class Bundle:
    def __init__(self, pack, name):
        self.pack = pack; self.name = name; self.size = pack.size[name]
        h = pack.read_prefix(name, 0x20000)
        k = struct.unpack_from('<H', h, 0x0C)[0]; p = 0x0E + 8 * k; n = U32(h, p + 8); dof = p + 12
        self.dir = [struct.unpack_from('<III', h, dof + 12 * i) for i in range(n)]
        off = dof + 12 * n; self.ranges = {}; self.index = {}
        for i, (t, c, s) in enumerate(self.dir): self.ranges[t] = (off, s, c); self.index[t] = i; off += s
        self.tail_off = off
    def payload(self, t):
        if t not in self.ranges: return None, 0
        off, s, c = self.ranges[t]; return self.pack.read_range(self.name, off, s), c
    def entities(self):
        tail = self.pack.read_range(self.name, self.tail_off, self.size - self.tail_off)
        cnt, sec = struct.unpack_from('<QQ', tail, 0); q = 16; ents = []
        for _ in range(cnt):
            eid, n = struct.unpack_from('<QQ', tail, q); q += 16
            ents.append((eid, [struct.unpack_from('<II', tail, q + 8 * j) for j in range(n)])); q += 8 * n
        return ents

def debug_names(payload, count):
    q = 0; out = []
    for _ in range(count):
        a, b, l = struct.unpack_from('<III', payload, q); q += 12; out.append(payload[q:q + l].decode('utf8', 'replace')); q += l
    return out

def read_shell(p, q):
    if q + 8 > len(p): return None
    tl = U32(p, q)
    if tl > 255 or q + 4 + tl + 24 > len(p): return None
    t = p[q + 4:q + 4 + tl]; base = q + 4 + tl; h = U32(p, base)
    if tl > 0 and h != fnv1a32(t): return None
    if tl == 0 and h != 0: return None
    return dict(title=t.decode('utf8', 'replace'), flags=U32(p, base + 8), ci=U32(p, base + 12), rid=U64(p, base + 16), end=base + 24)

def read_pins(p, q):
    n = U32(p, q); q += 4; out = []
    if n > 500: return None, q
    for _ in range(n):
        if q + 8 > len(p): return None, q
        sc = U32(p, q + 4)
        if sc > 500 or q + 8 + 4 * sc > len(p): return None, q
        out.append(list(struct.unpack_from('<%di' % sc, p, q + 8))); q += 8 + 4 * sc
    return out, q

def read_nodes(p, q0):
    nodes = []; q = q0
    while True:
        s = read_shell(p, q)
        if not s: break
        o, q2 = read_pins(p, s['end'])
        if o is None: break
        d, q3 = read_pins(p, q2)
        if d is None or q3 + 4 > len(p): break
        fn = U32(p, q3)
        if fn > 500: break
        s.update(out=o, data=d, fallback=list(struct.unpack_from('<%di' % fn, p, q3 + 4))); nodes.append(s); q = q3 + 4 + 4 * fn
    return nodes, q

def graph_instances(payload):
    pos = []; q = 0
    while True:
        q = payload.find(DECL, q)
        if q < 0: break
        pos.append(q); q += 1
    res = []
    for i, q in enumerate(pos):
        qe = pos[i + 1] - PREAMBLE if i + 1 < len(pos) else len(payload)
        nodes, qn = read_nodes(payload, q); res.append(dict(index=i, nodes=nodes, nodes_end=qn, end=qe))
    return res

def tail_strings(p, a, b):
    out = []; q = a
    while q + 5 <= b:
        l = U32(p, q)
        if 1 <= l <= 300 and q + 4 + l <= b and all(32 <= x < 127 for x in p[q + 4:q + 4 + l]): out.append(p[q + 4:q + 4 + l].decode()); q += 4 + l
        else: q += 1
    return out

def sequence_refs(pack, p, a, b, n_expected):
    """41-byte records [u32 1][u64 timelineAsset][12 x 00][u32 A][u32 B][u8 0][u32 1][u32 0], unaligned; keep the longest stride-41 run"""
    hits = []
    for o in range(a, b - 7):
        v = U64(p, o); t = pack.ids.get(v)
        if t and t.endswith('.bintimeline'): hits.append((o, t))
    runs = []; cur = []
    for h in hits:
        if cur and h[0] - cur[-1][0] == 41: cur.append(h)
        else:
            if cur: runs.append(cur)
            cur = [h]
    if cur: runs.append(cur)
    best = max(runs, key=len) if runs else []
    if len(best) != n_expected and len(hits) == n_expected: best = hits
    return [t for o, t in best]

def read_graphs(pack, bundle_name, strings):
    bd = Bundle(pack, bundle_name)
    if T_GRAPH not in bd.ranges: return []
    gp, gc = bd.payload(T_GRAPH); names, nc = bd.payload(T_DEBUGNAME)
    paths = debug_names(names, nc) if names else []
    insts = graph_instances(gp); ents = bd.entities(); gd = bd.index[T_GRAPH]; dn = bd.index.get(T_DEBUGNAME)
    owner = {}
    for eid, pairs in ents:
        d = {dd: ii for ii, dd in pairs}
        if gd in d: owner[d[gd]] = (eid, paths[d[dn]] if dn in d and d[dn] < len(paths) else None)
    out = []
    for I in insts:
        refs = sequence_refs(pack, gp, I['nodes_end'], I['end'], sum(1 for n in I['nodes'] if n['flags'] == 0x40))
        strs = tail_strings(gp, I['nodes_end'], I['end'])
        opts = [s for s in strs if 'CHOICE_' in s and 'CHOICE_PROMPT_' not in s and 'CHOICE_FAIL_' not in s]
        facts = [s for s in strs if s.startswith('quests/') or s.startswith('conv_local/') or re.fullmatch(r'wf_[0-9a-f]{16}', s)]
        nodes = []; oi = 0
        for k, n in enumerate(I['nodes']):
            nd = dict(index=k, type=NODE_TYPES.get(n['flags'], 'flag_0x%x' % n['flags']), flags=n['flags'], title=n['title'], content_index=n['ci'], out_pins=n['out'], fallback=n['fallback'])
            if n['flags'] == 0x40 and n['ci'] < len(refs): nd['timeline'] = refs[n['ci']]
            if n['flags'] == 0x2:
                nd['options'] = []
                for _ in n['out']:
                    if oi < len(opts): nd['options'].append(dict(key=opts[oi], text=strings.get(opts[oi]))); oi += 1
            nodes.append(nd)
        eid, ep = owner.get(I['index'], (None, None))
        out.append(dict(bundle=os.path.basename(bundle_name), index=I['index'], entity_id='0x%016x' % eid if eid else None, entity_path=ep, nodes=nodes,
                        prompts=[dict(key=s, text=strings.get(s)) for s in strs if 'CHOICE_PROMPT_' in s], facts=facts, timelines=sorted(set(refs))))
    return out

# ------------------------------------------------------------------ quest grouping (structural: conversation-id grammar, entity path, facts)
CONV_RX = re.compile(r'^(?:cine_|con_|conv_)?(?P<quest>.+?)_s(?P<scene>\d{4})_g(?P<group>\d{3,4})[a-z]?(?:_(?P<name>.*))?$')
QUEST_SEG_RX = re.compile(r'^(mq|dq|wq|sq|cq|tq)_')
def quest_of(conv, graphs):
    """-> (quest_folder or None, source, grammar_id). Order: entity-path quest folder (consistent with conv-id grammar) > conv-id grammar > facts"""
    m = CONV_RX.match(conv); gid = m.group('quest') if m else None
    for g in graphs:
        segs = (g.get('entity_path') or '').split('/')
        for i, s in enumerate(segs):
            if QUEST_SEG_RX.match(s) and (gid is None or s.startswith(gid) or gid.startswith(s)): return s, 'entity-path', gid
            if s in ('quests', 'mini_quests', 'side_quests') and i + 1 < len(segs) and (gid is None or segs[i + 1].startswith(gid)): return segs[i + 1], 'entity-path', gid
    if gid: return gid, 'conversation-id', gid
    cnt = collections.Counter(f.split('/')[1] for g in graphs for f in g.get('facts', []) if f.startswith('quests/') and f.count('/') >= 2)
    if cnt: return cnt.most_common(1)[0][0], 'facts', None
    return None, None, None

def family_of(conv):
    return re.match(r'[a-z]+', conv).group(0) if re.match(r'[a-z]+', conv) else 'misc'


def hx(v): return '0x%016x' % v if isinstance(v, int) else v

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('root'); ap.add_argument('--out', default='dialogues_out'); ap.add_argument('--lang', default='en')
    ap.add_argument('--no-audio', action='store_true'); ap.add_argument('--only'); ap.add_argument('--local', help='read files from an extracted tree instead of the blobs (offline testing)')
    ap.add_argument('--no-graphs', action='store_true', help='skip the bundles (no graph/quest-by-path information)')
    a = ap.parse_args()
    pack = Pack(a.root, index_exts=('.bin', '.bintimeline', '.wem', '.bundle'), need_deps=(), local=a.local)
    strings = parse_string_table(pack.read('data/stringtables/locale/%s/string_table.bin' % a.lang, verify=False))
    dtypes = parse_dialogue_types(pack.read('data/dialogue/lines/dialoguetypes.bin', verify=False)) if 'data/dialogue/lines/dialoguetypes.bin' in pack.where else {}
    os.makedirs(a.out, exist_ok=True)

    # ---- timelines ------------------------------------------------------------------------------------------------
    tl_events = {}; seq_to_tl = collections.defaultdict(list)
    for name in sorted(n for n in pack.where if n.endswith('.bintimeline')):
        try: ev = timeline_events(pack.read(name, verify=False))
        except Exception as e: print('timeline %s: %s' % (name, e), file=sys.stderr); continue
        tl_events[name] = ev
        for e in ev:
            if e['cls'] == 'DialogueTimelineEvent':
                for r in e['refs'].get('dialogue', []):
                    p = pack.path_of(r)
                    if p and name not in seq_to_tl[p]: seq_to_tl[p].append(name)
    # ---- graphs ---------------------------------------------------------------------------------------------------
    graphs = []
    if not a.no_graphs:
        for b in sorted(n for n in pack.where if n.endswith('.bundle')):
            try: graphs += read_graphs(pack, b, strings)
            except Exception as e: print('bundle %s: %s' % (b, e), file=sys.stderr)
    graph_by_tl = collections.defaultdict(list)
    for g in graphs:
        for t in g['timelines']: graph_by_tl[t].append(g)
    print('%d timelines, %d graph instances' % (len(tl_events), len(graphs)), file=sys.stderr)

    # ---- conversations --------------------------------------------------------------------------------------------
    seq_files = sorted(n for n in pack.where if re.match(r'data/dialogue/lines/[^/]+/sequence_\d+\.bin$', n))
    by_conv = collections.defaultdict(list)
    for n in seq_files: by_conv[n.split('/')[3]].append(n)
    index = []; quests = collections.defaultdict(list)
    for conv, files in sorted(by_conv.items()):
        if a.only and not re.search(a.only, conv): continue
        cg = []; seen = set()
        for f in files:
            for t in seq_to_tl.get(f, []):
                for g in graph_by_tl.get(t, []):
                    if id(g) not in seen: seen.add(id(g)); cg.append(g)
        quest, src, gid = quest_of(conv, cg)
        folder = os.path.join(a.out, 'quests', safe(quest), safe(conv)) if quest else os.path.join(a.out, 'loose', safe(family_of(conv)), safe(conv))
        os.makedirs(folder, exist_ok=True)
        seqs = []; nlines = nwem = ncue = 0
        for f in files:
            seq = parse_sequence(pack.read(f, verify=False)); m = re.search(r'sequence_(\d+)\.bin$', f)
            side_path = 'data/dialogue/locale/%s/%s/sequence_%sstrings.bin' % (a.lang, conv, m.group(1))
            side = parse_sidecar(pack.read(side_path, verify=False)) if side_path in pack.where else None
            lines = join_lines(seq, side, strings)
            evs = [(t, e) for t in seq_to_tl.get(f, []) for e in tl_events.get(t, []) if e['cls'] == 'DialogueTimelineEvent' and any(pack.path_of(r) == f for r in e['refs'].get('dialogue', []))]
            by_wem = {}
            for t, e in evs:
                for w in e['refs'].get('sound_external_source', []): by_wem.setdefault(w, (t, e))
            cues = []; out_lines = []
            for i, ln in enumerate(lines):
                te = by_wem.get(ln['wem_rid']) if ln['wem_rid'] else None
                wem_path = pack.path_of(ln['wem_rid']) if ln['wem_rid'] and ln['wem_rid'] != NONE_RID else None
                if wem_path and a.lang != 'en': wem_path = re.sub(r'/locale/[^/]+/', '/locale/%s/' % a.lang, wem_path) if re.sub(r'/locale/[^/]+/', '/locale/%s/' % a.lang, wem_path) in pack.where else wem_path
                rec = dict(index=i, line_id=hx(ln['line_id']), string_key=ln['string_key'], speaker=ln['speaker'], text=ln['text'], subtitle=ln['subtitle'],
                           dialogue_type=dtypes.get(ln['type_id'], {}).get('name'), type_priority=dtypes.get(ln['type_id'], {}).get('priority'),
                           flags=ln['flags'], caption_flag=bool(ln['flags'][4]), post=ln['post'], wem=wem_path, wem_rid=hx(ln['wem_rid']) if ln['wem_rid'] else None,
                           animation=pack.path_of(ln['anim_rid']) if ln['anim_rid'] and ln['anim_rid'] != NONE_RID else None)
                if te:
                    t, e = te; rec.update(timeline=t, start_frame=e['start'], duration_frames=e['duration'], start_s=round(e['start'] / FPS, 3), duration_s=round(e['duration'] / FPS, 3), event_guid=e.get('guid'))
                    cc = subtitle_cues(ln, e['start'] / FPS, e['duration'] / FPS)
                    cues += cc; ncue += len(cc)
                if wem_path and not a.no_audio and wem_path in pack.where:
                    d = os.path.join(folder, 'audio'); os.makedirs(d, exist_ok=True)
                    open(os.path.join(d, os.path.basename(wem_path)), 'wb').write(pack.read(wem_path)); rec['audio_file'] = 'audio/' + os.path.basename(wem_path); nwem += 1
                out_lines.append(rec)
            nlines += len(out_lines)
            if cues: write_srt(os.path.join(folder, 'sequence_%s.srt' % m.group(1)), cues)
            seqs.append(dict(sequence=f, timelines=seq_to_tl.get(f, []), sidecar=side_path if side else None, lines=out_lines))
        gj = [dict(bundle=g['bundle'], entity_path=g['entity_path'], entity_id=g['entity_id'], facts=g['facts'], prompts=g['prompts'], nodes=g['nodes']) for g in cg]
        json.dump(dict(conversation=conv, quest=quest, quest_source=src, quest_grammar_id=gid, graphs=gj, sequences=seqs), open(os.path.join(folder, 'conversation.json'), 'w'), indent=1, ensure_ascii=False, default=str)
        index.append(dict(conversation=conv, quest=quest, source=src, sequences=len(files), lines=nlines, audio=nwem, subtitle_cues=ncue, graphs=len(cg), folder=os.path.relpath(folder, a.out)))
        if quest: quests[quest].append(conv)
        print('conv %s -> %s (%d lines, %d wem)' % (conv, quest or 'loose', nlines, nwem), file=sys.stderr)
    for q, cs in quests.items():
        d = os.path.join(a.out, 'quests', safe(q)); json.dump(dict(quest=q, conversations=cs), open(os.path.join(d, 'quest.json'), 'w'), indent=1)

    # ---- systemic dialogue: sys_dialogue_* line files + Sets/Playlists ---------------------------------------------
    sys_files = sorted(n for n in pack.where if re.match(r'data/dialogue/lines/sys_dialogue_[^/]+\.bin$', n))
    line_by_id = {}; sysdir = os.path.join(a.out, 'systemic')
    for f in sys_files:
        name = os.path.basename(f)[:-4]
        if a.only and not re.search(a.only, name): continue
        seq = parse_sequence(pack.read(f, verify=False)); sp = 'data/dialogue/locale/%s/%sstrings.bin' % (a.lang, name)
        side = parse_sidecar(pack.read(sp, verify=False)) if sp in pack.where else None
        lines = join_lines(seq, side, strings); recs = []
        for i, ln in enumerate(lines):
            wp = pack.path_of(ln['wem_rid']) if ln['wem_rid'] and ln['wem_rid'] != NONE_RID else None
            rec = dict(index=i, line_id=hx(ln['line_id']), string_key=ln['string_key'], speaker=ln['speaker'], text=ln['text'], subtitle=ln['subtitle'], wem=wp,
                       dialogue_type=dtypes.get(ln['type_id'], {}).get('name'), flags=ln['flags'], animation=pack.path_of(ln['anim_rid']) if ln['anim_rid'] and ln['anim_rid'] != NONE_RID else None)
            if wp and not a.no_audio and wp in pack.where:
                d = os.path.join(sysdir, safe(name), 'audio'); os.makedirs(d, exist_ok=True)
                open(os.path.join(d, os.path.basename(wp)), 'wb').write(pack.read(wp)); rec['audio_file'] = 'audio/' + os.path.basename(wp)
            recs.append(rec); line_by_id[ln['line_id']] = (name, rec)
        os.makedirs(os.path.join(sysdir, safe(name)), exist_ok=True)
        json.dump(dict(file=f, lines=recs), open(os.path.join(sysdir, safe(name), 'lines.json'), 'w'), indent=1, ensure_ascii=False, default=str)
    sysbin = 'data/dialogue/systemic/systemicdialogue.bin'
    if sysbin in pack.where and not a.only:
        b = pack.read(sysbin, verify=False); cnt = U32(b, 0x10); objs = rmdl_objs(b, 0x18 + 16 * cnt, len(b))
        KEYS = dict(set=0xDFAC0045, item=0x91BF8253, setdef=0xB0CA6253)
        items = [o for o in objs if o['key'] == KEYS['item']]; sets = [o for o in objs if o['key'] == KEYS['set']]; defs = [o for o in objs if o['key'] == KEYS['setdef']]
        item_line = [U64(b, o['pay'][0] + 4) for o in items]; k = 0; out_sets = []; unresolved = 0
        for si, o in enumerate(sets):
            s, e = o['pay']; defid = U64(b, s + 8); n = U32(b, s + 16); its = []
            for j in range(n):
                lid = item_line[k] if k < len(item_line) else None; k += 1
                hit = line_by_id.get(lid)
                if not hit: unresolved += 1
                its.append(dict(line_id=hx(lid) if lid else None, file=hit[0] if hit else None, string_key=hit[1]['string_key'] if hit else None, speaker=hit[1]['speaker'] if hit else None,
                                text=hit[1]['text'] if hit else None, wem=hit[1]['wem'] if hit else None))
            out_sets.append(dict(set_index=si, definition_id=hx(defid), items=its))
        json.dump(dict(sets=out_sets, definitions_raw=[b[o['pay'][0]:o['pay'][1]].hex() for o in defs], items=len(items), consumed=k, unresolved_items=unresolved,
                       note='Set.items are the next n PlaylistItem objects in file order; definition ids / voice profiles / events / handlers are not decoded'),
                  open(os.path.join(sysdir, 'sets.json'), 'w'), indent=1, ensure_ascii=False, default=str)
        print('sets: %d, items %d (unresolved %d)' % (len(out_sets), len(items), unresolved), file=sys.stderr)
    json.dump(index, open(os.path.join(a.out, 'index.json'), 'w'), indent=1)
    print('conversations: %d, in quests: %d (%d quests), loose: %d' % (len(index), sum(1 for i in index if i['quest']), len(quests), sum(1 for i in index if not i['quest'])), file=sys.stderr)

if __name__ == '__main__': main()
