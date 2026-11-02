# Control (Northlight) — Address & Structure Tables

## RMDTOC Header

| Off | Type | Field |
|-----|------|-------|
| `0x00` | `u32` | `'COTR'` (`0x52544F43`) |
| `0x04` | `u32` | version = 3 |
| `0x08` | `u32` | table_off |
| `0x0C` | `u32` | table_size |
| `0x10` | `u32` | archives_off |
| `0x14` | `u32` | archives_count |
| `0x18` | `u32` | paths_off |
| `0x1C` | `u32` | paths_count |
| `0x20` | `u32` | files_off |
| `0x24` | `u32` | files_count |
| `0x28` | `u32` | strings_off |
| `0x2C` | `u32` | strings_size |
| `0x30` | `u32` | types_off |
| `0x34` | `u32` | types_count |
| `0x38` | `u32` | metadata_off (DMKP) |
| `0x3C` | `u32` | metadata_size |
| `0x40..0x4F` | — | reserved (0) |
| `0x50` | `u32` | chunks_off |
| `0x54` | `u32` | chunks_size |
| `0x58` | — | descriptor table |

## Descriptor (table_off + 16·i)

| Rel | Type | Field |
|-----|------|-------|
| `+3` | `u40` | data_off |
| `+8` | `u32` | decomp_size |
| `+12` | `u32` | comp_size (`0` = raw) |

## Logical Tables

| Table | Stride | Layout |
|-------|--------|--------|
| Strings | var | UTF-8 @ `strings_off + rel` |
| Archives | `0x18` | `{u32 name_off, u32 name_len, u64 hash, u64 blob_size}` |
| Paths | `0x1C` | `{u32 parent @0, u32 name_off @0x14, u32 name_len @0x18}` |
| Files | `0x20` | `{u32 chunk_rel, u32 chunk_bytes, u32 path_idx, u32 name_off, u32 name_len, u32 total_size, u32 meta_rel, u32 meta_size}` |
| Chunks | `16` | `{u8 flags, u8 archive, u8 0, u40 blob_off, u32 decomp, u32 comp}` |
| Types | `8` | `{u32 rel_off, u32 size}` → class name |

Chunk `flags`: `0x10` = LZ4, `0x00` = stored.

## DMKP

```
'DMKP' | u32 n | n×{u32 typeIndex, u16 start, u16 end} | body
```

| TOC-local | Class | Payload |
|-----------|-------|---------|
| 0 | `r::FileInfoMetadata` | `{u32 1, u32 size, u32 0, u32 CRC32}` |
| 1/2 | `r::ResourceMetadata` | `{u32 3, u32 1, u64 primaryID}` |

`primaryID = CityHash64(canonical path)` (294 625)

## EXE Entry Points

| VA | Role |
|----|------|
| `0x140000000` | image base |
| `0x14322D310` | TOC view builder |
| `0x143229970` | DMKP parser |
| `0x1432299F0` | type-key normaliser |
| `0x141CECBF0` | texture format names |
| `0x14493B3B0` | DXGI format map |

## TextureMetadata / .tex (148 B)

| Off | Type | Field |
|-----|------|-------|
| `+0x00` | `u32` | tag = 8 |
| `+0x04` | `u32` | m_tileMode = `0xFFFFFFFF` |
| `+0x08` | `u16` | m_flags |
| `+0x0A` | `u16` | width |
| `+0x0C` | `u16` | height |
| `+0x0E` | `u16` | depth |
| `+0x10` | `u8` | m_mipmapCount |
| `+0x11` | `u8` | m_type = 0 |
| `+0x12` | `u8` | m_format (1–46) |
| `+0x13` | `u8` | m_filter |
| `+0x14` | `u32` | row_count n |
| `+0x18` | n×`{u32,u32}` | `{data_offset, bytes_remaining}` |
| … | 20 B | trailer `{u32 x, u32 y, u32 0, f32 1.0, f32}` |

## Material (.material)

```
u32 20 | u32 1 | u32 propertyCount
n×{u32 nameLen, name, u32 type, value}
```

type 0–3 = float vec 4/8/12/16 B · type 4 = texture slot · type 12 = Emission

## MeshMetadata / .binfbx

```
u32 38 | u32 1 | f32[6] AABB | f32 0 | f32[4] sphere
u8 hasBones | u8 missingMat | u8 extraMat
u32 animFrames=1 | u64 skeleton_id | u32 0xFFFFFFFF
u32 pathLen | lodTemplatePath
44 B LOD prefix | (streamable+1)×MeshFileLayout(48 B)
u8 flag | u32 submesh_count | n×{u32,u64 id} | 20 B footer
```

Native starts `u32 0x5C`.

## Audio Inventory

| Type | Count | Bytes | Role |
|------|-------|-------|------|
| `.wem` media | 44 969 | 12.6 GB | SFX / music |
| `.wem` dialogue | 112 433 | 7.5 GB | spoken (8 lang) |
| `.bnk` | 5 786 | 14.4 MB | Wwise HIRC |
| `.sndevent` | 5 705 | 0 | event-ID + bank dep |

BKHD: `'BKHD' | u32 0x28 | u32 154 | u32 bankID | …`  
HIRC event type 4: `objectID == bankID`

## Dialogue / ECS Hashes

| Hash | Name |
|------|------|
| `0x56283CF2` | ConversationGraphComponent |
| `0x3E13EE09` | ConversationGraphComponentDebug |
| `0x74C736B4` | DebugNameComponent |
| `0xE3E6E41B` | LuaScriptComponent |
| `0x58FE2733` | DialogueLine |
| `0x4135DAB6` | DialogueString |
| `0x1BFC72D5` | RID reference |
| `0x71E86E82` | TimelineResource |
| `0x79E3C0DA` | Timeline |
| `0x36B2DD1E` | TimelineTrack |
| `0xDBFF2F1F` | TimelineEvent |
| `0xAAB3C695` | DialogueTimelineEvent |
| `0xB61ABB1B` | CameraTimelineEvent |
| `0xC81CB61E` | AnimationParameterTimelineEvent |
| `0x9CEA7162` | ScriptTimelineEvent |
| `0x7378CA33` | asset: audio |
| `0xBA32F39E` | asset: anim clip |
| `0x6DD154FF` | asset: sequence.bin |
| `0xF24361E4` | asset: dialogue string |
| `0x91BF8253` | PlaylistItem |
| `0xDFAC0045` | Set |
| `0x7DE2D7D6` | Condition |
| `0xBF724AE9` | EventHandler |
| `0xD029D60B` | Event |
| `0xB0CA6253` | SetDefinition |
| `0x58ED0605` | VoiceProfile |
| `0x427EBFF2` | Variable |
| `0xF58CBE35` | EventSystem |

## Metadata Class Keys (selected)

| Class | Key | Count | Ext |
|-------|-----|-------|-----|
| TextureMetadata | — | 38 659 | `.tex` |
| MaterialMetadata | — | 11 877 | `.material` |
| MeshMetadata | — | 24 363 | `.binfbx` |
| ShaderMetadata | `0x5D7EBDC5` | 97 | `.binshader` |
| StringTableMetadata | `0x47DFC9E2` | 15 | `string_table.bin` |
| SkeletonMetadata | `0x338D8396` | 433 | `.binskeleton` |
| PhysXClothMetadata | `0xCF1FBC60` | 109 | `.binapx` |
| IlluminationVolumeGIData | — | 2 506 | `.ivgidata` |
| ParticleMetadata | `0x25A7D865` | 1 | `.mps` |

## Other Render

| Ext | Count | Meta |
|-----|-------|------|
| `.ivgidata`/`.ivtree` | 2 506 | `u32 1 \| u32 hdr∈{12,16}` |
| `.sdf` | 637 | `u32 0` |
| `.particle` | 1 370 | v7 |
| `.flare` | 55 | — |

## Misc

| Item | Value |
|------|-------|
| FNV-1a seed | `0x811C9DC5` · prime `0x01000193` |
| ConversationGraph size | `0x110` |
| BNDL header | `0x0E + 8k` |
| Sequence record | 41 B unaligned |
| Node flag sequence | `0x40` |
| Node flag choice | `0x2` |
