# CONTROL Resonant (Northlight Engine) — Address & Structure Tables

## RMDTOC Header

| Off          | Type  | Field                          |
| ------------ | ----- | ------------------------------ |
| `0x00`       | `u32` | `'COTR'` (`0x52544F43`)        |
| `0x04`       | `u32` | version = 3                    |
| `0x08`       | `u32` | table_off (= `0x58`)           |
| `0x0C`       | `u32` | table_size (16 × descriptors)  |
| `0x10`       | `u32` | archives_off (= 0 logical)     |
| `0x14`       | `u32` | archives_count                 |
| `0x18`       | `u32` | paths_off                      |
| `0x1C`       | `u32` | paths_count                    |
| `0x20`       | `u32` | files_off                      |
| `0x24`       | `u32` | files_count                    |
| `0x28`       | `u32` | strings_off                    |
| `0x2C`       | `u32` | strings_size                   |
| `0x30`       | `u32` | types_off                      |
| `0x34`       | `u32` | types_count                    |
| `0x38`       | `u32` | metadata_off (DMKP)            |
| `0x3C`       | `u32` | metadata_size                  |
| `0x40..0x4F` | —     | reserved (0)                   |
| `0x50`       | `u32` | chunks_off                     |
| `0x54`       | `u32` | chunks_size                    |
| `0x58`       | —     | descriptor table               |

## Descriptor (table_off + 16·i)

| Rel  | Type  | Field                           |
| ---- | ----- | ------------------------------- |
| `+0` | 3 B   | undecoded                       |
| `+3` | `u40` | data_off                        |
| `+8` | `u32` | decomp_size                     |
| `+12`| `u32` | comp_size (`0` = raw, else LZ4) |

## Logical Tables

| Table    | Stride | Layout                                                                                          |
| -------- | ------ | ----------------------------------------------------------------------------------------------- |
| Strings  | var    | UTF-8 @ `strings_off + rel`                                                                     |
| Archives | `0x18` | `{u32 name_off, u32 name_len, u64 hash, u64 blob_size}`                                         |
| Paths    | `0x1C` | `{u32 parent @0, …, u32 name_off @0x14, u32 name_len @0x18}`; `0x04..0x13` undecoded            |
| Files    | `0x20` | `{u32 chunk_rel, u32 chunk_bytes, u32 path_idx, u32 name_off, u32 name_len, u32 total_size, u32 meta_rel, u32 meta_size}` |
| Chunks   | `16`   | `{u8 flags, u8 archive, u8 0, u40 blob_off, u32 decomp, u32 comp}`                              |
| Types    | `8`    | `{u32 rel_off, u32 size}` → class name (151 entries, 43 classes)                                |
| Metadata | var    | `meta_rel` / `meta_size` → DMKP record                                                          |

Chunk `flags`: `0x10` = LZ4, `0x00` = stored. Byte 2 = 0 always.

## DMKP

`'DMKP' | u32 n | n×{u32 typeIndex, u16 start, u16 end} | body`

| Class                 | Section  | Payload                                                      |
| --------------------- | -------- | ------------------------------------------------------------ |
| `r::FileInfoMetadata` | 16 B     | `{u32 1, u32 size, u32 0, u32 CRC32}`                        |
| `r::ResourceMetadata` | 20+12N B | `{u32 3, u32 1, u64 primaryID, u32 N, N×{u32 1, u64 depID}}` |

`typeIndex` TOC-local. `primaryID = CityHash64(canon(path))` (`/`→`\`, lower, strip `data\`/`data_pc\`).

## EXE Entry Points

| VA            | Role                     |
| ------------- | ------------------------ |
| `0x140000000` | image base               |
| `0x14322D310` | TOC view builder         |
| `0x143229970` | DMKP parser              |
| `0x1432299F0` | type-index → runtime key |
| `0x143321D40` | CityHash64 path          |
| `0x14493B3B0` | DXGI format table (5×u32)|
| `0x141CECBF0` | format switch (code)     |

## TextureMetadata (TOC, 38 659)

| Off     | Type          | Field                                      |
| ------- | ------------- | ------------------------------------------ |
| `+0x00` | `u32`         | tag = 8                                    |
| `+0x04` | `u32`         | `0xFFFFFFFF`                               |
| `+0x08` | `u16`         | m_flags (bit0 = Bink)                      |
| `+0x0A` | `u16`         | width                                      |
| `+0x0C` | `u16`         | height                                     |
| `+0x0E` | `u16`         | depth                                      |
| `+0x10` | `u8`          | mip count                                  |
| `+0x11` | `u8`          | m_type = 0                                 |
| `+0x12` | `u8`          | m_format (1–46)                            |
| `+0x13` | `u8`          | m_filter                                   |
| `+0x14` | `u32`         | row_count n                                |
| `+0x18` | n×`{u32,u32}` | `{data_offset, bytes_remaining}`           |
| …       | 20 B          | trailer `{u32 x, u32 y, u32 0, f32 1.0, f32 0.0}` |

Size = `4·(11 + 2n)`.

## .tex File (DDS / Bink)

### DDS (148 B header)

| Off    | Type      | Field                 |
| ------ | --------- | --------------------- |
| `0x00` | `char[4]` | `"DDS "`              |
| `0x04` | `u32`     | dwSize = 124          |
| `0x08` | `u32`     | dwFlags               |
| `0x0C` | `u32`     | height                |
| `0x10` | `u32`     | width                 |
| `0x54` | `char[4]` | `"DX10"`              |
| `0x80` | `u32`     | dxgiFormat            |
| `0x84` | `u32`     | resourceDimension = 3 |
| `0x94` | —         | mip data              |

### Bink (`KB2j`)

| Off    | Type  | Field       |
| ------ | ----- | ----------- |
| `0x00` | char  | `"KB2j"`    |
| `0x04` | `u32` | size − 8    |
| `0x08` | `u32` | frame count |
| `0x14` | `u32` | width       |
| `0x18` | `u32` | height      |

## Material (.material)

```
u32 20 | u32 1 | u32 propertyCount
n×{u32 nameLen, name, u32 type, value}
```

type 0–3 = float vec 4/8/12/16 B · type 4 = texture slot · type 12 = Emission (bool)

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

| Type            | Count   | Bytes   | Role                |
| --------------- | ------- | ------- | ------------------- |
| `.wem` media    | 44 969  | 12.6 GB | SFX / music         |
| `.wem` dialogue | 112 433 | 7.5 GB  | spoken (8 lang)     |
| `.bnk`          | 5 786   | 14.4 MB | Wwise HIRC          |
| `.sndevent`     | 5 705   | 0       | event-ID + bank dep |

BKHD: `'BKHD' | u32 0x28 | u32 154 | u32 bankID | …`  
HIRC event type 4: `objectID == bankID`  
bankID / eventID = FNV-1 32 (lower name)

## Dialogue / ECS Hashes

| Hash         | Name                            |
| ------------ | ------------------------------- |
| `0x56283CF2` | ConversationGraphComponent      |
| `0x3E13EE09` | ConversationGraphComponentDebug |
| `0x74C736B4` | DebugNameComponent              |
| `0xE3E6E41B` | LuaScriptComponent              |
| `0x58FE2733` | DialogueLine                    |
| `0x4135DAB6` | DialogueString                  |
| `0x1BFC72D5` | RID reference                   |
| `0x71E86E82` | TimelineResource                |
| `0x79E3C0DA` | Timeline                        |
| `0x36B2DD1E` | TimelineTrack                   |
| `0xDBFF2F1F` | TimelineEvent                   |
| `0xAAB3C695` | DialogueTimelineEvent           |
| `0xB61ABB1B` | CameraTimelineEvent             |
| `0xC81CB61E` | AnimationParameterTimelineEvent |
| `0x9CEA7162` | ScriptTimelineEvent             |
| `0x7378CA33` | asset: audio                    |
| `0xBA32F39E` | asset: anim clip                |
| `0x6DD154FF` | asset: sequence.bin             |
| `0xF24361E4` | asset: dialogue string          |
| `0x91BF8253` | PlaylistItem                    |
| `0xDFAC0045` | Set                             |
| `0x7DE2D7D6` | Condition                       |
| `0xBF724AE9` | EventHandler                    |
| `0xD029D60B` | Event                           |
| `0xB0CA6253` | SetDefinition                   |
| `0x58ED0605` | VoiceProfile                    |
| `0x427EBFF2` | Variable                        |
| `0xF58CBE35` | EventSystem                     |
| `0xC26E1FD3` | VideoTimelineEvent              |
| `0x5823FB20` | SoundTimelineEvent              |
| `0x383FCF03` | METATEXTURE                     |
| `0x38ABEE66` | SOUND_EVENT                     |

## Metadata Classes (all 43)

| Class                                      | Runtime-key  | Count  | Ext                        |
| ------------------------------------------ | ------------ | ------ | -------------------------- |
| `r::FileInfoMetadata`                      | `0x95e8c0ef` | 294625 | —                          |
| `r::ResourceMetadata`                      | `0x368b4205` | 294625 | —                          |
| `snd_legacy::ExternalSourceMetadata`       | `0xa668d49d` | 112433 | `.wem`                     |
| `snd::SoundMediaMetadata`                  | `0x43222909` | 44969  | `.wem`                     |
| `rend::TextureMetadata`                    | `0x968a49b7` | 38659  | `.tex`                     |
| `content::AnimationSourceMetadata`         | `0x5a69f730` | 24376  | `.binfbx`/`.binanimclip`   |
| `rend::MeshMetadata`                       | `0xfe276448` | 24363  | `.binfbx`                  |
| `puppet::ClipMetadata`                     | `0x5215f16f` | 13036  | `.binanimclip`             |
| `rend::MaterialMetadata`                   | `0x3b8e5067` | 11877  | `.material`                |
| `snd_legacy::SoundBankMetadata`            | `0xdb3975dd` | 11491  | `.bnk`/`.sndevent`         |
| `physics::CollisionPackageMetadata`        | `0xcc074b60` | 10123  | `.binpx`                   |
| `snd_legacy::DialogueMetadata`             | `0xf9126641` | 5847   | `.bin`                     |
| `snd_legacy::DialogueStringTableMetadata`  | `0x302f5b71` | 5846   | `.bin`                     |
| `coregame::TimelineMetadata`               | `0x826dae80` | 5260   | `.bintimeline`             |
| `rend::IlluminationVolumeTreeMetadata`     | `0xfd2565a2` | 2506   | `.ivtree`                  |
| `rend::IlluminationVolumeGIDataMetadata`   | `0xb194d640` | 2506   | `.ivgidata`                |
| `rend::ParticleSystemMetadata`             | `0x32f0de4b` | 1370   | `.particle`                |
| `content::LuaScriptMetadata`               | `0x5d1d277a` | 813    | `.binlua`                  |
| `rend::SDFVolumeMetadata`                  | `0x53cd678d` | 637    | `.sdf`                     |
| `puppet::MotionDatabaseMetadata`           | `0x1b92f6c5` | 495    | `.binmotiondb`             |
| `puppet::SkeletonMetadata`                 | `0x338d8396` | 433    | `.binskeleton`             |
| `puppet::GraphMetadata`                    | `0x731dc02f` | 368    | `.binanimgraph`            |
| `coreshared::MercunaNavmeshMetadata`       | `0x1dca03e3` | 269    | `.binmnav`                 |
| `coreshared::MercunaNavmesh3DMetadata`     | `0xa8b7ea33` | 269    | `.binmnav3d`               |
| `puppet::RBFMetadata`                      | `0x3d75eea`  | 198    | `.rbf`                     |
| `coreshared::EQSQueryMetadata`             | `0xefaf9cc7` | 135    | `.bineqs`                  |
| `coreshared::BehaviorTreeMetadata`         | `0x464171b2` | 121    | `.binbt`                   |
| `physics::PhysXClothMetadata`              | `0xcf1fbc60` | 109    | `.binapx`                  |
| `rend::ShaderMetadata`                     | `0x5d7ebdc5` | 97     | `.binshader`               |
| `coreshared::GfxGraphMetadata`             | `0x97b97719` | 96     | `.gfxgraph`                |
| `physics::RagdollProfileMetadata`          | `0xcd632cb4` | 83     | `.binragdollprof`          |
| `puppet::MixerMetadata`                    | `0x191a97f6` | 64     | `.binanimmixer`            |
| `rend::FlareMetadata`                      | `0x4d1fcae`  | 55     | `.flare`                   |
| `ui::FontMetadata`                         | `0x751b8481` | 23     | `.ttf`/`.otf`              |
| `ui::CSSMetadata`                          | `0x34eb980a` | 17     | `.css`                     |
| `loc::StringTableMetadata`                 | `0x47dfc9e2` | 15     | `.bin`                     |
| `rend::GeometryTransformMetadata`          | `0x1f96d6d8` | 14     | `.gt`                      |
| `physics::ClothProfileMetadata`            | `0x2555edc9` | 12     | `.binclothprof`            |
| `puppet::BlendSpaceMetadata`               | `0xfdc51eaa` | 11     | `.binblendspace`           |
| `coreshared::FiniteStateMachineMetadata`   | `0x711aa8c7` | 2      | `.binfsm`                  |
| `snd_legacy::SystemicDialogueMetadata`     | `0x461ba033` | 1      | `.bin`                     |
| `coreshared::ParticleMetadata`             | `0x25a7d865` | 1      | `.mps`                     |
| `ui::PageMetadata`                         | `0x83e69a63` | 1      | `.ui`                      |

## Other Render

| Ext                   | Count | Meta                       |
| --------------------- | ----- | -------------------------- |
| `.ivgidata`/`.ivtree` | 2 506 | `u32 1 \| u32 hdr∈{12,16}` |
| `.sdf`                | 637   | `u32 0`                    |
| `.particle`           | 1 370 | v7                         |
| `.flare`              | 55    | —                          |

## Misc

| Item                   | Value                             |
| ---------------------- | --------------------------------- |
| FNV-1a seed            | `0x811C9DC5` · prime `0x01000193` |
| ConversationGraph size | `0x110`                           |
| BNDL header            | `0x0E + 8k`                       |
| Sequence record        | 41 B unaligned                    |
| Node flag sequence     | `0x40`                            |
| Node flag choice       | `0x2`                             |
| Wwise version          | 154                               |
| Packages total         | 24 TOC / 296 484 files / 177.8 GB |
