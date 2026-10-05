"""Universal DDS/DX10 decoder for the Resonant Asset Browser.

The DDS container/header handling is implemented here.  BC1/BC3/BC4/BC5/
BC6H/BC7 decompression is delegated to the established cross-platform
texture2ddecoder package.  BC2 is decoded here because texture2ddecoder's
Python binding exposes BC3 but not BC2; BC2 color is BC1 plus explicit 4-bit
alpha, exactly as defined by the DDS/DXGI format.

Public API:
    decode_dds(data: bytes) -> PIL.Image.Image

The module can bootstrap texture2ddecoder into a private directory beside
this file when it is not installed.  No global pip installation is required.
"""

from __future__ import annotations

import importlib
import os
import platform
import subprocess
import sys
import tempfile
from io import BytesIO
from pathlib import Path
import struct

try:
    from PIL import Image
except ImportError as exc:
    raise ImportError("Pillow is required by the GUI to display decoded DDS images.") from exc


_CACHE = Path(__file__).resolve().parent / ".dds_decoder_runtime"


def _load_texture2ddecoder():
    try:
        return importlib.import_module("texture2ddecoder")
    except ImportError:
        pass

    _CACHE.mkdir(parents=True, exist_ok=True)
    cache_str = str(_CACHE)
    if cache_str not in sys.path:
        sys.path.insert(0, cache_str)

    try:
        return importlib.import_module("texture2ddecoder")
    except ImportError:
        pass

    # Install only into our private cache.  texture2ddecoder publishes
    # Windows/Linux wheels and is based on Perfare's Texture2DDecoder.
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        "--upgrade",
        "--target",
        str(_CACHE),
        "texture2ddecoder==1.0.6",
    ]
    try:
        subprocess.check_call(cmd)
    except Exception as exc:
        raise RuntimeError(
            "The DDS codec texture2ddecoder could not be installed into "
            f"{_CACHE}. Install texture2ddecoder==1.0.6 manually if the "
            "machine is offline."
        ) from exc

    importlib.invalidate_caches()
    return importlib.import_module("texture2ddecoder")


_CODEC = None
_CODEC_ERROR = None


def _codec():
    global _CODEC, _CODEC_ERROR
    if _CODEC is None:
        if _CODEC_ERROR is not None:
            raise _CODEC_ERROR
        try:
            _CODEC = _load_texture2ddecoder()
        except Exception as exc:
            _CODEC_ERROR = exc
            raise
    return _CODEC


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


# DXGI_FORMAT values.
# Typeless/UNORM/SRGB variants are accepted where their byte layout is the
# same. The viewer renders the decoded first mip as RGBA.
BC1 = {70, 71, 72}
BC2 = {73, 74, 75}
BC3 = {76, 77, 78}
BC4 = {79, 80, 81}
BC5 = {82, 83, 84}
BC6U = {94, 95}
BC6S = {96}
BC7 = {97, 98, 99}

R32G32B32A32_FLOAT = {1, 2, 3, 4}
R16G16B16A16_UNORM = {9, 11}
R16G16B16A16_FLOAT = {10}
R10G10B10A2 = {23, 24, 25}
UNCOMPRESSED_RGBA = {27, 28, 29, 30, 31, 32}
R16G16_UNORM = {33, 35, 36}
R16G16_SNORM = {37}
R32 = {39, 40, 41, 42}
R8G8 = {43, 44, 45, 46, 47}
R8 = {48, 49, 50, 51, 52}
A8 = {53}
UNCOMPRESSED_BGRA = {87, 88, 89, 90, 91, 92, 93}


def _rgb565(v: int):
    r = ((v >> 11) & 31) * 255 // 31
    g = ((v >> 5) & 63) * 255 // 63
    b = (v & 31) * 255 // 31
    return r, g, b


def _bc1_block(block: bytes):
    c0 = _u16(block, 0)
    c1 = _u16(block, 2)
    a = _rgb565(c0)
    b = _rgb565(c1)
    if c0 > c1:
        colors = [
            (*a, 255),
            (*b, 255),
            ((2*a[0] + b[0]) // 3, (2*a[1] + b[1]) // 3, (2*a[2] + b[2]) // 3, 255),
            ((a[0] + 2*b[0]) // 3, (a[1] + 2*b[1]) // 3, (a[2] + 2*b[2]) // 3, 255),
        ]
    else:
        colors = [
            (*a, 255),
            (*b, 255),
            ((a[0] + b[0]) // 2, (a[1] + b[1]) // 2, (a[2] + b[2]) // 2, 255),
            (0, 0, 0, 0),
        ]
    bits = int.from_bytes(block[4:8], "little")
    out = []
    for i in range(16):
        out.append(colors[(bits >> (2*i)) & 3])
    return out


def _alpha_values(block: bytes, signed=False):
    a0, a1 = block[0], block[1]
    vals = [a0, a1]
    if a0 > a1:
        vals += [
            (6*a0 + a1) // 7,
            (5*a0 + 2*a1) // 7,
            (4*a0 + 3*a1) // 7,
            (3*a0 + 4*a1) // 7,
            (2*a0 + 5*a1) // 7,
            (a0 + 6*a1) // 7,
        ]
    else:
        vals += [
            (4*a0 + a1) // 5,
            (3*a0 + 2*a1) // 5,
            (2*a0 + 3*a1) // 5,
            (a0 + 4*a1) // 5,
            0,
            255,
        ]
    bits = int.from_bytes(block[2:8], "little")
    return [vals[(bits >> (3*i)) & 7] for i in range(16)]


def _decode_bc2(data: bytes, width: int, height: int) -> bytes:
    bw = (width + 3) // 4
    bh = (height + 3) // 4
    out = bytearray(width * height * 4)
    need = bw * bh * 16
    if len(data) < need:
        raise ValueError(f"Truncated BC2 payload: need {need}, got {len(data)}")
    p = 0
    for by in range(bh):
        for bx in range(bw):
            block = data[p:p+16]
            p += 16
            colors = _bc1_block(block[8:16])
            alpha_bits = int.from_bytes(block[:8], "little")
            for y in range(4):
                for x in range(4):
                    i = y*4 + x
                    a = ((alpha_bits >> (4*i)) & 0xF) * 17
                    r, g, b, _ = colors[i]
                    px = bx*4 + x
                    py = by*4 + y
                    if px < width and py < height:
                        q = (py*width + px)*4
                        out[q:q+4] = bytes((r, g, b, a))
    return bytes(out)


def _decode_external(fmt: str, payload: bytes, width: int, height: int, *, signed=False):
    codec = _codec()
    blocks = ((width + 3) // 4) * ((height + 3) // 4)
    bpb = 8 if fmt in ("bc1", "bc4") else 16
    payload = payload[:blocks*bpb]
    fn = getattr(codec, f"decode_{fmt}", None)
    if fn is None:
        raise RuntimeError(f"texture2ddecoder does not expose decode_{fmt}().")
    raw = fn(payload, width, height)
    if raw is None:
        raise RuntimeError(f"texture2ddecoder failed to decode {fmt} texture.")
    return bytes(raw)


def _raw_bgra_to_rgba(raw: bytes, width: int, height: int) -> Image.Image:
    expected = width * height * 4
    if len(raw) != expected:
        raise ValueError(f"Decoder returned {len(raw)} bytes, expected {expected}.")
    return Image.frombytes("RGBA", (width, height), raw, "raw", "BGRA")


def _decode_r16g16_snorm(data: bytes, width: int, height: int) -> Image.Image:
    """Visualize DXGI_FORMAT_R16G16_SNORM as RGBA.

    Each channel is a signed 16-bit normalized value. The display mapping is
    [-1, 1] -> [0, 255], with B=0 and A=255. This preserves the two source
    channels without pretending they are an ordinary RGB texture.
    """
    count = width * height
    need = count * 4
    if len(data) < need:
        raise ValueError(f"Truncated R16G16_SNORM payload: need {need}, got {len(data)}")
    out = bytearray(count * 4)
    for i in range(count):
        r16, g16 = struct.unpack_from("<hh", data, i * 4)
        r = max(0, min(255, int(round((r16 / 32767.0 * 0.5 + 0.5) * 255.0))))
        g = max(0, min(255, int(round((g16 / 32767.0 * 0.5 + 0.5) * 255.0))))
        q = i * 4
        out[q:q+4] = bytes((r, g, 0, 255))
    return Image.frombytes("RGBA", (width, height), bytes(out))


def _need_payload(payload: bytes, size: int, label: str):
    if len(payload) < size:
        raise ValueError(f"Truncated {label} payload: need {size}, got {len(payload)}")

def _decode_r16g16_unorm(data: bytes, width: int, height: int) -> Image.Image:
    count = width * height
    need = count * 4
    _need_payload(data, need, "R16G16")
    out = bytearray(count * 4)
    for i in range(count):
        r16, g16 = struct.unpack_from("<HH", data, i * 4)
        q = i * 4
        out[q:q+4] = bytes((r16 >> 8, g16 >> 8, 0, 255))
    return Image.frombytes("RGBA", (width, height), bytes(out))

def _decode_r16g16b16a16(data: bytes, width: int, height: int, floating=False) -> Image.Image:
    count = width * height
    need = count * 8
    _need_payload(data, need, "R16G16B16A16")
    out = bytearray(count * 4)
    for i in range(count):
        if floating:
            vals = struct.unpack_from("<eeee", data, i * 8)
            rgba = [max(0, min(255, int(round(v * 255.0)))) for v in vals]
        else:
            vals = struct.unpack_from("<HHHH", data, i * 8)
            rgba = [v >> 8 for v in vals]
        out[i*4:i*4+4] = bytes(rgba)
    return Image.frombytes("RGBA", (width, height), bytes(out))

def _decode_r10g10b10a2(data: bytes, width: int, height: int) -> Image.Image:
    count = width * height
    need = count * 4
    _need_payload(data, need, "R10G10B10A2")
    out = bytearray(count * 4)
    for i in range(count):
        v = struct.unpack_from("<I", data, i * 4)[0]
        r = (v & 0x3FF) * 255 // 1023
        g = ((v >> 10) & 0x3FF) * 255 // 1023
        b = ((v >> 20) & 0x3FF) * 255 // 1023
        a = ((v >> 30) & 0x3) * 255 // 3
        out[i*4:i*4+4] = bytes((r, g, b, a))
    return Image.frombytes("RGBA", (width, height), bytes(out))

def _decode_r32(data: bytes, width: int, height: int, floating=False) -> Image.Image:
    count = width * height
    need = count * 4
    _need_payload(data, need, "R32")
    out = bytearray(count * 4)
    for i in range(count):
        v = struct.unpack_from("<f", data, i*4)[0] if floating else struct.unpack_from("<I", data, i*4)[0]
        if floating:
            c = max(0, min(255, int(round(v * 255.0))))
        else:
            c = (v >> 24) & 0xFF
        out[i*4:i*4+4] = bytes((c, c, c, 255))
    return Image.frombytes("RGBA", (width, height), bytes(out))


def decode_dds(data: bytes) -> Image.Image:
    """Decode a DDS/DX10 image into a Pillow RGBA image."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("decode_dds expects bytes-like data")
    data = bytes(data)
    if len(data) < 128 or data[:4] != b"DDS ":
        raise ValueError("Not a DDS file.")
    if _u32(data, 4) != 124:
        raise ValueError("Unsupported DDS header size.")

    height = _u32(data, 12)
    width = _u32(data, 16)
    if width <= 0 or height <= 0:
        raise ValueError(f"Invalid DDS dimensions: {width}x{height}")

    fourcc = data[84:88]

    if fourcc == b"DX10":
        if len(data) < 148:
            raise ValueError("DDS DX10 header is truncated.")
        dxgi = _u32(data, 128)
        resource_dimension = _u32(data, 132)
        misc_flag = _u32(data, 136)
        array_size = _u32(data, 140)
        if resource_dimension != 3:
            raise NotImplementedError("Only DX10 Texture2D resources are supported.")
        if array_size != 1:
            raise NotImplementedError("Texture arrays are not supported by the single-image viewer.")
        payload = data[148:]

        if dxgi in BC1:
            raw = _decode_external("bc1", payload, width, height)
            return _raw_bgra_to_rgba(raw, width, height)
        if dxgi in BC2:
            return Image.frombytes("RGBA", (width, height), _decode_bc2(payload, width, height))
        if dxgi in BC3:
            raw = _decode_external("bc3", payload, width, height)
            return _raw_bgra_to_rgba(raw, width, height)
        if dxgi in BC4:
            raw = _decode_external("bc4", payload, width, height)
            img = _raw_bgra_to_rgba(raw, width, height)
            r = img.getchannel("R")
            return Image.merge("RGBA", (r, r, r, Image.new("L", img.size, 255)))
        if dxgi in BC5:
            raw = _decode_external("bc5", payload, width, height)
            return _raw_bgra_to_rgba(raw, width, height)
        if dxgi in BC6U:
            raw = _decode_external("bc6", payload, width, height)
            return _raw_bgra_to_rgba(raw, width, height)
        if dxgi in BC6S:
            codec = _codec()
            fn = getattr(codec, "decode_bc6", None)
            if fn is None:
                raise RuntimeError("texture2ddecoder has no BC6 decoder.")
            raw = fn(payload[:((width+3)//4)*((height+3)//4)*16], width, height)
            return _raw_bgra_to_rgba(bytes(raw), width, height)
        if dxgi in BC7:
            raw = _decode_external("bc7", payload, width, height)
            return _raw_bgra_to_rgba(raw, width, height)
        if dxgi in UNCOMPRESSED_RGBA:
            return Image.frombytes("RGBA", (width, height), payload[:width*height*4], "raw", "RGBA")
        if dxgi in UNCOMPRESSED_BGRA:
            return Image.frombytes("RGBA", (width, height), payload[:width*height*4], "raw", "BGRA")
        if dxgi in R8:
            raw = payload[:width*height]
            return Image.merge("RGBA", (Image.frombytes("L", (width, height), raw), Image.new("L", (width,height)), Image.new("L", (width,height)), Image.new("L", (width,height),255)))
        if dxgi in R8G8:
            raw = payload[:width*height*2]
            _need_payload(raw, width*height*2, "R8G8")
            out = bytearray(width*height*4)
            for i in range(width*height):
                r, g = raw[i*2:i*2+2]
                out[i*4:i*4+4] = bytes((r, g, 0, 255))
            return Image.frombytes("RGBA", (width, height), bytes(out))
        if dxgi in R16G16_SNORM:
            return _decode_r16g16_snorm(payload, width, height)
        if dxgi in R16G16_UNORM:
            return _decode_r16g16_unorm(payload, width, height)
        if dxgi in R16G16B16A16_FLOAT:
            return _decode_r16g16b16a16(payload, width, height, floating=True)
        if dxgi in R16G16B16A16_UNORM:
            return _decode_r16g16b16a16(payload, width, height, floating=False)
        if dxgi in R10G10B10A2:
            return _decode_r10g10b10a2(payload, width, height)
        if dxgi in R32:
            return _decode_r32(payload, width, height, floating=(dxgi == 40))
        if dxgi in A8:
            raw = payload[:width*height]
            _need_payload(raw, width*height, "A8")
            return Image.merge("RGBA", (Image.new("L", (width, height)), Image.new("L", (width, height)), Image.new("L", (width, height)), Image.frombytes("L", (width, height), raw)))
        if dxgi in R32G32B32A32_FLOAT:
            need = width * height * 16
            _need_payload(payload, need, "R32G32B32A32")
            out = bytearray(width * height * 4)
            for i in range(width * height):
                vals = struct.unpack_from("<ffff", payload, i * 16)
                out[i*4:i*4+4] = bytes(max(0, min(255, int(round(v * 255.0)))) for v in vals)
            return Image.frombytes("RGBA", (width, height), bytes(out))

        # Pillow is a useful final fallback for DX10 variants that this small
        # explicit decoder does not need to interpret itself.  In particular,
        # this covers less common DXGI layouts on systems where Pillow's DDS
        # plugin knows the format.
        try:
            with Image.open(BytesIO(data)) as image:
                return image.convert("RGBA")
        except Exception:
            pass
        raise NotImplementedError(f"Unsupported DXGI_FORMAT {dxgi}.")

    # Legacy DDS formats.
    payload = data[128:]
    if fourcc == b"DXT1":
        raw = _decode_external("bc1", payload, width, height)
        return _raw_bgra_to_rgba(raw, width, height)
    if fourcc in (b"DXT2", b"DXT3"):
        return Image.frombytes("RGBA", (width, height), _decode_bc2(payload, width, height))
    if fourcc in (b"DXT4", b"DXT5"):
        raw = _decode_external("bc3", payload, width, height)
        return _raw_bgra_to_rgba(raw, width, height)
    if fourcc in (b"ATI1", b"BC4U"):
        raw = _decode_external("bc4", payload, width, height)
        img = _raw_bgra_to_rgba(raw, width, height)
        r = img.getchannel("R")
        return Image.merge("RGBA", (r, r, r, Image.new("L", img.size, 255)))
    if fourcc in (b"ATI2", b"BC5U"):
        raw = _decode_external("bc5", payload, width, height)
        return _raw_bgra_to_rgba(raw, width, height)

    # Common legacy uncompressed RGBA/BGRA formats.
    pf_flags = _u32(data, 80)
    bit_count = _u32(data, 88)
    rmask = _u32(data, 92)
    gmask = _u32(data, 96)
    bmask = _u32(data, 100)
    amask = _u32(data, 104)
    if pf_flags & 0x40 and bit_count == 32:
        if (rmask, gmask, bmask, amask) == (0x00FF0000, 0x0000FF00, 0x000000FF, 0xFF000000):
            return Image.frombytes("RGBA", (width, height), payload[:width*height*4], "raw", "BGRA")
        if (rmask, gmask, bmask, amask) == (0x000000FF, 0x0000FF00, 0x00FF0000, 0xFF000000):
            return Image.frombytes("RGBA", (width, height), payload[:width*height*4], "raw", "RGBA")

    # Pillow remains a final legacy-format fallback; it is not used for DX10.
    try:
        with Image.open(BytesIO(data)) as image:
            return image.convert("RGBA")
    except Exception as exc:
        raise NotImplementedError(
            f"Unsupported legacy DDS format: FourCC={fourcc!r}, bit_count={bit_count}, "
            f"masks={rmask:#x}/{gmask:#x}/{bmask:#x}/{amask:#x}"
        ) from exc


def decode_dds_file(path):
    return decode_dds(Path(path).read_bytes())
