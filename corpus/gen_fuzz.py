#!/usr/bin/env -S uv run --locked
"""
Seed-driven corpus generator for the fuzz_container target.

Each corpus file is synthesised by drawing random choices from a seeded RNG,
keeping every output <= 4 KiB.  Files are named by a short content hash so
running the script multiple times is idempotent and never creates duplicates.

Usage:
    uv run --locked corpus/gen_fuzz.py [output_dir] [--count N] [--seed S]

    output_dir  where to write corpus files
                (default: fuzz/corpus/fuzz_container)
    --count N   total number of files to generate (default: 68)
    --seed  S   base RNG seed (default: 0)

Examples:
    uv run --locked corpus/gen_fuzz.py                         # 68 deterministic entries
    uv run --locked corpus/gen_fuzz.py --count 1000 --seed 42  # 1000 varied entries
"""

import argparse
import gzip
import hashlib
import io
import random
import struct
import sys
import zlib
import zipfile
from pathlib import Path


MAX_SIZE = 4096


# ---------------------------------------------------------------------------
# Low-level format builders
# ---------------------------------------------------------------------------

def _make_zlib(data: bytes, level: int = 6) -> bytes:
    return zlib.compress(data, level)


def _make_gzip(data: bytes, level: int = 6) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=level, mtime=0) as f:
        f.write(data)
    return buf.getvalue()


_PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _png_chunk(ctype: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)


def _make_png(width: int, height: int, color_type: int,
              filter_type: int, n_idat: int) -> bytes:
    channels = {0: 1, 2: 3, 4: 2, 6: 4}[color_type]
    raw = b""
    for y in range(height):
        row = bytes([filter_type])
        for x in range(width):
            v = (x * 13 + y * 7) & 0xFF
            row += bytes([v] * channels)
        raw += row
    compressed = zlib.compress(raw, 6)
    ihdr = _png_chunk(
        b"IHDR",
        struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0),
    )
    chunk_sz = max(1, (len(compressed) + n_idat - 1) // n_idat)
    idat = b"".join(
        _png_chunk(b"IDAT", compressed[i : i + chunk_sz])
        for i in range(0, len(compressed), chunk_sz)
    )
    return _PNG_SIG + ihdr + idat + _png_chunk(b"IEND", b"")


# Standard JFIF luminance Huffman tables (JPEG spec Annex K)
_DC_COUNTS = bytes([0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0])
_DC_SYMS   = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
_AC_COUNTS = bytes([0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125])
_AC_SYMS   = bytes([
    0x01,0x02,0x03,0x00,0x04,0x11,0x05,0x12,0x21,0x31,0x41,0x06,0x13,0x51,0x61,
    0x07,0x22,0x71,0x14,0x32,0x81,0x91,0xA1,0x08,0x23,0x42,0xB1,0xC1,0x15,0x52,
    0xD1,0xF0,0x24,0x33,0x62,0x72,0x82,0x09,0x0A,0x16,0x17,0x18,0x19,0x1A,0x25,
    0x26,0x27,0x28,0x29,0x2A,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x43,0x44,0x45,
    0x46,0x47,0x48,0x49,0x4A,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5A,0x63,0x64,
    0x65,0x66,0x67,0x68,0x69,0x6A,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A,0x83,
    0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,
    0x9A,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xB2,0xB3,0xB4,0xB5,0xB6,
    0xB7,0xB8,0xB9,0xBA,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xD2,0xD3,
    0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,
    0xE9,0xEA,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,
])


def _build_huff_codes(counts: bytes, symbols: bytes) -> dict:
    codes: dict = {}
    code = 0
    idx = 0
    for length in range(1, 17):
        for _ in range(counts[length - 1]):
            codes[symbols[idx]] = (code, length)
            idx += 1
            code += 1
        code <<= 1
    return codes


def _jpeg_seg(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


def _encode_mcu_bits(codes_dc: dict, codes_ac: dict, dc_diff: int) -> str:
    cat = 0 if dc_diff == 0 else abs(dc_diff).bit_length()
    dc_code, dc_len = codes_dc[cat]
    bits = f"{dc_code:0{dc_len}b}"
    if cat > 0:
        v = dc_diff if dc_diff > 0 else dc_diff + (1 << cat) - 1
        bits += f"{v:0{cat}b}"
    ac_code, ac_len = codes_ac[0x00]  # EOB
    bits += f"{ac_code:0{ac_len}b}"
    return bits


def _make_jpeg(width: int, height: int, luma: int) -> bytes:
    assert width % 8 == 0 and height % 8 == 0
    codes_dc = _build_huff_codes(_DC_COUNTS, _DC_SYMS)
    codes_ac = _build_huff_codes(_AC_COUNTS, _AC_SYMS)
    dc_val = 8 * (luma - 128)
    bit_str = ""
    prev_dc = 0
    for _ in range((width // 8) * (height // 8)):
        bit_str += _encode_mcu_bits(codes_dc, codes_ac, dc_val - prev_dc)
        prev_dc = dc_val
    while len(bit_str) % 8:
        bit_str += "1"
    scan_raw = bytes(int(bit_str[i : i + 8], 2) for i in range(0, len(bit_str), 8))
    scan = b""
    for b in scan_raw:
        scan += bytes([b])
        if b == 0xFF:
            scan += b"\x00"
    soi  = b"\xFF\xD8"
    app0 = _jpeg_seg(0xE0, b"JFIF\x00\x01\x01\x00" + struct.pack(">HH", 1, 1) + b"\x00\x00")
    dqt  = _jpeg_seg(0xDB, b"\x00" + bytes([1] * 64))
    sof0 = _jpeg_seg(0xC0, bytes([8]) + struct.pack(">HH", height, width)
                     + bytes([1, 1, 0x11, 0]))
    dht_dc = _jpeg_seg(0xC4, bytes([0x00]) + _DC_COUNTS + _DC_SYMS)
    dht_ac = _jpeg_seg(0xC4, bytes([0x10]) + _AC_COUNTS + _AC_SYMS)
    sos = _jpeg_seg(0xDA, bytes([1, 1, 0x00, 0, 63, 0]))
    eoi = b"\xFF\xD9"
    return soi + app0 + dqt + sof0 + dht_dc + dht_ac + sos + scan + eoi


def _make_zip(entries: list) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data, deflate in entries:
            method = zipfile.ZIP_DEFLATED if deflate else zipfile.ZIP_STORED
            zf.writestr(zipfile.ZipInfo(name), data, compress_type=method)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Random content generators
# ---------------------------------------------------------------------------

def _content(rng: random.Random, n: int) -> bytes:
    """Pick a content type randomly and return n bytes of it."""
    kind = rng.choice(["repeat", "zeros", "ascending", "pseudo"])
    if kind == "repeat":
        pattern = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 16)))
        return (pattern * (n // len(pattern) + 1))[:n]
    if kind == "zeros":
        return bytes(n)
    if kind == "ascending":
        return bytes(i & 0xFF for i in range(n))
    # pseudo-random but deterministic
    out = b""
    i = rng.randint(0, 0xFFFF)
    while len(out) < n:
        out += hashlib.sha256(i.to_bytes(4, "little")).digest()
        i += 1
    return out[:n]


# ---------------------------------------------------------------------------
# Per-category generators — each returns bytes or None if over MAX_SIZE
# ---------------------------------------------------------------------------

def _gen_zlib(rng: random.Random) -> bytes:
    level   = rng.choice([0, 0, 1, 6, 6, 9])
    # stored blocks inflate: output ≈ input + small overhead
    max_pt  = 2000 if level == 0 else 3000
    size    = rng.randint(0, max_pt)
    data    = _content(rng, size)
    result  = _make_zlib(data, level)
    if rng.random() < 0.25:
        junk = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 16)))
        result = junk + result
    if rng.random() < 0.25:
        junk = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 16)))
        result = result + junk
    return result


def _gen_gzip(rng: random.Random) -> bytes:
    level = rng.choice([0, 0, 1, 6, 6, 9])
    max_pt = 2000 if level == 0 else 3000
    size   = rng.randint(0, max_pt)
    return _make_gzip(_content(rng, size), level)


def _gen_zip(rng: random.Random) -> bytes:
    n = rng.randint(0, 4)
    entries = []
    budget = MAX_SIZE - 100  # leave room for ZIP overhead per entry
    for i in range(n):
        deflate = rng.random() < 0.6
        # For stored entries, size is visible in output; keep budget in mind
        max_entry = min(1500, budget // max(n, 1))
        size = rng.randint(0, max_entry)
        data = _content(rng, size)
        name = f"f{i}.dat"
        entries.append((name, data, deflate))
    return _make_zip(entries)


def _gen_png(rng: random.Random) -> bytes:
    # Dimensions: any combo; clamp so raw bytes stay < ~3500
    color_type = rng.choice([0, 0, 2, 2, 2, 4, 6])
    channels   = {0: 1, 2: 3, 4: 2, 6: 4}[color_type]
    # raw size = height * (1 + width * channels)
    max_dim = 32
    width  = rng.randint(1, max_dim)
    height = rng.randint(1, max_dim)
    filter_type = rng.randint(0, 4)
    n_idat = rng.choice([1, 1, 1, 2, 3, 5, 10])
    return _make_png(width, height, color_type, filter_type, n_idat)


def _gen_jpeg(rng: random.Random) -> bytes:
    mcu_w = rng.randint(1, 4)  # 1-4 MCUs wide  → 8-32 pixels
    mcu_h = rng.randint(1, 4)
    luma  = rng.randint(0, 255)
    return _make_jpeg(mcu_w * 8, mcu_h * 8, luma)


def _gen_near_miss(rng: random.Random) -> bytes:
    """Header bytes that look like a known format but fail validation."""
    kind = rng.choice(["zlib", "jpeg", "png", "zip", "gzip"])
    junk = bytes(rng.randint(0, 255) for _ in range(rng.randint(5, 60)))
    if kind == "zlib":
        # CMF=0x78 (deflate, 32K window), FLG chosen so CMF*256+FLG % 31 != 0
        flg = rng.choice([b for b in range(256)
                          if (0x78 * 256 + b) % 31 != 0 and (0x78 * 256 + b) & 0x2000 == 0])
        return bytes([0x78, flg]) + junk
    if kind == "jpeg":
        return b"\xFF\xD8" + junk
    if kind == "png":
        return _PNG_SIG[:rng.randint(1, 7)] + junk
    if kind == "zip":
        return b"PK\x03\x04" + junk
    # gzip
    return bytes([0x1F, 0x8B, 0x08]) + junk


def _gen_edge(rng: random.Random) -> bytes:
    """Very small or degenerate inputs."""
    kind = rng.choice([
        "empty", "one", "two", "ascii",
        "zlib_empty", "zlib_one", "zlib_all_zeros",
        "png_tiny", "jpeg_min",
    ])
    if kind == "empty":
        return b""
    if kind == "one":
        return bytes([rng.randint(0, 255)])
    if kind == "two":
        return bytes([rng.randint(0, 255), rng.randint(0, 255)])
    if kind == "ascii":
        n = rng.randint(1, 64)
        return bytes(rng.randint(0x20, 0x7E) for _ in range(n))
    if kind == "zlib_empty":
        return _make_zlib(b"")
    if kind == "zlib_one":
        return _make_zlib(bytes([rng.randint(0, 255)]))
    if kind == "zlib_all_zeros":
        return _make_zlib(bytes(rng.randint(1, 64)))
    if kind == "png_tiny":
        ct = rng.choice([0, 2])
        return _make_png(1, 1, ct, 0, 1)
    # jpeg_min
    return _make_jpeg(8, 8, rng.randint(0, 255))


def _gen_mixed(rng: random.Random) -> bytes:
    """Two or three format blobs concatenated."""
    # Atom generators (cheap to call)
    atoms = [_gen_zlib, _gen_gzip, _gen_png, _gen_jpeg]
    n = rng.randint(2, 3)
    parts = []
    budget = MAX_SIZE
    for _ in range(n):
        gen = rng.choice(atoms)
        # Save RNG state so we can retry if it's too big
        blob = gen(rng)
        if len(blob) <= budget:
            parts.append(blob)
            budget -= len(blob)
        if budget <= 0:
            break
    return b"".join(parts)


# ---------------------------------------------------------------------------
# Top-level sample generator
# ---------------------------------------------------------------------------

CATEGORIES = [
    ("zlib",       _gen_zlib,       20),   # weight
    ("gzip",       _gen_gzip,       10),
    ("zip",        _gen_zip,        15),
    ("png",        _gen_png,        25),
    ("jpeg",       _gen_jpeg,       10),
    ("near_miss",  _gen_near_miss,   8),
    ("edge",       _gen_edge,        7),
    ("mixed",      _gen_mixed,       5),
]

_NAMES, _FUNS, _WEIGHTS = zip(*CATEGORIES)


def generate_one(rng: random.Random) -> tuple[str, bytes]:
    """Generate one (label, bytes) pair using rng."""
    gen = rng.choices(_FUNS, weights=_WEIGHTS, k=1)[0]
    data = gen(rng)
    assert len(data) <= MAX_SIZE, f"entry is {len(data)} bytes (> {MAX_SIZE})"
    digest = hashlib.sha1(data).hexdigest()[:16]
    label  = f"{gen.__name__.lstrip('_gen_')}_{digest}"
    return label, data


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("output_dir", nargs="?",
                    default=str(Path(__file__).resolve().parents[1] / "fuzz" / "corpus" / "fuzz_container"))
    ap.add_argument("--count", type=int, default=68,
                    help="number of corpus files to generate (default: 68)")
    ap.add_argument("--seed", type=int, default=0,
                    help="base RNG seed (default: 0)")
    args = ap.parse_args()

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    written = skipped = 0
    seen: set[bytes] = set()

    # Pre-load existing corpus hashes so we don't double-count them
    for p in outdir.iterdir():
        if p.is_file():
            seen.add(p.read_bytes())

    i = 0
    attempts = 0
    max_attempts = args.count * 20  # give up after too many near-misses

    while i < args.count and attempts < max_attempts:
        rng = random.Random(args.seed + attempts)
        attempts += 1
        try:
            label, data = generate_one(rng)
        except Exception:
            continue

        if data in seen:
            skipped += 1
            continue

        seen.add(data)
        path = outdir / f"{label}.bin"
        # Avoid clobbering a differently-named file with identical content
        if not path.exists():
            path.write_bytes(data)
        written += 1
        i += 1

        if written % 100 == 0:
            print(f"  ... {written}/{args.count} written")

    print(f"\n{written} file(s) written, {skipped} duplicate(s) skipped")
    print(f"Corpus: {outdir}")


if __name__ == "__main__":
    main()
