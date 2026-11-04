#!/usr/bin/env -S uv run --locked
"""
Generate a test corpus for preflate-rs end-to-end regression testing.

Creates a variety of files that exercise every preflate container block type:
  - PNG  -> BLOCK_TYPE_PNG / BLOCK_TYPE_WEBP  (via PNG IDAT detection)
  - JPEG -> BLOCK_TYPE_JPEG_LEPTON            (via Lepton re-compression)
  - ZIP / zlib / gzip -> BLOCK_TYPE_DEFLATE   (via DEFLATE stream detection)
  - Unrecognised bytes -> BLOCK_TYPE_LITERAL

Also writes manifest.ini alongside the corpus files with expected block counts
and overhead thresholds for diagnostic comparison.

Usage:
    uv run --locked --extra jpeg corpus/gen_corpus.py
    uv run --locked --extra jpeg corpus/gen_corpus.py path/to/dir
    uv run --locked corpus/gen_corpus.py --no-jpeg

Requirements:
    - uv (manages Python 3.14+ and the project environment)
    - The jpeg extra enables optional JPEG generation; skipped without it
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import struct
import sys
import zlib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── PNG generation (pure Python stdlib) ───────────────────────────────────────

def _png_chunk(name: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(name + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + name + data + struct.pack(">I", crc)


def make_png(pixels: bytes, width: int, height: int, color_type: int,
             compress_level: int = 6) -> bytes:
    """
    Encode raw pixel data as a PNG file.

    color_type: 2 = RGB (3 bytes/pixel), 6 = RGBA (4 bytes/pixel)
    pixels:     raw bytes, no filter bytes, rows top-to-bottom
    """
    channels = {2: 3, 6: 4}[color_type]
    row_bytes = width * channels

    # Prepend filter-type byte 0 (None) to every row
    filtered = bytearray()
    for row in range(height):
        filtered.append(0)
        filtered.extend(pixels[row * row_bytes: (row + 1) * row_bytes])

    compressed = zlib.compress(bytes(filtered), compress_level)

    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n"
    png += _png_chunk(b"IHDR", ihdr_data)
    png += _png_chunk(b"IDAT", compressed)
    png += _png_chunk(b"IEND", b"")
    return png


def make_solid_rgb_png(width: int, height: int,
                       r: int, g: int, b: int) -> bytes:
    return make_png(bytes([r, g, b] * width * height), width, height, 2)


def make_gradient_rgb_png(width: int, height: int) -> bytes:
    """RGB PNG where R varies with X, G varies with Y, B is constant."""
    pixels = bytearray()
    for y in range(height):
        for x in range(width):
            pixels.append((x * 255) // max(width - 1, 1))
            pixels.append((y * 255) // max(height - 1, 1))
            pixels.append(128)
    return make_png(bytes(pixels), width, height, 2)


def make_solid_rgba_png(width: int, height: int,
                        r: int, g: int, b: int, a: int) -> bytes:
    return make_png(bytes([r, g, b, a] * width * height), width, height, 6)



# ── JPEG generation (requires Pillow) ─────────────────────────────────────────

def make_jpeg(width: int, height: int, quality: int = 85) -> bytes | None:
    """
    Generate a JPEG using Pillow.  Returns None if Pillow is not installed.
    The image is a simple RGB gradient so it has meaningful DCT content.
    """
    try:
        from PIL import Image  # type: ignore
    except ImportError:
        return None

    img = Image.new("RGB", (width, height))
    pixels = img.load()
    for y in range(height):
        for x in range(width):
            pixels[x, y] = (
                int(x * 255 / max(width - 1, 1)),
                int(y * 255 / max(height - 1, 1)),
                128,
            )
    buf = io.BytesIO()
    # subsampling=0 keeps 4:4:4 chroma; optimize=False keeps a predictable
    # baseline JPEG structure that Lepton handles reliably.
    img.save(buf, format="JPEG", quality=quality, optimize=False, subsampling=0)
    return buf.getvalue()


# ── Compressed stream helpers ──────────────────────────────────────────────────

def make_zlib_stream(data: bytes, level: int = 6) -> bytes:
    """Wrap data in a zlib stream (2-byte header + deflate + adler32)."""
    return zlib.compress(data, level)


def make_gzip_stream(data: bytes, filename: str = "data.bin") -> bytes:
    """Wrap data in a gzip stream with a fixed mtime for reproducibility."""
    buf = io.BytesIO()
    with gzip.GzipFile(filename=filename, mode="wb", fileobj=buf, mtime=0) as f:
        f.write(data)
    return buf.getvalue()


# ── ZIP generation ─────────────────────────────────────────────────────────────

def make_zip(entries: list[tuple[str, bytes, int]]) -> bytes:
    """
    entries: list of (archive_name, raw_data, compress_method)
             compress_method: zipfile.ZIP_STORED or zipfile.ZIP_DEFLATED
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data, method in entries:
            zf.writestr(zipfile.ZipInfo(name), data, method)
    return buf.getvalue()


# ── Fake PDF generation ────────────────────────────────────────────────────────

def make_fake_pdf(jpeg_data: bytes | None, stream_text: bytes) -> bytes:
    """
    Minimal syntactically-valid PDF containing:
      - A FlateDecode (zlib-wrapped) object stream
      - Optionally a DCTDecode (JPEG) image XObject

    The file is not a renderable PDF — it is only meant to exercise the
    preflate container scanner's ability to locate embedded streams.
    """
    objects: list[bytes] = []

    # Object 1: catalog
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    # Object 2: page tree
    objects.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    # Object 3: page
    objects.append(
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n"
        b"endobj\n"
    )
    # Object 4: FlateDecode stream (zlib with 2-byte header)
    compressed = zlib.compress(stream_text, 6)
    objects.append(
        b"4 0 obj\n"
        b"<< /Length " + str(len(compressed)).encode() + b" /Filter /FlateDecode >>\n"
        b"stream\n" + compressed + b"\nendstream\nendobj\n"
    )
    # Object 5: JPEG image XObject (optional)
    if jpeg_data is not None:
        objects.append(
            b"5 0 obj\n"
            b"<< /Type /XObject /Subtype /Image\n"
            b"   /Width 100 /Height 100\n"
            b"   /ColorSpace /DeviceRGB /BitsPerComponent 8\n"
            b"   /Filter /DCTDecode\n"
            b"   /Length " + str(len(jpeg_data)).encode() + b" >>\n"
            b"stream\n" + jpeg_data + b"\nendstream\nendobj\n"
        )

    # Assemble: header + objects + xref + trailer
    pdf = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets: list[int] = []
    for obj in objects:
        offsets.append(len(pdf))
        pdf += obj

    xref_pos = len(pdf)
    xref = b"xref\n"
    xref += f"0 {len(objects) + 1}\n".encode()
    xref += b"0000000000 65535 f \n"
    for off in offsets:
        xref += f"{off:010d} 00000 n \n".encode()

    trailer = (
        b"trailer\n"
        b"<< /Size " + str(len(objects) + 1).encode() + b" /Root 1 0 R >>\n"
        b"startxref\n" + str(xref_pos).encode() + b"\n%%EOF\n"
    )
    return pdf + xref + trailer


# ── Manifest ───────────────────────────────────────────────────────────────────

@dataclass
class ManifestEntry:
    description: str
    deflate_streams: int = 0
    jpeg_blocks: int = 0
    png_webp_blocks: int = 0
    max_overhead_pct: float = 5.0
    min_deflate_savings_pct: Optional[float] = None


def write_manifest(path: Path, entries: dict[str, ManifestEntry]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Preflate corpus manifest\n")
        f.write("# Generated by corpus/gen_corpus.py\n")
        f.write("#\n")
        f.write("# Keys per section:\n")
        f.write("#   deflate_streams       expected DEFLATE stream block count\n")
        f.write("#   jpeg_blocks           expected JPEG Lepton block count\n")
        f.write("#   png_webp_blocks       expected PNG/WebP IDAT block count\n")
        f.write("#   max_overhead_pct      max correction overhead %\n")
        f.write("#                         (overhead_bytes / uncompressed_size * 100)\n")
        f.write("#   min_deflate_savings_pct  min % saving vs plain Zstd baseline\n")
        f.write("\n")
        for filename, e in entries.items():
            f.write(f"[{filename}]\n")
            f.write(f"description={e.description}\n")
            f.write(f"deflate_streams={e.deflate_streams}\n")
            f.write(f"jpeg_blocks={e.jpeg_blocks}\n")
            f.write(f"png_webp_blocks={e.png_webp_blocks}\n")
            f.write(f"max_overhead_pct={e.max_overhead_pct}\n")
            if e.min_deflate_savings_pct is not None:
                f.write(f"min_deflate_savings_pct={e.min_deflate_savings_pct}\n")
            f.write("\n")


# ── Main ───────────────────────────────────────────────────────────────────────

# Text payload reused in several files (~13 KB when repeated; well above the
# 1 KB MIN_BLOCKSIZE that preflate uses to decide whether to compress a stream)
_LOREM = (
    b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
    b"Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
    b"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. "
) * 100

_FOX = b"The quick brown fox jumps over the lazy dog. " * 300


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "output_dir", nargs="?", default=None,
        help="Output directory (default: corpus/generated)",
    )
    parser.add_argument(
        "--no-jpeg", action="store_true",
        help="Skip JPEG generation even if Pillow is installed",
    )
    args = parser.parse_args()

    out = Path(args.output_dir) if args.output_dir else Path(__file__).parent / "generated"
    out.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, ManifestEntry] = {}
    generated: list[tuple[str, int]] = []

    def emit(name: str, data: bytes, entry: ManifestEntry) -> None:
        (out / name).write_bytes(data)
        manifest[name] = entry
        generated.append((name, len(data)))

    # ── Standalone PNG images ──────────────────────────────────────────────────
    # Solid-colour PNGs: the entire image compresses to a tiny IDAT (< 1 KB).
    # The container scanner intentionally skips IDAT streams whose compressed
    # size is <= MIN_BLOCKSIZE — the preflate overhead would exceed any saving.
    # These files are kept as regression tests for that threshold behaviour.
    emit(
        "png_rgb_solid.png",
        make_solid_rgb_png(400, 300, 30, 80, 180),
        ManifestEntry(
            description=(
                "Solid blue RGB PNG 400x300 — IDAT compresses to <1 KB "
                "so skipped by scanner (treated as literal)"
            ),
            png_webp_blocks=0,
            max_overhead_pct=5.0,
        ),
    )

    emit(
        "png_rgb_gradient.png",
        make_gradient_rgb_png(320, 240),
        ManifestEntry(
            description="Gradient RGB PNG 320×240 (X=red, Y=green)",
            png_webp_blocks=1,
            max_overhead_pct=3.0,
        ),
    )

    emit(
        "png_rgba_solid.png",
        make_solid_rgba_png(256, 256, 200, 100, 50, 128),
        ManifestEntry(
            description=(
                "Solid RGBA PNG 256x256 — IDAT compresses to <1 KB "
                "so skipped by scanner (treated as literal)"
            ),
            png_webp_blocks=0,
            max_overhead_pct=5.0,
        ),
    )

    # ── JPEG images ────────────────────────────────────────────────────────────
    jpeg_data: bytes | None = None
    if not args.no_jpeg:
        jpeg_data = make_jpeg(160, 120, quality=85)
        if jpeg_data is None:
            print(
                "NOTE: Pillow not installed; JPEG corpus files skipped.\n"
                "      Re-run with uv run --locked --extra jpeg to generate them.",
                file=sys.stderr,
            )
        else:
            emit(
                "jpeg_160x120.jpg",
                jpeg_data,
                ManifestEntry(
                    description="JPEG 160×120 gradient, quality=85",
                    jpeg_blocks=1,
                    max_overhead_pct=0.0,  # Lepton carries no CABAC overhead
                ),
            )

    # ── Raw compressed streams ─────────────────────────────────────────────────
    emit(
        "zlib_lorem.bin",
        make_zlib_stream(_LOREM),
        ManifestEntry(
            description="Raw zlib stream (~13 KB of repeated text)",
            deflate_streams=1,
            max_overhead_pct=1.0,
        ),
    )

    emit(
        "gzip_lorem.gz",
        make_gzip_stream(_LOREM, filename="lorem.txt"),
        ManifestEntry(
            description="Gzip stream (~13 KB of repeated text)",
            deflate_streams=1,
            max_overhead_pct=1.0,
        ),
    )

    # ── ZIP archives ───────────────────────────────────────────────────────────

    # Two deflated text entries → 2 DEFLATE streams
    emit(
        "zip_deflated_text.zip",
        make_zip([
            ("lorem.txt", _LOREM, zipfile.ZIP_DEFLATED),
            ("fox.txt",   _FOX,   zipfile.ZIP_DEFLATED),
        ]),
        ManifestEntry(
            description="ZIP with 2 deflated text entries",
            deflate_streams=2,
            max_overhead_pct=1.0,
        ),
    )

    # PNG stored in ZIP (method=STORED): raw PNG bytes are visible in the ZIP
    # body, so the preflate scanner finds the PNG IDAT stream directly.
    # Use a gradient PNG — solid-colour PNGs compress to < MIN_BLOCKSIZE so
    # the scanner intentionally skips their tiny IDATs (not worth the overhead).
    stored_png = make_gradient_rgb_png(200, 150)
    emit(
        "zip_png_stored.zip",
        make_zip([("image.png", stored_png, zipfile.ZIP_STORED)]),
        ManifestEntry(
            description="ZIP with 1 stored gradient PNG (IDAT large enough for scanner)",
            png_webp_blocks=1,
            max_overhead_pct=2.0,
        ),
    )

    # Deflated text + stored PNG in same archive
    emit(
        "zip_text_and_png.zip",
        make_zip([
            ("readme.txt", _FOX,       zipfile.ZIP_DEFLATED),
            ("image.png",  stored_png, zipfile.ZIP_STORED),
        ]),
        ManifestEntry(
            description="ZIP: deflated text + stored gradient PNG",
            deflate_streams=1,
            png_webp_blocks=1,
            max_overhead_pct=2.0,
        ),
    )

    # Five stored gradient PNGs + one deflated text (stress-test PNG counting).
    # Gradient PNGs have IDATs well above MIN_BLOCKSIZE so all five are detected.
    many_png_entries: list[tuple[str, bytes, int]] = []
    for i in range(5):
        # Shift the gradient phase per image so each PNG is distinct
        offset = i * 50
        pixels = bytearray()
        w, h = 120, 90
        for y in range(h):
            for x in range(w):
                pixels.append((x * 255 // (w - 1) + offset) % 256)
                pixels.append((y * 255 // (h - 1) + offset * 2) % 256)
                pixels.append((offset * 3) % 256)
        png = make_png(bytes(pixels), w, h, 2)
        many_png_entries.append((f"img_{i:02d}.png", png, zipfile.ZIP_STORED))
    many_png_entries.append(("index.txt", _LOREM, zipfile.ZIP_DEFLATED))
    emit(
        "zip_many_pngs.zip",
        make_zip(many_png_entries),
        ManifestEntry(
            description="ZIP: 5 stored gradient PNGs + 1 deflated text",
            deflate_streams=1,
            png_webp_blocks=5,
            max_overhead_pct=2.0,
        ),
    )

    if jpeg_data is not None:
        # JPEG stored in ZIP → Lepton should detect it
        emit(
            "zip_jpeg_stored.zip",
            make_zip([("photo.jpg", jpeg_data, zipfile.ZIP_STORED)]),
            ManifestEntry(
                description="ZIP with 1 stored JPEG (raw JPEG bytes visible to scanner)",
                jpeg_blocks=1,
                max_overhead_pct=0.0,
            ),
        )

        # Full mix: deflated text + stored PNG + stored JPEG
        emit(
            "zip_mixed.zip",
            make_zip([
                ("readme.txt", _FOX,                        zipfile.ZIP_DEFLATED),
                ("image.png",  make_gradient_rgb_png(150, 100), zipfile.ZIP_STORED),
                ("photo.jpg",  jpeg_data,                    zipfile.ZIP_STORED),
            ]),
            ManifestEntry(
                description="ZIP: deflated text + stored PNG + stored JPEG",
                deflate_streams=1,
                jpeg_blocks=1,
                png_webp_blocks=1,
                max_overhead_pct=2.0,
            ),
        )

    # ── PDF-like file ──────────────────────────────────────────────────────────
    pdf_text = b"PDF object stream with compressible repeated content. " * 300
    emit(
        "fake_pdf.pdf",
        make_fake_pdf(jpeg_data, pdf_text),
        ManifestEntry(
            description=(
                "Minimal PDF: FlateDecode stream"
                + (" + DCTDecode JPEG image" if jpeg_data is not None else "")
            ),
            deflate_streams=1,
            jpeg_blocks=1 if jpeg_data is not None else 0,
            max_overhead_pct=1.0,
        ),
    )

    # ── Write manifest ─────────────────────────────────────────────────────────
    manifest_path = out / "manifest.ini"
    write_manifest(manifest_path, manifest)

    # ── Summary ────────────────────────────────────────────────────────────────
    total_bytes = sum(sz for _, sz in generated)
    print(f"Generated {len(generated)} corpus files -> {out}")
    print()
    col = max(len(n) for n, _ in generated)
    for name, size in generated:
        print(f"  {name:{col}s}  {size:>9,} bytes")
    print()
    print(f"  {'manifest.ini':{col}s}  (expected block counts and overhead thresholds)")
    print()
    print(f"Total: {total_bytes:,} bytes across {len(generated)} files")
    print()
    print("Next steps:")
    print(f'  cargo run --release -p preflate_util -- --baseline "{out}"')


if __name__ == "__main__":
    main()
