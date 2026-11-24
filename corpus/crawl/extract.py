"""Cut reported DEFLATE streams out of a scanned document, keeping only what reproduces them.

Offsets follow `container/src/diagnostics.rs`: `deflate_offset` is the absolute start of the raw
DEFLATE data (zlib, gzip, zip, raw), while PNG IDAT streams have no `deflate_offset` and `offset`
points at the first IDAT chunk's length field.

PNG streams are deliberately *not* reduced to raw DEFLATE. Low-overhead standalone PNGs are kept
unchanged; otherwise they are saved as a minimal PNG whose
IDAT chunks are copied verbatim (original chunk split, CRCs and zlib header/trailer), so rescanning
the extract exercises the container's IDAT parsing and reassembly rather than only the DEFLATE model.
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
IHDR_HEADER = b"\x00\x00\x00\x0dIHDR"
IHDR_CHUNK_BYTES = 25


def png_chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


IEND_CHUNK = png_chunk(b"IEND", b"")


@dataclass
class Extract:
    suffix: str
    data: bytes
    location: dict[str, Any] = field(default_factory=dict)


def idat_run(body: bytes, offset: int) -> list[tuple[int, int]]:
    """Whole-chunk byte ranges of the consecutive IDAT chunks starting at `offset`, as `parse_idat` walks them.

    CRCs are not checked: a bad CRC is copied unchanged so the extract reproduces the original failure.
    A chunk extending past the end of the document ends the run.
    """
    chunks: list[tuple[int, int]] = []
    position = offset
    while position + 8 <= len(body) and body[position + 4:position + 8] == b"IDAT":
        (length,) = struct.unpack_from(">I", body, position)
        end = position + length + 12
        if end > len(body):
            break
        chunks.append((position, end))
        position = end
    return chunks


def png_header_chunks(body: bytes, idat_offset: int) -> tuple[bytes, dict[str, int]]:
    """Verbatim IHDR (the one `scan_deflate` would pair with this IDAT) and any PLTE between it and the IDAT."""
    ihdr = body.rfind(IHDR_HEADER, 0, idat_offset)
    if ihdr < 0 or ihdr + IHDR_CHUNK_BYTES > idat_offset:
        return b"", {}
    kept = bytearray(body[ihdr:ihdr + IHDR_CHUNK_BYTES])
    found = {"ihdr_offset": ihdr}
    position = ihdr + IHDR_CHUNK_BYTES
    while position + 12 <= idat_offset:
        (length,) = struct.unpack_from(">I", body, position)
        end = position + length + 12
        if end > idat_offset:
            break
        if body[position + 4:position + 8] == b"PLTE":
            kept += body[position:end]
            found["plte_offset"] = position
        position = end
    return bytes(kept), found


def extract_png(body: bytes, stream: Mapping[str, Any]) -> Extract | None:
    offset = stream.get("offset")
    if not isinstance(offset, int):
        return None
    chunks = idat_run(body, offset)
    if not chunks:
        return None
    header, found = png_header_chunks(body, offset)
    data = PNG_SIGNATURE + header + body[chunks[0][0]:chunks[-1][1]] + IEND_CHUNK
    location = {"extract": "png", "idat_offset": offset, **found,
                "idat_chunks": [[start, end - start - 12] for start, end in chunks],
                "idat_bytes": chunks[-1][1] - chunks[0][0]}
    original = body.startswith(PNG_SIGNATURE) and len(body) * 10 <= len(data) * 11
    location["png_storage"] = "original" if original else "minimal"
    if original:
        data = body
    return Extract(".png", data, location)


def extract_stream(body: bytes, stream: Mapping[str, Any], *, failure_window: int) -> Extract | None:
    """Raw DEFLATE slice (or minimal PNG) for one reported stream, or None when it cannot be located."""
    if stream.get("kind") == "png_idat" and stream.get("deflate_offset") is None:
        return extract_png(body, stream)
    start = stream.get("deflate_offset")
    if not isinstance(start, int) or not 0 <= start < len(body):
        return None
    length = int(stream.get("deflate_bytes") or 0)
    if stream.get("status") == "ok":
        end = start + length
        if length <= 0 or end > len(body):
            return None
    else:
        # A failed stream's reported length is only what was processed before the failure.
        end = min(len(body), start + max(length, failure_window))
    return Extract(".deflate", body[start:end], {"extract": "deflate", "range": [start, end]})


def compare(original: Mapping[str, Any], rescanned: Sequence[Mapping[str, Any]], extract: str) -> tuple[str, str]:
    """Whether a rescanned extract reproduces the original detection: ("match"|"mismatch", detail)."""
    kind = "png_idat" if extract == "png" else "raw"
    found = [stream for stream in rescanned if stream.get("kind") == kind]
    if not found:
        kinds = ",".join(sorted({str(stream.get("kind")) for stream in rescanned})) or "nothing"
        return "mismatch", f"no {kind} stream detected (found {kinds})"
    stream = found[0]
    keys = ("status", "deflate_bytes", "plaintext_bytes", "correction_bytes", "verified")
    if original.get("status") != "ok":
        keys = ("status", "error_code")
    differences = [f"{key} {original.get(key)!r}->{stream.get(key)!r}" for key in keys
                   if original.get(key) != stream.get(key)]
    if len(found) > 1:
        differences.append(f"{len(found)} {kind} streams")
    return ("mismatch", "; ".join(differences)) if differences else ("match", "")
