"""Read completed native scanner runs without loading a whole corpus into memory."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Generator
from pathlib import Path
from typing import Any


def scan_records(path: str | Path, label: str | None = None) -> Generator[tuple[str, dict[str, Any]], None, None]:
    connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=60)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("BEGIN")
        versions = [row[0] for row in connection.execute("SELECT version FROM schema_info")]
        if versions != [1]:
            raise ValueError("Unsupported corpus database schema")
        runs = connection.execute(
            "SELECT * FROM runs" + (" WHERE label=?" if label is not None else ""),
            (label,) if label is not None else (),
        ).fetchmany(2)
        if len(runs) != 1 or runs[0]["state"] != "complete":
            raise ValueError("Select exactly one completed scanner run")
        run = runs[0]
        summary = json.loads(run["summary_json"])
        if not isinstance(summary, dict) or summary.get("entries") != run["imported_files"]:
            raise ValueError("Scanner file count does not reconcile")
        yield "header", {
            "schema_version": 1, "configuration": json.loads(run["configuration_json"]),
            "started_unix_seconds": run["started_unix_seconds"], "build_identity": run["build_identity"],
        }
        files = connection.execute(
            "SELECT rf.*,f.path,v.size_bytes,v.modified_unix_seconds FROM run_files rf "
            "JOIN file_versions v ON v.id=rf.file_version_id JOIN files f ON f.id=v.file_id "
            "WHERE rf.run_id=? ORDER BY rf.ordinal", (run["id"],),
        )
        entries = 0
        totals = dict.fromkeys(("successful_streams", "verified_streams", "successful_deflate_bytes",
                               "successful_plaintext_bytes", "successful_correction_bytes"), 0)
        for file in files:
            entries += 1
            record = {key: file[key] for key in
                      ("path", "size_bytes", "modified_unix_seconds", "status", "error", "elapsed_ms")}
            record["rejected_candidates"] = json.loads(file["rejected_candidates_json"])
            record["streams"] = []
            streams = connection.execute(
                "SELECT s.*,r.*,p.settings_json FROM streams s JOIN stream_results r ON r.stream_id=s.id "
                "LEFT JOIN profiles p ON p.id=r.profile_id "
                "WHERE s.file_version_id=? AND r.run_id=? ORDER BY s.signature_offset,s.id",
                (file["file_version_id"], run["id"]),
            )
            for row in streams:
                stream = {key: row[key] for key in (
                    "deflate_offset", "kind", "member_name", "deflate_bytes", "plaintext_bytes",
                    "status", "error_code", "error", "signature_confidence", "elapsed_ms", "chunks",
                )}
                stream.update(
                    offset=row["signature_offset"], verified=bool(row["verified"]),
                    correction_bytes=row["reconstruction_bytes"], blocks=row["block_count"],
                    parameters=json.loads(row["settings_json"]) if row["settings_json"] is not None else None,
                    nonzero_corrections=json.loads(row["corrections_json"]),
                )
                if row["block_detail"] != "unavailable" or row["token_count"] is not None:
                    blocks = []
                    for block in connection.execute(
                        "SELECT * FROM block_results WHERE run_id=? AND stream_id=? ORDER BY block_index",
                        (run["id"], row["id"]),
                    ):
                        blocks.append({
                            "index": block["block_index"], "chunk": block["chunk_index"],
                            **{key: block[key] for key in
                               ("plaintext_offset", "plaintext_bytes", "kind", "literals")},
                            "last": bool(block["last"]), "references": block["references_count"],
                        })
                    stream["trace"] = dict(
                        blocks=blocks, chunks=[], blocks_truncated=row["block_detail"] != "complete",
                        token_count=row["token_count"], token_mismatches=row["token_mismatches"],
                    )
                chunks = connection.execute(
                    "SELECT * FROM chunk_results WHERE run_id=? AND stream_id=? ORDER BY chunk_index",
                    (run["id"], row["id"]),
                )
                for chunk in chunks:
                    trace = stream.setdefault("trace", dict(blocks=[], chunks=[], blocks_truncated=True))
                    trace["chunks"].append({
                        "index": chunk["chunk_index"], "correction_bytes": chunk["reconstruction_bytes"],
                        "blocks": chunk["block_count"], "nonzero_corrections": json.loads(chunk["corrections_json"]),
                        **{key: chunk[key] for key in (
                            "deflate_offset", "deflate_bytes", "plaintext_offset", "plaintext_bytes",
                            "block_profile", "elapsed_ms", "status", "stage", "error",
                        )},
                    })
                record["streams"].append(stream)
                if stream["status"] == "ok":
                    totals["successful_streams"] += 1
                    totals["verified_streams"] += stream["verified"]
                    totals["successful_deflate_bytes"] += stream["deflate_bytes"]
                    totals["successful_plaintext_bytes"] += stream["plaintext_bytes"]
                    totals["successful_correction_bytes"] += stream["correction_bytes"]
            yield "file", record
        if entries != summary["entries"] or any(summary.get(key) != value for key, value in totals.items()):
            raise ValueError("Scanner rows do not reconcile with the summary")
        yield "summary", summary
    finally:
        connection.close()
