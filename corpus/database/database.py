"""SQLite corpus analysis and transactional merging of completed scanner runs."""

from __future__ import annotations

import contextlib
import json
import math
import sqlite3
import statistics
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from itertools import groupby
from pathlib import Path
from typing import Any

from .scan import scan_records


PROFILE_FIELDS = (
    "hash_algorithm", "matching_type", "strategy", "add_policy", "block_type_strategy",
    "window_bits", "nice_length", "max_chain", "max_token_count", "max_dist_3_matches",
    "matches_to_start_detected", "very_far_matches_detected",
)
TOKEN_CORRECTIONS = (
    "LiteralPredictionWrong", "ReferencePredictionWrong", "LenCorrection",
    "DistOnlyCorrection", "DistAfterLenCorrection",
)
COHORT_FIELDS = ("hash_algorithm", "matching_type", "add_policy", "window_bits")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)








def stream_identity(stream: dict[str, Any]) -> tuple[Any, ...]:
    return (
        stream["offset"], stream.get("deflate_offset"), stream["kind"], stream.get("member_name"),
        stream["deflate_bytes"], stream["plaintext_bytes"],
    )


class CorpusDatabase:
    def __init__(
        self, path: str | Path, *, timeout_seconds: float = 60,
        journal_mode: str = "WAL", synchronous: str = "NORMAL", profile_cache_entries: int = 4096,
    ):
        if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("Database timeout must be positive and finite")
        if journal_mode not in ("WAL", "DELETE") or synchronous not in ("NORMAL", "FULL", "EXTRA"):
            raise ValueError("Unsupported safe SQLite connection policy")
        if type(profile_cache_entries) is not int or profile_cache_entries < 1:
            raise ValueError("Profile cache size must be a positive integer")
        self.path = Path(path)
        self.connection = sqlite3.connect(self.path, timeout=timeout_seconds)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        existing = self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchone()
        if existing:
            try:
                versions = [row[0] for row in self.connection.execute("SELECT version FROM schema_info")]
                if versions != [1]:
                    raise ValueError("Unsupported corpus database schema")
            except (sqlite3.Error, ValueError):
                self.close()
                raise
        self.connection.execute(f"PRAGMA journal_mode={journal_mode}")
        self.connection.execute(f"PRAGMA synchronous={synchronous}")
        self.connection.executescript(Path(__file__).with_name("schema.sql").read_text())
        self._profiles: dict[str, int] = {}
        self._profile_cache_entries = profile_cache_entries

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> CorpusDatabase:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _profile(self, settings: dict[str, Any] | None) -> int | None:
        if settings is None:
            return None
        key = canonical(settings)
        if key not in self._profiles:
            values = [settings.get(field) for field in PROFILE_FIELDS]
            self.connection.execute(
                f"INSERT OR IGNORE INTO profiles(settings_json,{','.join(PROFILE_FIELDS)}) "
                f"VALUES ({','.join('?' for _ in range(len(values)+1))})", (key, *values),
            )
            row = self.connection.execute("SELECT id FROM profiles WHERE settings_json=?", (key,)).fetchone()
            if len(self._profiles) >= self._profile_cache_entries:
                self._profiles.clear()
            self._profiles[key] = row[0]
        return self._profiles[key]

    def _file_version(self, record: dict[str, Any], run: int, ordinal: int) -> int:
        db = self.connection
        db.execute("INSERT OR IGNORE INTO files(path) VALUES (?)", (record["path"],))
        file_id = db.execute("SELECT id FROM files WHERE path=?", (record["path"],)).fetchone()[0]
        size, modified = record.get("size_bytes"), record.get("modified_unix_seconds")
        # Missing metadata cannot establish equivalence between runs.
        identity = canonical([size, modified] if size is not None and modified is not None
                             else [size, modified, run, ordinal])
        db.execute(
            "INSERT OR IGNORE INTO file_versions(file_id,size_bytes,modified_unix_seconds,identity_key) "
            "VALUES (?,?,?,?)", (file_id, size, modified, identity),
        )
        return db.execute(
            "SELECT id FROM file_versions WHERE file_id=? AND identity_key=?", (file_id, identity)
        ).fetchone()[0]

    def _stream(self, run: int, file_version: int, stream: dict[str, Any]) -> None:
        db = self.connection
        values = stream_identity(stream)
        identity = canonical(values)
        db.execute(
            "INSERT OR IGNORE INTO streams(file_version_id,identity_key,signature_offset,"
            "deflate_offset,kind,member_name,deflate_bytes,plaintext_bytes) VALUES (?,?,?,?,?,?,?,?)",
            (file_version, identity, *values),
        )
        stream_id = db.execute(
            "SELECT id FROM streams WHERE file_version_id=? AND identity_key=?",
            (file_version, identity),
        ).fetchone()[0]
        trace = stream.get("trace") or {}
        blocks = trace.get("blocks", [])
        detail = "complete" if trace and not trace.get("blocks_truncated") and len(blocks) == stream["blocks"] else (
            "partial" if blocks else "unavailable"
        )
        db.execute(
            "INSERT INTO stream_results(run_id,stream_id,profile_id,status,verified,signature_confidence,"
            "error_code,error,reconstruction_bytes,chunks,block_count,elapsed_ms,corrections_json,"
            "token_mismatches,token_count,block_detail,settings_source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run, stream_id, self._profile(stream.get("parameters")), stream["status"],
             int(stream["verified"]), stream.get("signature_confidence"), stream.get("error_code"),
             stream.get("error"), stream["correction_bytes"], stream["chunks"], stream["blocks"],
             stream.get("elapsed_ms"), canonical(stream.get("nonzero_corrections", {})),
             trace.get("token_mismatches"), trace.get("token_count"), detail,
             "stream_finalized" if stream.get("parameters") is not None else "unavailable"),
        )
        db.executemany(
            "INSERT INTO block_results VALUES (?,?,?,?,?,?,?,?,?,?)",
            ((run, stream_id, b["index"], b["chunk"], b["plaintext_offset"], b["plaintext_bytes"],
              b["kind"], int(b["last"]), b["literals"], b["references"]) for b in blocks),
        )
        for chunk in trace.get("chunks", []):
            fields = (
                "deflate_offset", "deflate_bytes", "plaintext_offset", "plaintext_bytes",
                "correction_bytes", "blocks", "block_profile", "elapsed_ms", "status", "stage", "error",
            )
            db.execute(
                "INSERT INTO chunk_results VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (run, stream_id, chunk["index"], *(chunk.get(key) for key in fields),
                 canonical(chunk.get("nonzero_corrections", {}))),
            )


    def runs(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute(
            "SELECT id,label,build_identity,state,imported_files,imported_summary_json FROM runs ORDER BY id"
        )]

    def record_run(
        self, records: Iterable[dict[str, Any]], label: str, *, header: dict[str, Any] | None = None,
        summary: dict[str, Any] | None = None,
    ) -> int:
        """Store typed scanner records atomically; failed copies never become queryable runs."""
        if not label.strip():
            raise ValueError("Run label must not be empty")
        header = header or {}
        db = self.connection
        totals = dict.fromkeys(("entries", "successful_streams", "verified_streams", "successful_deflate_bytes",
                               "successful_plaintext_bytes", "successful_correction_bytes"), 0)
        try:
            with db:
                if db.execute("SELECT 1 FROM runs WHERE label=?", (label,)).fetchone():
                    raise ValueError(f"Run label already exists: {label}")
                cursor = db.execute(
                    "INSERT INTO runs(label,build_identity,report_path,report_size,report_mtime_ns,"
                    "configuration_json,started_unix_seconds,state) VALUES (?,?,?,0,0,?,?,'importing')",
                    (label, header.get("build_identity") or header.get("configuration", {}).get("build_identity"),
                     str(self.path.resolve()), canonical(header.get("configuration", {})),
                     header.get("started_unix_seconds")),
                )
                run = cursor.lastrowid
                if run is None:
                    raise RuntimeError("SQLite did not assign a scanner run ID")
                for ordinal, record in enumerate(records, 1):
                    version = self._file_version(record, run, ordinal)
                    db.execute(
                        "INSERT INTO run_files VALUES (?,?,?,?,?,?,?)",
                        (run, ordinal, version, record["status"], record.get("error"), record.get("elapsed_ms"),
                         canonical(record.get("rejected_candidates", {}))),
                    )
                    totals["entries"] += 1
                    for stream in record["streams"]:
                        self._stream(run, version, stream)
                        if stream["status"] == "ok":
                            totals["successful_streams"] += 1
                            totals["verified_streams"] += stream["verified"]
                            totals["successful_deflate_bytes"] += stream["deflate_bytes"]
                            totals["successful_plaintext_bytes"] += stream["plaintext_bytes"]
                            totals["successful_correction_bytes"] += stream["correction_bytes"]
                if summary is not None and any(summary.get(key) != value for key, value in totals.items()):
                    raise ValueError("Scanner totals do not reconcile")
                db.execute(
                    "UPDATE runs SET state='complete',imported_files=?,summary_json=?,imported_summary_json=? WHERE id=?",
                    (totals["entries"], canonical(summary if summary is not None else totals), canonical(totals), run),
                )
        except BaseException:
            self._profiles.clear()
            raise
        return run

    def merge_scan(
        self, source: str | Path, label: str, *, source_label: str | None = None,
        transform: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> int:
        """Copy one completed SQLite run, optionally replacing per-file source metadata."""
        if Path(source).resolve() == self.path.resolve():
            raise ValueError("Source and destination databases must differ")
        with contextlib.closing(scan_records(source, source_label)) as records:
            _, header = next(records)
            summary: dict[str, Any] = {}

            def files() -> Iterable[dict[str, Any]]:
                for kind, record in records:
                    if kind == "file":
                        yield transform(record) if transform is not None else record
                    elif kind == "summary":
                        summary.update(record)

            return self.record_run(files(), label, header=header, summary=summary)

    def _run(self, label: str) -> int:
        row = self.connection.execute(
            "SELECT id FROM runs WHERE label=? AND state='complete'", (label,)
        ).fetchone()
        if row is None:
            raise ValueError(f"No completed run: {label}")
        return row[0]

    def _scope(self, runs: Sequence[str], name: str, *, materialized: bool = False) -> tuple[str, list[Any]]:
        if isinstance(runs, str) or not runs or len(set(runs)) != len(runs):
            raise ValueError("Provide a nonempty ordered sequence of distinct run labels")
        identifiers = [self._run(label) for label in runs]
        if len(identifiers) == 1:
            return f"{name} AS (SELECT * FROM stream_results WHERE run_id=?)", identifiers
        requested = ",".join(f"(?,{priority})" for priority in range(len(identifiers)))
        # Pin file -> stream -> result lookup; run-first plans repeat a full scan for every file.
        return f"""
            {name}_requested(run_id,priority) AS (VALUES {requested}),
            {name}_files AS (
                SELECT rf.run_id,rf.file_version_id,
                       row_number() OVER (PARTITION BY v.file_id
                         ORDER BY q.priority DESC,rf.ordinal DESC) AS precedence
                FROM {name}_requested q JOIN run_files rf ON rf.run_id=q.run_id
                JOIN file_versions v ON v.id=rf.file_version_id
            ),
            {name} AS {"MATERIALIZED" if materialized else ""} (
                SELECT r.* FROM {name}_files f
                CROSS JOIN streams s ON s.file_version_id=f.file_version_id
                CROSS JOIN stream_results r ON r.run_id=f.run_id AND r.stream_id=s.id
                WHERE f.precedence=1
            )""", identifiers

    def compare_runs(self, before: str, after: str, limit: int = 30) -> dict[str, Any]:
        return self.compare_run_sets([before], [after], limit)

    def compare_run_sets(
        self, before: Sequence[str], after: Sequence[str], limit: int = 30,
    ) -> dict[str, Any]:
        """Compare ordered scopes; the last listed observation replaces a whole file."""
        if limit < 1:
            raise ValueError("limit must be positive")
        old, old_parameters = self._scope(before, "old", materialized=True)
        new, new_parameters = self._scope(after, "new", materialized=True)
        prefix = f"WITH {old},{new} "
        parameters = old_parameters + new_parameters
        pair = """FROM old a JOIN new b USING(stream_id)
                  JOIN streams s ON s.id=a.stream_id
                  WHERE a.status='ok' AND b.status='ok'
                  AND a.verified=1 AND b.verified=1"""
        totals = dict(self.connection.execute(
            prefix + """SELECT count(*) AS compared_streams,
            coalesce(sum(a.reconstruction_bytes),0) AS before_bytes,
            coalesce(sum(b.reconstruction_bytes),0) AS after_bytes,
            coalesce(sum(b.reconstruction_bytes<a.reconstruction_bytes),0) AS improved_streams,
            coalesce(sum(b.reconstruction_bytes>a.reconstruction_bytes),0) AS worsened_streams,
            coalesce(sum(b.reconstruction_bytes-a.reconstruction_bytes>=65536 OR
              (b.reconstruction_bytes-a.reconstruction_bytes>=1024 AND
               b.reconstruction_bytes>=a.reconstruction_bytes*1.1)),0) AS major_regressions """ + pair,
            parameters,
        ).fetchone())
        totals["unmatched_previously_successful_streams"] = self.connection.execute(
            prefix + "SELECT count(*) FROM old a LEFT JOIN new b USING(stream_id) "
            "WHERE a.status='ok' AND b.stream_id IS NULL", parameters,
        ).fetchone()[0]
        totals["new_successful_streams"] = self.connection.execute(
            prefix + "SELECT count(*) FROM new b LEFT JOIN old a USING(stream_id) "
            "WHERE b.status='ok' AND a.stream_id IS NULL", parameters,
        ).fetchone()[0]
        totals["previously_successful_now_failed"] = self.connection.execute(
            prefix + "SELECT count(*) FROM old a JOIN new b USING(stream_id) "
            "WHERE a.status='ok' AND (b.status!='ok' OR b.verified=0)", parameters,
        ).fetchone()[0]
        bands = [dict(row) for row in self.connection.execute(
            prefix + """SELECT CASE WHEN s.deflate_bytes<=1024 THEN 'tiny' ELSE 'larger' END AS size_band,
            count(*) AS streams,sum(a.reconstruction_bytes) AS before_bytes,
            sum(b.reconstruction_bytes) AS after_bytes,
            sum(max(b.reconstruction_bytes-a.reconstruction_bytes,0)) AS bytes_added,
            sum(max(a.reconstruction_bytes-b.reconstruction_bytes,0)) AS bytes_saved """ +
            pair + " GROUP BY size_band", parameters,
        )]
        changes = {}
        for name, operator, order in (("regressions", ">", "DESC"), ("improvements", "<", "ASC")):
            rows = self.connection.execute(
                prefix + f"""SELECT s.id AS stream_id,f.path,s.signature_offset,s.member_name,s.deflate_bytes,
            a.reconstruction_bytes AS before_bytes,b.reconstruction_bytes AS after_bytes,
            b.reconstruction_bytes-a.reconstruction_bytes AS added_bytes,
            a.profile_id AS before_profile_id,b.profile_id AS after_profile_id,
            old_run.label AS before_run,new_run.label AS after_run
            FROM old a JOIN new b USING(stream_id)
            JOIN streams s ON s.id=a.stream_id JOIN file_versions v ON v.id=s.file_version_id
            JOIN files f ON f.id=v.file_id
            JOIN runs old_run ON old_run.id=a.run_id JOIN runs new_run ON new_run.id=b.run_id
            WHERE a.status='ok' AND b.status='ok'
            AND a.verified=1 AND b.verified=1 AND b.reconstruction_bytes{operator}a.reconstruction_bytes
            ORDER BY added_bytes {order},s.id LIMIT ?""", [*parameters, limit],
            )
            changes[name] = [dict(row) for row in rows]
        return {"run_sets": {"before": list(before), "after": list(after),
                             "file_precedence": "last listed run wins"},
                "totals": totals, "size_bands": bands, **changes}

    def outliers(
        self, runs: Sequence[str], *, settings: Mapping[str, str | int | bool | None] | None = None,
        limit: int = 30, min_deflate_bytes: int = 1025, max_plaintext_bytes: int | None = None,
        max_file_bytes: int | None = None, one_per_file: bool = False,
        without_oracle: bool = False,
    ) -> list[dict[str, Any]]:
        """Select verified residuals with replay metadata, without reading source files."""
        if limit < 1:
            raise ValueError("limit must be positive")
        scope, parameters = self._scope(runs, "selected")
        conditions = ["r.status='ok'", "r.verified=1", "s.deflate_bytes>=?"]
        if without_oracle:
            conditions.append(
                "NOT EXISTS (SELECT 1 FROM oracle_results o WHERE o.run_id=r.run_id AND o.stream_id=r.stream_id)"
            )
        for value in (min_deflate_bytes, max_plaintext_bytes, max_file_bytes):
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError("Byte limits must be nonnegative integers")
        parameters.append(min_deflate_bytes)
        for field, value in (settings or {}).items():
            if field not in PROFILE_FIELDS or (value is not None and type(value) not in (str, int, bool)):
                raise ValueError(f"Invalid effective setting filter: {field}")
            conditions.append(f'p."{field}" IS ?')
            parameters.append(value)
        for column, maximum in (("s.plaintext_bytes", max_plaintext_bytes), ("v.size_bytes", max_file_bytes)):
            if maximum is not None:
                conditions.append(f"{column}<=?")
                parameters.append(maximum)
        rows = self.connection.execute(f"""
            WITH {scope}, candidates AS (
                SELECT r.run_id,n.label AS run_label,r.stream_id,f.path,v.size_bytes,
                       v.modified_unix_seconds,s.signature_offset,s.deflate_offset,s.kind,
                       s.member_name,s.deflate_bytes,s.plaintext_bytes,r.reconstruction_bytes,
                       r.profile_id,p.settings_json,
                       row_number() OVER (PARTITION BY v.file_id
                         ORDER BY r.reconstruction_bytes DESC,r.stream_id) AS file_rank
                FROM selected r JOIN streams s ON s.id=r.stream_id
                JOIN file_versions v ON v.id=s.file_version_id JOIN files f ON f.id=v.file_id
                JOIN runs n ON n.id=r.run_id LEFT JOIN profiles p ON p.id=r.profile_id
                WHERE {" AND ".join(conditions)}
            )
            SELECT * FROM candidates {"WHERE file_rank=1" if one_per_file else ""}
            ORDER BY reconstruction_bytes DESC,stream_id LIMIT ?
        """, [*parameters, limit])
        result = []
        for row in rows:
            item = dict(row)
            item.pop("file_rank")
            encoded = item.pop("settings_json")
            item["settings"] = json.loads(encoded) if encoded is not None else None
            item["oracle"] = self._oracle_result(item["run_id"], item["stream_id"])
            item["perfect_settings"] = item["oracle"]["perfect_settings"] if item["oracle"] else None
            result.append(item)
        return result


    def _oracle_result(self, run_id: int, stream_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT o.*,b.settings_json AS best_settings,p.settings_json AS perfect_settings "
            "FROM oracle_results o JOIN profiles b ON b.id=o.best_profile_id "
            "LEFT JOIN profiles p ON p.id=o.perfect_profile_id WHERE o.run_id=? AND o.stream_id=?",
            (run_id, stream_id),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        for field in ("best_settings", "perfect_settings"):
            result[field] = json.loads(result[field]) if result[field] is not None else None
        result["search"] = json.loads(result.pop("search_json"))
        result["demonstrated_savings_bytes"] = result["baseline_bytes"] - result["best_bytes"]
        return result

    def oracle_opportunities(self, runs: Sequence[str], limit: int = 30) -> list[dict[str, Any]]:
        """Rank evaluated larger streams by same-evaluator demonstrated savings."""
        if limit < 1:
            raise ValueError("limit must be positive")
        scope, parameters = self._scope(runs, "selected", materialized=True)
        rows = self.connection.execute(f"""
            WITH {scope}
            SELECT e.*,n.label AS run_label FROM oracle_results o
            JOIN selected r USING(run_id,stream_id)
            JOIN oracle_stream_settings e USING(run_id,stream_id)
            JOIN runs n ON n.id=r.run_id
            WHERE e.deflate_bytes>1024
            ORDER BY e.demonstrated_savings_bytes DESC,e.stream_id LIMIT ?
        """, [*parameters, limit])
        return [dict(row) for row in rows]

    def oracle_cohorts(self, runs: Sequence[str]) -> dict[str, Any]:
        """Count unmeasured larger-stream similarities, without projecting oracle savings."""
        scope, parameters = self._scope(runs, "selected", materialized=True)
        mask = "+".join(
            f"(CASE WHEN coalesce(json_extract(r.corrections_json,'$.{name}'),0)>0 THEN {1 << index} ELSE 0 END)"
            for index, name in enumerate(TOKEN_CORRECTIONS)
        )
        fields = ",".join(f"p.{field}" for field in COHORT_FIELDS)
        fingerprint = f"json_array({fields})"
        equality = " AND ".join(f"p.{field} IS f.{field}" for field in COHORT_FIELDS)
        exact = "EXISTS(SELECT 1 FROM seeds z WHERE z.profile_id=e.profile_id)"
        pattern = "EXISTS(SELECT 1 FROM seeds z WHERE z.fingerprint_id=e.fingerprint_id AND z.token_mask=e.token_mask)"
        exact_pattern = (
            "EXISTS(SELECT 1 FROM seeds z WHERE z.profile_id=e.profile_id AND z.token_mask=e.token_mask)"
        )
        metrics = {"settings": "1", "token_pattern": pattern,
                   "exact_settings": exact, "exact_token_pattern": exact_pattern}
        aggregates = []
        for name, condition in metrics.items():
            aggregates.extend((
                f"count(CASE WHEN {condition} THEN 1 END) AS {name}_streams",
                f"count(DISTINCT CASE WHEN {condition} THEN e.file_id END) AS {name}_files",
                f"coalesce(sum(CASE WHEN {condition} THEN e.reconstruction_bytes ELSE 0 END),0) AS {name}_bytes",
            ))
        rows = self.connection.execute(f"""
            WITH {scope},
            observed AS MATERIALIZED (
                SELECT r.profile_id,{fields},{fingerprint} AS fingerprint_id,{mask} AS token_mask,
                       o.baseline_bytes-o.best_bytes AS demonstrated_savings,
                       o.perfect_profile_id IS NOT NULL AS perfect
                FROM oracle_results o JOIN selected r USING(run_id,stream_id)
                JOIN streams s ON s.id=r.stream_id JOIN profiles p ON p.id=r.profile_id
                WHERE r.status='ok' AND r.verified=1 AND s.deflate_bytes>1024
            ),
            fingerprints AS MATERIALIZED (
                SELECT DISTINCT fingerprint_id,{",".join(COHORT_FIELDS)} FROM observed
            ),
            seeds AS MATERIALIZED (
                SELECT DISTINCT r.profile_id,r.token_mask,f.fingerprint_id
                FROM observed r JOIN fingerprints f ON
                    {" AND ".join(f"r.{field} IS f.{field}" for field in COHORT_FIELDS)}
            ),
            profile_matches AS MATERIALIZED (
                SELECT p.id,f.fingerprint_id FROM profiles p JOIN fingerprints f ON {equality}
            ),
            eligible AS MATERIALIZED (
                SELECT r.profile_id,r.reconstruction_bytes,v.file_id,pm.fingerprint_id,{mask} AS token_mask
                FROM selected r JOIN profile_matches pm ON pm.id=r.profile_id
                JOIN streams s ON s.id=r.stream_id JOIN file_versions v ON v.id=s.file_version_id
                WHERE r.status='ok' AND r.verified=1 AND s.deflate_bytes>1024
                  AND NOT EXISTS(SELECT 1 FROM oracle_results o WHERE o.run_id=r.run_id AND o.stream_id=r.stream_id)
            ),
            grouped AS (
                SELECT e.fingerprint_id,{",".join(aggregates)} FROM eligible e GROUP BY e.fingerprint_id
            ),
            counts AS (
                SELECT NULL AS fingerprint_id,{",".join(aggregates)} FROM eligible e
                UNION ALL
                SELECT f.fingerprint_id,
                    {",".join(f"coalesce(g.{name}_{suffix},0)" for name in metrics for suffix in ("streams","files","bytes"))}
                FROM fingerprints f LEFT JOIN grouped g USING(fingerprint_id)
            )
            SELECT c.*,
                (SELECT count(*) FROM observed o WHERE c.fingerprint_id IS NULL OR o.fingerprint_id=c.fingerprint_id)
                    AS seed_streams,
                (SELECT coalesce(sum(perfect),0) FROM observed o WHERE c.fingerprint_id IS NULL OR o.fingerprint_id=c.fingerprint_id)
                    AS perfect_seed_streams,
                (SELECT coalesce(sum(demonstrated_savings),0) FROM observed o WHERE c.fingerprint_id IS NULL OR o.fingerprint_id=c.fingerprint_id)
                    AS seed_savings_bytes
            FROM counts c ORDER BY c.fingerprint_id IS NOT NULL,c.fingerprint_id
        """, parameters)
        counts = [dict(row) for row in rows]
        groups = []
        for row in counts[1:]:
            row["settings"] = dict(zip(COHORT_FIELDS, json.loads(row.pop("fingerprint_id"))))
            groups.append(row)
        total = counts[0]
        total.pop("fingerprint_id")
        return {
            "seed_streams": total["seed_streams"],
            "basis": "Same hash/parser/insertion/window; exact settings additionally require the same complete profile",
            "token_pattern_basis": "Same set of nonzero token correction types, not counts or raw payload identity",
            "scope": "Unmeasured verified successful streams >1024 bytes in the ordered current-known run set",
            "totals": total,
            "groups": sorted(groups, key=lambda group: group["token_pattern_bytes"], reverse=True),
        }

    def family_overhead(self, runs: Sequence[str]) -> list[dict[str, Any]]:
        """Group effective signatures, not asserted compressor identities."""
        scope, parameters = self._scope(runs, "selected")
        return [dict(row) for row in self.connection.execute(f"""
            WITH {scope}, grouped AS (
                SELECT CASE
                    WHEN p.matching_type LIKE 'MiniZ%' OR p.hash_algorithm='MiniZFast' THEN 'miniz-style'
                    WHEN p.hash_algorithm LIKE 'Libdeflate%' THEN 'libdeflate-style'
                    WHEN p.hash_algorithm='RandomVector' THEN 'table-hash / Windows-style'
                    WHEN p.hash_algorithm IN ('ZlibNG','Crc32cHash') THEN 'zlib-ng-style'
                    WHEN p.hash_algorithm LIKE 'Chromium%' THEN 'Chromium-style'
                    WHEN p.hash_algorithm='None' THEN 'no dictionary'
                    WHEN p.hash_algorithm LIKE 'Zlib {{%' THEN 'zlib-style / shared hash'
                    ELSE 'unavailable / other' END AS family,
                    CASE WHEN s.deflate_bytes<=1024 THEN 'tiny' ELSE 'larger' END AS size_band,
                    count(*) AS streams,
                    sum(r.status!='ok') AS failures,
                    sum(r.status='ok' AND r.verified=0) AS unverified,
                    sum(r.status='ok' AND r.verified=1) AS verified_streams,
                    sum(CASE WHEN r.status='ok' AND r.verified=1 THEN s.deflate_bytes ELSE 0 END) AS deflate_bytes,
                    sum(CASE WHEN r.status='ok' AND r.verified=1 THEN r.reconstruction_bytes ELSE 0 END) AS reconstruction_bytes
                FROM selected r JOIN streams s ON s.id=r.stream_id
                LEFT JOIN profiles p ON p.id=r.profile_id GROUP BY family,size_band
            )
            SELECT *,100.0*reconstruction_bytes/nullif(deflate_bytes,0) AS reconstruction_percent,
                   100.0*reconstruction_bytes/nullif(sum(reconstruction_bytes) OVER (),0) AS overhead_share_percent
            FROM grouped ORDER BY reconstruction_bytes DESC,family,size_band
        """, parameters)]

    def stream(self, run: str, stream_id: int) -> dict[str, Any]:
        run_id = self._run(run)
        row = self.connection.execute(
            "SELECT * FROM oracle_stream_settings WHERE run_id=? AND stream_id=?",
            (run_id, stream_id),
        ).fetchone()
        if row is None:
            raise ValueError("Stream not present in the selected run")
        return {
            "result": dict(row),
            "blocks": [dict(item) for item in self.connection.execute(
                "SELECT * FROM effective_block_settings WHERE run_id=? AND stream_id=? "
                "ORDER BY block_index", (run_id, stream_id),
            )],
            "estimator_results": [dict(item) for item in self.connection.execute(
                "SELECT e.*,p.settings_json FROM estimator_results e LEFT JOIN profiles p "
                "ON p.id=e.profile_id WHERE run_id=? AND stream_id=? ORDER BY stage,candidate_index",
                (run_id, stream_id),
            )],
        }

    def priorities(self, run: str, limit: int = 30) -> list[dict[str, Any]]:
        if limit < 1:
            raise ValueError("limit must be positive")
        return [dict(row) for row in self.connection.execute(
            "SELECT * FROM investigation_areas WHERE run_id=? "
            "ORDER BY failures DESC,excess_above_one_percent_bytes DESC LIMIT ?",
            (self._run(run), limit),
        )]


    def timings(self, run: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT s.*,b.label AS batch_label,b.controlled,b.verification_enabled,b.scope,"
            "b.metadata_json,f.status FROM timing_samples s JOIN timing_batches b ON b.id=s.batch_id "
            "LEFT JOIN performance_imports i ON i.batch_id=b.id "
            "LEFT JOIN timing_file_results f ON f.batch_id=s.batch_id AND f.sample_index=s.sample_index "
            "WHERE s.run_id=? AND (i.state IS NULL OR i.state='complete') "
            "ORDER BY s.batch_id,s.case_label,s.sample_index", (self._run(run),),
        )
        result = []
        for _, group in groupby(rows, key=lambda row: (row["batch_id"], row["case_label"])):
            samples = list(group)
            first = samples[0]
            usable = [sample for sample in samples if sample["status"] in (None, "ok", "no_streams")]
            cpu = [sample["cpu_seconds"] for sample in usable if sample["cpu_seconds"] is not None]
            result.append({
                key: first[key] for key in (
                    "batch_label", "case_label", "controlled", "verification_enabled", "scope", "metadata_json",
                )
            } | {
                "samples": len(samples), "usable_samples": len(usable), "cpu_samples": len(cpu),
                "status_counts": dict(Counter(sample["status"] or "not_recorded" for sample in samples)),
                "median_cpu_seconds": statistics.median(cpu) if cpu else None,
                "median_wall_seconds": statistics.median(sample["wall_seconds"] for sample in usable) if usable else None,
            })
        return result


    def check(self) -> dict[str, Any]:
        return {
            "integrity": [row[0] for row in self.connection.execute("PRAGMA integrity_check")],
            "foreign_key_errors": [tuple(row) for row in self.connection.execute("PRAGMA foreign_key_check")],
        }

    def delete_run(self, label: str) -> None:
        with self.connection:
            self.connection.execute(
                "DELETE FROM timing_batches WHERE id IN (SELECT batch_id FROM timing_samples "
                "WHERE run_id=(SELECT id FROM runs WHERE label=?))", (label,),
            )
            cursor = self.connection.execute("DELETE FROM runs WHERE label=?", (label,))
            if cursor.rowcount != 1:
                raise ValueError(f"Unknown run: {label}")

    def backup(self, destination: str | Path) -> None:
        path = Path(destination)
        with path.open("xb"):
            pass
        with contextlib.closing(sqlite3.connect(path)) as target:
            self.connection.backup(target)

    def vacuum(self) -> None:
        self.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.connection.execute("VACUUM")
