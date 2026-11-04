"""Compression-type signatures and the Common Crawl catalog."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TIERS = ("family", "variant", "exact", "failure")
_ARGUMENTS = re.compile(r"\s*[\{\(].*$")


def _kind(value: Any) -> str:
    """Strip estimated numeric arguments: `AddFirst(106)` -> `AddFirst`, `Lazy { .. }` -> `Lazy`."""
    return _ARGUMENTS.sub("", str(value))


def stream_signatures(settings: Mapping[str, Any] | None) -> dict[str, str]:
    """Effective-settings signatures. These group behaviour, they do not prove producer identity."""
    if settings is None:
        return {"family": "unavailable", "variant": "unavailable", "exact": "unavailable"}
    family = " | ".join((
        str(settings.get("hash_algorithm")), _kind(settings.get("matching_type")),
        str(settings.get("strategy")), _kind(settings.get("add_policy")),
    ))
    variant = " | ".join((
        str(settings.get("hash_algorithm")), str(settings.get("matching_type")),
        str(settings.get("strategy")), _kind(settings.get("add_policy")),
        str(settings.get("block_type_strategy")), f"w{settings.get('window_bits')}",
    ))
    exact = json.dumps(settings, sort_keys=True, separators=(",", ":"))
    return {"family": family, "variant": variant, "exact": exact}


def failure_signature(kind: str, status: str, error_code: str | None) -> str:
    return f"{kind} | {status} | {error_code or 'unknown'}"


@dataclass
class Tally:
    files: int = 0
    streams: int = 0
    deflate_bytes: int = 0

    def add(self, streams: int, deflate_bytes: int) -> None:
        self.files += 1
        self.streams += streams
        self.deflate_bytes += deflate_bytes


@dataclass
class Census:
    """Per-tier signature tallies; `files` counts distinct files containing the signature."""

    tallies: dict[str, dict[str, Tally]] = field(default_factory=lambda: {tier: {} for tier in TIERS})
    files: int = 0
    runs: list[str] = field(default_factory=list)

    def add_file(self, observed: Mapping[tuple[str, str], tuple[int, int]]) -> None:
        self.files += 1
        for (tier, signature), (streams, deflate_bytes) in observed.items():
            self.tallies[tier].setdefault(signature, Tally()).add(streams, deflate_bytes)

    def files_with(self, tier: str, signature: str) -> int:
        tally = self.tallies[tier].get(signature)
        return tally.files if tally else 0






CATALOG_SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY,
    digest TEXT NOT NULL UNIQUE,
    crawl TEXT NOT NULL,
    url TEXT NOT NULL,
    mime TEXT,
    warc_filename TEXT NOT NULL,
    warc_offset INTEGER NOT NULL,
    warc_length INTEGER NOT NULL,
    truncated TEXT,
    body_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    scan_status TEXT NOT NULL,
    streams INTEGER NOT NULL,
    saved_path TEXT,
    reasons_json TEXT NOT NULL,
    selection TEXT CHECK (selection IN ('rare','sampled','both')),
    processed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS records_sha256 ON records(sha256);
CREATE TABLE IF NOT EXISTS signature_counts (
    tier TEXT NOT NULL,
    signature TEXT NOT NULL,
    files INTEGER NOT NULL,
    streams INTEGER NOT NULL,
    deflate_bytes INTEGER NOT NULL,
    saved INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(tier, signature)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY,
    crawl TEXT NOT NULL,
    shard TEXT NOT NULL,
    range_start INTEGER NOT NULL,
    range_bytes INTEGER NOT NULL,
    cdx_lines INTEGER NOT NULL,
    matched INTEGER NOT NULL,
    fetched INTEGER NOT NULL,
    saved INTEGER NOT NULL,
    downloaded_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS shards (
    url TEXT PRIMARY KEY,
    size_bytes INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS saved_streams (
    id INTEGER PRIMARY KEY,
    record_id INTEGER NOT NULL REFERENCES records(id),
    stream_index INTEGER NOT NULL,
    selection TEXT NOT NULL CHECK (selection IN ('rare','sampled','both')),
    reasons_json TEXT NOT NULL,
    kind TEXT,
    offset INTEGER,
    deflate_offset INTEGER,
    member_name TEXT,
    location_json TEXT NOT NULL,
    extract TEXT NOT NULL CHECK (extract IN ('deflate','png')),
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    status TEXT,
    deflate_bytes INTEGER,
    verify TEXT CHECK (verify IN ('match','mismatch')),
    verify_detail TEXT,
    UNIQUE(record_id, stream_index)
);
CREATE INDEX IF NOT EXISTS saved_streams_sha256 ON saved_streams(sha256);
"""


class Catalog:
    """Public crawl observations and saves; private scans live in a separate database."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, timeout=60)
        self.connection.row_factory = sqlite3.Row
        tables = {row[0] for row in self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        if "schema_info" in tables:
            versions = [row[0] for row in self.connection.execute("SELECT version FROM schema_info")]
            if versions != [1]:
                self.close()
                raise ValueError("Unsupported corpus database schema")
        elif tables - {"records", "signature_counts", "samples", "shards", "saved_streams"}:
            self.close()
            raise ValueError("Not a Common Crawl catalog")
        self.connection.executescript(
            (Path(__file__).resolve().parents[1] / "database" / "schema.sql").read_text())
        self.connection.executescript(CATALOG_SCHEMA)
        columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(records)")}
        if "selection" not in columns:
            with self.connection:
                self.connection.execute("ALTER TABLE records ADD COLUMN selection TEXT "
                                        "CHECK (selection IN ('rare','sampled','both'))")
                # Before sampling existed, every saved payload was a rare save.
                self.connection.execute("UPDATE records SET selection='rare' WHERE saved_path IS NOT NULL")
        self.connection.execute("CREATE INDEX IF NOT EXISTS records_selection ON records(selection)")

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> Catalog:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def census(self) -> tuple[Census, dict[tuple[str, str], int]]:
        census = Census()
        saved: dict[tuple[str, str], int] = {}
        for row in self.connection.execute("SELECT * FROM signature_counts"):
            if row["tier"] in census.tallies:
                census.tallies[row["tier"]][row["signature"]] = Tally(row["files"], row["streams"], row["deflate_bytes"])
            if row["saved"]:
                saved[row["tier"], row["signature"]] = row["saved"]
        census.files = self.connection.execute("SELECT count(*) FROM records").fetchone()[0]
        return census, saved

    def seen_digests(self, digests: Iterable[str]) -> set[str]:
        found: set[str] = set()
        values = list(digests)
        for start in range(0, len(values), 500):
            chunk = values[start:start + 500]
            found.update(row[0] for row in self.connection.execute(
                f"SELECT digest FROM records WHERE digest IN ({','.join('?' * len(chunk))})", chunk,
            ))
        return found

    def seen_sha256(self, sha256: str) -> bool:
        return self.connection.execute("SELECT 1 FROM records WHERE sha256=?", (sha256,)).fetchone() is not None

    def shard_size(self, url: str) -> int | None:
        row = self.connection.execute("SELECT size_bytes FROM shards WHERE url=?", (url,)).fetchone()
        return row[0] if row else None

    def remember_shard(self, url: str, size: int) -> None:
        with self.connection:
            self.connection.execute("INSERT OR REPLACE INTO shards VALUES (?,?)", (url, size))

    def record(
        self, meta: Mapping[str, Any], *, sha256: str, body_bytes: int, scan_status: str, streams: int,
        observed: Mapping[tuple[str, str], tuple[int, int]], saved_path: str | None,
        reasons: Sequence[Mapping[str, Any]], saved_keys: Iterable[tuple[str, str]], selection: str | None = None,
    ) -> int:
        db = self.connection
        with db:
            record_id = db.execute(
                "INSERT INTO records(digest,crawl,url,mime,warc_filename,warc_offset,warc_length,truncated,"
                "body_bytes,sha256,scan_status,streams,saved_path,reasons_json,selection) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (meta["digest"], meta["crawl"], meta["url"], meta.get("mime"), meta["filename"],
                 meta["offset"], meta["length"], meta.get("truncated"), body_bytes, sha256, scan_status,
                 streams, saved_path, json.dumps(list(reasons), sort_keys=True), selection),
            ).lastrowid
            if record_id is None:
                raise RuntimeError("SQLite did not assign a crawl record ID")
            for (tier, signature), (count, deflate_bytes) in observed.items():
                db.execute(
                    "INSERT INTO signature_counts(tier,signature,files,streams,deflate_bytes) VALUES (?,?,1,?,?) "
                    "ON CONFLICT(tier,signature) DO UPDATE SET files=files+1,streams=streams+excluded.streams,"
                    "deflate_bytes=deflate_bytes+excluded.deflate_bytes",
                    (tier, signature, count, deflate_bytes),
                )
            for tier, signature in saved_keys:
                db.execute(
                    "INSERT INTO signature_counts(tier,signature,files,streams,deflate_bytes,saved) "
                    "VALUES (?,?,0,0,0,1) ON CONFLICT(tier,signature) DO UPDATE SET saved=saved+1",
                    (tier, signature),
                )
        return record_id

    def save_streams(self, record_id: int, rows: Iterable[Mapping[str, Any]]) -> None:
        with self.connection:
            self.connection.executemany(
                "INSERT INTO saved_streams(record_id,stream_index,selection,reasons_json,kind,offset,deflate_offset,"
                "member_name,location_json,extract,path,sha256,bytes,status,deflate_bytes,verify,verify_detail) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(record_id, row["index"], row["selection"], json.dumps(row["reasons"]), row.get("kind"),
                  row.get("offset"), row.get("deflate_offset"), row.get("member_name"),
                  json.dumps(row["location"], sort_keys=True), row["extract"], row["path"], row["sha256"],
                  row["bytes"], row.get("status"), row.get("deflate_bytes"), row.get("verify"),
                  row.get("verify_detail") or None) for row in rows],
            )

    def sample(self, **values: Any) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT INTO samples(crawl,shard,range_start,range_bytes,cdx_lines,matched,fetched,saved,"
                "downloaded_bytes) VALUES (:crawl,:shard,:range_start,:range_bytes,:cdx_lines,:matched,"
                ":fetched,:saved,:downloaded_bytes)", values,
            )


class Known:
    """Common Crawl evidence, updated in memory as the crawl proceeds."""

    def __init__(self, crawl: Census, saved: dict[tuple[str, str], int]):
        self.crawl = crawl
        self.saved = saved

    def files(self, tier: str, signature: str) -> int:
        return self.crawl.files_with(tier, signature)

    def observe(self, observed: Mapping[tuple[str, str], tuple[int, int]], saved_keys: Iterable[tuple[str, str]]) -> None:
        self.crawl.add_file(observed)
        for key in saved_keys:
            self.saved[key] = self.saved.get(key, 0) + 1
