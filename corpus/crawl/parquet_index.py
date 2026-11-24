"""Bounded range reads of random Common Crawl Parquet row groups."""

from __future__ import annotations

import gzip
import io
import random
from dataclasses import dataclass
from typing import Any

from . import commoncrawl
from .rarity import Catalog
from .settings import CrawlSettings

POOL_LIMIT = 10_000
MAX_ROW_GROUP_ROWS = 4_000_000
MIME_COLUMNS = ["content_mime_type", "content_mime_detected"]
LOCATION_COLUMNS = ["url", "fetch_time", "fetch_status", "content_digest",
                    "warc_filename", "warc_record_offset", "warc_record_length"]


class RangeFile(io.RawIOBase):
    def __init__(self, fetcher: commoncrawl.Fetcher, url: str, size: int, limit: int):
        super().__init__()
        self.fetcher, self.url, self.size, self.limit = fetcher, url, size, limit
        self.position = 0
        self.downloaded = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.position

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence not in (io.SEEK_SET, io.SEEK_CUR, io.SEEK_END):
            raise ValueError("Invalid seek mode")
        position = offset + (self.position if whence == io.SEEK_CUR else self.size if whence == io.SEEK_END else 0)
        if position < 0:
            raise ValueError("Negative seek position")
        self.position = position
        return position

    def read(self, size: int = -1) -> bytes:
        length = max(0, min(self.size - self.position, self.size if size < 0 else size))
        if not length:
            return b""
        if self.downloaded + length > self.limit:
            raise ValueError(f"Parquet index refill exceeded {self.limit / 1048576:g} MiB; "
                             "increase --parquet-max-index-mib or use --index-source cdx")
        data = self.fetcher.get(self.url, self.position, self.position + length - 1)
        if len(data) != length:
            raise ValueError(f"Incorrect Parquet range length: expected {length}, received {len(data)}")
        self.position += length
        self.downloaded += length
        return data


@dataclass
class CandidatePool:
    url: str
    group: int
    rows: int
    matched: int
    records: list[dict[str, Any]]


class ParquetIndex:
    def __init__(self) -> None:
        try:
            import pyarrow.parquet as pq
        except ModuleNotFoundError as error:
            if error.name != "pyarrow":
                raise
            raise RuntimeError("Parquet sampling requires the optional dependency: "
                               "uv run --locked --extra parquet python -m corpus.crawl crawl "
                               "--index-source parquet") from error
        self.pq = pq
        self.pool: CandidatePool | None = None
        self.crawl: str | None = None

    @property
    def active_crawl(self) -> str | None:
        return self.crawl if self.pool is not None and self.pool.records else None

    def _refill(self, crawl: str, settings: CrawlSettings, fetcher: commoncrawl.Fetcher,
                catalog: Catalog, rng: random.Random) -> CandidatePool:
        from pyarrow import timestamp

        cache = settings.cache_dir / f"{crawl}-cc-index-table.paths"
        if not cache.is_file():
            raw = fetcher.get(f"{settings.data_url.rstrip('/')}/crawl-data/{crawl}/cc-index-table.paths.gz")
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(gzip.decompress(raw).decode("utf-8"), encoding="utf-8")
        paths = [p for p in cache.read_text(encoding="utf-8").splitlines()
                 if "/subset=warc/" in p and p.endswith(".parquet")]
        if not paths:
            raise ValueError(f"No WARC Parquet files in the manifest for {crawl}")
        url = f"{settings.data_url.rstrip('/')}/{rng.choice(paths)}"
        size = catalog.shard_size(url)
        if size is None:
            size = fetcher.size(url)
            catalog.remember_shard(url, size)
        with RangeFile(fetcher, url, size, settings.parquet_max_index_mib * 1048576) as remote:
            parquet = self.pq.ParquetFile(remote)
            if not parquet.num_row_groups:
                raise ValueError(f"No Parquet row groups in {url}")
            group = rng.randrange(parquet.num_row_groups)
            rows = parquet.metadata.row_group(group).num_rows
            if rows > MAX_ROW_GROUP_ROWS:
                raise ValueError(f"Parquet row group has {rows} rows; limit is {MAX_ROW_GROUP_ROWS}")
            indices: list[tuple[int, dict[str, Any]]] = []
            matched = position = 0
            for batch in parquet.iter_batches(batch_size=8192, row_groups=[group],
                                              columns=MIME_COLUMNS, use_threads=False):
                for row in batch.to_pylist():
                    mime = {"mime": row["content_mime_type"], "mime-detected": row["content_mime_detected"]}
                    if commoncrawl.eligible_mime(mime, settings):
                        matched += 1
                        if len(indices) < POOL_LIMIT:
                            indices.append((position, mime))
                        else:
                            slot = rng.randrange(matched)
                            if slot < POOL_LIMIT:
                                indices[slot] = (position, mime)
                    position += 1
            selected = dict(indices)
            records: list[dict[str, Any]] = []
            position = 0
            if selected:
                for batch in parquet.iter_batches(batch_size=8192, row_groups=[group],
                                                  columns=LOCATION_COLUMNS, use_threads=False):
                    # Preserve UTC epoch values without requiring a system timezone database.
                    time_index = batch.schema.get_field_index("fetch_time")
                    times = batch.column(time_index)
                    batch = batch.set_column(time_index, "fetch_time", times.cast(timestamp(times.type.unit)))
                    for row in batch.to_pylist():
                        mime = selected.get(position)
                        position += 1
                        if mime is None:
                            continue
                        length = row["warc_record_length"]
                        if row["fetch_status"] != 200 or length is None or not 0 < length <= settings.max_record_bytes:
                            continue
                        if (not all(isinstance(row[key], str) and row[key]
                                    for key in ("url", "content_digest", "warc_filename"))
                                or not isinstance(row["warc_record_offset"], int)
                                or row["warc_record_offset"] < 0 or row["fetch_time"] is None):
                            raise ValueError(f"Incomplete WARC location in {url}, row group {group}")
                        records.append({**mime, "url": row["url"], "status": "200",
                                        "digest": row["content_digest"].removeprefix("sha1:"),
                                        "filename": row["warc_filename"], "offset": row["warc_record_offset"],
                                        "length": length, "timestamp": row["fetch_time"].strftime("%Y%m%d%H%M%S")})
        rng.shuffle(records)
        return CandidatePool(url, group, rows, matched, records)

    def candidates(self, crawl: str, settings: CrawlSettings, fetcher: commoncrawl.Fetcher,
                   catalog: Catalog, rng: random.Random) -> CandidatePool:
        if self.pool is None or not self.pool.records or self.crawl != crawl:
            self.pool = self._refill(crawl, settings, fetcher, catalog, rng)
            self.crawl = crawl
        return self.pool
