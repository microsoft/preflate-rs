"""Minimal Common Crawl access: index shards, CDX ranges and single WARC records."""

from __future__ import annotations

import fnmatch
import gzip
import io
import json
import logging
import random
import threading
import time
import zlib
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.exceptions import MaxRetryError, ProtocolError
from urllib3.util.retry import Retry
from warcio.archiveiterator import ArchiveIterator

from .settings import CrawlSettings

class Fetcher:
    """Pooled HTTP GETs that back off on throttling; counts downloaded bytes across threads."""

    def __init__(self, user_agent: str, *, timeout: int = 120, retries: int = 6, pool: int = 4):
        self.timeout = timeout
        self.downloaded = 0
        self._lock = threading.Lock()
        retry = Retry(total=retries, backoff_factor=2, backoff_max=60, backoff_jitter=1.0,
                      status_forcelist=(429, 500, 502, 503, 504), allowed_methods=("GET", "HEAD"),
                      respect_retry_after_header=True, raise_on_status=False)
        self._retry = retry
        self.session = requests.Session()
        self.session.headers["User-Agent"] = user_agent
        self.session.mount("https://", HTTPAdapter(max_retries=retry, pool_maxsize=max(pool, 1)))
        self.session.mount("http://", HTTPAdapter(max_retries=retry, pool_maxsize=max(pool, 1)))

    def close(self) -> None:
        self.session.close()

    def get(self, url: str, start: int | None = None, end: int | None = None) -> bytes:
        headers = {}
        if start is not None:
            headers["Range"] = f"bytes={start}-{end if end is not None else ''}"
        retry = self._retry
        while True:
            try:
                with self.session.get(url, headers=headers, timeout=self.timeout, stream=True) as response:
                    response.raise_for_status()
                    if start is not None and response.status_code != 206:
                        raise ValueError(f"Server ignored byte range for {url}")
                    data = response.content
                break
            except requests.exceptions.ChunkedEncodingError as error:
                # requests reads bodies outside the adapter's retry loop.
                try:
                    retry = retry.increment(method="GET", url=url, error=ProtocolError(str(error)))
                except MaxRetryError:
                    raise error
                logging.getLogger(__name__).warning("Incomplete download of %s; retrying: %s", url, error)
                retry.sleep()
        with self._lock:
            self.downloaded += len(data)
        return data

    def size(self, url: str) -> int:
        response = self.session.head(url, timeout=self.timeout, allow_redirects=True)
        response.raise_for_status()
        length = response.headers.get("Content-Length")
        if length is None:
            raise ValueError(f"No Content-Length for {url}")
        return int(length)


def resolve_crawl(choice: str, collections: Sequence[str], recent: int, rng: random.Random) -> str:
    if choice == "latest":
        return collections[0]
    if choice == "random":
        return rng.choice(list(collections[:max(recent, 1)]))
    return choice


def list_collections(fetcher: Fetcher, index_url: str, cache_dir: Path, max_age_seconds: int = 86400) -> list[str]:
    cache = cache_dir / "collinfo.json"
    if not cache.is_file() or time.time() - cache.stat().st_mtime > max_age_seconds:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(fetcher.get(index_url.rstrip("/") + "/collinfo.json"))
    return [item["id"] for item in json.loads(cache.read_text(encoding="utf-8"))]


def cdx_shards(fetcher: Fetcher, data_url: str, crawl: str, cache_dir: Path) -> list[str]:
    cache = cache_dir / f"{crawl}-cc-index.paths"
    if not cache.is_file():
        cache.parent.mkdir(parents=True, exist_ok=True)
        raw = fetcher.get(f"{data_url.rstrip('/')}/crawl-data/{crawl}/cc-index.paths.gz")
        cache.write_text(gzip.decompress(raw).decode("utf-8"), encoding="utf-8")
    return [line for line in cache.read_text(encoding="utf-8").split() if "/cdx-" in line and line.endswith(".gz")]


def _looks_like_cdx(text: bytes) -> bool:
    first = text.split(b"\n", 1)[0]
    parts = first.split(b" ", 2)
    return len(parts) == 3 and len(parts[1]) == 14 and parts[1].isdigit() and parts[2].startswith(b"{")


def cdx_lines(data: bytes) -> list[str]:
    """Decode whole gzip members from an arbitrary byte range of a CDX shard.

    The range starts and ends mid-member; resynchronize on the first member that
    decodes to CDX text and drop the incomplete final member.
    """
    lines: list[str] = []
    position = 0
    synchronized = False
    while position < len(data):
        start = data.find(b"\x1f\x8b\x08", position)
        if start < 0:
            break
        decoder = zlib.decompressobj(31)
        try:
            text = decoder.decompress(data[start:])
        except zlib.error:
            if synchronized:
                break
            position = start + 1
            continue
        if not decoder.eof:
            break
        if not _looks_like_cdx(text):
            if synchronized:
                break
            position = start + 1
            continue
        synchronized = True
        lines.extend(text.decode("utf-8", "replace").splitlines())
        position = len(data) - len(decoder.unused_data)
    return lines


def parse_cdx_line(line: str) -> dict[str, Any] | None:
    parts = line.split(" ", 2)
    if len(parts) != 3:
        return None
    try:
        record = json.loads(parts[2])
        record["offset"] = int(record["offset"])
        record["length"] = int(record["length"])
        record.setdefault("timestamp", parts[1])
    except (ValueError, KeyError, TypeError):
        return None
    if not all(isinstance(record.get(key), str) for key in ("url", "filename", "digest")):
        return None
    return record


def mime_of(record: dict[str, Any]) -> str:
    return str(record.get("mime-detected") or record.get("mime") or "").lower()


def matches_mime(record: dict[str, Any], patterns: Sequence[str]) -> bool:
    mimes = {mime_of(record), str(record.get("mime") or "").lower()} - {""}
    return any(fnmatch.fnmatchcase(mime, pattern.lower()) for mime in mimes for pattern in patterns)


def is_text_mime(record: dict[str, Any]) -> bool:
    """Use detected MIME preferentially, rather than a potentially misleading server label."""
    mime = mime_of(record).split(";", 1)[0].strip()
    return (mime.startswith("text/")
            or mime.endswith(("+xml", "+json"))
            or mime in {"application/xml", "application/json", "application/javascript",
                        "application/x-javascript", "application/ecmascript",
                        "application/x-www-form-urlencoded"})


def eligible_record(record: dict[str, Any], settings: CrawlSettings) -> bool:
    return (record.get("status") == "200" and 0 < record["length"] <= settings.max_record_bytes
            and eligible_mime(record, settings))


def eligible_mime(record: dict[str, Any], settings: CrawlSettings) -> bool:
    return (not is_text_mime(record) if settings.exclude_text else
            settings.no_mime_filter or matches_mime(record, settings.mime_patterns))


def parse_warc_record(data: bytes) -> tuple[dict[str, str], int, bytes]:
    """Return WARC headers, HTTP status and the undecoded payload of one gzip-compressed response record.

    The payload keeps any Content-Encoding, since those gzip/deflate bodies are themselves scan targets.
    """
    for record in ArchiveIterator(io.BytesIO(data)):
        if record.rec_type != "response":
            raise ValueError(f"Unexpected WARC-Type {record.rec_type!r}")
        headers = {name.lower(): value for name, value in record.rec_headers.headers}
        status = record.http_headers.get_statuscode() if record.http_headers else ""
        return headers, int(status) if status.isdigit() else 0, record.raw_stream.read()
    raise ValueError("Not a WARC record")
