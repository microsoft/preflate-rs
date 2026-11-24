"""The `[crawl]` section of the machine-local corpus TOML."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

OFFICE_MIME_PATTERNS = (
    "application/msword",
    "application/vnd.ms-word*",
    "application/vnd.ms-excel*",
    "application/vnd.ms-powerpoint*",
    "application/vnd.openxmlformats-officedocument.*",
    "application/vnd.oasis.opendocument.*",
    "application/x-tika-msoffice*",
    "application/x-tika-ooxml*",
)

DEFAULT_MIME_PATTERNS = (
    "application/pdf",
    "image/png",
    "image/apng",
    "image/tiff",
    "image/x-icon",
    "image/vnd.microsoft.icon",
    "application/zip",
    "application/gzip",
    "application/x-gzip",
    "application/epub+zip",
    "application/java-archive",
    "application/vnd.android.package-archive",
    "application/vnd.openxmlformats-officedocument.*",
    "application/vnd.oasis.opendocument.*",
    "application/vnd.ms-*",
    "application/x-shockwave-flash",
    "font/woff",
    "application/font-woff",
    "application/x-font-woff",
)


@dataclass
class CrawlSettings:
    storage: Path
    scanner: Path | None = None
    # Public crawl scans never read or write private-directory scan databases.
    crawl_db: Path | None = None
    # "latest", "random" (among recent_crawls) or explicit CC-MAIN-YYYY-WW labels.
    crawls: list[str] = field(default_factory=lambda: ["latest"])
    recent_crawls: int = 12
    mime_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_MIME_PATTERNS))
    no_mime_filter: bool = False
    exclude_text: bool = False
    data_url: str = "https://data.commoncrawl.org"
    index_url: str = "https://index.commoncrawl.org"
    user_agent: str = "preflate-rs-rare-crawl/0.1 (+https://github.com/microsoft/preflate-rs)"
    cdx_range_mib: int = 4
    index_source: str = "cdx"
    parquet_max_index_mib: int = 128
    records_per_batch: int = 64
    max_record_bytes: int = 16 * 1024 * 1024
    parallelism: int = 4
    fetch_workers: int = 4
    request_timeout_seconds: int = 120
    request_retries: int = 6
    batches: int = 10
    max_download_mib: int = 4096
    # Fraction of scanned files drawn into the representative sample (independent of rarity); 0 disables.
    sample_rate: float = 0.05
    status_interval_seconds: int = 300
    max_consecutive_failures: int = 5
    scan_max_file_mib: int = 64
    scan_timeout_seconds: int = 3600
    min_deflate_bytes: int = 1025
    min_saved_deflate_bytes: int = 4097
    family_max_files: int = 2
    variant_max_files: int = 0
    exact_max_files: int = -1
    failure_max_files: int = 2
    poor_ratio: float = 0.05
    poor_min_deflate_bytes: int = 4096
    max_saved_per_signature: int = 3
    # Streams saved from one sampled document (drawn uniformly); 0 saves every stream.
    max_sampled_streams_per_file: int = 64
    # Bytes kept after deflate_offset for a failed stream, whose reported length may be partial.
    failure_window_kib: int = 1024
    # Rescan saved extracts and record whether they reproduce the original detection.
    verify_saved: bool = True
    keep_scratch: bool = False
    seed: int | None = None

    @property
    def corpus_dir(self) -> Path:
        return self.storage / "corpus"

    @property
    def sources_dir(self) -> Path:
        return self.storage / "sources"

    @property
    def legacy_dir(self) -> Path:
        return self.storage / "legacy_documents"

    @property
    def scratch_dir(self) -> Path:
        return self.storage / "scratch"

    @property
    def cache_dir(self) -> Path:
        return self.storage / "cache"

    @property
    def crawl_db_path(self) -> Path:
        return self.crawl_db or self.storage / "commoncrawl.sqlite"

    @property
    def catalog_path(self) -> Path:
        # Sampling state and normalized scan results share the public crawl database.
        return self.crawl_db_path

_PATHS = ("storage", "scanner", "crawl_db")
_NONNEGATIVE = (
    "recent_crawls", "cdx_range_mib", "records_per_batch", "max_record_bytes", "fetch_workers",
    "request_timeout_seconds", "request_retries", "batches", "max_download_mib",
    "scan_max_file_mib", "scan_timeout_seconds", "min_deflate_bytes", "poor_min_deflate_bytes",
    "max_saved_per_signature", "status_interval_seconds", "max_consecutive_failures",
    "max_sampled_streams_per_file", "failure_window_kib", "min_saved_deflate_bytes", "parallelism",
    "parquet_max_index_mib",
)
# -1 disables a rarity tier; 0 means "never seen before".
_THRESHOLDS = ("family_max_files", "variant_max_files", "exact_max_files", "failure_max_files")


def settings_from_config(config: dict[str, Any], base: Path) -> CrawlSettings:
    """Build Common Crawl settings without consulting private scan databases."""
    crawl = config.get("crawl")
    if not isinstance(crawl, dict):
        raise ValueError("Local config requires a [crawl] table with crawl.storage")
    known = {item.name for item in fields(CrawlSettings)}
    unknown = sorted(set(crawl) - known)
    if unknown:
        raise ValueError(f"Unknown [crawl] settings: {', '.join(unknown)}")
    values = dict(crawl)
    locations = config.get("locations") or {}
    values.setdefault("scanner", locations.get("scanner"))
    if isinstance(values.get("crawls"), str):
        values["crawls"] = [values["crawls"]]
    for name in _PATHS:
        value = values.get(name)
        if value is None:
            continue
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"crawl.{name} must be a nonempty path")
        values[name] = (base / value).resolve()
    if values.get("storage") is None:
        raise ValueError("crawl.storage is required")
    for name in _NONNEGATIVE:
        if name in values and (type(values[name]) is not int or values[name] < 0):
            raise ValueError(f"crawl.{name} must be a nonnegative integer")
    for name in _THRESHOLDS:
        if name in values and (type(values[name]) is not int or values[name] < -1):
            raise ValueError(f"crawl.{name} must be an integer >= -1")
    for name in ("crawls", "mime_patterns"):
        value = values.get(name)
        if value is not None and (not isinstance(value, list) or not all(isinstance(v, str) and v for v in value)):
            raise ValueError(f"crawl.{name} must be a list of nonempty strings")
    if not values.get("crawls", ["latest"]):
        raise ValueError("crawl.crawls must not be empty")
    if "poor_ratio" in values and (type(values["poor_ratio"]) not in (int, float) or values["poor_ratio"] <= 0):
        raise ValueError("crawl.poor_ratio must be positive")
    if "sample_rate" in values and (type(values["sample_rate"]) not in (int, float)
                                    or not 0 <= values["sample_rate"] <= 1):
        raise ValueError("crawl.sample_rate must be between 0 and 1")
    if values.get("fetch_workers", 1) < 1 or values.get("cdx_range_mib", 1) < 1:
        raise ValueError("crawl.fetch_workers and crawl.cdx_range_mib must be positive")
    if values.get("parallelism", 4) < 1:
        raise ValueError("crawl.parallelism must be positive")
    if values.get("seed") is not None and type(values["seed"]) is not int:
        raise ValueError("crawl.seed must be an integer")
    for name in ("keep_scratch", "verify_saved", "no_mime_filter", "exclude_text"):
        if type(values.get(name, False)) is not bool:
            raise ValueError(f"crawl.{name} must be a boolean")
    settings = CrawlSettings(**values)
    if settings.index_source not in ("cdx", "parquet"):
        raise ValueError("crawl.index_source must be cdx or parquet")
    if settings.parquet_max_index_mib < 1:
        raise ValueError("crawl.parquet_max_index_mib must be positive")
    private = (config.get("database") or {}).get("path")
    if private is not None and (base / private).resolve() == settings.crawl_db_path.resolve():
        raise ValueError("crawl.crawl_db must differ from the private scan database")
    return settings


def load_settings(path: str | Path) -> CrawlSettings:
    source = Path(path).resolve()
    with source.open("rb") as stream:
        config = tomllib.load(stream)
    return settings_from_config(config, source.parent)
