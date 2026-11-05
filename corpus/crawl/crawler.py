"""Sample Common Crawl, scan payloads with release preflate_scan and keep rare streams."""

from __future__ import annotations

import calendar
import concurrent.futures
import contextlib
import copy
import hashlib
import json
import os
import random
import shutil
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from corpus.database.database import CorpusDatabase

from . import commoncrawl, extract
from .rarity import Catalog, Known, failure_signature, stream_signatures
from .settings import CrawlSettings
from .scanning import run_scanner
from .storage import file_hash, payload_path, source_path

if TYPE_CHECKING:
    from .parquet_index import ParquetIndex

MIME_EXTENSIONS = {
    "application/pdf": ".pdf", "image/png": ".png", "image/apng": ".png", "image/tiff": ".tif",
    "image/x-icon": ".ico", "image/vnd.microsoft.icon": ".ico", "application/zip": ".zip",
    "application/gzip": ".gz", "application/x-gzip": ".gz", "application/epub+zip": ".epub",
    "application/java-archive": ".jar", "application/vnd.android.package-archive": ".apk",
    "application/x-shockwave-flash": ".swf", "font/woff": ".woff", "application/font-woff": ".woff",
    "application/x-font-woff": ".woff",
}
# Highest-priority evidence first in source metadata.
REASON_ORDER = ("rare_family", "rare_variant", "rare_exact", "rare_failure", "poor_model")

Observed = dict[tuple[str, str], tuple[int, int]]
Scanner = Callable[[Path, Path], None]


def extension(url: str, mime: str) -> str:
    suffix = PurePosixPath(urlparse(url).path).suffix.lower()
    if 1 < len(suffix) <= 6 and suffix[1:].isalnum():
        return suffix
    return MIME_EXTENSIONS.get(mime, ".bin")


@dataclass
class Evaluation:
    observed: Observed = field(default_factory=dict)
    reasons: list[dict[str, Any]] = field(default_factory=list)
    save_keys: list[tuple[str, str]] = field(default_factory=list)
    # Stream indices (into the file's report) carrying each observed or poor-model signature.
    triggers: dict[tuple[str, str], list[int]] = field(default_factory=dict)

    def rare_streams(self, per_key: int) -> dict[int, list[str]]:
        """Stream index -> reasons, for up to `per_key` triggering streams of each saved signature."""
        reasons = {(item["tier"], item["signature"]): item["reason"] for item in self.reasons}
        chosen: dict[int, list[str]] = {}
        for key in self.save_keys:
            for index in self.triggers.get(key, [])[:max(per_key, 1)]:
                chosen.setdefault(index, []).append(reasons[key])
        return chosen


def evaluate(file_report: Mapping[str, Any], *, truncated: bool, known: Known, settings: CrawlSettings) -> Evaluation:
    """Judge one scanned file against earlier Common Crawl records."""
    result = Evaluation()
    thresholds = {
        "family": settings.family_max_files, "variant": settings.variant_max_files,
        "exact": settings.exact_max_files, "failure": settings.failure_max_files,
    }
    candidates: list[tuple[str, tuple[str, str], dict[str, Any]]] = []
    for index, stream in enumerate(file_report.get("streams", [])):
        location = {"offset": stream.get("offset"), "kind": stream.get("kind"),
                    "deflate_bytes": stream.get("deflate_bytes")}
        if stream.get("status") == "ok":
            if stream.get("deflate_bytes", 0) < settings.min_deflate_bytes:
                continue
            signatures = stream_signatures(stream.get("parameters")).items()
            deflate_bytes = stream["deflate_bytes"]
            ratio = stream.get("correction_bytes", 0) / max(deflate_bytes, 1)
            if deflate_bytes >= max(settings.poor_min_deflate_bytes, settings.min_saved_deflate_bytes) and ratio >= settings.poor_ratio:
                family = dict(signatures)["family"]
                result.triggers.setdefault(("poor_model", family), []).append(index)
                candidates.append(("poor_model", ("poor_model", family),
                                   {**location, "signature": family, "correction_ratio": round(ratio, 4)}))
        elif truncated:
            # Truncated payloads produce artificial failures; they are not new compressor behaviour.
            continue
        else:
            signatures = (("failure", failure_signature(stream.get("kind", "?"), stream["status"],
                                                        stream.get("error_code"))),)
            deflate_bytes = stream.get("deflate_bytes", 0)
        for tier, signature in signatures:
            count, total = result.observed.get((tier, signature), (0, 0))
            result.observed[tier, signature] = (count + 1, total + deflate_bytes)
            if deflate_bytes >= settings.min_saved_deflate_bytes:
                result.triggers.setdefault((tier, signature), []).append(index)
    for (tier, signature) in result.observed:
        limit = thresholds[tier]
        if limit < 0:
            continue
        seen = known.files(tier, signature)
        if seen <= limit:
            reason = "rare_failure" if tier == "failure" else f"rare_{tier}"
            candidates.append((reason, (tier, signature), {"signature": signature, "known_files": seen}))
    cap = settings.max_saved_per_signature
    for reason, key, detail in sorted(candidates, key=lambda item: REASON_ORDER.index(item[0])):
        result.reasons.append({"reason": reason, "tier": key[0], **detail})
        if result.triggers.get(key) and known.saved.get(key, 0) < cap and key not in result.save_keys:
            result.save_keys.append(key)
    return result


def _scanned_files(report: Path) -> dict[str, dict[str, Any]]:
    from corpus.database.json_scan import json_scan_records

    return {Path(record["path"]).name: record for kind, record in json_scan_records(report) if kind == "file"}


def _capture_seconds(meta: Mapping[str, Any]) -> int | None:
    try:
        stamp = time.strptime(str(meta.get("timestamp")), "%Y%m%d%H%M%S")
    except ValueError:
        return None
    return calendar.timegm(stamp)


def merge_crawl_scan(
    report: Path, names: Mapping[str, Mapping[str, Any]], *, label: str,
    crawl_db: CorpusDatabase,
) -> None:
    """Persist a completed JSON batch, replacing temporary paths with captured URLs."""
    from corpus.database.json_scan import json_scan_records

    with contextlib.closing(json_scan_records(report)) as records:
        _, header = next(records)
        summary: dict[str, Any] = {}

        def files():
            seen: set[str] = set()
            for kind, record in records:
                if kind == "file":
                    name = Path(record["path"]).name
                    if name not in names or name in seen:
                        raise ValueError("Scanner JSON batch contains an unknown or duplicate payload")
                    seen.add(name)
                    meta = names[name]
                    record.update(path=meta["url"], modified_unix_seconds=_capture_seconds(meta))
                    yield record
                elif kind == "summary":
                    summary.update(record)
            if seen != set(names):
                raise ValueError("Scanner JSON batch is missing expected downloaded payloads")

        crawl_db.record_run(files(), label, header=header, summary=summary)


def selection_marker(rare: bool, sampled: bool) -> str | None:
    return "both" if rare and sampled else "rare" if rare else "sampled" if sampled else None


def process_batch(
    entries: Sequence[tuple[dict[str, Any], bytes]], *, settings: CrawlSettings, known: Known,
    catalog: Catalog, scan: Scanner, batch_dir: Path, crawl_db: CorpusDatabase,
    sample_rng: random.Random | None = None, log: Callable[[str], None] = print,
) -> dict[str, int]:
    """Scan fetched payloads together, import the scan, then save streams from rare and sampled files.

    Only the selected DEFLATE streams are kept (PNG IDAT runs retain PNG framing), with source metadata
    recording where each came from. The representative sample is a Bernoulli draw per scanned file,
    independent of rarity, so it stays unbiased; rare files that are also drawn are marked `both`.
    """
    draw = (sample_rng or random.Random()).random
    payload_dir = batch_dir / "payloads"
    payload_dir.mkdir(parents=True)
    staged: list[tuple[dict[str, Any], str, str, int]] = []
    hashes: set[str] = set()
    duplicates = 0
    for index, (meta, body) in enumerate(entries):
        digest = hashlib.sha256(body).hexdigest()
        if digest in hashes or catalog.seen_sha256(digest):
            catalog.record(meta, sha256=digest, body_bytes=len(body), scan_status="duplicate", streams=0,
                           observed={}, saved_path=None, reasons=(), saved_keys=(), selection=None)
            duplicates += 1
            continue
        hashes.add(digest)
        name = f"{index:05d}{extension(meta['url'], meta.get('mime', ''))}"
        (payload_dir / name).write_bytes(body)
        staged.append((meta, name, digest, len(body)))
    totals = {"scanned": len(staged), "duplicates": duplicates, "saved": 0, "sampled": 0, "streams": 0, "rare": 0,
              "saved_documents": 0, "saved_streams": 0, "saved_bytes": 0, "verify_mismatches": 0}
    if not staged:
        return totals
    report = batch_dir / "scan.json"
    scan(payload_dir, report)
    merge_crawl_scan(report, {name: meta for meta, name, _, _ in staged}, label=batch_dir.name,
                     crawl_db=crawl_db)
    scanned = _scanned_files(report)
    extract_dir = batch_dir / "extracts"
    extract_dir.mkdir()
    pending: list[_Pending] = []
    batch_known = Known(copy.deepcopy(known.crawl), known.saved.copy())
    for meta, name, digest, size in staged:
        record = scanned.get(name, {"status": "missing", "streams": []})
        streams = record.get("streams", [])
        evaluation = evaluate(record, truncated=bool(meta.get("truncated")), known=batch_known, settings=settings)
        batch_known.observe(evaluation.observed, evaluation.save_keys)
        rare = bool(evaluation.save_keys)
        sampled = settings.sample_rate > 0 and draw() < settings.sample_rate
        item = _Pending(meta, name, digest, size, record, evaluation, selection_marker(rare, sampled))
        pending.append(item)
        if not (rare or sampled) or not streams:
            # Sampled files without streams count toward the distribution but need nothing saved.
            continue
        chosen = evaluation.rare_streams(settings.max_saved_per_signature) if rare else {}
        if sampled:
            indices = [index for index, stream in enumerate(streams)
                       if stream.get("deflate_bytes", 0) >= settings.min_saved_deflate_bytes]
            limit = settings.max_sampled_streams_per_file
            if limit and len(indices) > limit:
                indices = sorted(random.Random(digest).sample(indices, limit))
            for index in indices:
                chosen.setdefault(index, [])
        if not chosen:
            continue
        item.metadata = source_path(settings, digest)
        body = (payload_dir / name).read_bytes()
        for index in sorted(chosen):
            stream = streams[index]
            piece = extract.extract_stream(body, stream, failure_window=settings.failure_window_kib * 1024)
            if piece is None:
                item.unlocated.append(index)
                continue
            scratch = extract_dir / f"{len(item.saves):04d}-{digest[:20]}{piece.suffix}"
            scratch.write_bytes(piece.data)
            item.saves.append({
                "index": index, "scratch": scratch, "piece": piece, "stream": stream,
                "selection": selection_marker(bool(chosen[index]), sampled), "reasons": chosen[index],
            })
    if settings.verify_saved and any(item.saves for item in pending):
        verify_report = batch_dir / "verify.json"
        scan(extract_dir, verify_report)
        rescanned = _scanned_files(verify_report)
        for item in pending:
            for save in item.saves:
                streams = rescanned.get(save["scratch"].name, {}).get("streams", [])
                save["verify"], save["verify_detail"] = extract.compare(
                    save["stream"], streams, save["piece"].location["extract"])
    for item in pending:
        saved_path = _save(item, settings, totals, log=log) if item.metadata is not None else None
        totals["saved_documents"] += saved_path is not None
        streams = item.record.get("streams", [])
        totals["saved"] += item.selection in ("rare", "both")
        totals["sampled"] += item.selection in ("sampled", "both")
        totals["streams"] += len(streams)
        totals["rare"] += bool(item.evaluation.reasons)
        record_id = catalog.record(
            item.meta, sha256=item.digest, body_bytes=item.size, scan_status=item.record["status"],
            streams=len(streams), observed=item.evaluation.observed, saved_path=saved_path,
            reasons=item.evaluation.reasons, saved_keys=item.evaluation.save_keys, selection=item.selection)
        catalog.save_streams(record_id, item.rows)
        known.observe(item.evaluation.observed, item.evaluation.save_keys)
    return totals


@dataclass
class _Pending:
    meta: dict[str, Any]
    name: str
    digest: str
    size: int
    record: dict[str, Any]
    evaluation: Evaluation
    selection: str | None
    metadata: Path | None = None
    saves: list[dict[str, Any]] = field(default_factory=list)
    unlocated: list[int] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)


STREAM_FIELDS = ("status", "error_code", "deflate_bytes", "plaintext_bytes", "correction_bytes", "verified",
                 "parameters")


def _save(item: _Pending, settings: CrawlSettings, totals: dict[str, int], *, log: Callable[[str], None]) -> str:
    """Store payloads by content hash and write source metadata outside the scanned corpus."""
    assert item.metadata is not None
    item.metadata.parent.mkdir(parents=True, exist_ok=True)
    streams = item.record.get("streams", [])
    saved = []
    for save in item.saves:
        piece: extract.Extract = save["piece"]
        stream = save["stream"]
        sha = hashlib.sha256(piece.data).hexdigest()
        target = payload_path(settings, sha, piece.location["extract"])
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.move(save["scratch"], target)
            totals["saved_streams"] += 1
            totals["saved_bytes"] += len(piece.data)
        elif file_hash(target) != sha:
            raise ValueError(f"Stored payload checksum mismatch: {target}")
        path = str(target)
        verify = save.get("verify")
        if verify == "mismatch":
            totals["verify_mismatches"] += 1
            log(f"  verify mismatch: {item.meta['url']} stream {save['index']} ({stream.get('kind')}): "
                f"{save['verify_detail']}")
        location = {key: stream.get(key) for key in ("kind", "offset", "deflate_offset", "member_name")}
        location.update(piece.location)
        entry = {"index": save["index"], "file": os.path.relpath(target, item.metadata.parent), "sha256": sha,
                 "bytes": len(piece.data), "selection": save["selection"], "reasons": save["reasons"],
                 "verify": verify, "verify_detail": save.get("verify_detail"), "location": location,
                 "stream": {key: stream.get(key) for key in STREAM_FIELDS}}
        saved.append(entry)
        item.rows.append({**entry, "path": path, "extract": piece.location["extract"], **location,
                          "status": stream.get("status"), "deflate_bytes": stream.get("deflate_bytes")})
    source = {key: item.meta.get(key) for key in ("crawl", "url", "mime", "timestamp", "filename", "offset",
                                                    "length", "digest", "truncated")}
    source.update(sha256=item.digest, body_bytes=item.size)
    document = {
        "source": source, "selection": item.selection, "reasons": item.evaluation.reasons,
        "scan_status": item.record.get("status"), "streams_total": len(streams), "saved": saved,
        "unlocated": [{"index": index, **{key: streams[index].get(key) for key in (
            "kind", "offset", "deflate_offset", "member_name", "status", "error_code", "deflate_bytes")}}
            for index in item.unlocated],
    }
    item.metadata.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return str(item.metadata)


def _fetch(fetcher: commoncrawl.Fetcher, settings: CrawlSettings, meta: dict[str, Any]) -> tuple[dict[str, Any], bytes] | None:
    url = f"{settings.data_url.rstrip('/')}/{meta['filename']}"
    data = fetcher.get(url, meta["offset"], meta["offset"] + meta["length"] - 1)
    headers, status, body = commoncrawl.parse_warc_record(data)
    if status != 200 or not body:
        return None
    if headers.get("warc-truncated"):
        meta["truncated"] = meta.get("truncated") or headers["warc-truncated"]
    return meta, body


def load_known(catalog: Catalog, *, log: Callable[[str], None] = print) -> Known:
    crawl, saved = catalog.census()
    log(f"crawl evidence: {crawl.files} files")
    return Known(crawl, saved)


def novel_signatures(known: Known) -> set[tuple[str, str]]:
    """Non-exact signatures observed by Common Crawl."""
    return {(tier, signature) for tier, tallies in known.crawl.tallies.items() if tier != "exact"
            for signature, tally in tallies.items() if tally.files}


class Progress:
    """Cumulative crawl counters with a periodic, human-readable status block."""

    def __init__(self, known: Known, interval_seconds: int, log: Callable[[str], None]):
        self.known = known
        self.interval = interval_seconds
        self.log = log
        self.started = self.last = time.monotonic()
        self.totals = {"batches": 0, "failed_batches": 0, "fetched": 0, "scanned": 0, "streams": 0,
                       "saved": 0, "sampled": 0, "rare": 0, "errors": 0, "downloaded_bytes": 0,
                       "saved_documents": 0, "saved_streams": 0, "saved_bytes": 0, "verify_mismatches": 0}
        self.novel_at_start = self.novel_seen = novel_signatures(known)

    def add(self, outcome: Mapping[str, int]) -> None:
        for key, value in outcome.items():
            if key in self.totals:
                self.totals[key] += value

    def maybe_report(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and (self.interval == 0 or now - self.last < self.interval):
            return
        self.last = now
        hours = max(now - self.started, 1e-9) / 3600
        t = self.totals
        novel = novel_signatures(self.known)
        fresh = sorted(novel - self.novel_seen)
        self.novel_seen = novel
        by_tier = {tier: sum(key[0] == tier for key in novel) for tier in ("family", "variant", "failure")}
        lines = [
            f"== status {time.strftime('%H:%M:%S')} after {(now - self.started) / 60:.1f} min: "
            f"{t['batches']} batches ({t['failed_batches']} failed), {t['scanned']} files scanned "
            f"({t['scanned'] / hours:.0f}/h), {t['streams']} streams, {t['downloaded_bytes'] / 1048576:.0f} MiB",
            f"   saved: {t['saved']} rare, {t['sampled']} sampled documents -> {t['saved_streams']} streams "
            f"({t['saved_bytes'] / 1048576:.1f} MiB), extract verify mismatches: {t['verify_mismatches']}; "
            f"files with rare evidence: {t['rare']}; fetch errors: {t['errors']}",
            "   observed crawl signatures: " + ", ".join(f"{k} {v}" for k, v in by_tier.items())
            + f" (+{len(novel - self.novel_at_start)} this run)",
        ]
        lines += [f"   new: [{tier}] {signature}" for tier, signature in fresh[:10]]
        if len(fresh) > 10:
            lines.append(f"   ... and {len(fresh) - 10} more")
        self.log("\n".join(lines))
        sys.stdout.flush()


@dataclass
class BatchPlan:
    number: int
    crawl: str
    shard: str
    start: int
    span: int
    lines: int
    matched: int
    fresh: int
    chosen: list[dict[str, Any]]
    index_bytes: int


@dataclass
class DownloadedBatch:
    plan: BatchPlan
    entries: list[tuple[dict[str, Any], bytes]]
    errors: int
    downloaded_bytes: int


def _prepare_batch(
    number: int, *, settings: CrawlSettings, rng: random.Random, fetcher: commoncrawl.Fetcher,
    catalog: Catalog, collections: Sequence[str], excluded: set[str],
    parquet_index: ParquetIndex | None = None,
) -> BatchPlan:
    """Choose records on the coordinator thread; never share a SQLite connection with workers."""
    before = fetcher.downloaded
    crawl_id = (parquet_index.active_crawl if parquet_index is not None else None)
    if crawl_id is None:
        crawl_id = commoncrawl.resolve_crawl(rng.choice(settings.crawls), collections, settings.recent_crawls, rng)
    if parquet_index is not None:
        pool = parquet_index.candidates(crawl_id, settings, fetcher, catalog, rng)
        unique = {record["digest"]: record for record in pool.records}
        fresh = [unique[digest] for digest in sorted(set(unique) - catalog.seen_digests(unique) - excluded)]
        chosen = rng.sample(fresh, min(len(fresh), settings.records_per_batch))
        reserved = {record["digest"] for record in chosen} | excluded
        pool.records = [record for record in fresh if record["digest"] not in reserved]
        for record in chosen:
            record.update(crawl=crawl_id, mime=commoncrawl.mime_of(record))
        return BatchPlan(number, crawl_id, pool.url, pool.group, 0, pool.rows, pool.matched, len(fresh),
                         chosen, fetcher.downloaded - before)
    shards = commoncrawl.cdx_shards(fetcher, settings.data_url, crawl_id, settings.cache_dir)
    shard = f"{settings.data_url.rstrip('/')}/{rng.choice(shards)}"
    size = catalog.shard_size(shard)
    if size is None:
        size = fetcher.size(shard)
        catalog.remember_shard(shard, size)
    span = min(settings.cdx_range_mib * 1024 * 1024, size)
    start = rng.randrange(0, max(size - span, 0) + 1)
    lines = commoncrawl.cdx_lines(fetcher.get(shard, start, start + span - 1))
    records = [record for record in map(commoncrawl.parse_cdx_line, lines) if record
               and commoncrawl.eligible_record(record, settings)]
    unique = {record["digest"]: record for record in records}
    fresh = [unique[digest] for digest in sorted(set(unique) - catalog.seen_digests(unique) - excluded)]
    chosen = rng.sample(fresh, min(len(fresh), settings.records_per_batch))
    for record in chosen:
        record.update(crawl=crawl_id, mime=commoncrawl.mime_of(record))
    return BatchPlan(number, crawl_id, shard, start, span, len(lines), len(records), len(fresh),
                     chosen, fetcher.downloaded - before)


def _download_batch(
    plan: BatchPlan, *, settings: CrawlSettings, fetcher: commoncrawl.Fetcher,
    stop: threading.Event, log: Callable[[str], None],
) -> DownloadedBatch:
    """One bounded batch of downloads, overlapped with the preceding batch's scan/import."""
    before = fetcher.downloaded
    entries: list[tuple[dict[str, Any], bytes]] = []
    errors = 0
    def fetch(record: dict[str, Any]) -> tuple[dict[str, Any], bytes] | None:
        if stop.is_set():
            raise concurrent.futures.CancelledError()
        return _fetch(fetcher, settings, record)

    pool = concurrent.futures.ThreadPoolExecutor(min(settings.fetch_workers, settings.parallelism))
    try:
        futures = [pool.submit(fetch, record) for record in plan.chosen]
        for future in concurrent.futures.as_completed(futures):
            if stop.is_set():
                raise concurrent.futures.CancelledError()
            try:
                result = future.result()
            except Exception as error:  # one bad record must not stop the batch
                errors += 1
                log(f"  fetch failed: {error}")
                continue
            if result is not None:
                entries.append(result)
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    entries.sort(key=lambda entry: (entry[0]["filename"], entry[0]["offset"]))
    return DownloadedBatch(plan, entries, errors, plan.index_bytes + fetcher.downloaded - before)


def _finish_batch(
    batch: DownloadedBatch, *, settings: CrawlSettings, sample_rng: random.Random, catalog: Catalog,
    crawl_db: CorpusDatabase, known: Known, scan: Scanner, log: Callable[[str], None],
) -> dict[str, int]:
    plan = batch.plan
    entries = batch.entries
    batch_dir = settings.scratch_dir / f"batch-{time.strftime('%Y%m%d-%H%M%S')}-{plan.number:04d}"
    try:
        outcome = process_batch(entries, settings=settings, known=known, catalog=catalog, scan=scan,
                                batch_dir=batch_dir, crawl_db=crawl_db, sample_rng=sample_rng, log=log)
    finally:
        if not settings.keep_scratch:
            shutil.rmtree(batch_dir, ignore_errors=True)
    downloaded = batch.downloaded_bytes
    catalog.sample(crawl=plan.crawl, shard=plan.shard, range_start=plan.start, range_bytes=plan.span, cdx_lines=plan.lines,
                   matched=plan.matched, fetched=len(entries),
                   saved=outcome["saved_documents"],
                   downloaded_bytes=downloaded)
    log(f"batch {plan.number + 1}: {plan.crawl} {Path(plan.shard).name}@{plan.start} lines={plan.lines} "
        f"matched={plan.matched} new={plan.fresh} fetched={len(entries)} scanned={outcome['scanned']} "
        f"streams={outcome['streams']} rare={outcome['rare']} saved={outcome['saved']} "
        f"sampled={outcome['sampled']} kept_streams={outcome['saved_streams']} "
        f"({outcome['saved_bytes'] / 1024:.0f}KiB) mismatches={outcome['verify_mismatches']} "
        f"errors={batch.errors} downloaded={downloaded / 1048576:.1f}MiB")
    sys.stdout.flush()
    return {**outcome, "fetched": len(entries), "errors": batch.errors, "downloaded_bytes": downloaded}


def crawl(settings: CrawlSettings, *, batches: int | None = None, log: Callable[[str], None] = print) -> dict[str, Any]:
    """Run batches until the count or download budget is reached (0 means unlimited) or Ctrl+C."""
    if settings.scanner is None or not settings.scanner.is_file():
        raise FileNotFoundError("Release preflate_scan not found; build it with "
                                "`cargo build --release -p preflate_util --bin preflate_scan` and set locations.scanner")
    if settings.parallelism < 1:
        raise ValueError("crawl.parallelism must be positive")
    if settings.index_source not in ("cdx", "parquet"):
        raise ValueError("crawl.index_source must be cdx or parquet")
    parquet_index: ParquetIndex | None = None
    if settings.index_source == "parquet":
        from .parquet_index import ParquetIndex
        parquet_index = ParquetIndex()
    rng = random.Random(settings.seed)
    sample_rng = random.Random(None if settings.seed is None else settings.seed + 1)
    fetcher = commoncrawl.Fetcher(settings.user_agent, timeout=settings.request_timeout_seconds,
                                  retries=settings.request_retries, pool=min(settings.fetch_workers, settings.parallelism))
    scan = run_scanner(settings.scanner, settings)
    limit = settings.batches if batches is None else batches
    budget = settings.max_download_mib * 1024 * 1024
    settings.scratch_dir.mkdir(parents=True, exist_ok=True)
    interrupted = False
    with (Catalog(settings.catalog_path) as catalog, CorpusDatabase(settings.crawl_db_path) as crawl_db,
          contextlib.closing(fetcher)):
        known = load_known(catalog, log=log)
        progress = Progress(known, settings.status_interval_seconds, log)
        log(f"crawling {'until stopped (Ctrl+C)' if limit == 0 else f'{limit} batches'}; "
            f"budget {'unlimited' if budget == 0 else f'{settings.max_download_mib} MiB'}; "
            f"sample rate {settings.sample_rate:g}; minimum saved DEFLATE {settings.min_saved_deflate_bytes} bytes; "
            f"parallelism {settings.parallelism} (downloads {min(settings.fetch_workers, settings.parallelism)}); "
            f"index {settings.index_source}; "
            f"MIME filter {'exclude text' if settings.exclude_text else 'disabled' if settings.no_mime_filter else ','.join(settings.mime_patterns)}; "
            f"status every {settings.status_interval_seconds}s")
        collections = commoncrawl.list_collections(fetcher, settings.index_url, settings.cache_dir)
        number = 0
        consecutive = 0
        stop = threading.Event()
        downloader = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        pending: concurrent.futures.Future[DownloadedBatch] | None = None

        def prefetch(number: int, excluded: set[str]) -> concurrent.futures.Future[DownloadedBatch]:
            try:
                plan = _prepare_batch(number, settings=settings, rng=rng, fetcher=fetcher, catalog=catalog,
                                      collections=collections, excluded=excluded, parquet_index=parquet_index)
            except Exception as error:
                failed: concurrent.futures.Future[DownloadedBatch] = concurrent.futures.Future()
                failed.set_exception(error)
                return failed
            return downloader.submit(_download_batch, plan, settings=settings, fetcher=fetcher, stop=stop, log=log)

        try:
            while limit == 0 or number < limit:
                if pending is None and budget and fetcher.downloaded >= budget:
                    log(f"download budget of {settings.max_download_mib} MiB reached")
                    break
                try:
                    if pending is None:
                        pending = prefetch(number, set())
                    current, pending = pending, None
                    batch = current.result()
                    if (limit == 0 or number + 1 < limit) and (budget == 0 or fetcher.downloaded < budget):
                        pending = prefetch(number + 1, {record["digest"] for record in batch.plan.chosen})
                    outcome = _finish_batch(batch, settings=settings, sample_rng=sample_rng, catalog=catalog,
                                            crawl_db=crawl_db, known=known, scan=scan, log=log)
                except Exception as error:  # keep long runs alive across transient network/scan failures
                    consecutive += 1
                    progress.totals["failed_batches"] += 1
                    log(f"batch {number + 1} failed ({consecutive}/{settings.max_consecutive_failures}): {error!r}")
                    if consecutive >= settings.max_consecutive_failures:
                        raise
                    time.sleep(min(300, 15 * 2 ** (consecutive - 1)))
                else:
                    consecutive = 0
                    progress.totals["batches"] += 1
                    progress.add(outcome)
                number += 1
                progress.totals["downloaded_bytes"] = fetcher.downloaded
                progress.maybe_report()
        except KeyboardInterrupt:
            interrupted = True
            log("interrupted; every completed record is kept")
        finally:
            stop.set()
            if pending is not None:
                pending.cancel()
                log("stopping download prefetch; uncommitted prefetched records remain eligible on restart")
            downloader.shutdown(wait=True, cancel_futures=True)
            progress.totals["downloaded_bytes"] = fetcher.downloaded
        progress.maybe_report(force=True)
    totals: dict[str, Any] = dict(progress.totals)
    totals["downloaded_mib"] = round(totals.pop("downloaded_bytes") / 1048576, 1)
    totals["interrupted"] = interrupted
    return totals
