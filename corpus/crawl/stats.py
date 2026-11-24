"""Rarity and representative-distribution statistics within Common Crawl."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from typing import Any

from .rarity import TIERS, Catalog, Census, stream_signatures
from .settings import CrawlSettings


def _rows(crawl: Census, saved: dict[tuple[str, str], int], tier: str) -> list[dict[str, Any]]:
    rows = []
    for signature, tally in crawl.tallies[tier].items():
        rows.append({
            "tier": tier, "signature": signature,
            "crawl_files": tally.files, "crawl_streams": tally.streams,
            "crawl_deflate_bytes": tally.deflate_bytes,
            "saved": saved.get((tier, signature), 0),
        })
    return rows


def _distribution(db: sqlite3.Connection, settings: CrawlSettings, crawl: Census, limit: int) -> dict[str, Any]:
    """Family shares of OK streams: all scanned crawl files, and the representative sample alone."""
    sample: Counter[str] = Counter()
    sample_bytes: Counter[str] = Counter()
    rows = db.execute(
        "SELECT r.id AS record, p.settings_json, s.deflate_bytes FROM records r "
        "JOIN files f ON f.path=r.url JOIN file_versions v ON v.file_id=f.id AND v.size_bytes=r.body_bytes "
        "JOIN streams s ON s.file_version_id=v.id JOIN stream_results x ON x.stream_id=s.id "
        "LEFT JOIN profiles p ON p.id=x.profile_id "
        "WHERE r.selection IN ('sampled','both') AND x.status='ok' AND s.deflate_bytes>=?",
        (settings.min_deflate_bytes,))
    seen: set[int] = set()
    for row in rows:
        seen.add(row["record"])
        family = stream_signatures(json.loads(row["settings_json"]) if row["settings_json"] else None)["family"]
        sample[family] += 1
        sample_bytes[family] += row["deflate_bytes"]
    sample_files = db.execute("SELECT count(*) FROM records WHERE selection IN ('sampled','both')").fetchone()[0]
    total_streams = sum(t.streams for t in crawl.tallies["family"].values()) or 1
    total_bytes = sum(t.deflate_bytes for t in crawl.tallies["family"].values()) or 1
    sample_streams = sum(sample.values()) or 1
    families = sorted(crawl.tallies["family"].items(), key=lambda item: -item[1].streams)[:limit]
    return {
        "sample_files": sample_files, "sample_files_with_streams": len(seen), "sample_streams": sum(sample.values()),
        "families": [{
            "signature": signature, "files": tally.files, "streams": tally.streams,
            "stream_share": tally.streams / total_streams, "byte_share": tally.deflate_bytes / total_bytes,
            "sample_streams": sample[signature], "sample_stream_share": sample[signature] / sample_streams,
            "sample_byte_share": sample_bytes[signature] / (sum(sample_bytes.values()) or 1),
        } for signature, tally in families],
    }


def rarity_stats(settings: CrawlSettings, *, limit: int = 25) -> dict[str, Any]:
    if limit < 1:
        raise ValueError("Statistics limit must be positive")
    crawl, saved = Census(), {}
    records: dict[str, Any] = {}
    if settings.catalog_path.is_file():
        with Catalog(settings.catalog_path) as catalog:
            crawl, saved = catalog.census()
            db = catalog.connection
            records = dict(db.execute(
                "SELECT count(*) AS records, coalesce(sum(saved_path IS NOT NULL),0) AS saved,"
                "coalesce(sum(scan_status='duplicate'),0) AS duplicates,"
                "coalesce(sum(body_bytes),0) AS payload_bytes FROM records").fetchone())
            records.update(dict(db.execute(
                "SELECT count(*) AS cdx_samples, coalesce(sum(downloaded_bytes),0) AS downloaded_bytes,"
                "coalesce(sum(cdx_lines),0) AS cdx_lines FROM samples").fetchone()))
            records["by_mime"] = dict(Counter({row[0] or "?": row[1] for row in db.execute(
                "SELECT mime,count(*) FROM records GROUP BY mime")}).most_common(15))
            reasons: Counter[str] = Counter()
            for (encoded,) in db.execute("SELECT reasons_json FROM records WHERE saved_path IS NOT NULL"):
                reasons.update({item["reason"] for item in json.loads(encoded)})
            records["saved_by_reason"] = dict(reasons.most_common())
            records["selection"] = {row[0]: row[1] for row in db.execute(
                "SELECT selection,count(*) FROM records WHERE selection IS NOT NULL GROUP BY selection")}
            records["database"] = str(settings.crawl_db_path)
            kept = db.execute(
                "SELECT count(*), coalesce(sum(bytes),0), coalesce(sum(verify='match'),0),"
                "coalesce(sum(verify='mismatch'),0) FROM saved_streams").fetchone()
            records["saved_streams"] = {
                "streams": kept[0], "bytes": kept[1], "verify_match": kept[2], "verify_mismatch": kept[3],
                "by_extract": {row[0]: row[1] for row in db.execute(
                    "SELECT extract || ':' || coalesce(kind,'?'), count(*) FROM saved_streams GROUP BY 1")},
                "mismatches": [dict(row) for row in db.execute(
                    "SELECT r.url, s.stream_index, s.kind, s.verify_detail, s.path FROM saved_streams s "
                    "JOIN records r ON r.id=s.record_id WHERE s.verify='mismatch' ORDER BY s.id DESC LIMIT ?",
                    (limit,))],
            }
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='stream_results'").fetchone():
                records.update(dict(db.execute(
                    "SELECT (SELECT count(*) FROM runs WHERE state='complete') AS imported_runs,"
                    "(SELECT count(*) FROM stream_results) AS imported_streams").fetchone()))
                records["distribution"] = _distribution(db, settings, crawl, limit)
    thresholds = {"family": settings.family_max_files, "variant": settings.variant_max_files,
                  "exact": settings.exact_max_files, "failure": settings.failure_max_files}
    tiers: dict[str, Any] = {}
    rare: dict[str, list[dict[str, Any]]] = {}
    for tier in TIERS:
        rows = _rows(crawl, saved, tier)
        files = [row["crawl_files"] for row in rows]
        tiers[tier] = {
            "crawl_signatures": len(files),
            "single_file": sum(count == 1 for count in files),
            "at_most_threshold": sum(count <= max(thresholds[tier], 0) for count in files)
            if thresholds[tier] >= 0 else None,
        }
        if tier != "exact":
            ordered = sorted(rows, key=lambda row: (row["crawl_files"],
                                                    -row["crawl_deflate_bytes"], row["signature"]))
            rare[tier] = ordered[:limit]
    return {
        "scope": {"crawl_files": crawl.files,
                  "min_deflate_bytes": settings.min_deflate_bytes, "thresholds": thresholds,
                  "signature_basis": "effective estimated settings, not producer identity"},
        "tiers": tiers,
        "rarest": rare,
        "crawl": records,
    }


def render(stats: dict[str, Any]) -> str:
    lines = []
    scope = stats["scope"]
    lines.append(f"Common Crawl scope: {scope['crawl_files']} files; "
                 f"OK streams >= {scope['min_deflate_bytes']} DEFLATE bytes. Signatures are effective "
                 "settings, not proof of producer identity.")
    lines.append("")
    lines.append(f"{'tier':8} {'signatures':>10} {'1 file':>7} {'<=thr':>6}")
    for tier, row in stats["tiers"].items():
        threshold = "-" if row["at_most_threshold"] is None else row["at_most_threshold"]
        lines.append(f"{tier:8} {row['crawl_signatures']:>10} {row['single_file']:>7} {threshold:>6}")

    def table(title: str, rows: list[dict[str, Any]]) -> None:
        lines.append("")
        lines.append(title)
        if not rows:
            lines.append("  (none)")
            return
        lines.append(f"  {'files':>10} {'streams':>12} {'MiB':>9} {'saved':>5}  signature")
        for row in rows:
            lines.append(f"  {row['crawl_files']:>10} {row['crawl_streams']:>12} "
                         f"{row['crawl_deflate_bytes'] / 1048576:>9.2f} "
                         f"{row['saved']:>5}  [{row['tier']}] {row['signature']}")

    for tier, rows in stats["rarest"].items():
        table(f"Rarest {tier} signatures (fewest Common Crawl files):", rows)
    crawl = stats["crawl"]
    lines.append("")
    if crawl:
        lines.append(f"Crawl: {crawl['records']} records ({crawl['duplicates']} duplicates), {crawl['saved']} saved, "
                     f"{crawl['cdx_samples']} CDX samples, {crawl['downloaded_bytes'] / 1048576:.1f} MiB downloaded")
        lines.append(f"  saved by reason: {crawl['saved_by_reason']}")
        lines.append(f"  records by MIME: {crawl['by_mime']}")
        lines.append(f"  selection marker: {crawl.get('selection', {})}")
        kept = crawl.get("saved_streams")
        if kept:
            lines.append(f"  saved streams: {kept['streams']} ({kept['bytes'] / 1048576:.1f} MiB) {kept['by_extract']}; "
                         f"extract verify: {kept['verify_match']} match, {kept['verify_mismatch']} mismatch")
            for row in kept["mismatches"]:
                lines.append(f"    mismatch {row['kind']} #{row['stream_index']}: {row['verify_detail']}  "
                             f"{row['url']} -> {row['path']}")
        lines.append(f"  database: {crawl['database']} ({crawl.get('imported_runs', 0)} imported batch runs, "
                     f"{crawl.get('imported_streams', 0)} stream results)")
        distribution = crawl.get("distribution")
        if distribution and distribution["families"]:
            lines.append("")
            lines.append(f"Representative family distribution of OK streams >= {scope['min_deflate_bytes']} bytes "
                         f"(all scanned crawl files; sample = {distribution['sample_files']} randomly drawn files, "
                         f"{distribution['sample_streams']} streams):")
            lines.append(f"  {'files':>6} {'streams':>8} {'stream%':>7} {'bytes%':>7} {'sample%':>7} {'smp B%':>7}  family")
            for row in distribution["families"]:
                lines.append(f"  {row['files']:>6} {row['streams']:>8} {row['stream_share']:>7.1%} "
                             f"{row['byte_share']:>7.1%} {row['sample_stream_share']:>7.1%} "
                             f"{row['sample_byte_share']:>7.1%}  {row['signature']}")
    else:
        lines.append("Crawl: no catalog yet")
    return "\n".join(lines)
