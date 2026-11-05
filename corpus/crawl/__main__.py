import argparse
import json
from pathlib import Path

from .settings import OFFICE_MIME_PATTERNS, load_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Rare-compression stats and Common Crawl sampling")
    parser.add_argument("--config", default="corpus.local.toml",
                        help="Local TOML with a [crawl] table; defaults to corpus.local.toml in the working directory")
    commands = parser.add_subparsers(dest="command", required=True)
    stats = commands.add_parser("stats", help="Rarity and representative distribution within Common Crawl")
    stats.add_argument("--limit", type=int, default=25)
    stats.add_argument("--json", action="store_true")
    commands.add_parser("migrate-storage", help="Migrate saved streams to content-addressed storage; retain legacy documents")
    crawl = commands.add_parser("crawl", help="Sample random Common Crawl records; save rare streams and a random sample")
    crawl.add_argument("--batches", type=int, help="Overrides crawl.batches; 0 runs until Ctrl+C")
    crawl.add_argument("--max-download-mib", type=int, help="Overrides crawl.max_download_mib; 0 is unlimited")
    crawl.add_argument("--sample-rate", type=float, help="Overrides crawl.sample_rate (0..1)")
    crawl.add_argument("--parallelism", type=int, help="Maximum workers per download/scan stage (default 4)")
    crawl.add_argument("--min-saved-deflate-bytes", type=int,
                       help="Minimum compressed DEFLATE bytes to save (default 4097; 0 disables)")
    crawl.add_argument("--status-interval", type=int, dest="status_interval_seconds",
                       help="Overrides crawl.status_interval_seconds")
    crawl.add_argument("--seed", type=int, help="Overrides crawl.seed")
    crawl.add_argument("--index-source", choices=("cdx", "parquet"),
                       help="Index sampling source (default cdx); parquet requires uv --extra parquet")
    crawl.add_argument("--parquet-max-index-mib", type=int,
                       help="Maximum Parquet index bytes per pool refill (default 128 MiB)")
    mime = crawl.add_mutually_exclusive_group()
    mime.add_argument("--mime", action="append", dest="mime_patterns", metavar="PATTERN",
                       help="Overrides crawl.mime_patterns (repeatable), e.g. --mime image/png to focus on IDAT")
    mime.add_argument("--no-mime-filter", action="store_true",
                      help="Accept all content types, including missing MIME; retain other safety limits")
    mime.add_argument("--exclude-text", action="store_true",
                      help="Accept all types except text/*, XML, JSON and JavaScript; retain other safety limits")
    mime.add_argument("--office-only", action="store_true",
                      help="Only Office documents: Word, Excel, PowerPoint, OpenDocument and generic Office MIME")
    args = parser.parse_args()
    path = Path(args.config)
    if not path.is_file():
        parser.error(f"Config not found: {path}")
    settings = load_settings(path)
    if args.command == "migrate-storage":
        from .storage import migrate_storage

        print(json.dumps(migrate_storage(settings), indent=2))
        return
    if args.command == "stats":
        from .stats import rarity_stats, render

        if args.limit < 1:
            parser.error("--limit must be positive")
        result = rarity_stats(settings, limit=args.limit)
        print(json.dumps(result, indent=2) if args.json else render(result))
        return
    from .crawler import crawl as run_crawl

    for name in ("batches", "max_download_mib", "seed", "status_interval_seconds", "min_saved_deflate_bytes",
                 "parallelism", "parquet_max_index_mib"):
        value = getattr(args, name)
        if value is not None:
            if name in ("parallelism", "parquet_max_index_mib") and value < 1:
                parser.error(f"--{name.replace('_', '-')} must be positive")
            if value < 0:
                parser.error(f"--{name.replace('_seconds', '').replace('_', '-')} must be nonnegative")
            setattr(settings, name, value)
    if args.index_source is not None:
        settings.index_source = args.index_source
    if args.sample_rate is not None:
        if not 0 <= args.sample_rate <= 1:
            parser.error("--sample-rate must be between 0 and 1")
        settings.sample_rate = args.sample_rate
    if args.mime_patterns or args.office_only:
        settings.mime_patterns = list(OFFICE_MIME_PATTERNS) if args.office_only else args.mime_patterns
        settings.no_mime_filter = False
        settings.exclude_text = False
    elif args.no_mime_filter:
        settings.no_mime_filter = True
        settings.exclude_text = False
    elif args.exclude_text:
        settings.exclude_text = True
        settings.no_mime_filter = False
    try:
        print(json.dumps(run_crawl(settings), indent=2))
    except KeyboardInterrupt:
        print("interrupted; completed records remain in the crawl database")
        raise SystemExit(130)


if __name__ == "__main__":
    main()
