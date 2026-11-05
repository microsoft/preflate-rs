"""Scan local/private files and analyze SQLite corpus runs."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

from .config import load_local_config
from .database import CorpusDatabase


def main() -> None:
    parser = argparse.ArgumentParser(description="Directory scanning and SQLite corpus analysis")
    parser.add_argument("--db", help="SQLite database; overrides database.path in the local config")
    parser.add_argument("--config", help="Local TOML; defaults to corpus.local.toml")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Scan local files or SQLite-selected inputs into a new SQLite run")
    scan.add_argument("input")
    scan.add_argument("--label", required=True)
    scan.add_argument("--scanner", help="Release preflate_scan executable")
    scan.add_argument("--hydrate", action="store_true", help="Explicitly allow downloading cloud-only files")
    scan.add_argument("--no-verify", action="store_true", help="Encode-only timing; disables reconstruction verification")
    scan.add_argument("--max-file-mib", type=int, default=256)
    scan.add_argument("--build-identity")
    scan.add_argument("--jobs", type=int, help="Native file workers (default: 4)")
    source = scan.add_mutually_exclusive_group()
    source.add_argument("--from-run", help="Select local files from this completed run in the input database")
    source.add_argument("--from-crawl", action="store_true", help="Select saved payloads from the input crawl catalog")
    scan.add_argument("--source-root", help="Storage root for --from-crawl")
    merge = commands.add_parser("merge", help="Copy a completed SQLite scan, not a legacy JSON report")
    merge.add_argument("source")
    merge.add_argument("--source-label")
    merge.add_argument("--label", required=True)
    commands.add_parser("runs")
    comparison = commands.add_parser("compare")
    comparison.add_argument("before")
    comparison.add_argument("after")
    comparison.add_argument("--limit", type=int)
    sets = commands.add_parser("compare-set", help="Compare ordered run sets; last run wins per file")
    sets.add_argument("--before", action="append", required=True)
    sets.add_argument("--after", action="append", required=True)
    sets.add_argument("--limit", type=int)
    for name in ("families", "oracle-opportunities", "oracle-cohorts"):
        command = commands.add_parser(name)
        command.add_argument("runs", nargs="*")
        if name == "oracle-opportunities":
            command.add_argument("--limit", type=int)
    outliers = commands.add_parser("outliers")
    outliers.add_argument("runs", nargs="*")
    outliers.add_argument("--setting", action="append", default=[], metavar="NAME=VALUE")
    outliers.add_argument("--limit", type=int)
    outliers.add_argument("--min-deflate-bytes", type=int)
    outliers.add_argument("--max-plaintext-bytes", type=int)
    outliers.add_argument("--max-file-bytes", type=int)
    outliers.add_argument("--one-per-file", action="store_true")
    outliers.add_argument("--without-oracle", action="store_true")
    for name in ("priorities", "timings", "stream"):
        command = commands.add_parser(name)
        command.add_argument("run")
        if name == "priorities":
            command.add_argument("--limit", type=int)
        elif name == "stream":
            command.add_argument("stream_id", type=int)
    commands.add_parser("check")
    commands.add_parser("vacuum")
    delete = commands.add_parser("delete-run")
    delete.add_argument("label")
    delete.add_argument("--confirm", action="store_true", required=True)
    backup = commands.add_parser("backup")
    backup.add_argument("destination")
    args = parser.parse_args()
    path = Path(args.config or "corpus.local.toml")
    config = load_local_config(path) if args.config is not None or (not args.db and path.is_file()) else {}
    connection = config.get("database", {})
    args.db = args.db or connection.get("path")
    if not args.db:
        parser.error("Pass --db or configure database.path in corpus.local.toml")
    if hasattr(args, "runs"):
        args.runs = args.runs or config.get("scope", {}).get("runs", [])
        if not args.runs:
            parser.error("Provide run labels or configure scope.runs")
    if hasattr(args, "limit") and args.limit is None:
        args.limit = config.get("queries", {}).get("limit", 30)
    if args.command == "outliers" and args.min_deflate_bytes is None:
        args.min_deflate_bytes = config.get("queries", {}).get("min_deflate_bytes", 1025)
    if args.command == "scan":
        if args.source_root is not None and not args.from_crawl:
            parser.error("--source-root requires --from-crawl")
        default = Path(__file__).resolve().parents[2] / "target" / "release" / (
            "preflate_scan.exe" if sys.platform == "win32" else "preflate_scan")
        scanner = args.scanner or config.get("locations", {}).get("scanner") or str(default)
        command = [scanner, args.input, "--database", args.db, "--label", args.label,
                   "--max-file-mib", str(args.max_file_mib)]
        for flag in ("hydrate", "no_verify"):
            if getattr(args, flag):
                command.append("--" + flag.replace("_", "-"))
        if args.build_identity is not None:
            command.extend(("--build-identity", args.build_identity))
        if args.jobs is not None:
            command.extend(("--jobs", str(args.jobs)))
        if args.from_run is not None:
            command.extend(("--from-run", args.from_run))
        if args.from_crawl:
            command.append("--from-crawl")
        if args.source_root is not None:
            command.extend(("--source-root", args.source_root))
        subprocess.run(command, check=True)
        return
    options = {field: connection[field] for field in
               ("timeout_seconds", "journal_mode", "synchronous", "profile_cache_entries") if field in connection}
    with CorpusDatabase(args.db, **options) as database:
        if args.command == "merge":
            result = {"run_id": database.merge_scan(args.source, args.label, source_label=args.source_label)}
        elif args.command == "runs":
            result = database.runs()
        elif args.command == "compare":
            result = database.compare_runs(args.before, args.after, args.limit)
        elif args.command == "compare-set":
            result = database.compare_run_sets(args.before, args.after, args.limit)
        elif args.command == "families":
            result = database.family_overhead(args.runs)
        elif args.command == "oracle-opportunities":
            result = database.oracle_opportunities(args.runs, args.limit)
        elif args.command == "oracle-cohorts":
            result = database.oracle_cohorts(args.runs)
        elif args.command == "outliers":
            settings = {}
            for item in args.setting:
                field, separator, value = item.partition("=")
                if not separator or not field or field in settings:
                    parser.error("--setting requires distinct NAME=VALUE filters")
                try:
                    settings[field] = json.loads(value)
                except json.JSONDecodeError:
                    settings[field] = value
            result = database.outliers(
                args.runs, settings=settings, limit=args.limit,
                min_deflate_bytes=args.min_deflate_bytes, max_plaintext_bytes=args.max_plaintext_bytes,
                max_file_bytes=args.max_file_bytes, one_per_file=args.one_per_file,
                without_oracle=args.without_oracle,
            )
        elif args.command == "priorities":
            result = database.priorities(args.run, args.limit)
        elif args.command == "timings":
            result = database.timings(args.run)
        elif args.command == "stream":
            result = database.stream(args.run, args.stream_id)
        elif args.command == "check":
            result = database.check()
            print(json.dumps(result, indent=2))
            if result["integrity"] != ["ok"] or result["foreign_key_errors"]:
                raise SystemExit(1)
            return
        elif args.command == "delete-run":
            database.delete_run(args.label)
            result = {"deleted": args.label}
        elif args.command == "backup":
            database.backup(args.destination)
            result = {"backup": args.destination}
        else:
            database.vacuum()
            result = {"vacuum": "complete"}
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
