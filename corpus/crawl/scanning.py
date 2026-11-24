"""Bounded release-scanner processes with a streaming JSON batch result."""

from __future__ import annotations

import concurrent.futures
import contextlib
import json
import subprocess
import tempfile
import threading
import time
from collections import Counter
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from corpus.database.json_scan import json_scan_records

from .settings import CrawlSettings


def _invoke(scanner: Path, source: Path, report: Path, settings: CrawlSettings, stop: threading.Event) -> None:
    if stop.is_set():
        raise concurrent.futures.CancelledError()
    command = [str(scanner), str(source), "--output", str(report), "--jobs", "1",
               "--max-file-mib", str(max(1, settings.scan_max_file_mib))]
    with subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True) as process:
        deadline = time.monotonic() + settings.scan_timeout_seconds
        try:
            while True:
                if stop.is_set():
                    raise concurrent.futures.CancelledError()
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(command, settings.scan_timeout_seconds)
                try:
                    _, stderr = process.communicate(timeout=0.2)
                    break
                except subprocess.TimeoutExpired:
                    continue
            if process.returncode != 0:
                raise RuntimeError(f"preflate_scan failed ({process.returncode}): {stderr[-2000:]}")
        except BaseException:
            process.kill()
            process.communicate()
            raise


def _merge(reports: Sequence[Path], directory: Path, report: Path, elapsed_ms: float) -> None:
    summary: dict[str, Any] = {}
    errors: Counter[str] = Counter()
    worst: list[dict[str, Any]] = []
    header: dict[str, Any] = {}

    def files():
        for part in reports:
            with contextlib.closing(json_scan_records(part)) as records:
                next(records)
                for kind, record in records:
                    if kind == "file":
                        yield record
                    elif kind == "summary":
                        for key, value in record.items():
                            if key == "candidate_error_counts":
                                errors.update(value)
                            elif key == "worst_streams":
                                worst.extend(value)
                                worst.sort(key=lambda item: item["correction_ratio"], reverse=True)
                                del worst[20:]
                            elif key not in ("weighted_correction_ratio", "elapsed_ms"):
                                if type(value) not in (int, float):
                                    raise ValueError(f"Cannot merge scanner summary field {key}: {value!r}")
                                summary[key] = summary.get(key, 0) + value
        size = summary.get("successful_deflate_bytes", 0)
        summary.update(candidate_error_counts=dict(errors), worst_streams=worst, elapsed_ms=elapsed_ms,
                       weighted_correction_ratio=summary.get("successful_correction_bytes", 0) / size if size else None)

    if report.exists():
        raise FileExistsError(report)
    if reports:
        with contextlib.closing(json_scan_records(reports[0])) as records:
            _, metadata = next(records)
            header.update(metadata)
            header["configuration"].update(input=str(directory.resolve()), output=str(report))
            header["root"] = str(directory.resolve())
    with report.open("x", encoding="utf-8") as output:
        output.write(json.dumps(header)[:-1] + ',"files":[')
        first = True
        for record in files():
            if not first:
                output.write(",")
            json.dump(record, output)
            first = False
        output.write('],"summary":')
        json.dump(summary, output)
        output.write("}\n")


def run_scanner(scanner: Path, settings: CrawlSettings) -> Callable[[Path, Path], None]:
    def scan(directory: Path, report: Path) -> None:
        files = sorted(path for path in directory.iterdir() if path.is_file())
        stop = threading.Event()
        if settings.parallelism == 1 or len(files) <= 1:
            _invoke(scanner, directory, report, settings, stop)
            return
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="scanner-", dir=report.parent) as scratch:
            parts = [Path(scratch) / f"{index:05d}.json" for index in range(len(files))]
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=settings.parallelism)
            try:
                futures = [pool.submit(_invoke, scanner, source, part, settings, stop)
                           for source, part in zip(files, parts)]
                for future in concurrent.futures.as_completed(futures, timeout=settings.scan_timeout_seconds):
                    future.result()
            except TimeoutError as error:
                stop.set()
                raise TimeoutError(f"Scanner stage exceeded {settings.scan_timeout_seconds}s") from error
            except BaseException:
                stop.set()
                raise
            finally:
                pool.shutdown(wait=True, cancel_futures=True)
            _merge(parts, directory, report, (time.monotonic() - started) * 1000)
    return scan
