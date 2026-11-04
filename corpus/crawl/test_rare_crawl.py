import gzip
import hashlib
import json
import random
import struct
import sys
import tempfile
import threading
import unittest
import zlib
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

from corpus.database.database import CorpusDatabase

from . import commoncrawl, crawler, extract, scanning
from .crawler import BatchPlan, DownloadedBatch, _scanned_files, evaluate, extension, process_batch, run_scanner
from .rarity import CATALOG_SCHEMA, Catalog, Census, Known, stream_signatures
from .settings import OFFICE_MIME_PATTERNS, CrawlSettings, settings_from_config
from .stats import rarity_stats
from .storage import migrate_storage, payload_path, source_path

ZLIB = dict(hash_algorithm="Zlib { hash_mask: 32767, hash_shift: 5 }", matching_type="Lazy { good_length: 8, max_lazy: 16 }",
            strategy="Default", add_policy="AddFirst(106)", block_type_strategy="Dynamic", window_bits=15,
            nice_length=128, max_chain=128, max_token_count=16383, max_dist_3_matches=4096,
            matches_to_start_detected=False, very_far_matches_detected=False)
ODD = {**ZLIB, "hash_algorithm": "MiniZFast", "matching_type": "MiniZ", "add_policy": "AddAll"}


def stream(parameters=ZLIB, *, status="ok", deflate_bytes=5000, correction=10, error_code=None, offset=0):
    return dict(offset=offset, deflate_offset=offset + 2, kind="zlib", member_name=None, status=status,
                error_code=error_code, verified=status == "ok", deflate_bytes=deflate_bytes,
                plaintext_bytes=deflate_bytes * 3, correction_bytes=correction, chunks=1, blocks=1,
                parameters=parameters if status == "ok" else None, nonzero_corrections={})


def fake_stream(kind, offset, deflate_offset, deflate, parameters):
    plaintext = len(zlib.decompressobj(-15).decompress(deflate))
    return dict(offset=offset, deflate_offset=deflate_offset, kind=kind, member_name=None, status="ok",
                error_code=None, verified=True, deflate_bytes=len(deflate), plaintext_bytes=plaintext,
                correction_bytes=10, chunks=1, blocks=1, parameters=parameters, nonzero_corrections={})


def make_png(compressed, *, split):
    """PNG with an ancillary chunk, a PLTE and the zlib data split across IDAT chunks of `split` bytes."""
    ihdr = extract.png_chunk(b"IHDR", struct.pack(">IIBBBBB", 16, 16, 8, 2, 0, 0, 0))
    chunks = [extract.png_chunk(b"IDAT", compressed[start:start + split]) for start in range(0, len(compressed), split)]
    return (extract.PNG_SIGNATURE + ihdr + extract.png_chunk(b"tEXt", b"Comment\0hello")
            + extract.png_chunk(b"PLTE", bytes(range(48))) + b"".join(chunks) + extract.IEND_CHUNK)


def write_report(path, records):
    ok = [s for record in records for s in record["streams"] if s["status"] == "ok"]
    summary = dict(entries=len(records), successful_streams=len(ok), verified_streams=len(ok),
                   successful_deflate_bytes=sum(s["deflate_bytes"] for s in ok),
                   successful_plaintext_bytes=sum(s["plaintext_bytes"] for s in ok),
                   successful_correction_bytes=sum(s["correction_bytes"] for s in ok))
    header = dict(schema_version=1, configuration={}, started_unix_seconds=1)
    with CorpusDatabase(path) as database:
        database.record_run(records, "scan", header=header, summary=summary)
    return path


class RareCrawlTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.settings = CrawlSettings(storage=self.root / "store", min_saved_deflate_bytes=0)

    def tearDown(self):
        self.temporary.cleanup()

    def test_signatures_strip_estimated_arguments_only_at_family_tier(self):
        family = stream_signatures(ZLIB)["family"]
        self.assertEqual(family, "Zlib { hash_mask: 32767, hash_shift: 5 } | Lazy | Default | AddFirst")
        other = stream_signatures({**ZLIB, "add_policy": "AddFirst(4)", "matching_type": "Lazy { good_length: 4, max_lazy: 4 }"})
        self.assertEqual(other["family"], family)
        self.assertNotEqual(other["variant"], stream_signatures(ZLIB)["variant"])

    def test_cdx_lines_resynchronize_and_drop_partial_member(self):
        def member(index):
            rows = [f"com,example)/{index}/{n} 20260101000000 " + json.dumps(dict(
                url=f"https://example.com/{n}", mime="application/pdf", status="200", digest=f"D{index}{n}",
                length="10", offset="5", filename="crawl-data/x.warc.gz")) for n in range(3)]
            return gzip.compress(("\n".join(rows) + "\n").encode())
        first, second, third = member(1), member(2), member(3)
        data = first[len(first) // 2:] + second + third[:len(third) // 2]
        lines = commoncrawl.cdx_lines(data)
        self.assertEqual(len(lines), 3)
        self.assertTrue(all("/2/" in line for line in lines))
        record = commoncrawl.parse_cdx_line(lines[0])
        self.assertEqual(record["offset"], 5)
        self.assertTrue(commoncrawl.matches_mime(record, ["application/*"]))
        self.assertFalse(commoncrawl.matches_mime(record, ["image/png"]))

    def test_parse_warc_response_record(self):
        body = b"%PDF-1.4 payload"
        http = b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n\r\n" + body
        warc = (b"WARC/1.0\r\nWARC-Type: response\r\nWARC-Target-URI: https://x/a.pdf\r\n"
                b"WARC-Truncated: length\r\nContent-Length: "
                + str(len(http)).encode() + b"\r\n\r\n" + http + b"\r\n\r\n")
        headers, status, payload = commoncrawl.parse_warc_record(gzip.compress(warc))
        self.assertEqual((status, payload, headers["warc-truncated"]), (200, body, "length"))
        self.assertEqual(extension("https://x/a/file.PDF?q=1", "application/pdf"), ".pdf")
        self.assertEqual(extension("https://x/download", "image/png"), ".png")

    def test_fetcher_retries_incomplete_bodies(self):
        fetcher = commoncrawl.Fetcher("test", retries=1)
        self.addCleanup(fetcher.close)
        broken = MagicMock(status_code=206)
        type(broken).content = PropertyMock(side_effect=commoncrawl.requests.exceptions.ChunkedEncodingError("short body"))
        complete = MagicMock(status_code=206, content=b"complete")
        for response in (broken, complete):
            response.__enter__.return_value = response
        with (patch.object(fetcher.session, "get", side_effect=[broken, complete]) as get,
              patch.object(commoncrawl.Retry, "sleep"),
              self.assertLogs(commoncrawl.__name__, level="WARNING")):
            self.assertEqual(fetcher.get("https://example.com/warc", 1, 8), b"complete")
        self.assertEqual(get.call_count, 2)
        self.assertEqual(fetcher.downloaded, 8)
        broken.__exit__.assert_called_once()
        with (patch.object(fetcher.session, "get", return_value=broken) as get,
              patch.object(commoncrawl.Retry, "sleep"),
              self.assertLogs(commoncrawl.__name__, level="WARNING")):
            with self.assertRaises(commoncrawl.requests.exceptions.ChunkedEncodingError):
                fetcher.get("https://example.com/warc", 1, 8)
        self.assertEqual(get.call_count, 2)
        self.assertEqual(fetcher.downloaded, 8)

    def test_evaluate_thresholds_caps_and_truncation(self):
        observed = Census()
        observed.add_file({("family", stream_signatures(ZLIB)["family"]): (1, 5000),
                          ("variant", stream_signatures(ZLIB)["variant"]): (1, 5000)})
        observed.add_file({("family", stream_signatures(ZLIB)["family"]): (1, 5000)})
        observed.add_file({("family", stream_signatures(ZLIB)["family"]): (1, 5000)})
        known = Known(observed, {})
        common = evaluate({"streams": [stream()]}, truncated=False, known=known, settings=self.settings)
        self.assertEqual(common.reasons, [])
        odd = evaluate({"streams": [stream(ODD), stream(ODD, deflate_bytes=100)]}, truncated=False,
                       known=known, settings=self.settings)
        self.assertEqual([r["reason"] for r in odd.reasons], ["rare_family", "rare_variant"])
        self.assertEqual(odd.observed["family", stream_signatures(ODD)["family"]], (1, 5000))
        failed = {"streams": [stream(status="error", error_code="Weird")]}
        self.assertEqual(evaluate(failed, truncated=True, known=known, settings=self.settings).reasons, [])
        self.assertEqual(evaluate(failed, truncated=False, known=known, settings=self.settings).reasons[0]["reason"],
                         "rare_failure")
        poor = evaluate({"streams": [stream(correction=1000)]}, truncated=False, known=known, settings=self.settings)
        self.assertEqual([r["reason"] for r in poor.reasons], ["poor_model"])
        for _ in range(3):
            known.observe({}, odd.save_keys)
        capped = evaluate({"streams": [stream(ODD)]}, truncated=False, known=Known(Census(), known.saved),
                          settings=self.settings)
        self.assertTrue(capped.reasons)
        self.assertEqual(capped.save_keys, [])


    def test_process_batch_saves_rare_streams_and_updates_catalog(self):
        def scan(directory, report):
            records = []
            for path in sorted(directory.iterdir()):
                data = path.read_bytes()
                if path.suffix == ".deflate":
                    streams = [fake_stream("raw", 0, 0, data, ZLIB)]
                elif data.startswith(extract.PNG_SIGNATURE):
                    offset = data.index(b"IDAT") - 4
                    joined = b"".join(data[start + 8:start + 8 + length]
                                      for start, length in [(s, e - s - 12) for s, e in extract.idat_run(data, offset)])
                    streams = [fake_stream("png_idat", offset, None, joined[2:-4], ODD)]
                else:
                    params = ODD if data.startswith(b"odd!") else ZLIB
                    streams = [fake_stream("zlib", 4, 6, data[6:-8], params)]
                records.append(dict(path=str(path), size_bytes=len(data), modified_unix_seconds=1,
                                    status="ok", elapsed_ms=1, streams=streams))
            write_report(report, records)

        def meta(n, suffix="pdf"):
            return dict(digest=f"D{n}", crawl="CC-MAIN-TEST", url=f"https://example.com/{n}.{suffix}",
                        mime="application/pdf", filename="crawl-data/x.warc.gz", offset=n, length=10,
                        timestamp="20260101000000")

        rng = random.Random(2)
        text = b"".join(b"line %d of text %x\n" % (n, rng.getrandbits(48)) for n in range(400))
        odd = b"odd!" + zlib.compress(text) + b"tail"
        common = b"comm" + zlib.compress(text[::-1]) + b"tail"
        png = make_png(zlib.compress(text, 9), split=1000)
        with Catalog(self.settings.catalog_path) as catalog:
            observed = Census()
            observed.add_file({("family", stream_signatures(ZLIB)["family"]): (1, 1),
                              ("variant", stream_signatures(ZLIB)["variant"]): (1, 1)})
            for _ in range(3):
                observed.add_file({("family", stream_signatures(ZLIB)["family"]): (1, 1)})
            known = Known(observed, {})
            entries = [(meta(1), odd), (meta(2), common), (meta(3), odd), (meta(4, "png"), png)]
            self.settings.sample_rate = 1.0
            with CorpusDatabase(self.settings.crawl_db_path) as crawl_db:
                totals = process_batch(entries, settings=self.settings, known=known, catalog=catalog, scan=scan,
                                       batch_dir=self.root / "batch", crawl_db=crawl_db, log=lambda _: None)
                paths = [row[0] for row in crawl_db.connection.execute(
                    "SELECT f.path FROM files f JOIN file_versions v ON v.file_id=f.id ORDER BY f.path")]
                self.assertEqual(paths, ["https://example.com/1.pdf", "https://example.com/2.pdf",
                                         "https://example.com/4.png"])
                self.assertEqual(crawl_db.connection.execute(
                    "SELECT DISTINCT modified_unix_seconds FROM file_versions").fetchall()[0][0], 1767225600)
                self.assertEqual(crawl_db.runs()[0]["label"], "batch")
            self.assertEqual((totals["scanned"], totals["duplicates"], totals["saved"], totals["sampled"]), (3, 1, 2, 3))
            self.assertEqual((totals["saved_streams"], totals["verify_mismatches"]), (3, 0))
            self.assertEqual(totals["saved_documents"], 3)
            # Only the streams are kept: no whole documents.
            self.assertFalse(list(self.settings.corpus_dir.rglob("*.pdf")))
            raw = sorted(self.settings.corpus_dir.rglob("*.deflate"))
            self.assertEqual(len(raw), 2)
            rare = payload_path(self.settings, hashlib.sha256(odd[6:-8]).hexdigest(), "deflate")
            self.assertEqual(rare.read_bytes(), odd[6:-8])
            self.assertEqual(len(rare.stem), 64)
            self.assertEqual(rare.parent.name, rare.stem[:2])
            metadata = source_path(self.settings, hashlib.sha256(odd).hexdigest())
            source = json.loads(metadata.read_text())
            self.assertEqual((source["source"]["url"], source["selection"]), ("https://example.com/1.pdf", "both"))
            entry = source["saved"][0]
            self.assertEqual((metadata.parent / entry["file"]).resolve(), rare.resolve())
            self.assertEqual((entry["selection"], entry["verify"], entry["location"]["range"]), ("both", "match", [6, len(odd) - 8]))
            # PNG streams are kept as minimal PNGs with the original IDAT chunks.
            (saved_png,) = self.settings.corpus_dir.rglob("*.png")
            self.assertTrue(saved_png.read_bytes().endswith(extract.IEND_CHUNK))
            self.assertIn(png[png.index(b"IDAT") - 4:png.index(b"IEND") - 4], saved_png.read_bytes())
            png_entry = json.loads(source_path(self.settings, hashlib.sha256(png).hexdigest()).read_text())["saved"][0]
            compressed_bytes = len(zlib.compress(text, 9))
            self.assertEqual([length for _, length in png_entry["location"]["idat_chunks"]],
                             [min(1000, compressed_bytes - start) for start in range(0, compressed_bytes, 1000)])
            markers = dict(catalog.connection.execute("SELECT url, selection FROM records"))
            self.assertEqual(markers, {"https://example.com/1.pdf": "both", "https://example.com/2.pdf": "sampled",
                                       "https://example.com/3.pdf": None, "https://example.com/4.png": "both"})
            rows = catalog.connection.execute("SELECT extract, selection, verify FROM saved_streams ORDER BY id").fetchall()
            self.assertEqual([tuple(row) for row in rows], [("deflate", "both", "match"), ("deflate", "sampled", "match"),
                                                            ("png", "both", "match")])
            crawl, saved_counts = catalog.census()
            self.assertEqual(crawl.files_with("family", stream_signatures(ODD)["family"]), 2)
            self.assertEqual(saved_counts["family", stream_signatures(ODD)["family"]], 2)
            self.assertEqual(catalog.seen_digests(["D1", "D2", "D9"]), {"D1", "D2"})
            self.assertFalse(list(self.settings.corpus_dir.rglob("*.json")))
        result = rarity_stats(self.settings)
        self.assertEqual(result["crawl"]["saved"], 3)
        self.assertEqual(result["crawl"]["selection"], {"both": 2, "sampled": 1})
        self.assertEqual(result["crawl"]["saved_streams"]["verify_match"], 3)
        distribution = result["crawl"]["distribution"]
        self.assertEqual((distribution["sample_files"], distribution["sample_streams"]), (3, 3))
        self.assertAlmostEqual(sum(row["sample_stream_share"] for row in distribution["families"]), 1.0)

    def test_extract_png_keeps_idat_chunks_verbatim(self):
        compressed = zlib.compress(random.Random(1).randbytes(3000))
        png = b"junk" + make_png(compressed, split=50)
        idat = png.index(b"IDAT") - 4
        piece = extract.extract_stream(png, {"kind": "png_idat", "offset": idat, "deflate_offset": None,
                                             "status": "ok", "deflate_bytes": len(compressed) - 6},
                                       failure_window=1024)
        self.assertEqual(piece.suffix, ".png")
        self.assertNotIn(b"tEXt", piece.data)
        self.assertTrue(piece.data.startswith(extract.PNG_SIGNATURE + png[png.index(b"IHDR") - 4:png.index(b"IHDR") + 21]))
        self.assertIn(b"PLTE", piece.data)
        chunks = extract.idat_run(piece.data, piece.data.index(b"IDAT") - 4)
        self.assertEqual(b"".join(piece.data[s + 8:e - 4] for s, e in chunks), compressed)
        self.assertEqual(piece.location["ihdr_offset"], png.index(b"IHDR") - 4)
        # A corrupt CRC is copied unchanged so the extract reproduces the original failure.
        broken = bytearray(png)
        broken[idat + 8 + 10] ^= 0xFF
        self.assertIn(bytes(broken[idat:idat + 62]), extract.extract_png(bytes(broken), {"offset": idat}).data)
        self.assertIsNone(extract.extract_stream(png, {"kind": "zip", "deflate_offset": None}, failure_window=1))
        failed = extract.extract_stream(b"x" * 100, {"kind": "zlib", "deflate_offset": 10, "status": "error",
                                                     "deflate_bytes": 0}, failure_window=40)
        self.assertEqual(failed.location["range"], [10, 50])
        self.assertEqual(extract.compare({"status": "ok", "deflate_bytes": 5}, [{"kind": "raw", "status": "ok",
                                                                                "deflate_bytes": 6}], "deflate")[0],
                         "mismatch")

    def test_extract_png_original_overhead_threshold(self):
        compressed = zlib.compress(random.Random(7).randbytes(3000))
        minimal = (extract.PNG_SIGNATURE
                   + extract.png_chunk(b"IHDR", struct.pack(">IIBBBBB", 16, 16, 8, 2, 0, 0, 0))
                   + extract.png_chunk(b"IDAT", compressed) + extract.IEND_CHUNK)
        allowance = len(minimal) // 10
        for extra, expected in ((allowance, "original"), (allowance + 1, "minimal")):
            ancillary = extract.png_chunk(b"tEXt", b"x" * (extra - 12))
            png = minimal[:-12] + ancillary + extract.IEND_CHUNK
            piece = extract.extract_png(png, {"offset": png.index(b"IDAT") - 4})
            self.assertEqual(piece.location["png_storage"], expected)
            self.assertEqual(piece.data, png if expected == "original" else minimal)
        embedded = b"document" + minimal
        piece = extract.extract_png(embedded, {"offset": embedded.index(b"IDAT") - 4})
        self.assertEqual(piece.location["png_storage"], "minimal")
        self.assertEqual(piece.data, minimal)

    def test_real_scanner_reproduces_extracts(self):
        scanner = Path(__file__).resolve().parents[2] / "target" / "release" / (
            "preflate_scan.exe" if sys.platform == "win32" else "preflate_scan")
        if not scanner.is_file():
            self.skipTest("release preflate_scan is not built")
        text = b"".join(b"%d: the quick brown fox %d\n" % (n, n * n) for n in range(3000))
        document = b"%PDF-ish\n" + zlib.compress(text, 6) + b"\nmore\n" + make_png(zlib.compress(text[::-1], 9), split=4096)
        source, extracts = self.root / "source", self.root / "extracts"
        source.mkdir()
        extracts.mkdir()
        (source / "doc.bin").write_bytes(document)
        png = make_png(zlib.compress(text[::-1], 9), split=4096)
        (source / "original.png").write_bytes(png)
        scan = run_scanner(scanner, self.settings)
        scan(source, self.root / "source-scan.sqlite")
        records = _scanned_files(self.root / "source-scan.sqlite")
        record = records["doc.bin"]
        kinds = sorted(stream["kind"] for stream in record["streams"] if stream["status"] == "ok")
        self.assertEqual(kinds, ["png_idat", "zlib"])
        pieces = {}
        for index, stream in enumerate(record["streams"]):
            piece = extract.extract_stream(document, stream, failure_window=1024)
            if piece is not None and stream["status"] == "ok":
                (extracts / f"{index}{piece.suffix}").write_bytes(piece.data)
                pieces[f"{index}{piece.suffix}"] = (stream, piece)
        (png_stream,) = records["original.png"]["streams"]
        piece = extract.extract_stream(png, png_stream, failure_window=1024)
        self.assertEqual(piece.location["png_storage"], "original")
        self.assertEqual(piece.data, png)
        (extracts / "original.png").write_bytes(piece.data)
        pieces["original.png"] = (png_stream, piece)
        scan(extracts, self.root / "extracts-scan.sqlite")
        rescanned = _scanned_files(self.root / "extracts-scan.sqlite")
        for name, (stream, piece) in pieces.items():
            self.assertEqual(extract.compare(stream, rescanned[name]["streams"], piece.location["extract"]),
                             ("match", ""), name)
        self.settings.parallelism = 1
        scan(source, self.root / "serial-scan.sqlite")
        serial = _scanned_files(self.root / "serial-scan.sqlite")
        for name, record in records.items():
            original = record["streams"]
            repeated = serial[name]["streams"]
            self.assertEqual(len(original), len(repeated))
            for first, second in zip(original, repeated):
                for key in ("kind", "status", "offset", "deflate_offset", "deflate_bytes", "plaintext_bytes",
                            "correction_bytes", "parameters", "verified"):
                    self.assertEqual(first.get(key), second.get(key), (name, key))

    def test_scanner_worker_limit_and_merged_totals(self):
        source = self.root / "scan-input"
        source.mkdir()
        for n in range(7):
            (source / f"{n}.deflate").write_bytes(b"synthetic")
        self.settings.parallelism = 3
        barrier = threading.Barrier(3)
        lock = threading.Lock()
        active = maximum = started = 0
        def invoke(scanner, path, report, settings, stop):
            nonlocal active, maximum, started
            with lock:
                active += 1
                maximum = max(maximum, active)
                started += 1
                wait = started <= 3
            try:
                if wait:
                    barrier.wait(timeout=5)
                write_report(report, [dict(path=str(path), size_bytes=9, modified_unix_seconds=1,
                                          status="ok", elapsed_ms=1, streams=[stream()])])
            finally:
                with lock:
                    active -= 1
        report = self.root / "parallel-scan.sqlite"
        with patch.object(scanning, "_invoke", side_effect=invoke):
            run_scanner(Path("unused"), self.settings)(source, report)
        self.assertEqual(maximum, 3)
        self.assertEqual(len(_scanned_files(report)), 7)
        with CorpusDatabase(self.root / "parallel.sqlite") as db:
            db.merge_scan(report, "parallel")
            self.assertEqual(db.connection.execute("SELECT count(*) FROM stream_results").fetchone()[0], 7)
        self.assertFalse(list(self.root.glob("scanner-*")))

    def test_scanner_failure_cancels_other_workers(self):
        source = self.root / "failed-input"
        source.mkdir()
        for n in range(6):
            (source / f"{n}.deflate").write_bytes(b"synthetic")
        self.settings.parallelism = 2
        both_started = threading.Barrier(2)
        cancelled = threading.Event()
        def invoke(scanner, path, report, settings, stop):
            if path.name not in ("0.deflate", "1.deflate"):
                return
            both_started.wait(timeout=5)
            if path.name == "0.deflate":
                raise RuntimeError("scanner failed")
            if stop.wait(timeout=5):
                cancelled.set()
        report = self.root / "failed-scan.sqlite"
        with patch.object(scanning, "_invoke", side_effect=invoke):
            with self.assertRaisesRegex(RuntimeError, "scanner failed"):
                run_scanner(Path("unused"), self.settings)(source, report)
        self.assertTrue(cancelled.is_set())
        self.assertFalse(report.exists())
        self.assertFalse(list(self.root.glob("scanner-*")))

    def test_download_worker_limit(self):
        self.settings.parallelism = 2
        self.settings.fetch_workers = 8
        barrier = threading.Barrier(2)
        active = maximum = started = 0
        lock = threading.Lock()
        records = [dict(digest=f"D{n}", filename="w", offset=n) for n in range(5)]
        plan = BatchPlan(0, "C", "shard", 0, 10, 5, 5, 5, records, 10)
        def fetch(fetcher, settings, record):
            nonlocal active, maximum, started
            with lock:
                active += 1
                maximum = max(maximum, active)
                started += 1
                wait = started <= 2
            try:
                if wait:
                    barrier.wait(timeout=5)
                return record, b"bytes"
            finally:
                with lock:
                    active -= 1
        with patch.object(crawler, "_fetch", side_effect=fetch):
            result = crawler._download_batch(plan, settings=self.settings, fetcher=MagicMock(downloaded=10),
                                              stop=threading.Event(), log=lambda _: None)
        self.assertEqual(maximum, 2)
        self.assertEqual(len(result.entries), 5)
        self.assertEqual(result.downloaded_bytes, 10)

    def test_scanner_cancellation_kills_and_reaps_process(self):
        process = MagicMock()
        process.__enter__.return_value = process
        stop = threading.Event()
        def communicate(**kwargs):
            if kwargs:
                stop.set()
                raise scanning.subprocess.TimeoutExpired("scanner", 0.2)
            return None, ""
        process.communicate.side_effect = communicate
        with patch.object(scanning.subprocess, "Popen", return_value=process):
            with self.assertRaises(scanning.concurrent.futures.CancelledError):
                scanning._invoke(Path("scanner"), self.root, self.root / "report-scan.sqlite", self.settings, stop)
        process.kill.assert_called_once()
        self.assertEqual(process.communicate.call_count, 2)

    def test_pipeline_overlaps_prefetch_with_serial_imports(self):
        self.settings.scanner = self.root / "scanner.exe"
        self.settings.scanner.touch()
        self.settings.batches = 3
        next_download = threading.Event()
        first_scan = threading.Event()
        coordinator = threading.get_ident()
        prepared = []
        imported = []
        fetcher = MagicMock(downloaded=0)
        def prepare(number, **kwargs):
            self.assertEqual(threading.get_ident(), coordinator)
            if number == 1:
                self.assertEqual(kwargs["excluded"], {"D0"})
            if number == 2:
                self.assertEqual(imported, [0])
            prepared.append(number)
            return BatchPlan(number, "C", "shard", 0, 10, 1, 1, 1, [dict(digest=f"D{number}")], 0)
        def download(plan, **kwargs):
            self.assertNotEqual(threading.get_ident(), coordinator)
            if plan.number == 1:
                next_download.set()
                self.assertTrue(first_scan.wait(timeout=5))
            return DownloadedBatch(plan, [], 0, 0)
        def finish(batch, **kwargs):
            self.assertEqual(threading.get_ident(), coordinator)
            if batch.plan.number == 0:
                self.assertTrue(next_download.wait(timeout=5))
                first_scan.set()
            imported.append(batch.plan.number)
            return dict(fetched=1, scanned=1, downloaded_bytes=0)
        with (patch.object(commoncrawl, "Fetcher", return_value=fetcher),
              patch.object(commoncrawl, "list_collections", return_value=["C"]),
              patch.object(crawler, "load_known", return_value=Known(Census(), {})),
              patch.object(crawler, "_prepare_batch", side_effect=prepare),
              patch.object(crawler, "_download_batch", side_effect=download),
              patch.object(crawler, "_finish_batch", side_effect=finish)):
            result = crawler.crawl(self.settings, log=lambda _: None)
        self.assertEqual(prepared, [0, 1, 2])
        self.assertEqual(imported, [0, 1, 2])
        self.assertEqual(result["batches"], 3)
        self.assertFalse(result["interrupted"])

    def test_prefetch_preparation_failure_does_not_discard_current_batch(self):
        self.settings.scanner = self.root / "scanner.exe"
        self.settings.scanner.touch()
        self.settings.batches = 2
        fetcher = MagicMock(downloaded=0)
        imported = []
        def prepare(number, **kwargs):
            if number == 1:
                raise RuntimeError("index request failed")
            return BatchPlan(number, "C", "shard", 0, 10, 0, 0, 0, [], 0)
        def finish(batch, **kwargs):
            imported.append(batch.plan.number)
            return {}
        with (patch.object(commoncrawl, "Fetcher", return_value=fetcher),
              patch.object(commoncrawl, "list_collections", return_value=["C"]),
              patch.object(crawler, "load_known", return_value=Known(Census(), {})),
              patch.object(crawler, "_prepare_batch", side_effect=prepare),
              patch.object(crawler, "_download_batch", side_effect=lambda plan, **kw: DownloadedBatch(plan, [], 0, 0)),
              patch.object(crawler, "_finish_batch", side_effect=finish),
              patch.object(crawler.time, "sleep")):
            result = crawler.crawl(self.settings, log=lambda _: None)
        self.assertEqual(imported, [0])
        self.assertEqual((result["batches"], result["failed_batches"]), (1, 1))

    def test_pipeline_interrupt_stops_prefetch(self):
        self.settings.scanner = self.root / "scanner.exe"
        self.settings.scanner.touch()
        self.settings.batches = 0
        started = threading.Event()
        stopped = threading.Event()
        fetcher = MagicMock(downloaded=0)
        def prepare(number, **kwargs):
            return BatchPlan(number, "C", "shard", 0, 10, 0, 0, 0, [], 0)
        def download(plan, **kwargs):
            if plan.number == 1:
                started.set()
                if kwargs["stop"].wait(timeout=5):
                    stopped.set()
            return DownloadedBatch(plan, [], 0, 0)
        def finish(batch, **kwargs):
            self.assertTrue(started.wait(timeout=5))
            raise KeyboardInterrupt
        with (patch.object(commoncrawl, "Fetcher", return_value=fetcher),
              patch.object(commoncrawl, "list_collections", return_value=["C"]),
              patch.object(crawler, "load_known", return_value=Known(Census(), {})),
              patch.object(crawler, "_prepare_batch", side_effect=prepare),
              patch.object(crawler, "_download_batch", side_effect=download),
              patch.object(crawler, "_finish_batch", side_effect=finish)):
            result = crawler.crawl(self.settings, log=lambda _: None)
        self.assertTrue(stopped.is_set())
        self.assertTrue(result["interrupted"])

    def test_pipeline_budget_finishes_current_without_prefetch(self):
        self.settings.scanner = self.root / "scanner.exe"
        self.settings.scanner.touch()
        self.settings.batches = 10
        self.settings.max_download_mib = 1
        fetcher = MagicMock(downloaded=0)
        def prepare(number, **kwargs):
            return BatchPlan(number, "C", "shard", 0, 10, 0, 0, 0, [], 0)
        def download(plan, **kwargs):
            fetcher.downloaded = 2 * 1048576
            return DownloadedBatch(plan, [], 0, fetcher.downloaded)
        with (patch.object(commoncrawl, "Fetcher", return_value=fetcher),
              patch.object(commoncrawl, "list_collections", return_value=["C"]),
              patch.object(crawler, "load_known", return_value=Known(Census(), {})),
              patch.object(crawler, "_prepare_batch", side_effect=prepare) as prepare_mock,
              patch.object(crawler, "_download_batch", side_effect=download),
              patch.object(crawler, "_finish_batch", return_value={}) as finish):
            result = crawler.crawl(self.settings, log=lambda _: None)
        prepare_mock.assert_called_once()
        finish.assert_called_once()
        self.assertEqual(result["batches"], 1)
        self.assertEqual(result["downloaded_mib"], 2)

    def test_parallelism_settings_validation(self):
        for invalid in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                settings_from_config({"crawl": {"storage": "store", "parallelism": invalid}}, self.root)
        configured = settings_from_config({"crawl": {"storage": "store", "parallelism": 6}}, self.root)
        self.assertEqual(configured.parallelism, 6)

    def test_unfiltered_preparation_keeps_non_mime_safety_filters(self):
        records = [
            dict(digest="pdf", mime="application/pdf", status="200", length=10),
            dict(digest="html", mime="text/html", status="200", length=10),
            dict(digest="unknown", status="200", length=10),
            dict(digest="error", mime="text/html", status="404", length=10),
            dict(digest="large", mime="text/html", status="200", length=self.settings.max_record_bytes + 1),
            dict(digest="seen", mime="text/html", status="200", length=10),
            dict(digest="reserved", mime="text/html", status="200", length=10),
        ]
        catalog = MagicMock()
        catalog.shard_size.return_value = 100
        catalog.seen_digests.return_value = {"seen"}
        with (patch.object(commoncrawl, "cdx_shards", return_value=["index/cdx-000.gz"]),
              patch.object(commoncrawl, "cdx_lines", return_value=records),
              patch.object(commoncrawl, "parse_cdx_line", side_effect=lambda record: record)):
            for enabled, expected in ((False, {"pdf"}), (True, {"pdf", "html", "unknown"})):
                self.settings.no_mime_filter = enabled
                plan = crawler._prepare_batch(
                    0, settings=self.settings, rng=random.Random(1), fetcher=MagicMock(downloaded=0),
                    catalog=catalog, collections=["C"], excluded={"reserved"})
                self.assertEqual({record["digest"] for record in plan.chosen}, expected)

    def test_unfiltered_cli_and_explicit_mime_override(self):
        from .__main__ import main
        config = self.root / "local.toml"
        config.touch()
        cases = [
            (["--no-mime-filter"], False, True),
            ([], False, False),
            (["--mime", "image/png"], True, False),
        ]
        for arguments, configured, expected in cases:
            self.settings.no_mime_filter = configured
            with (patch.object(sys, "argv", ["rare-crawl", "--config", str(config), "crawl", *arguments]),
                  patch("corpus.crawl.__main__.load_settings", return_value=self.settings),
                  patch.object(crawler, "crawl", return_value={}) as run,
                  patch("builtins.print")):
                main()
                self.assertEqual(run.call_args.args[0].no_mime_filter, expected)
        with (patch.object(sys, "argv", ["rare-crawl", "--config", str(config), "crawl",
                                        "--mime", "image/png", "--no-mime-filter"]),
              patch("sys.stderr")):
            with self.assertRaises(SystemExit) as error:
                main()
            self.assertEqual(error.exception.code, 2)
        with self.assertRaises(ValueError):
            settings_from_config({"crawl": {"storage": "store", "no_mime_filter": "true"}}, self.root)

    def test_exclude_text_mime_types(self):
        for mime in ("text/html", "TEXT/PLAIN; charset=UTF-8", "text/x-robots", "application/xhtml+xml",
                     "application/atom+xml", "image/svg+xml", "application/json", "application/ld+json",
                     "application/xml", "application/javascript", "application/x-javascript",
                     "application/ecmascript", "application/x-www-form-urlencoded"):
            self.assertTrue(commoncrawl.is_text_mime({"mime": mime}), mime)
        for mime in ("application/pdf", "application/octet-stream", "application/zip", "image/png",
                     "application/gzip", "font/woff", "application/msword", ""):
            self.assertFalse(commoncrawl.is_text_mime({"mime": mime}), mime)
        self.assertFalse(commoncrawl.is_text_mime({}))
        self.assertFalse(commoncrawl.is_text_mime({"mime": "text/html", "mime-detected": "application/pdf"}))

    def test_office_only_preset_and_cli(self):
        for mime in ("application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
                     "application/vnd.ms-word.document.macroEnabled.12",
                     "application/vnd.ms-excel.sheet.macroenabled.12",
                     "application/vnd.ms-powerpoint.presentation.macroenabled.12",
                     "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                     "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
                     "application/vnd.oasis.opendocument.spreadsheet", "application/x-tika-msoffice",
                     "application/x-tika-msoffice-embedded", "application/x-tika-ooxml"):
            self.assertTrue(commoncrawl.matches_mime({"mime": mime}, OFFICE_MIME_PATTERNS), mime)
        for mime in ("application/pdf", "text/html", "application/zip", "application/octet-stream", "image/png", ""):
            self.assertFalse(commoncrawl.matches_mime({"mime": mime}, OFFICE_MIME_PATTERNS), mime)
        self.assertTrue(commoncrawl.matches_mime(
            {"mime": "application/msword", "mime-detected": "application/octet-stream"}, OFFICE_MIME_PATTERNS))
        from .__main__ import main
        config = self.root / "office.toml"
        config.touch()
        self.settings.exclude_text = self.settings.no_mime_filter = True
        with (patch.object(sys, "argv", ["rare-crawl", "--config", str(config), "crawl", "--office-only"]),
              patch("corpus.crawl.__main__.load_settings", return_value=self.settings),
              patch.object(crawler, "crawl", return_value={}) as run, patch("builtins.print")):
            main()
            settings = run.call_args.args[0]
            self.assertEqual(settings.mime_patterns, list(OFFICE_MIME_PATTERNS))
            self.assertFalse(settings.exclude_text)
            self.assertFalse(settings.no_mime_filter)
        for other in (["--exclude-text"], ["--no-mime-filter"], ["--mime", "image/png"]):
            with (patch.object(sys, "argv", ["rare-crawl", "crawl", "--office-only", *other]),
                  patch("sys.stderr")):
                with self.assertRaises(SystemExit) as error:
                    main()
                self.assertEqual(error.exception.code, 2)

    def test_exclude_text_preparation_and_cli(self):
        records = [dict(digest=mime, mime=mime, status="200", length=10)
                   for mime in ("text/html", "application/xhtml+xml", "application/pdf",
                                "image/png", "application/octet-stream", "")]
        catalog = MagicMock()
        catalog.shard_size.return_value = 100
        catalog.seen_digests.return_value = set()
        self.settings.exclude_text = True
        with (patch.object(commoncrawl, "cdx_shards", return_value=["index/cdx-000.gz"]),
              patch.object(commoncrawl, "cdx_lines", return_value=records),
              patch.object(commoncrawl, "parse_cdx_line", side_effect=lambda record: record)):
            plan = crawler._prepare_batch(
                0, settings=self.settings, rng=random.Random(1), fetcher=MagicMock(downloaded=0),
                catalog=catalog, collections=["C"], excluded=set())
            self.assertEqual({r["mime"] for r in plan.chosen},
                             {"application/pdf", "image/png", "application/octet-stream", ""})
        from .__main__ import main
        config = self.root / "local.toml"
        config.touch()
        for args, expected in ((["--exclude-text"], True), (["--no-mime-filter"], False),
                               (["--mime", "image/png"], False)):
            self.settings.exclude_text = True
            with (patch.object(sys, "argv", ["rare-crawl", "--config", str(config), "crawl", *args]),
                  patch("corpus.crawl.__main__.load_settings", return_value=self.settings),
                  patch.object(crawler, "crawl", return_value={}) as run, patch("builtins.print")):
                main()
                self.assertEqual(run.call_args.args[0].exclude_text, expected)
        with self.assertRaises(ValueError):
            settings_from_config({"crawl": {"storage": "store", "exclude_text": "true"}}, self.root)

    def test_catalog_migration_marks_previous_saves_rare(self):
        import sqlite3

        path = self.root / "old.sqlite"
        with sqlite3.connect(path) as old:
            old.executescript(CATALOG_SCHEMA.replace(
                "    selection TEXT CHECK (selection IN ('rare','sampled','both')),\n", ""))
            for n, saved in ((1, "x.pdf"), (2, None)):
                old.execute("INSERT INTO records(digest,crawl,url,warc_filename,warc_offset,warc_length,body_bytes,"
                            "sha256,scan_status,streams,saved_path,reasons_json) VALUES (?,?,?,?,0,1,1,?,?,0,?,?)",
                            (f"D{n}", "C", f"u{n}", "w", f"s{n}", "ok", saved, "[]"))
        old.close()
        with Catalog(path) as catalog:
            self.assertEqual(dict(catalog.connection.execute("SELECT url, selection FROM records")),
                             {"u1": "rare", "u2": None})

    def test_batch_respects_signature_caps_and_accumulates_evidence(self):
        def scan(directory, report):
            write_report(report, [
                dict(path=str(path), size_bytes=path.stat().st_size, modified_unix_seconds=1,
                     status="ok", elapsed_ms=1, streams=[stream(deflate_bytes=1025, offset=0)])
                for path in sorted(directory.iterdir())
            ])

        entries = [(dict(digest=f"D{n}", crawl="C", url=f"https://example.com/{n}.pdf",
                         filename="w", offset=n, length=1100), bytes([n]) * 1100)
                   for n in range(8)]
        self.settings.verify_saved = False
        self.settings.sample_rate = 0
        self.settings.variant_max_files = 100
        with (Catalog(self.settings.catalog_path) as catalog,
              CorpusDatabase(self.settings.crawl_db_path) as crawl_db):
            known = Known(*catalog.census())
            outcome = process_batch(entries, settings=self.settings, known=known, catalog=catalog, scan=scan,
                                    batch_dir=self.root / "capped-batch", crawl_db=crawl_db)
            self.assertEqual(outcome["saved"], 3)
            self.assertEqual(outcome["saved_documents"], 3)
            self.assertEqual(known.files("family", stream_signatures(ZLIB)["family"]), 8)
            self.assertEqual(known.saved["family", stream_signatures(ZLIB)["family"]], 3)
            self.assertEqual(known.saved["variant", stream_signatures(ZLIB)["variant"]], 3)
            self.assertEqual(catalog.census()[1], known.saved)
            reasons = json.loads(catalog.connection.execute(
                "SELECT reasons_json FROM records ORDER BY id DESC LIMIT 1").fetchone()[0])
            self.assertNotIn("rare_family", [reason["reason"] for reason in reasons])

    def test_saved_size_threshold_filters_before_sampling_and_rare_caps(self):
        self.assertEqual(CrawlSettings(storage=self.root).min_saved_deflate_bytes, 4097)
        self.settings.min_saved_deflate_bytes = 4097
        self.settings.sample_rate = 1
        self.settings.max_sampled_streams_per_file = 1
        self.settings.verify_saved = False
        reports = [
            stream(deflate_bytes=4095),
            stream(deflate_bytes=4096, offset=5000),
            stream(deflate_bytes=4097, offset=10000),
        ]
        def scan(directory, report):
            write_report(report, [dict(path=str(path), size_bytes=path.stat().st_size,
                                      modified_unix_seconds=1, status="ok", elapsed_ms=1, streams=reports)
                                  for path in directory.iterdir()])
        known = Known(Census(), {})
        small = evaluate({"streams": reports[:2]}, truncated=False, known=known, settings=self.settings)
        self.assertTrue(small.observed)
        self.assertFalse(small.save_keys)
        eligible = evaluate({"streams": reports}, truncated=False, known=known, settings=self.settings)
        self.assertEqual(set(eligible.rare_streams(3)), {2})
        meta = dict(digest="threshold", crawl="C", url="https://example.com/threshold",
                    filename="w", offset=0, length=15000)
        with (Catalog(self.settings.catalog_path) as catalog,
              CorpusDatabase(self.settings.crawl_db_path) as crawl_db):
            outcome = process_batch([(meta, b"x" * 15000)], settings=self.settings, known=known, catalog=catalog,
                                    scan=scan, batch_dir=self.root / "threshold", crawl_db=crawl_db)
            self.assertEqual(outcome["streams"], 3)
            self.assertEqual(outcome["saved_streams"], 1)
            row = catalog.connection.execute("SELECT stream_index,deflate_bytes,selection FROM saved_streams").fetchone()
            self.assertEqual(tuple(row), (2, 4097, "both"))
        for invalid in (-1, 1.5, True):
            with self.assertRaises(ValueError):
                settings_from_config({"crawl": {"storage": "store", "min_saved_deflate_bytes": invalid}}, self.root)

    def test_storage_migration_preserves_payloads_metadata_and_legacy_documents(self):
        payload = b"synthetic stream bytes"
        sha = hashlib.sha256(payload).hexdigest()
        old_paths = []
        with Catalog(self.settings.catalog_path) as catalog:
            for n in range(2):
                document_sha = hashlib.sha256(f"document-{n}".encode()).hexdigest()
                folder = self.settings.corpus_dir / "rare_family" / "signature" / document_sha[:20]
                folder.mkdir(parents=True)
                path = folder / "s0000-zlib.deflate"
                path.write_bytes(payload)
                old_paths.append(path)
                row = dict(index=0, selection="both", reasons=["rare_family"], kind="zlib", offset=10,
                           deflate_offset=12, member_name=None, location={"range": [12, 33]},
                           extract="deflate", path=str(path), sha256=sha, bytes=len(payload),
                           status="ok", deflate_bytes=len(payload), verify="match")
                metadata = {"source": {"sha256": document_sha, "url": f"https://example.com/{n}"},
                            "saved": [{"index": 0, "file": path.name, "sha256": sha}]}
                (folder / "source.json").write_text(json.dumps(metadata), encoding="utf-8")
                record_id = catalog.record(
                    dict(digest=f"D{n}", crawl="C", url=f"https://example.com/{n}", filename="w", offset=n, length=1),
                    sha256=document_sha, body_bytes=100, scan_status="ok", streams=1, observed={},
                    saved_path=str(folder), reasons=[], saved_keys=[], selection="both")
                catalog.save_streams(record_id, [row])
            legacy = self.settings.corpus_dir / "sampled" / "pdf" / "old.pdf"
            legacy.parent.mkdir(parents=True)
            legacy.write_bytes(b"original legacy document")
            legacy_sha = hashlib.sha256(legacy.read_bytes()).hexdigest()
            sidecar = legacy.with_name(legacy.name + ".json")
            sidecar.write_text('{"url":"https://example.com/legacy"}', encoding="utf-8")
            catalog.record(dict(digest="legacy", crawl="C", url="https://example.com/legacy",
                                filename="w", offset=0, length=1),
                           sha256=legacy_sha, body_bytes=24, scan_status="ok", streams=0, observed={},
                           saved_path=str(legacy), reasons=[], saved_keys=[], selection="sampled")
        result = migrate_storage(self.settings)
        self.assertEqual((result["payloads"], result["sources"], result["legacy_documents"]), (1, 2, 1))
        target = payload_path(self.settings, sha, "deflate")
        self.assertEqual(target.read_bytes(), payload)
        self.assertTrue(all(not p.exists() for p in old_paths))
        self.assertFalse(legacy.exists())
        self.assertEqual((self.settings.legacy_dir / f"{legacy_sha}.pdf").read_bytes(), b"original legacy document")
        self.assertTrue((self.settings.legacy_dir / f"{legacy_sha}.pdf.json").exists())
        self.assertEqual([p for p in self.settings.corpus_dir.rglob("*") if p.is_file()], [target])
        with Catalog(self.settings.catalog_path) as catalog:
            self.assertEqual({r[0] for r in catalog.connection.execute("SELECT path FROM saved_streams")}, {str(target)})
            for (path,) in catalog.connection.execute("SELECT saved_path FROM records WHERE selection='both'"):
                metadata = Path(path)
                saved = json.loads(metadata.read_text())["saved"][0]
                self.assertEqual((metadata.parent / saved["file"]).resolve(), target.resolve())
        self.assertEqual(migrate_storage(self.settings), dict(payloads=0, sources=0, legacy_documents=0, removed_files=0,
                                                           retained_empty_directories=0))

    def test_storage_migration_aborts_on_corrupt_payload(self):
        old = self.settings.corpus_dir / "old" / "stream.deflate"
        old.parent.mkdir(parents=True)
        old.write_bytes(b"corrupt")
        sha = hashlib.sha256(b"expected").hexdigest()
        document_sha = hashlib.sha256(b"document").hexdigest()
        with Catalog(self.settings.catalog_path) as catalog:
            record_id = catalog.record(
                dict(digest="D", crawl="C", url="https://example.com", filename="w", offset=0, length=1),
                sha256=document_sha, body_bytes=1, scan_status="ok", streams=1, observed={},
                saved_path=str(old.parent), reasons=[], saved_keys=[], selection="rare")
            catalog.save_streams(record_id, [dict(index=0, selection="rare", reasons=[], location={}, extract="deflate",
                                                path=str(old), sha256=sha, bytes=8)])
        with self.assertRaisesRegex(ValueError, "Source checksum mismatch"):
            migrate_storage(self.settings)
        self.assertEqual(old.read_bytes(), b"corrupt")
        with Catalog(self.settings.catalog_path) as catalog:
            self.assertEqual(catalog.connection.execute("SELECT path FROM saved_streams").fetchone()[0], str(old))

    def test_settings_defaults_from_shared_local_config(self):
        settings = settings_from_config({
            "database": {"path": str(self.root / "h.sqlite")}, "scope": {"runs": ["a", "b"]},
            "locations": {"scanner": "scan.exe"}, "crawl": {"storage": "store", "crawls": "latest"},
        }, self.root)
        self.assertFalse(hasattr(settings, "history_db"))
        self.assertEqual(settings.scanner, (self.root / "scan.exe").resolve())
        self.assertEqual(settings.crawls, ["latest"])
        self.assertEqual(settings.catalog_path, (self.root / "store" / "commoncrawl.sqlite").resolve())
        self.assertEqual(settings.crawl_db_path, settings.catalog_path)
        with self.assertRaises(ValueError):
            settings_from_config({"database": {"path": "h.sqlite"},
                                  "crawl": {"storage": "s", "crawl_db": "h.sqlite"}}, self.root)
        with self.assertRaises(ValueError):
            settings_from_config({"crawl": {"storage": "s", "typo": 1}}, self.root)
        with self.assertRaises(ValueError):
            settings_from_config({"crawl": {}}, self.root)

    def test_crawl_never_reads_private_scan_database_or_scope_report(self):
        private = self.root / "private.sqlite"
        private.write_bytes(b"private database must not be opened")
        settings = settings_from_config({
            "database": {"path": str(private)},
            "scope": {"report": "nonexistent-private-report.json"},
            "crawl": {"storage": "public"},
        }, self.root)
        with Catalog(settings.catalog_path) as catalog:
            known = crawler.load_known(catalog, log=lambda _: None)
            self.assertEqual(known.crawl.files, 0)
        self.assertEqual(private.read_bytes(), b"private database must not be opened")
        for key in ("history_db", "history_runs"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "Unknown"):
                settings_from_config({"crawl": {"storage": "public", key: "removed"}}, self.root)


if __name__ == "__main__":
    unittest.main()
