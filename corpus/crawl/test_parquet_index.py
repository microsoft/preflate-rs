import datetime
import gzip
import io
import random
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from . import crawler
from .parquet_index import ParquetIndex, RangeFile
from .settings import CrawlSettings, settings_from_config

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except ModuleNotFoundError:
    pa = pq = None


class RangeTests(unittest.TestCase):
    def test_ranges_seeks_and_limit(self):
        fetcher = MagicMock()
        fetcher.get.side_effect = lambda url, start, end: b"0123456789"[start:end + 1]
        with RangeFile(fetcher, "url", 10, 5) as remote:
            self.assertTrue(remote.readable() and remote.seekable())
            remote.seek(-3, io.SEEK_END)
            self.assertEqual(remote.read(), b"789")
            self.assertEqual(remote.read(), b"")
            remote.seek(-2, io.SEEK_CUR)
            self.assertEqual(remote.read(1), b"8")
            self.assertEqual(remote.tell(), 9)
            remote.seek(0)
            with self.assertRaisesRegex(ValueError, "exceeded"):
                remote.read(2)
            with self.assertRaises(ValueError):
                remote.seek(-1)
            with self.assertRaises(ValueError):
                remote.seek(0, 10)
        self.assertEqual(fetcher.get.call_count, 2)

    def test_short_range_rejected(self):
        with RangeFile(MagicMock(get=MagicMock(return_value=b"x")), "url", 10, 10) as remote:
            with self.assertRaisesRegex(ValueError, "range length"):
                remote.read(2)

    def test_settings_and_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for values in ({"index_source": "bad"}, {"parquet_max_index_mib": 0},
                           {"parquet_max_index_mib": True}):
                with self.assertRaises(ValueError):
                    settings_from_config({"crawl": {"storage": "store", **values}}, root)
            settings = settings_from_config({"crawl": {"storage": "store", "index_source": "parquet"}}, root)
            config = root / "config.toml"
            config.touch()
            from .__main__ import main
            with (patch.object(sys, "argv", ["crawl", "--config", str(config), "crawl",
                                            "--index-source", "parquet", "--parquet-max-index-mib", "32"]),
                  patch("corpus.crawl.__main__.load_settings", return_value=settings),
                  patch.object(crawler, "crawl", return_value={}) as run, patch("builtins.print")):
                main()
                self.assertEqual(run.call_args.args[0].index_source, "parquet")
                self.assertEqual(run.call_args.args[0].parquet_max_index_mib, 32)


@unittest.skipIf(pa is None, "requires uv --extra parquet")
class ParquetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.settings = CrawlSettings(storage=Path(self.temporary.name), mime_patterns=["image/png"],
                                      records_per_batch=1)
        rows = []
        for i in range(12):
            rows.append(dict(url=f"https://example.test/{i}",
                             fetch_time=datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc),
                             fetch_status=404 if i == 2 else 200, content_digest=f"sha1:D{i}",
                             warc_filename="crawl-data/test.warc.gz", warc_record_offset=i * 100,
                             warc_record_length=self.settings.max_record_bytes + 1 if i == 4 else 100,
                             content_mime_type="image/png" if i % 2 == 0 else "text/html",
                             content_mime_detected="application/octet-stream" if i == 0 else None))
        sink = io.BytesIO()
        pq.write_table(pa.Table.from_pylist(rows), sink)
        self.data = sink.getvalue()
        self.fetcher = MagicMock(downloaded=0)

        def get(url, start=None, end=None):
            data = (gzip.compress(b"index/subset=warc/test.parquet\nindex/subset=robotstxt/skip.parquet\n")
                    if start is None else self.data[start:end + 1])
            self.fetcher.downloaded += len(data)
            return data

        self.fetcher.get.side_effect = get
        self.catalog = MagicMock()
        self.catalog.shard_size.return_value = len(self.data)
        self.catalog.seen_digests.return_value = set()
        self.index = ParquetIndex()

    def test_filter_normalization_and_pool_reuse(self):
        rng = random.Random(1)
        pool = self.index.candidates("CC", self.settings, self.fetcher, self.catalog, rng)
        self.assertEqual(pool.rows, 12)
        self.assertEqual(pool.matched, 6)
        self.assertEqual({r["digest"] for r in pool.records}, {"D0", "D6", "D8", "D10"})
        record = next(r for r in pool.records if r["digest"] == "D0")
        self.assertEqual(record["timestamp"], "20260102030405")
        self.assertEqual(record["mime"], "image/png")
        calls = self.fetcher.get.call_count
        self.assertIs(self.index.candidates("CC", self.settings, self.fetcher, self.catalog, rng), pool)
        self.assertEqual(self.fetcher.get.call_count, calls)

    def test_preparation_deduplicates_and_drains_without_more_index_reads(self):
        self.settings.crawls = ["CC"]
        self.catalog.seen_digests.return_value = {"D0"}
        arguments = dict(settings=self.settings, fetcher=self.fetcher, catalog=self.catalog,
                         rng=random.Random(1), collections=[], excluded={"D6"}, parquet_index=self.index)
        first = crawler._prepare_batch(0, **arguments)
        calls = self.fetcher.get.call_count
        second = crawler._prepare_batch(1, **arguments)
        self.assertEqual({r["digest"] for r in first.chosen + second.chosen}, {"D8", "D10"})
        self.assertEqual(self.fetcher.get.call_count, calls)
        self.assertGreater(first.index_bytes, 0)
        self.assertEqual(second.index_bytes, 0)
        self.assertTrue(all(r["crawl"] == "CC" for r in first.chosen + second.chosen))
        self.assertTrue(all(r["mime"] == "image/png" for r in first.chosen + second.chosen))

    def test_no_matches_skips_location_columns(self):
        self.settings.mime_patterns = ["application/pdf"]
        readers = []
        def open_parquet(remote):
            reader = MagicMock(wraps=pq.ParquetFile(remote))
            reader.num_row_groups = 1
            readers.append(reader)
            return reader
        with patch.object(self.index, "pq") as mocked:
            mocked.ParquetFile.side_effect = open_parquet
            pool = self.index.candidates("CC", self.settings, self.fetcher, self.catalog, random.Random(1))
        self.assertEqual((pool.matched, pool.records), (0, []))
        self.assertEqual(readers[0].iter_batches.call_count, 1)
        self.assertEqual(readers[0].iter_batches.call_args.kwargs["columns"],
                         ["content_mime_type", "content_mime_detected"])

    def test_reservoir_and_row_limit(self):
        self.settings.no_mime_filter = True
        with patch("corpus.crawl.parquet_index.POOL_LIMIT", 3):
            pool = self.index.candidates("CC", self.settings, self.fetcher, self.catalog, random.Random(1))
        self.assertEqual(pool.matched, 12)
        self.assertLessEqual(len(pool.records), 3)
        with patch("corpus.crawl.parquet_index.MAX_ROW_GROUP_ROWS", 2):
            with self.assertRaisesRegex(ValueError, "limit is 2"):
                self.index._refill("CC", self.settings, self.fetcher, self.catalog, random.Random(1))


if __name__ == "__main__":
    unittest.main()
