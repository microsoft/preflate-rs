import contextlib
import copy
import io
import json
import sqlite3
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock
import ijson

from .database import PROFILE_FIELDS, CorpusDatabase, scan_records
from .json_scan import json_scan_records
from .profiles import profile_fields


def parameter_report(hash_algorithm="RandomVector", matching="Greedy", *, nice_length=32, max_chain=128):
    if hash_algorithm == "Libdeflate4":
        index = "LibdeflateDualHash"
    else:
        function = {
            "Libdeflate4Fast": "Libdeflate4",
            "Libdeflate4Fast15": "Libdeflate4_15",
        }.get(hash_algorithm, hash_algorithm) if isinstance(hash_algorithm, str) else hash_algorithm
        index = {"Chain": {"hash": function}}
    parser = (
        {"Lazy": {"lookahead": {"max_lazy": 16, "behavior": {"Zlib": {"good_length": 8}}},
                  "minimum": {"Three": {"short_match_cutoff": 4096}}}}
        if matching == "Lazy" else
        {"LibdeflateLazy": {"two_positions": False, "short_match_cutoff": 4096}}
        if matching == "LibdeflateLazy" else {"Greedy": {"short_match_cutoff": 4096}}
    )
    common = dict(
        dictionary=dict(index=index, window_bits=15, insertion="AddAll"),
        distance={"Window": {"history": {"matches_to_start": False}, "bounds": "Lookahead"}},
        search=dict(budget=dict(max_chain=max_chain), nice_length=nice_length, input_tail="HashMinimum"),
    )
    behavior = {"Chain": dict(common=common, parser=parser)}
    if matching == "MiniZ":
        common["distance"] = {"Enabled": {"matches_to_start": False}}
        common["search"] = dict(budget=dict(max_chain=max_chain), max_probes=128, input_tail="HashMinimum")
        behavior = {"MiniZ": dict(common=common, greedy=False, short_match_cutoff=4096)}
    return dict(reconstruction=dict(max_token_count=16383, block_type_strategy="Dynamic", behavior=behavior),
                model="custom")


class CorpusDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.db = CorpusDatabase(self.root / "history.sqlite")

    def tearDown(self):
        self.db.close()
        self.temporary.cleanup()

    def test_profile_indexes_only_active_reconstruction_fields(self):
        report = parameter_report(matching="Lazy")
        chain = report["reconstruction"]["behavior"]["Chain"]
        chain["parser"]["Lazy"]["minimum"] = "FilteredSix"
        indexed = profile_fields(report)
        self.assertEqual(indexed["max_chain"], 128)
        self.assertNotIn("max_dist_3_matches", indexed)
        self.assertNotIn("nice_length", profile_fields(parameter_report(matching="MiniZ")))
        stored = dict(reconstruction=dict(
            max_token_count=16383, block_type_strategy="Uncompressed",
            behavior={"NoDictionary": {"strategy": "Store"}}), model="custom")
        self.assertEqual(profile_fields(stored), dict(
            max_token_count=16383, block_type_strategy="Uncompressed",
            hash_algorithm="None", strategy="Store"))
        with self.assertRaises(ValueError):
            self.db._profile(dict(hash_algorithm="RandomVector", max_chain=128))
        for invalid in (
            {**report, "model": []},
            {**report, "reconstruction": []},
            {"reconstruction": report["reconstruction"], "estimation": {"model": "custom"}},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.db._profile(invalid)

    def test_profile_index_and_window_summaries_do_not_depend_on_model(self):
        for index, expected in (
            ({"Chain": {"hash": "Libdeflate4"}}, "Libdeflate4Fast"),
            ({"Chain": {"hash": "Libdeflate4_15"}}, "Libdeflate4Fast15"),
            ("LibdeflateDualHash", "Libdeflate4"),
        ):
            for bounds in ("Full", "ExcludeOldest", "Lookahead", "LookaheadMinusOne"):
                with self.subTest(index=index, bounds=bounds):
                    report = parameter_report()
                    common = report["reconstruction"]["behavior"]["Chain"]["common"]
                    common["dictionary"]["index"] = index
                    common["distance"] = {"Window": {
                        "history": {"matches_to_start": True}, "bounds": bounds,
                    }}
                    fields = profile_fields(report)
                    self.assertEqual(fields["hash_algorithm"], expected)
                    self.assertEqual(fields["strategy"], bounds)
                    self.assertTrue(fields["matches_to_start_detected"])
                    self.assertEqual(fields["very_far_matches_detected"],
                                     bounds in ("Full", "ExcludeOldest"))
                    report["model"] = "zlib"
                    self.assertEqual(profile_fields(report), fields)

    def test_json_scan_streams_records_and_validates_completion_and_totals(self):
        record = self.file_record()
        summary = dict(entries=1, successful_streams=1, verified_streams=1,
                       successful_deflate_bytes=2000, successful_plaintext_bytes=9000,
                       successful_correction_bytes=40)
        document = dict(schema_version=1, configuration={}, files=[record], summary=summary)
        path = self.root / "scan.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        records = list(json_scan_records(path))
        self.assertEqual([kind for kind, _ in records], ["header", "file", "summary"])
        self.assertEqual(records[1][1], record)
        self.assertEqual(records[2][1], summary)
        for invalid in (
            {**document, "schema_version": 2},
            {key: value for key, value in document.items() if key != "summary"},
            {**document, "summary": {**summary, "verified_streams": 0}},
            {**document, "files": [0]},
        ):
            with self.subTest(invalid=invalid):
                path.write_text(json.dumps(invalid), encoding="utf-8")
                with self.assertRaises((ValueError, ijson.JSONError)):
                    list(json_scan_records(path))
        path.write_text('{"schema_version":1,"configuration":{},"files":['
                        + json.dumps(record) + ',{"path":', encoding="utf-8")
        with contextlib.closing(json_scan_records(path)) as records:
            self.assertEqual(next(records)[0], "header")
            self.assertEqual(next(records), ("file", record))
            with self.assertRaises((ValueError, ijson.JSONError)):
                list(records)

    def report(self, name, correction=40, modified=1, traced=False, footer=True, source="synthetic.bin"):
        stream = dict(
            offset=0, deflate_offset=2, kind="zlib", member_name=None, status="ok",
            verified=True, deflate_bytes=2000, plaintext_bytes=9000, correction_bytes=correction,
            chunks=1, blocks=1, parameters=parameter_report(),
            nonzero_corrections={"LenCorrection": 2},
        )
        if traced:
            stream["trace"] = dict(blocks_truncated=False, token_mismatches=2, token_count=80,
                                   blocks=[dict(index=0, chunk=0, plaintext_offset=0,
                                                plaintext_bytes=9000, kind="dynamic_huffman",
                                                last=True, literals=10, references=70)],
                                   chunks=[dict(index=0, status="ok")])
        record = dict(path=source, size_bytes=2200, modified_unix_seconds=modified,
                      status="ok", elapsed_ms=2, streams=[stream])
        header = dict(schema_version=1, configuration={"no_verify": False}, started_unix_seconds=1)
        path = self.root / name
        with CorpusDatabase(path) as database:
            database.record_run([record], "scan", header=header)
            if not footer:
                with database.connection:
                    database.connection.execute("UPDATE runs SET state='importing'")
        return path

    def file_record(self):
        with contextlib.closing(scan_records(self.report("template.sqlite"))) as records:
            return next(value for kind, value in records if kind == "file")

    def files_report(self, name, records):
        streams = [stream for record in records for stream in record["streams"] if stream["status"] == "ok"]
        summary = dict(entries=len(records), successful_streams=len(streams),
                       verified_streams=sum(stream["verified"] for stream in streams),
                       successful_deflate_bytes=sum(stream["deflate_bytes"] for stream in streams),
                       successful_plaintext_bytes=sum(stream["plaintext_bytes"] for stream in streams),
                       successful_correction_bytes=sum(stream["correction_bytes"] for stream in streams))
        header = dict(schema_version=1, configuration={"no_verify": False}, started_unix_seconds=1)
        path = self.root / name
        with CorpusDatabase(path) as database:
            database.record_run(records, "scan", header=header, summary=summary)
        return path

    def test_run_sets_compare_disjoint_replays_and_last_file_wins(self):
        for label, source, cost in [("a", "a.bin", 40), ("b", "b.bin", 80),
                                    ("fixed-a", "a.bin", 10), ("fixed-b", "b.bin", 70)]:
            self.db.merge_scan(self.report(label + ".sqlite", correction=cost, source=source), label)
        result = self.db.compare_run_sets(["a", "b"], ["fixed-a", "fixed-b"])
        self.assertEqual(result["totals"]["compared_streams"], 2)
        self.assertEqual(result["totals"]["before_bytes"], 120)
        self.assertEqual(result["totals"]["after_bytes"], 80)
        self.assertEqual(result["totals"]["improved_streams"], 2)
        self.assertEqual([row["added_bytes"] for row in result["improvements"]], [-30, -10])
        self.assertEqual(result["improvements"][0]["before_run"], "a")
        self.assertEqual(self.db.compare_run_sets(["a", "b"], ["a", "b", "fixed-a"])["totals"]["after_bytes"], 90)
        self.assertEqual(self.db.compare_run_sets(["a", "b"], ["fixed-a", "a", "b"])["totals"]["after_bytes"], 120)

    def test_run_set_replaces_whole_files_without_stale_streams_or_snapshots(self):
        record = self.file_record()
        extra = copy.deepcopy(record["streams"][0])
        extra.update(offset=100, deflate_offset=102)
        record["streams"].append(extra)
        self.db.merge_scan(self.files_report("full.sqlite", [record]), "full")
        record["streams"].pop()
        self.db.merge_scan(self.files_report("partial.sqlite", [record]), "partial")
        result = self.db.compare_run_sets(["full"], ["full", "partial"])["totals"]
        self.assertEqual(result["compared_streams"], 1)
        self.assertEqual(result["unmatched_previously_successful_streams"], 1)
        record["modified_unix_seconds"] = 2
        self.db.merge_scan(self.files_report("changed.sqlite", [record]), "changed")
        result = self.db.compare_run_sets(["partial"], ["partial", "changed"])["totals"]
        self.assertEqual(result["compared_streams"], 0)
        self.assertEqual(result["unmatched_previously_successful_streams"], 1)
        self.assertEqual(result["new_successful_streams"], 1)
        record.update(status="skipped", streams=[])
        self.db.merge_scan(self.files_report("skipped.sqlite", [record]), "skipped")
        result = self.db.compare_run_sets(["partial"], ["partial", "skipped"])["totals"]
        self.assertEqual(result["compared_streams"], 0)
        self.assertEqual(result["unmatched_previously_successful_streams"], 1)

    def test_query_scopes_reject_ambiguous_or_incomplete_runs(self):
        self.db.merge_scan(self.report("ok.sqlite"), "ok")
        with self.assertRaises(ValueError):
            self.db.merge_scan(self.report("partial.sqlite", footer=False), "partial")
        for scope in ([], "ok", ["ok", "ok"], ["partial"], ["missing"]):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                self.db.family_overhead(scope)
        with self.assertRaisesRegex(ValueError, "positive"):
            self.db.compare_run_sets(["ok"], ["ok"], limit=0)

    def test_multi_run_scope_uses_file_and_exact_result_indexes(self):
        for label in ("one", "two"):
            self.db.merge_scan(self.report(label + ".sqlite", source=label + ".bin"), label)
        scope, parameters = self.db._scope(["one", "two"], "selected")
        query = "WITH " + scope + " SELECT count(*) FROM selected"
        plan = [row[3] for row in self.db.connection.execute("EXPLAIN QUERY PLAN " + query, parameters)]
        self.assertTrue(any("file_version_id=?" in step for step in plan), plan)
        self.assertTrue(any("run_id=? AND stream_id=?" in step for step in plan), plan)
        self.assertEqual(self.db.connection.execute(query, parameters).fetchone()[0], 2)

    def test_outliers_filter_settings_limits_and_rank_once_per_file(self):
        record = self.file_record()
        extra = copy.deepcopy(record["streams"][0])
        extra.update(offset=100, deflate_offset=102, correction_bytes=80)
        record["streams"].append(extra)
        self.db.merge_scan(self.files_report("multiple.sqlite", [record]), "multiple")
        result = self.db.outliers(["multiple"], settings={"hash_algorithm": "RandomVector", "nice_length": 32})
        self.assertEqual([row["reconstruction_bytes"] for row in result], [80, 40])
        self.assertEqual(result[0]["settings"]["reconstruction"]["behavior"]["Chain"]["common"]["search"]["nice_length"], 32)
        self.assertEqual(result[0]["size_bytes"], 2200)
        self.assertEqual(result[0]["modified_unix_seconds"], 1)
        self.assertEqual(len(self.db.outliers(["multiple"], one_per_file=True)), 1)
        self.assertEqual(self.db.outliers(["multiple"], max_file_bytes=2199), [])
        self.assertEqual(self.db.outliers(["multiple"], max_plaintext_bytes=8999), [])
        self.assertEqual(self.db.outliers(["multiple"], min_deflate_bytes=2001), [])
        self.assertEqual(self.db.outliers(["multiple"], settings={"hash_algorithm": "' OR 1=1 --"}), [])
        self.assertEqual(len(self.db.outliers(["multiple"], settings={"max_chain": 128})), 2)
        for settings in ({"invalid_sql": 1}, {"hash_algorithm": []}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                self.db.outliers(["multiple"], settings=settings)
        with self.assertRaisesRegex(ValueError, "Byte limits"):
            self.db.outliers(["multiple"], max_file_bytes=-1)

    def test_family_overhead_separates_signatures_size_bands_and_unverified_results(self):
        record = self.file_record()
        template = record["streams"][0]
        record["streams"] = []
        specifications = [
            ("RandomVector", "Lazy", 1024, True, "ok", 10),
            ("RandomVector", "Lazy", 1025, True, "ok", 20),
            ({"Zlib": {"hash_mask": 32767, "hash_shift": 5}}, "MiniZ", 2000, True, "ok", 30),
            ("Libdeflate4", "LibdeflateLazy", 2000, False, "ok", 999),
            (None, None, 2000, False, "error", 0),
        ]
        for index, (hash_name, matching, size, verified, status, cost) in enumerate(specifications):
            stream = copy.deepcopy(template)
            stream.update(offset=index * 100, deflate_offset=index * 100 + 2, deflate_bytes=size,
                          verified=verified, status=status, correction_bytes=cost,
                          parameters=parameter_report(hash_name, matching) if hash_name else None)
            record["streams"].append(stream)
        self.db.merge_scan(self.files_report("families.sqlite", [record]), "families")
        rows = self.db.family_overhead(["families"])
        self.assertEqual(sum(row["reconstruction_bytes"] for row in rows), 60)
        self.assertEqual(sum(row["failures"] for row in rows), 1)
        self.assertEqual(sum(row["unverified"] for row in rows), 1)
        self.assertAlmostEqual(sum(row["overhead_share_percent"] for row in rows), 100)
        self.assertEqual(next(row["reconstruction_bytes"] for row in rows
                              if row["family"] == "miniz-style"), 30)
        self.assertEqual(next(row["deflate_bytes"] for row in rows
                              if row["family"] == "table-hash / Windows-style" and row["size_band"] == "tiny"), 1024)
        self.assertEqual(len(self.db.outliers(["families"], min_deflate_bytes=0)), 3)

    def test_query_cli_emits_json_without_csv_or_direct_sql(self):
        from .__main__ import main
        self.db.merge_scan(self.report("cli.sqlite"), "cli")
        for arguments in (
            ["compare-set", "--before", "cli", "--after", "cli"],
            ["families", "cli"],
            ["outliers", "cli", "--setting", "hash_algorithm=RandomVector", "--setting", "nice_length=32"],
        ):
            output = io.StringIO()
            with mock.patch("sys.argv", ["corpus.database", "--db", str(self.db.path), *arguments]):
                with contextlib.redirect_stdout(output):
                    main()
            self.assertTrue(json.loads(output.getvalue()))

    def test_merge_compare_and_recorded_block_settings(self):
        before = self.report("before.sqlite")
        after = self.report("after.sqlite", correction=2040, traced=True)
        self.db.merge_scan(before, "before")
        self.db.merge_scan(after, "after")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.db.merge_scan(after, "after")
        comparison = self.db.compare_runs("before", "after")
        self.assertEqual(comparison["totals"]["major_regressions"], 1)
        self.assertEqual(comparison["regressions"][0]["added_bytes"], 2000)
        self.assertEqual(comparison["regressions"][0]["before_run"], "before")
        self.assertEqual(comparison["regressions"][0]["after_run"], "after")
        block = self.db.connection.execute("SELECT * FROM effective_block_settings").fetchone()
        self.assertEqual(block["path"], "synthetic.bin")
        self.assertEqual(block["nice_length"], 32)
        self.assertEqual(block["settings_source"], "stream_finalized")
        self.assertEqual(block["estimator_evidence_state"], "unavailable")
        self.assertEqual(self.db.priorities("after")[0]["streams"], 1)
        self.assertEqual(self.db.check(), {"integrity": ["ok"], "foreign_key_errors": []})

    def test_changed_sources_are_not_matched(self):
        self.db.merge_scan(self.report("before.sqlite"), "before")
        self.db.merge_scan(self.report("after.sqlite", modified=2), "after")
        self.assertEqual(self.db.compare_runs("before", "after")["totals"]["compared_streams"], 0)

    def test_missing_source_metadata_cannot_match_between_runs(self):
        for label in ("before", "after"):
            path = self.report(label + ".sqlite", modified=None)
            self.db.merge_scan(path, label)
        self.assertEqual(self.db.compare_runs("before", "after")["totals"]["compared_streams"], 0)

    def test_profile_cache_is_bounded_without_losing_deduplication(self):
        first = self.db._profile(parameter_report(max_chain=0))
        for chain in range(1, 4100):
            self.db._profile(parameter_report(max_chain=chain))
        self.assertLessEqual(len(self.db._profiles), 4096)
        self.assertEqual(self.db._profile(parameter_report(max_chain=0)), first)
        self.assertEqual(self.db.connection.execute("SELECT count(*) FROM profiles").fetchone()[0], 4100)

    def test_merge_is_atomic_when_source_totals_are_invalid(self):
        source = self.report("invalid.sqlite", traced=True)
        with contextlib.closing(sqlite3.connect(source)) as connection, connection:
            connection.execute("UPDATE runs SET summary_json=json_set(summary_json,'$.successful_streams',9)")
        with self.assertRaisesRegex(ValueError, "reconcile"):
            self.db.merge_scan(source, "invalid")
        self.assertEqual(self.db.runs(), [])
        self.assertEqual(self.db.connection.execute("SELECT count(*) FROM profiles").fetchone()[0], 0)
        self.db.merge_scan(self.report("valid.sqlite"), "valid")
        self.assertEqual(self.db.check()["foreign_key_errors"], [])

    def test_merge_preserves_trace_and_metadata_and_remaps_only_requested_source(self):
        source = self.report("trace.sqlite", traced=True)
        self.db.merge_scan(source, "copy", transform=lambda record: {
            **record, "path": "https://example.com/public.bin", "modified_unix_seconds": 10,
        })
        with contextlib.closing(scan_records(self.db.path, "copy")) as records:
            result = next(record for kind, record in records if kind == "file")
        self.assertEqual(result["path"], "https://example.com/public.bin")
        self.assertEqual(result["modified_unix_seconds"], 10)
        self.assertEqual(result["streams"][0]["trace"]["blocks"][0]["references"], 70)
        self.assertEqual(result["streams"][0]["trace"]["chunks"][0]["status"], "ok")
        with contextlib.closing(scan_records(source)) as records:
            original = next(record for kind, record in records if kind == "file")
        self.assertEqual(original["path"], "synthetic.bin")

    def test_merge_requires_explicit_source_run_for_multiple_runs(self):
        self.db.merge_scan(self.report("one.sqlite"), "one")
        self.db.merge_scan(self.report("two.sqlite"), "two")
        with CorpusDatabase(self.root / "copy.sqlite") as other:
            with self.assertRaisesRegex(ValueError, "exactly one"):
                other.merge_scan(self.db.path, "ambiguous")
            other.merge_scan(self.db.path, "selected", source_label="two")
            self.assertEqual(other.runs()[0]["imported_files"], 1)
        with self.assertRaisesRegex(ValueError, "must differ"):
            self.db.merge_scan(self.db.path, "self")

    def test_record_run_checks_counts_and_clears_rolled_back_profiles(self):
        record = self.file_record()
        with self.assertRaisesRegex(ValueError, "reconcile"):
            self.db.record_run([record], "bad", summary={"entries": 2})
        self.assertEqual(self.db.runs(), [])
        self.db.record_run([record], "good")
        self.assertEqual(self.db.check()["foreign_key_errors"], [])
        with self.assertRaisesRegex(ValueError, "empty"):
            self.db.record_run([], " ")

    def test_refuses_unrelated_or_unsupported_database_without_modification(self):
        for name, schema in (
            ("unrelated", "CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES('keep')"),
            ("unsupported", "CREATE TABLE schema_info(version INTEGER); INSERT INTO schema_info VALUES(99)"),
        ):
            path = self.root / f"{name}.sqlite"
            with contextlib.closing(sqlite3.connect(path)) as connection, connection:
                connection.executescript(schema)
            before = path.read_bytes()
            with self.assertRaises((sqlite3.Error, ValueError)):
                CorpusDatabase(path)
            self.assertEqual(path.read_bytes(), before)

    def test_directory_scan_cli_uses_native_sqlite_and_preserves_privacy_defaults(self):
        from .__main__ import main
        with (mock.patch("sys.argv", [
            "corpus.database", "--db", str(self.db.path), "scan", str(self.root),
            "--label", "private", "--scanner", "release-scanner",
        ]), mock.patch("subprocess.run") as run):
            main()
        arguments = run.call_args.args[0]
        self.assertEqual(arguments[:2], ["release-scanner", str(self.root)])
        self.assertIn("--database", arguments)
        self.assertNotIn("--hydrate", arguments)
        self.assertNotIn("--no-verify", arguments)
        self.assertNotIn("--output", arguments)
        self.assertTrue(run.call_args.kwargs["check"])

    def test_database_scan_cli_passes_explicit_input_selection(self):
        from .__main__ import main
        for flags in (["--from-run", "before"], ["--from-crawl", "--source-root", str(self.root)]):
            with (self.subTest(flags=flags), mock.patch("sys.argv", [
                "corpus.database", "--db", str(self.db.path), "scan", "source.sqlite",
                "--label", "after", "--scanner", "release-scanner", "--jobs", "3", *flags,
            ]), mock.patch("subprocess.run") as run):
                main()
                self.assertEqual(run.call_args.args[0][-len(flags):], flags)
                arguments = run.call_args.args[0]
                self.assertEqual(arguments[arguments.index("--jobs") + 1], "3")
                self.assertTrue(run.call_args.kwargs["check"])

    def test_native_private_directory_scan_through_python_entry_point(self):
        from .__main__ import main
        scanner = Path(__file__).resolve().parents[2] / "target" / "release" / (
            "preflate_scan.exe" if sys.platform == "win32" else "preflate_scan")
        if not scanner.is_file():
            self.skipTest("release preflate_scan is not built")
        source = self.root / "private-directory"
        source.mkdir()
        compressor = zlib.compressobj(wbits=-15)
        payload = compressor.compress(b"synthetic directory regression " * 1000) + compressor.flush()
        (source / "sample.deflate").write_bytes(payload)
        with mock.patch("sys.argv", [
            "corpus.database", "--db", str(self.db.path), "scan", str(source),
            "--label", "local", "--scanner", str(scanner),
        ]):
            main()
        with contextlib.closing(scan_records(self.db.path, "local")) as records:
            values = list(records)
        file = next(value for kind, value in values if kind == "file")
        self.assertTrue(Path(file["path"]).samefile(source / "sample.deflate"))
        self.assertEqual(file["streams"][0]["verified"], True)
        self.assertEqual(values[-1][1]["successful_streams"], 1)

if __name__ == "__main__":
    unittest.main()
