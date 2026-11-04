use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

use miniz_oxide::deflate::compress_to_vec;
use rusqlite::Connection;
use serde_json::{Value, json};

fn scan(input: &Path, extra: &[&str], output: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_preflate_scan"))
        .arg(input)
        .args(extra)
        .arg("--output")
        .arg(output)
        .output()
        .unwrap()
}

fn success(result: Output) {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("corpus");
    fs::create_dir(&root).unwrap();
    for name in ["one.deflate", "two.deflate"] {
        fs::write(
            root.join(name),
            compress_to_vec(b"synthetic database scan", 0),
        )
        .unwrap();
    }
    let result = Command::new(env!("CARGO_BIN_EXE_preflate_scan"))
        .arg(&root)
        .arg("--database")
        .arg(directory.path().join("source.sqlite"))
        .args(["--label", "before"])
        .output()
        .unwrap();
    success(result);
    directory
}

fn report(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn selected_run_reopens_only_recorded_files_and_preserves_source_database() {
    let directory = fixture();
    let root = directory.path().join("corpus");
    fs::write(
        root.join("new.deflate"),
        compress_to_vec(b"not in selected run", 0),
    )
    .unwrap();
    fs::remove_file(root.join("two.deflate")).unwrap();
    let database = directory.path().join("source.sqlite");
    let before = fs::read(&database).unwrap();
    let output = directory.path().join("run.json");
    success(scan(&database, &["--from-run", "before"], &output));
    let result = report(&output);
    assert_eq!(result["summary"]["entries"], 2);
    assert_eq!(result["summary"]["successful_streams"], 1);
    assert_eq!(result["summary"]["filesystem_errors"], 1);
    assert_eq!(
        result["configuration"]["input"],
        json!(fs::canonicalize(root).unwrap())
    );
    assert_eq!(fs::read(&database).unwrap(), before);
}

#[test]
fn database_selection_writes_a_new_labelled_run_usable_by_match_checker() {
    let directory = fixture();
    let source = directory.path().join("source.sqlite");
    let output = directory.path().join("results.sqlite");
    let result = Command::new(env!("CARGO_BIN_EXE_preflate_scan"))
        .arg(&source)
        .args(["--from-run", "before", "--database"])
        .arg(&output)
        .args(["--label", "after"])
        .output()
        .unwrap();
    success(result);
    let db = Connection::open(&output).unwrap();
    assert_eq!(
        db.query_row("SELECT state FROM runs WHERE label='after'", [], |r| r
            .get::<_, String>(
            0
        ))
        .unwrap(),
        "complete"
    );
    drop(db);
    let check = Command::new(env!("CARGO_BIN_EXE_preflate_match_check"))
        .arg(output)
        .args(["--run", "after", "--output"])
        .arg(directory.path().join("check.json"))
        .output()
        .unwrap();
    success(check);
    let forbidden = Command::new(env!("CARGO_BIN_EXE_preflate_scan"))
        .arg(&source)
        .args(["--from-run", "before", "--database"])
        .arg(&source)
        .args(["--label", "must-not-exist"])
        .output()
        .unwrap();
    assert!(!forbidden.status.success());
}

#[test]
fn crawl_selection_deduplicates_saved_payloads_and_accepts_explicit_storage_root() {
    let directory = fixture();
    let source = directory.path().join("source.sqlite");
    let root = directory.path().join("corpus");
    let db = Connection::open(&source).unwrap();
    db.execute_batch("CREATE TABLE saved_streams(path TEXT NOT NULL);")
        .unwrap();
    for path in ["one.deflate", "one.deflate", "two.deflate"] {
        db.execute("INSERT INTO saved_streams VALUES (?)", [path])
            .unwrap();
    }
    drop(db);
    let before = fs::read(&source).unwrap();
    let output = directory.path().join("crawl.json");
    success(scan(
        &source,
        &["--from-crawl", "--source-root", root.to_str().unwrap()],
        &output,
    ));
    assert_eq!(report(&output)["summary"]["verified_streams"], 2);
    assert_eq!(fs::read(&source).unwrap(), before);
    let database = directory.path().join("crawl-results.sqlite");
    let result = Command::new(env!("CARGO_BIN_EXE_preflate_scan"))
        .arg(&source)
        .args(["--from-crawl", "--source-root"])
        .arg(&root)
        .arg("--database")
        .arg(&database)
        .args(["--label", "saved-payloads"])
        .output()
        .unwrap();
    success(result);
    let db = Connection::open(database).unwrap();
    let summary: String = db
        .query_row("SELECT summary_json FROM runs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&summary).unwrap()["verified_streams"],
        2
    );
    assert_eq!(fs::read(&source).unwrap(), before);
}

#[test]
fn incomplete_unknown_and_nonlocal_run_inputs_fail_explicitly() {
    let directory = fixture();
    let source = directory.path().join("source.sqlite");
    let output = directory.path().join("invalid.json");
    for args in [
        vec!["--from-run", "missing"],
        vec!["--from-run", "before", "--from-crawl"],
        vec!["--from-run", "before", "--trace"],
        vec!["--from-crawl", "--perf-output", "must-not-exist.jsonl"],
        vec!["--source-root", "."],
    ] {
        assert!(!scan(&source, &args, &output).status.success());
        assert!(!output.exists());
    }
    let db = Connection::open(&source).unwrap();
    db.execute("UPDATE runs SET state='importing'", []).unwrap();
    assert!(
        !scan(&source, &["--from-run", "before"], &output)
            .status
            .success()
    );
    assert!(!output.exists());
    db.execute("UPDATE runs SET state='complete'", []).unwrap();
    db.execute("UPDATE files SET path='https://example.com/' || id", [])
        .unwrap();
    drop(db);
    let result = scan(&source, &["--from-run", "before"], &output);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("non-local"));
    let missing = directory.path().join("missing.sqlite");
    assert!(
        !scan(
            &missing,
            &["--from-crawl"],
            &directory.path().join("missing.json")
        )
        .status
        .success()
    );
    assert!(!missing.exists());
}

#[test]
fn saved_payloads_cannot_escape_storage_or_expand_unlisted_directories() {
    let directory = fixture();
    let source = directory.path().join("source.sqlite");
    let root = directory.path().join("corpus");
    let outside = directory.path().join("outside.deflate");
    fs::write(&outside, compress_to_vec(b"outside source root", 0)).unwrap();
    let db = Connection::open(&source).unwrap();
    db.execute_batch("CREATE TABLE saved_streams(path TEXT NOT NULL);")
        .unwrap();
    for path in [&outside, &root] {
        db.execute(
            "INSERT INTO saved_streams VALUES (?)",
            [path.to_str().unwrap()],
        )
        .unwrap();
    }
    drop(db);
    let output = directory.path().join("bounded.json");
    success(scan(
        &source,
        &["--from-crawl", "--source-root", root.to_str().unwrap()],
        &output,
    ));
    let result = report(&output);
    assert_eq!(result["summary"]["successful_streams"], 0);
    assert_eq!(result["summary"]["filesystem_errors"], 1);
    assert_eq!(result["summary"]["skipped_entries"], 1);
}

#[test]
fn baseline_diff_counts_unchanged_results_without_writing_the_database() {
    let directory = fixture();
    let database = directory.path().join("source.sqlite");
    let before = fs::read(&database).unwrap();
    let output = directory.path().join("diff.json");
    let check = scan(
        &database,
        &["--baseline-run", "1", "--build-identity", "new-build"],
        &output,
    );
    let progress = String::from_utf8_lossy(&check.stderr);
    assert!(progress.contains("2/2 files (100.0%)"));
    assert!(!progress.contains("one.deflate"));
    assert!(!progress.contains("two.deflate"));
    assert!(progress.lines().count() <= 4);
    success(check);
    let result = report(&output);
    assert_eq!(result["report_type"], "baseline_diff");
    assert_eq!(result["baseline"]["run_id"], 1);
    assert_eq!(result["baseline"]["label"], "before");
    assert_eq!(result["current"]["build_identity"], "new-build");
    assert_eq!(result["comparison_compatible"], true);
    assert_eq!(result["differences"], json!([]));
    let coverage = &result["summary"]["coverage"];
    assert_eq!(coverage["files"], 2);
    assert_eq!(coverage["unchanged_streams"], 2);
    assert_eq!(coverage["verified_pairs"], 2);
    assert_eq!(result["summary"]["scan"]["verified_streams"], 2);
    assert_eq!(fs::read(&database).unwrap(), before);
    assert!(
        !scan(&database, &["--baseline-run", "1"], &output)
            .status
            .success()
    );
    assert_eq!(report(&output), result);
}

#[test]
fn baseline_diff_reports_size_settings_and_correction_changes_by_value() {
    let directory = fixture();
    let database = directory.path().join("source.sqlite");
    let db = Connection::open(&database).unwrap();
    db.execute(
        "UPDATE stream_results SET reconstruction_bytes=reconstruction_bytes+10 \
         WHERE stream_id=(SELECT min(stream_id) FROM stream_results)",
        [],
    )
    .unwrap();
    db.execute(
        "UPDATE stream_results SET corrections_json='{\"synthetic\":1}' \
         WHERE stream_id=(SELECT max(stream_id) FROM stream_results)",
        [],
    )
    .unwrap();
    db.execute(
        "UPDATE profiles SET settings_json=json_set(settings_json,'$.nice_length',12345)",
        [],
    )
    .unwrap();
    drop(db);
    let before = fs::read(&database).unwrap();
    let output = directory.path().join("changes.json");
    success(scan(&database, &["--baseline-run", "1"], &output));
    let result = report(&output);
    let coverage = &result["summary"]["coverage"];
    assert_eq!(coverage["improved_streams"], 1);
    assert_eq!(coverage["same_size_changed_streams"], 1);
    assert_eq!(coverage["unchanged_streams"], 0);
    let changes = result["differences"].as_array().unwrap();
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0]["classification"], "improved");
    assert_eq!(changes[1]["classification"], "same_size_changed");
    assert_eq!(
        changes[1]["changes"]["corrections"]["before"],
        json!({"synthetic": 1})
    );
    assert_eq!(
        changes[1]["changes"]["parameters"]["before"]["nice_length"],
        12345
    );
    assert_ne!(
        changes[1]["changes"]["parameters"]["after"]["nice_length"],
        12345
    );
    assert_eq!(fs::read(&database).unwrap(), before);
}

#[test]
fn baseline_diff_separates_changed_missing_and_unlisted_inputs() {
    let directory = fixture();
    let database = directory.path().join("source.sqlite");
    let root = directory.path().join("corpus");
    fs::write(
        root.join("one.deflate"),
        compress_to_vec(b"changed input size is different", 0),
    )
    .unwrap();
    fs::remove_file(root.join("two.deflate")).unwrap();
    fs::write(
        root.join("unlisted.deflate"),
        compress_to_vec(b"not selected", 0),
    )
    .unwrap();
    let output = directory.path().join("inputs.json");
    success(scan(&database, &["--baseline-run", "1"], &output));
    let result = report(&output);
    let coverage = &result["summary"]["coverage"];
    assert_eq!(coverage["files"], 2);
    assert_eq!(coverage["changed_input_files"], 1);
    assert_eq!(coverage["unavailable_files"], 1);
    assert_eq!(coverage["compared_streams"], 0);
    assert_eq!(coverage["uncompared_baseline_streams"], 2);
    assert_eq!(coverage["improved_streams"], 0);
    assert_eq!(coverage["regressed_streams"], 0);
    assert_eq!(result["differences"][0]["classification"], "input_changed");
    assert_eq!(result["differences"][1]["classification"], "unavailable");
}

#[test]
fn baseline_diff_flags_incompatible_configuration_and_rejects_invalid_modes() {
    let directory = fixture();
    let database = directory.path().join("source.sqlite");
    let output = directory.path().join("config.json");
    success(scan(
        &database,
        &["--baseline-run", "1", "--max-chain", "64"],
        &output,
    ));
    let result = report(&output);
    assert_eq!(result["comparison_compatible"], false);
    assert_eq!(
        result["configuration_differences"]["max_chain"],
        json!({"before": 4096, "after": 64})
    );
    let invalid = directory.path().join("invalid.json");
    for args in [
        vec!["--baseline-run", "0"],
        vec!["--baseline-run", "999"],
        vec!["--baseline-run", "1", "--from-run", "before"],
        vec!["--baseline-run", "1", "--from-crawl"],
        vec!["--baseline-run", "1", "--no-verify"],
        vec!["--baseline-run", "1", "--trace"],
        vec![
            "--baseline-run",
            "1",
            "--perf-output",
            "must-not-exist.jsonl",
        ],
        vec![
            "--baseline-run",
            "1",
            "--database",
            "must-not-exist.sqlite",
            "--label",
            "forbidden",
        ],
    ] {
        assert!(!scan(&database, &args, &invalid).status.success());
        assert!(!invalid.exists());
    }

    let db = Connection::open(database).unwrap();
    db.execute("UPDATE runs SET state='importing'", []).unwrap();
    assert!(
        !scan(
            &directory.path().join("source.sqlite"),
            &["--baseline-run", "1"],
            &invalid
        )
        .status
        .success()
    );
    assert!(!invalid.exists());
}

#[test]
fn baseline_diff_counts_new_missing_and_recovered_streams() {
    let directory = fixture();
    let database = directory.path().join("source.sqlite");
    let db = Connection::open(&database).unwrap();
    db.execute(
        "DELETE FROM stream_results WHERE stream_id=(SELECT min(stream_id) FROM stream_results)",
        [],
    )
    .unwrap();
    db.execute(
        "UPDATE stream_results SET status='error',verified=0,error='old failure'",
        [],
    )
    .unwrap();
    let (version, offset): (i64, i64) = db
        .query_row(
            "SELECT file_version_id,signature_offset FROM streams ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    db.execute(
            "INSERT INTO streams(file_version_id,identity_key,signature_offset,kind,deflate_bytes,plaintext_bytes) \
             VALUES (?,'synthetic-missing',?,'raw',10,20)",
            [version, offset + 1],
        )
        .unwrap();
    let missing = db.last_insert_rowid();
    db.execute(
        "INSERT INTO stream_results(run_id,stream_id,status,verified,reconstruction_bytes,chunks,\
             block_count,corrections_json,block_detail,settings_source) \
             VALUES (1,?,'ok',1,5,1,1,'{}','unavailable','unavailable')",
        [missing],
    )
    .unwrap();
    drop(db);
    let output = directory.path().join("coverage.json");
    success(scan(&database, &["--baseline-run", "1"], &output));
    let result = report(&output);
    assert_eq!(result["summary"]["coverage"]["new_streams"], 1);
    assert_eq!(result["summary"]["coverage"]["missing_streams"], 1);
    assert_eq!(result["summary"]["coverage"]["recovered_streams"], 1);
    assert_eq!(result["summary"]["coverage"]["baseline_streams"], 2);
    assert_eq!(result["summary"]["coverage"]["current_streams"], 2);
}

#[test]
fn baseline_diff_does_not_compare_unknown_file_identity() {
    let directory = fixture();
    let database = directory.path().join("source.sqlite");
    let db = Connection::open(&database).unwrap();
    db.execute("UPDATE file_versions SET modified_unix_seconds=NULL", [])
        .unwrap();
    drop(db);
    let output = directory.path().join("unknown.json");
    success(scan(&database, &["--baseline-run", "1"], &output));
    let result = report(&output);
    assert_eq!(result["summary"]["coverage"]["unknown_input_files"], 2);
    assert_eq!(result["summary"]["coverage"]["compared_streams"], 0);
    assert_eq!(
        result["summary"]["coverage"]["uncompared_baseline_streams"],
        2
    );
    assert_eq!(
        result["summary"]["coverage"]["uncompared_current_streams"],
        2
    );
}

#[test]
fn serial_and_parallel_scans_preserve_order_and_exact_observations() {
    fn remove_timings(value: &mut Value) {
        match value {
            Value::Object(object) => {
                object.remove("elapsed_ms");
                object.remove("plaintext_mib_per_second");
                for child in object.values_mut() {
                    remove_timings(child);
                }
            }
            Value::Array(array) => {
                for child in array {
                    remove_timings(child);
                }
            }
            _ => {}
        }
    }
    let directory = fixture();
    let root = directory.path().join("corpus");
    for index in 0..10 {
        fs::write(
            root.join(format!("extra-{index}.deflate")),
            compress_to_vec(
                &b"parallel exact reconstruction ".repeat(1000 + index * 100),
                6,
            ),
        )
        .unwrap();
    }
    let mut scans = Vec::new();
    for jobs in ["1", "4"] {
        let output = directory.path().join(format!("jobs-{jobs}.json"));
        success(scan(&root, &["--jobs", jobs], &output));
        let mut result = report(&output);
        assert_eq!(
            result["configuration"]["jobs"],
            jobs.parse::<u64>().unwrap()
        );
        assert_eq!(result["summary"]["verified_streams"], 12);
        remove_timings(&mut result);
        scans.push((result["files"].clone(), result["summary"].clone()));
    }
    assert_eq!(scans[0], scans[1]);
    for jobs in ["1", "4"] {
        let output = directory.path().join(format!("diff-jobs-{jobs}.json"));
        success(scan(
            &directory.path().join("source.sqlite"),
            &["--baseline-run", "1", "--jobs", jobs],
            &output,
        ));
        let result = report(&output);
        assert_eq!(result["differences"], json!([]));
        assert_eq!(result["comparison_compatible"], true);
        assert_eq!(result["summary"]["coverage"]["unchanged_streams"], 2);
    }
    let invalid = directory.path().join("invalid-workers.json");
    for jobs in ["0", "65"] {
        assert!(!scan(&root, &["--jobs", jobs], &invalid).status.success());
        assert!(!invalid.exists());
    }
    let perf = directory.path().join("invalid-perf.jsonl");
    let outcome = scan(
        &root,
        &["--jobs", "2", "--perf-output", perf.to_str().unwrap()],
        &invalid,
    );
    assert!(!outcome.status.success());
    assert!(String::from_utf8_lossy(&outcome.stderr).contains("--jobs 1"));
    assert!(!invalid.exists());
    assert!(!perf.exists());
}
