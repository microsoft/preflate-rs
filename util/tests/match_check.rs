use std::{fs, path::Path, process::Command};

use miniz_oxide::deflate::{compress_to_vec, compress_to_vec_zlib};
use rusqlite::Connection;
use serde_json::{Value, json};

fn scan_label(root: &Path, baseline: &Path, label: &str) {
    let result = Command::new(env!("CARGO_BIN_EXE_preflate_scan"))
        .arg(root)
        .args(["--chunk-mib", "1", "--database"])
        .arg(baseline)
        .args(["--label", label])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn scan(root: &Path, baseline: &Path) {
    scan_label(root, baseline, "baseline");
}

fn check_run(baseline: &Path, label: &str, output: &Path, extra: &[&str]) -> (bool, Value) {
    let result = Command::new(env!("CARGO_BIN_EXE_preflate_match_check"))
        .arg(baseline)
        .args(["--run", label, "--output"])
        .arg(output)
        .args(extra)
        .output()
        .unwrap();
    let report = serde_json::from_slice(&fs::read(output).unwrap()).unwrap_or_else(|error| {
        panic!(
            "invalid checker output: {error}; {}",
            String::from_utf8_lossy(&result.stderr)
        )
    });
    (result.status.success(), report)
}

fn check(baseline: &Path, output: &Path, extra: &[&str]) -> (bool, Value) {
    check_run(baseline, "baseline", output, extra)
}

fn fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("corpus");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("perfect.deflate"),
        compress_to_vec(b"synthetic", 0),
    )
    .unwrap();
    scan(&root, &directory.path().join("baseline.sqlite"));
    directory
}

fn copy_baseline(directory: &Path, name: &str) -> std::path::PathBuf {
    let path = directory.join(name);
    fs::copy(directory.join("baseline.sqlite"), &path).unwrap();
    path
}

fn parameters(path: &Path) -> Value {
    let db = Connection::open(path).unwrap();
    let settings: String = db
        .query_row("SELECT settings_json FROM profiles LIMIT 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    serde_json::from_str(&settings).unwrap()
}

fn rejected(baseline: &Path, label: &str, output: &Path) -> String {
    let result = Command::new(env!("CARGO_BIN_EXE_preflate_match_check"))
        .arg(baseline)
        .args(["--run", label, "--output"])
        .arg(output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    let error = String::from_utf8(result.stderr).unwrap();
    assert!(error.contains("Match check failed"), "{error}");
    error
}

fn png_chunk(output: &mut Vec<u8>, kind: &[u8; 4], bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(kind);
    output.extend_from_slice(bytes);
    let mut crc = crc32fast::Hasher::new();
    crc.update(kind);
    crc.update(bytes);
    output.extend_from_slice(&crc.finalize().to_be_bytes());
}

#[test]
fn unchanged_raw_zlib_png_tiny_and_multichunk_streams_pass() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("corpus");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("tiny.deflate"), compress_to_vec(b"synthetic", 0)).unwrap();
    let large = vec![b'x'; 2 * 1024 * 1024 + 17];
    fs::write(root.join("large.deflate"), compress_to_vec(&large, 0)).unwrap();
    fs::write(
        root.join("wrapped.bin"),
        compress_to_vec_zlib(&large[..4096], 0),
    )
    .unwrap();
    fs::write(
        root.join("tokens.deflate"),
        compress_to_vec(&b"abcdefghij".repeat(3000), 6),
    )
    .unwrap();
    let zlib = compress_to_vec_zlib(&large[..4096], 0);
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png_chunk(&mut png, b"IDAT", &zlib[..zlib.len() / 2]);
    png_chunk(&mut png, b"IDAT", &zlib[zlib.len() / 2..]);
    png_chunk(&mut png, b"IEND", &[]);
    fs::write(root.join("split.png"), png).unwrap();
    let baseline = directory.path().join("baseline.sqlite");
    scan(&root, &baseline);
    let before = fs::read(&baseline).unwrap();
    let db = Connection::open(&baseline).unwrap();
    let streams: i64 = db
        .query_row("SELECT count(*) FROM stream_results", [], |row| row.get(0))
        .unwrap();
    let chunks: i64 = db
        .query_row("SELECT max(chunks) FROM stream_results", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(streams, 5);
    assert!(chunks > 1);
    let (success, checked) = check(&baseline, &directory.path().join("result.json"), &[]);
    assert!(success, "{checked}");
    assert_eq!(checked["run"], "baseline");
    assert_eq!(checked["summary"]["eligible_streams"], 5);
    assert_eq!(checked["summary"]["unchanged_streams"], 5);
    assert_eq!(checked["summary"]["estimator_only_checks"], 2);
    assert_eq!(checked["summary"]["tiny_replay_checks"], 2);
    assert_eq!(checked["summary"]["cache_hits"], 1);
    assert_eq!(checked["changes"], json!([]));
    assert_eq!(fs::read(&baseline).unwrap(), before);
}

#[test]
fn every_parameter_field_is_frozen_and_reported() {
    let directory = fixture();
    let original = parameters(&directory.path().join("baseline.sqlite"));
    for (index, (name, value)) in original.as_object().unwrap().iter().enumerate() {
        let mut changed = original.clone();
        changed[name] = match value {
            Value::Bool(value) => json!(!value),
            Value::Number(value) => json!(value.as_u64().unwrap() + 1),
            Value::String(value) => json!(format!("{value}_changed")),
            _ => panic!("unexpected parameter type"),
        };
        let baseline = copy_baseline(directory.path(), &format!("changed-{index}.sqlite"));
        Connection::open(&baseline)
            .unwrap()
            .execute("UPDATE profiles SET settings_json=?", [changed.to_string()])
            .unwrap();
        let (success, checked) = check(
            &baseline,
            &directory.path().join(format!("result-{index}.json")),
            &[],
        );
        assert!(!success, "{name}");
        assert_eq!(checked["passed"], false);
        assert_eq!(checked["summary"]["changed_streams"], 1);
        assert_eq!(checked["changes"][0]["changed_fields"], json!([name]));
        assert_eq!(checked["changes"][0]["after"], original);
    }
}

#[test]
fn token_corrections_exclude_streams_but_tree_and_metadata_corrections_do_not() {
    let directory = fixture();
    for (index, (name, eligible)) in [
        ("LiteralPredictionWrong", false),
        ("ReferencePredictionWrong", false),
        ("LenCorrection", false),
        ("DistOnlyCorrection", false),
        ("DistAfterLenCorrection", false),
        ("TreeProfile", true),
        ("TreeCodeBitLengthCorrection", true),
        ("TokenCount", true),
    ]
    .into_iter()
    .enumerate()
    {
        let baseline = copy_baseline(directory.path(), &format!("corrections-{index}.sqlite"));
        Connection::open(&baseline)
            .unwrap()
            .execute(
                "UPDATE stream_results SET corrections_json=?",
                [json!({name: 1}).to_string()],
            )
            .unwrap();
        let (success, checked) = check(
            &baseline,
            &directory.path().join(format!("result-{index}.json")),
            &[],
        );
        assert_eq!(success, eligible, "{name}: {checked}");
        assert_eq!(checked["summary"]["eligible_streams"], u64::from(eligible));
    }
}

#[test]
fn changed_and_missing_sources_fail_instead_of_silently_skipping() {
    let directory = fixture();
    let source = directory.path().join("corpus").join("perfect.deflate");
    let baseline = directory.path().join("baseline.sqlite");
    fs::write(&source, b"changed").unwrap();
    let (success, checked) = check(&baseline, &directory.path().join("changed.json"), &[]);
    assert!(!success);
    assert_eq!(checked["summary"]["failed_streams"], 1);
    assert!(
        checked["changes"][0]["error"]
            .as_str()
            .unwrap()
            .contains("changed")
    );
    fs::remove_file(source).unwrap();
    let (success, checked) = check(&baseline, &directory.path().join("missing.json"), &[]);
    assert!(!success);
    assert_eq!(checked["summary"]["failed_streams"], 1);
}

#[test]
fn incomplete_inconsistent_and_unsupported_baselines_fail() {
    let directory = fixture();
    for (index, sql) in [
        "UPDATE runs SET state='importing'",
        "UPDATE runs SET summary_json=NULL",
        "UPDATE runs SET summary_json=json_set(summary_json,'$.successful_streams',999)",
        "UPDATE runs SET imported_files=999",
        "UPDATE runs SET configuration_json=json_set(configuration_json,'$.input','relative')",
        "UPDATE runs SET configuration_json=json_set(configuration_json,'$.max_file_mib',0)",
        "DROP TABLE schema_info; CREATE TABLE schema_info(version INTEGER); INSERT INTO schema_info VALUES(999)",
        "UPDATE stream_results SET corrections_json='not JSON'",
        "UPDATE streams SET deflate_bytes=-1",
    ].into_iter().enumerate() {
        let path = copy_baseline(directory.path(), &format!("bad-{index}.sqlite"));
        Connection::open(&path).unwrap().execute_batch(sql).unwrap();
        rejected(&path, "baseline", &directory.path().join(format!("result-{index}.json")));
    }
}

#[test]
fn explicit_size_filters_and_unverified_baselines_cannot_give_empty_success() {
    let directory = fixture();
    let baseline = directory.path().join("baseline.sqlite");
    let (success, checked) = check(
        &baseline,
        &directory.path().join("filtered.json"),
        &["--min-stream-bytes", "1024"],
    );
    assert!(!success);
    assert_eq!(checked["summary"]["excluded_by_size"], 1);
    Connection::open(&baseline)
        .unwrap()
        .execute_batch(
            "UPDATE stream_results SET verified=0; \
         UPDATE runs SET summary_json=json_set(summary_json,'$.verified_streams',0)",
        )
        .unwrap();
    let (success, checked) = check(&baseline, &directory.path().join("unverified.json"), &[]);
    assert!(!success);
    assert_eq!(checked["summary"]["eligible_streams"], 0);
}

#[test]
fn existing_outputs_are_preserved() {
    let directory = fixture();
    let output = directory.path().join("result.json");
    fs::write(&output, b"keep existing output").unwrap();
    rejected(
        &directory.path().join("baseline.sqlite"),
        "baseline",
        &output,
    );
    assert_eq!(fs::read(output).unwrap(), b"keep existing output");
}

#[test]
fn large_token_perfect_stream_uses_estimation_and_detects_changes() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("corpus");
    fs::create_dir(&root).unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("samples")
        .join("compressed_flate2_level2.deflate");
    fs::copy(&fixture, root.join("native.deflate")).unwrap();
    fs::copy(&fixture, root.join("duplicate.deflate")).unwrap();
    let baseline = directory.path().join("baseline.sqlite");
    scan(&root, &baseline);
    let (success, checked) = check(&baseline, &directory.path().join("unchanged.json"), &[]);
    assert!(success, "{checked}");
    assert_eq!(checked["summary"]["estimator_only_checks"], 1);
    assert_eq!(checked["summary"]["tiny_replay_checks"], 0);
    assert_eq!(checked["summary"]["cache_hits"], 1);
    assert_eq!(checked["summary"]["checked_streams"], 2);
    let db = Connection::open(&baseline).unwrap();
    let mut changed = parameters(&baseline);
    changed["max_chain"] = json!(999);
    db.execute(
        "INSERT INTO profiles(settings_json) VALUES (?)",
        [changed.to_string()],
    )
    .unwrap();
    let profile = db.last_insert_rowid();
    db.execute(
        "UPDATE stream_results SET profile_id=? WHERE stream_id=(SELECT min(id) FROM streams)",
        [profile],
    )
    .unwrap();
    let (success, checked) = check(&baseline, &directory.path().join("regression.json"), &[]);
    assert!(!success);
    assert_eq!(checked["summary"]["changed_streams"], 1);
    assert_eq!(
        checked["changes"][0]["changed_fields"],
        json!(["max_chain"])
    );
}

#[test]
fn explicit_trace_mismatches_and_invalid_payload_records_never_pass() {
    let directory = fixture();
    for (index, sql) in [
        "UPDATE stream_results SET token_mismatches=1",
        "UPDATE stream_results SET profile_id=NULL",
        "UPDATE streams SET deflate_offset=999999",
    ]
    .into_iter()
    .enumerate()
    {
        let baseline = copy_baseline(directory.path(), &format!("invalid-{index}.sqlite"));
        Connection::open(&baseline)
            .unwrap()
            .execute_batch(sql)
            .unwrap();
        let (success, checked) = check(
            &baseline,
            &directory
                .path()
                .join(format!("invalid-result-{index}.json")),
            &[],
        );
        assert!(!success, "{checked}");
        if index == 0 {
            assert_eq!(checked["summary"]["eligible_streams"], 0);
        } else {
            assert_eq!(checked["summary"]["failed_streams"], 1);
        }
    }
}

#[test]
fn run_selection_is_required_explicit_and_scoped() {
    let directory = fixture();
    let baseline = directory.path().join("baseline.sqlite");
    scan_label(&directory.path().join("corpus"), &baseline, "other");
    Connection::open(&baseline).unwrap().execute_batch(
        "UPDATE stream_results SET profile_id=NULL WHERE run_id=(SELECT id FROM runs WHERE label='other')",
    ).unwrap();
    let (success, checked) = check(&baseline, &directory.path().join("selected.json"), &[]);
    assert!(success, "{checked}");
    assert_eq!(checked["summary"]["baseline_files"], 1);
    assert_eq!(checked["summary"]["checked_streams"], 1);
    let (success, checked) = check_run(
        &baseline,
        "other",
        &directory.path().join("other.json"),
        &[],
    );
    assert!(!success);
    assert_eq!(checked["summary"]["failed_streams"], 1);
    rejected(
        &baseline,
        "missing",
        &directory.path().join("missing-run.json"),
    );
    let result = Command::new(env!("CARGO_BIN_EXE_preflate_match_check"))
        .arg(&baseline)
        .arg("--output")
        .arg(directory.path().join("no-label.json"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--run"));
}

#[test]
fn relative_scan_inputs_are_saved_absolutely_and_check_from_another_directory() {
    let directory = fixture();
    let baseline = directory.path().join("relative.sqlite");
    let result = Command::new(env!("CARGO_BIN_EXE_preflate_scan"))
        .current_dir(directory.path())
        .arg("corpus")
        .arg("--database")
        .arg(&baseline)
        .args(["--label", "baseline"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let (success, checked) = check(
        &baseline,
        &directory.path().join("relative-result.json"),
        &[],
    );
    assert!(success, "{checked}");
}

#[test]
fn missing_databases_and_legacy_json_are_not_created_or_imported() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.sqlite");
    rejected(&missing, "baseline", &directory.path().join("missing.json"));
    assert!(!missing.exists());
    let legacy = directory.path().join("legacy.json");
    fs::write(&legacy, b"{\"schema_version\":1}").unwrap();
    rejected(
        &legacy,
        "baseline",
        &directory.path().join("legacy-result.json"),
    );
    assert_eq!(fs::read(&legacy).unwrap(), b"{\"schema_version\":1}");
}

#[test]
fn url_outside_root_and_changed_timestamp_sources_fail_explicitly() {
    let directory = fixture();
    for (index, sql) in [
        "UPDATE files SET path='https://example.com/public.bin'",
        "UPDATE file_versions SET modified_unix_seconds=modified_unix_seconds+1",
    ]
    .into_iter()
    .enumerate()
    {
        let baseline = copy_baseline(directory.path(), &format!("source-{index}.sqlite"));
        Connection::open(&baseline)
            .unwrap()
            .execute_batch(sql)
            .unwrap();
        let (success, checked) = check(
            &baseline,
            &directory.path().join(format!("source-{index}.json")),
            &[],
        );
        assert!(!success);
        assert_eq!(checked["summary"]["failed_streams"], 1);
        assert_eq!(checked["summary"]["files_read"], 0);
    }
    let baseline = copy_baseline(directory.path(), "outside.sqlite");
    let outside = directory.path().join("outside.deflate");
    fs::copy(
        directory.path().join("corpus").join("perfect.deflate"),
        &outside,
    )
    .unwrap();
    Connection::open(&baseline)
        .unwrap()
        .execute(
            "UPDATE files SET path=?",
            [fs::canonicalize(outside).unwrap().to_str().unwrap()],
        )
        .unwrap();
    let (success, checked) = check(&baseline, &directory.path().join("outside.json"), &[]);
    assert!(!success);
    assert!(
        checked["changes"][0]["error"]
            .as_str()
            .unwrap()
            .contains("outside")
    );
    assert_eq!(checked["summary"]["files_read"], 0);
}
