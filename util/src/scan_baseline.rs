use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use rusqlite::params;
use serde::Serialize;
use serde_json::{Value, json};

use crate::{Cli, FileReport, Result, Summary, scan_source::DatabaseSource};

const CONFIGURATION_FIELDS: &[&str] = &[
    "max_chain",
    "max_file_mib",
    "chunk_mib",
    "max_stream_mib",
    "max_candidates",
    "raw",
    "no_verify",
    "hydrate",
    "include_rejected_candidates",
    "trace",
    "stream_offset",
];

// Keep file/version lookups before exact run results, never a full run scan per file.
const FILE_QUERY: &str = "SELECT v.id,v.size_bytes,v.modified_unix_seconds,rf.status,rf.error,rf.rejected_candidates_json \
     FROM files f CROSS JOIN file_versions v ON v.file_id=f.id \
     CROSS JOIN run_files rf INDEXED BY run_files_version ON rf.file_version_id=v.id \
     WHERE rf.run_id=? AND f.path=?";

const STREAMS_QUERY: &str = "SELECT s.signature_offset,s.deflate_offset,s.kind,s.member_name,s.deflate_bytes,s.plaintext_bytes,\
     r.status,r.verified,r.signature_confidence,r.error_code,r.error,r.reconstruction_bytes,\
     r.chunks,r.block_count,p.settings_json,r.corrections_json \
     FROM streams s CROSS JOIN stream_results r ON r.stream_id=s.id \
     LEFT JOIN profiles p ON p.id=r.profile_id WHERE r.run_id=? AND s.file_version_id=? \
     ORDER BY s.signature_offset,s.id";

#[derive(Default, Serialize)]
struct Coverage {
    files: u64,
    unchanged_input_files: u64,
    changed_input_files: u64,
    unknown_input_files: u64,
    unavailable_files: u64,
    changed_file_results: u64,
    baseline_streams: u64,
    current_streams: u64,
    uncompared_baseline_streams: u64,
    uncompared_current_streams: u64,
    compared_streams: u64,
    unchanged_streams: u64,
    improved_streams: u64,
    regressed_streams: u64,
    same_size_changed_streams: u64,
    failed_streams: u64,
    recovered_streams: u64,
    other_changed_streams: u64,
    new_streams: u64,
    missing_streams: u64,
    boundary_changed_streams: u64,
    verified_pairs: u64,
    baseline_reconstruction_bytes: u64,
    current_reconstruction_bytes: u64,
}

struct FileBaseline {
    version: i64,
    size: Option<u64>,
    modified: Option<u64>,
    outcome: Value,
}

fn file_baseline(source: &DatabaseSource, path: &Path) -> Result<FileBaseline> {
    let mut statement = source.connection.prepare(FILE_QUERY)?;
    let mut rows = statement.query(params![source.run, path.to_string_lossy()])?;
    let row = rows.next()?.ok_or("baseline file not found")?;
    let rejected: String = row.get(5)?;
    let baseline = FileBaseline {
        version: row.get(0)?,
        size: row
            .get::<_, Option<i64>>(1)?
            .map(u64::try_from)
            .transpose()?,
        modified: row
            .get::<_, Option<i64>>(2)?
            .map(u64::try_from)
            .transpose()?,
        outcome: json!({
            "status": row.get::<_, String>(3)?,
            "error": row.get::<_, Option<String>>(4)?,
            "rejected_candidates": serde_json::from_str::<Value>(&rejected)?,
        }),
    };
    if rows.next()?.is_some() {
        return Err("baseline contains multiple observations for one file path".into());
    }
    Ok(baseline)
}

type StreamKey = (u64, String, Option<String>);

fn unsigned(row: &rusqlite::Row<'_>, index: usize) -> Result<u64> {
    Ok(u64::try_from(row.get::<_, i64>(index)?)?)
}

fn key(stream: &Value) -> Result<StreamKey> {
    Ok((
        stream["offset"].as_u64().ok_or("missing stream offset")?,
        stream["kind"].as_str().ok_or("missing stream kind")?.into(),
        stream["member_name"].as_str().map(str::to_owned),
    ))
}

fn baseline_streams(source: &DatabaseSource, version: i64) -> Result<BTreeMap<StreamKey, Value>> {
    let mut statement = source.connection.prepare(STREAMS_QUERY)?;
    let mut rows = statement.query(params![source.run, version])?;
    let mut streams = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let settings: Option<String> = row.get(14)?;
        let corrections: String = row.get(15)?;
        let stream = json!({
            "offset": unsigned(row, 0)?,
            "deflate_offset": row.get::<_, Option<i64>>(1)?.map(u64::try_from).transpose()?,
            "kind": row.get::<_, String>(2)?,
            "member_name": row.get::<_, Option<String>>(3)?,
            "deflate_bytes": unsigned(row, 4)?,
            "plaintext_bytes": unsigned(row, 5)?,
            "status": row.get::<_, String>(6)?,
            "verified": row.get::<_, bool>(7)?,
            "signature_confidence": row.get::<_, Option<String>>(8)?,
            "error_code": row.get::<_, Option<String>>(9)?,
            "error": row.get::<_, Option<String>>(10)?,
            "reconstruction_bytes": unsigned(row, 11)?,
            "chunks": unsigned(row, 12)?,
            "blocks": unsigned(row, 13)?,
            "parameters": settings.as_deref().map(serde_json::from_str::<Value>).transpose()?,
            "corrections": serde_json::from_str::<Value>(&corrections)?,
        });
        if streams.insert(key(&stream)?, stream).is_some() {
            return Err("baseline has ambiguous stream locations".into());
        }
    }
    Ok(streams)
}

fn observation(stream: &crate::StreamReport) -> Result<Value> {
    let value = serde_json::to_value(stream)?;
    let mut result = json!({});
    for field in [
        "offset",
        "deflate_offset",
        "kind",
        "member_name",
        "deflate_bytes",
        "plaintext_bytes",
        "status",
        "verified",
        "signature_confidence",
        "error_code",
        "error",
        "chunks",
        "blocks",
        "parameters",
    ] {
        result[field] = value[field].clone();
    }
    result["reconstruction_bytes"] = value["correction_bytes"].clone();
    result["corrections"] = value["nonzero_corrections"].clone();
    Ok(result)
}

fn differences(before: &Value, after: &Value) -> Value {
    let mut changes = json!({});
    if let Some(fields) = before.as_object() {
        for (field, old) in fields {
            if old != &after[field] {
                changes[field] = json!({"before": old, "after": after[field]});
            }
        }
    }
    changes
}

fn compare_stream(before: &Value, after: &Value, coverage: &mut Coverage) -> &'static str {
    coverage.compared_streams += 1;
    let old_ok = before["status"] == "ok" && before["verified"] == true;
    let new_ok = after["status"] == "ok" && after["verified"] == true;
    if old_ok && !new_ok {
        coverage.failed_streams += 1;
        return "failed";
    }
    if !old_ok && new_ok {
        coverage.recovered_streams += 1;
        return "recovered";
    }
    if ["deflate_offset", "deflate_bytes", "plaintext_bytes"]
        .iter()
        .any(|field| before[field] != after[field])
    {
        coverage.boundary_changed_streams += 1;
        return "boundaries_changed";
    }
    if old_ok && new_ok {
        coverage.verified_pairs += 1;
        let old_bytes = before["reconstruction_bytes"]
            .as_u64()
            .expect("typed bytes");
        let new_bytes = after["reconstruction_bytes"].as_u64().expect("typed bytes");
        coverage.baseline_reconstruction_bytes += old_bytes;
        coverage.current_reconstruction_bytes += new_bytes;
        if new_bytes < old_bytes {
            coverage.improved_streams += 1;
            return "improved";
        }
        if new_bytes > old_bytes {
            coverage.regressed_streams += 1;
            return "regressed";
        }
    }
    if before == after {
        coverage.unchanged_streams += 1;
        "unchanged"
    } else if old_ok && new_ok {
        coverage.same_size_changed_streams += 1;
        "same_size_changed"
    } else {
        coverage.other_changed_streams += 1;
        "outcome_changed"
    }
}

pub fn run(source: &DatabaseSource, cli: &Cli, configuration: &Value) -> Result<Summary> {
    let run = source.run.ok_or("missing baseline run ID")?;
    let (label, build, config): (String, Option<String>, String) = source.connection.query_row(
        "SELECT label,build_identity,configuration_json FROM runs WHERE id=?",
        [run],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let baseline_configuration: Value = serde_json::from_str(&config)?;
    let mut configuration_differences = json!({});
    for field in CONFIGURATION_FIELDS {
        if baseline_configuration[field] != configuration[field] {
            configuration_differences[field] = json!({
                "before": baseline_configuration[field], "after": configuration[field],
            });
        }
    }
    let output_name = cli.output.as_ref().ok_or("missing baseline JSON output")?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_name)?;
    let output_path = fs::canonicalize(output_name)?;
    let mut output = BufWriter::new(file);
    let header = json!({
        "schema_version": 1, "report_type": "baseline_diff",
        "tool_version": env!("CARGO_PKG_VERSION"),
        "started_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "baseline": {"database": source.path, "run_id": run, "label": label,
            "build_identity": build, "configuration": baseline_configuration},
        "current": {"build_identity": cli.build_identity, "configuration": configuration},
        "input_identity": "path, size, second-precision mtime and stream boundaries; not a content hash",
        "comparison_compatible": configuration_differences.as_object().is_some_and(|v| v.is_empty()),
        "configuration_differences": configuration_differences,
    });
    let header = serde_json::to_string(&header)?;
    write!(
        output,
        "{},\"differences\":[",
        header.strip_suffix('}').ok_or("invalid header")?
    )?;
    let start = Instant::now();
    let mut summary = Summary::default();
    let mut coverage = Coverage::default();
    let mut progress = crate::scan_progress::Progress::new(Some(source.file_count));
    let mut first = true;
    let mut emit = |event: Value| -> Result<()> {
        if !first {
            writeln!(output, ",")?;
        }
        first = false;
        serde_json::to_writer(&mut output, &event)?;
        output.flush()?;
        Ok(())
    };
    source.scan_with_paths(&output_path, cli, |path, report| {
        summary.record(&report);
        progress.update(&summary, false);
        coverage.files += 1;
        let baseline = file_baseline(source, path)?;
        let mut streams = baseline_streams(source, baseline.version)?;
        coverage.baseline_streams += streams.len() as u64;
        coverage.current_streams += report.streams.len() as u64;
        if matches!(report.status, "error" | "skipped" | "panic") {
            coverage.unavailable_files += 1;
            coverage.uncompared_baseline_streams += streams.len() as u64;
            coverage.uncompared_current_streams += report.streams.len() as u64;
            emit(json!({"type": "file", "classification": "unavailable", "path": path,
                "before": baseline.outcome, "after": file_outcome(&report)}))?;
            return Ok(());
        }
        let identity_known = baseline.size.is_some() && baseline.modified.is_some()
            && report.size_bytes.is_some() && report.modified_unix_seconds.is_some();
        let identity_matches = baseline.size == report.size_bytes
            && baseline.modified == report.modified_unix_seconds;
        if !identity_known || !identity_matches {
            coverage.uncompared_baseline_streams += streams.len() as u64;
            coverage.uncompared_current_streams += report.streams.len() as u64;
            let classification = if identity_known {
                coverage.changed_input_files += 1;
                "input_changed"
            } else {
                coverage.unknown_input_files += 1;
                "input_identity_unknown"
            };
            emit(json!({"type": "file", "classification": classification, "path": path,
                "before": {"size_bytes": baseline.size, "modified_unix_seconds": baseline.modified},
                "after": {"size_bytes": report.size_bytes, "modified_unix_seconds": report.modified_unix_seconds},
                "baseline_streams": streams.len(), "current_streams": report.streams.len()}))?;
            return Ok(());
        }
        coverage.unchanged_input_files += 1;
        let outcome = file_outcome(&report);
        if baseline.outcome != outcome {
            coverage.changed_file_results += 1;
            emit(json!({"type": "file", "classification": "outcome_changed", "path": path,
                "changes": differences(&baseline.outcome, &outcome)}))?;
        }
        let mut seen = std::collections::BTreeSet::new();
        for stream in &report.streams {
            let current = observation(stream)?;
            let key = key(&current)?;
            if !seen.insert(key.clone()) {
                return Err("current scan has ambiguous stream locations".into());
            }
            if let Some(before) = streams.remove(&key) {
                let classification = compare_stream(&before, &current, &mut coverage);
                if classification != "unchanged" {
                    emit(json!({"type": "stream", "classification": classification, "path": path,
                        "offset": key.0, "kind": key.1, "member_name": key.2,
                        "changes": differences(&before, &current)}))?;
                }
            } else {
                coverage.new_streams += 1;
                emit(json!({"type": "stream", "classification": "new", "path": path, "after": current}))?;
            }
        }
        for before in streams.into_values() {
            coverage.missing_streams += 1;
            emit(json!({"type": "stream", "classification": "missing", "path": path, "before": before}))?;
        }
        Ok(())
    })?;
    crate::finish_summary(&mut summary, start);
    write!(output, "],\"summary\":")?;
    serde_json::to_writer(&mut output, &json!({"coverage": coverage, "scan": summary}))?;
    writeln!(output, "}}")?;
    output.flush()?;
    output.get_ref().sync_all()?;
    progress.update(&summary, true);
    Ok(summary)
}

fn file_outcome(report: &FileReport) -> Value {
    json!({"status": report.status, "error": report.error, "rejected_candidates": report.rejected_candidates})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_queries_use_file_scoped_indexes_not_full_run_searches() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(include_str!("../../corpus/database/schema.sql"))
            .unwrap();
        for (query, expected) in [
            (FILE_QUERY, "file_version_id=? AND run_id=?"),
            (STREAMS_QUERY, "run_id=? AND stream_id=?"),
        ] {
            let plan = db
                .prepare(&format!("EXPLAIN QUERY PLAN {query}"))
                .unwrap()
                .query_map([1, 1], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(plan.iter().any(|step| step.contains(expected)), "{plan:?}");
            assert!(
                !plan
                    .iter()
                    .any(|step| step.contains("PRIMARY KEY (run_id=?)")),
                "{plan:?}"
            );
        }
    }

    fn stream() -> Value {
        json!({
            "offset": 0, "deflate_offset": 0, "kind": "raw", "member_name": null,
            "deflate_bytes": 100, "plaintext_bytes": 1000, "status": "ok",
            "verified": true, "reconstruction_bytes": 10, "parameters": {"max_chain": 64},
            "corrections": {}, "chunks": 1, "blocks": 1,
        })
    }

    #[test]
    fn result_classification_separates_bytes_behaviour_failures_and_boundaries() {
        for (field, value, expected) in [
            ("reconstruction_bytes", json!(9), "improved"),
            ("reconstruction_bytes", json!(11), "regressed"),
            ("parameters", json!({"max_chain": 128}), "same_size_changed"),
            ("corrections", json!({"mismatch": 1}), "same_size_changed"),
            ("verified", json!(false), "failed"),
            ("status", json!("error"), "failed"),
            ("deflate_bytes", json!(101), "boundaries_changed"),
            ("plaintext_bytes", json!(1001), "boundaries_changed"),
        ] {
            let before = stream();
            let mut after = before.clone();
            after[field] = value;
            let mut coverage = Coverage::default();
            assert_eq!(compare_stream(&before, &after, &mut coverage), expected);
            assert_eq!(coverage.compared_streams, 1);
        }
        let current = stream();
        let mut failed = current.clone();
        failed["status"] = json!("error");
        failed["verified"] = json!(false);
        let mut coverage = Coverage::default();
        assert_eq!(
            compare_stream(&failed, &current, &mut coverage),
            "recovered"
        );
        assert_eq!(
            compare_stream(&current, &current, &mut coverage),
            "unchanged"
        );
        assert_eq!(coverage.recovered_streams, 1);
        assert_eq!(coverage.unchanged_streams, 1);
    }
}
