use std::{path::Path, time::Duration};

use rusqlite::{Connection, params};
use serde_json::{Value, json};

use crate::{Cli, FileReport, Result, Summary};

const PROFILE_FIELDS: &[&str] = &[
    "hash_algorithm",
    "matching_type",
    "strategy",
    "add_policy",
    "block_type_strategy",
    "window_bits",
    "nice_length",
    "max_chain",
    "max_token_count",
    "max_dist_3_matches",
    "matches_to_start_detected",
    "very_far_matches_detected",
];

fn sql(value: &Value) -> Result<rusqlite::types::Value> {
    use rusqlite::types::Value as Sql;
    Ok(match value {
        Value::Null => Sql::Null,
        Value::Bool(v) => Sql::Integer(i64::from(*v)),
        Value::Number(v) => {
            if let Some(v) = v.as_i64() {
                Sql::Integer(v)
            } else if v.is_f64() {
                Sql::Real(v.as_f64().ok_or("invalid SQLite real")?)
            } else {
                return Err("integer exceeds SQLite's signed 64-bit range".into());
            }
        }
        Value::String(v) => Sql::Text(v.clone()),
        _ => return Err("structured SQLite fields must be explicitly encoded".into()),
    })
}

fn insert(db: &Connection, table: &str, values: Value, ignore: bool) -> Result<()> {
    let fields = values.as_object().ok_or("expected SQLite columns")?;
    let columns = fields
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(",");
    let placeholders = vec!["?"; fields.len()].join(",");
    let values = fields.values().map(sql).collect::<Result<Vec<_>>>()?;
    db.execute(
        &format!(
            "INSERT {} INTO {table}({columns}) VALUES ({placeholders})",
            if ignore { "OR IGNORE" } else { "" }
        ),
        rusqlite::params_from_iter(values),
    )?;
    Ok(())
}

fn encoded(value: &Value, fallback: Value) -> String {
    if value.is_null() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

pub struct ScanDatabase {
    connection: Connection,
    run: i64,
    ordinal: u64,
}

impl ScanDatabase {
    pub fn create(path: &Path, label: &str, cli: &Cli) -> Result<Self> {
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(60))?;
        db.execute_batch("PRAGMA foreign_keys=ON;")?;
        let tables: i64 = db.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        if tables != 0 {
            let version: i64 =
                db.query_row("SELECT version FROM schema_info", [], |row| row.get(0))?;
            if version != 1 {
                return Err("unsupported corpus database schema".into());
            }
        }
        if label.trim().is_empty() {
            return Err("run label must not be empty".into());
        }
        db.execute_batch(include_str!("../../corpus/database/schema.sql"))?;
        let mut configuration = serde_json::to_value(cli)?;
        configuration["input"] = serde_json::to_value(std::fs::canonicalize(&cli.input)?)?;
        db.execute(
            "INSERT INTO runs(label,build_identity,report_path,report_size,report_mtime_ns,\
             configuration_json,started_unix_seconds,state) VALUES (?,?,?,0,0,?,?,'importing')",
            params![
                label,
                cli.build_identity,
                path.to_string_lossy(),
                serde_json::to_string(&configuration)?,
                i64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs()
                )?
            ],
        )?;
        let run = db.last_insert_rowid();
        Ok(Self {
            connection: db,
            run,
            ordinal: 0,
        })
    }

    fn profile(db: &Connection, settings: &Value) -> Result<Option<i64>> {
        if settings.is_null() {
            return Ok(None);
        }
        let mut columns = json!({"settings_json": settings.to_string()});
        for field in PROFILE_FIELDS {
            columns[*field] = settings[*field].clone();
        }
        insert(db, "profiles", columns, true)?;
        Ok(Some(db.query_row(
            "SELECT id FROM profiles WHERE settings_json=?",
            [settings.to_string()],
            |row| row.get(0),
        )?))
    }

    fn file_version(db: &Connection, record: &Value, run: i64, ordinal: u64) -> Result<i64> {
        insert(db, "files", json!({"path": record["path"]}), true)?;
        let file: i64 = db.query_row(
            "SELECT id FROM files WHERE path=?",
            [sql(&record["path"])?],
            |row| row.get(0),
        )?;
        let size = &record["size_bytes"];
        let modified = &record["modified_unix_seconds"];
        let identity = if size.is_null() || modified.is_null() {
            json!([size, modified, run, ordinal])
        } else {
            json!([size, modified])
        }
        .to_string();
        insert(
            db,
            "file_versions",
            json!({
                "file_id": file, "size_bytes": size, "modified_unix_seconds": modified, "identity_key": identity,
            }),
            true,
        )?;
        Ok(db.query_row(
            "SELECT id FROM file_versions WHERE file_id=? AND identity_key=?",
            params![file, identity],
            |row| row.get(0),
        )?)
    }

    pub fn record(&mut self, report: &FileReport) -> Result<()> {
        let record = serde_json::to_value(report)?;
        let ordinal = self.ordinal + 1;
        let db = self.connection.transaction()?;
        let version = Self::file_version(&db, &record, self.run, ordinal)?;
        insert(
            &db,
            "run_files",
            json!({
                "run_id": self.run, "ordinal": ordinal, "file_version_id": version,
                "status": record["status"], "error": record["error"], "elapsed_ms": record["elapsed_ms"],
                "rejected_candidates_json": encoded(&record["rejected_candidates"], json!({})),
            }),
            false,
        )?;
        for stream in record["streams"]
            .as_array()
            .ok_or("missing scanner streams")?
        {
            let identity = json!([
                stream["offset"],
                stream["deflate_offset"],
                stream["kind"],
                stream["member_name"],
                stream["deflate_bytes"],
                stream["plaintext_bytes"],
            ])
            .to_string();
            insert(
                &db,
                "streams",
                json!({
                    "file_version_id": version, "identity_key": identity,
                    "signature_offset": stream["offset"], "deflate_offset": stream["deflate_offset"],
                    "kind": stream["kind"], "member_name": stream["member_name"],
                    "deflate_bytes": stream["deflate_bytes"], "plaintext_bytes": stream["plaintext_bytes"],
                }),
                true,
            )?;
            let stream_id: i64 = db.query_row(
                "SELECT id FROM streams WHERE file_version_id=? AND identity_key=?",
                params![version, identity],
                |row| row.get(0),
            )?;
            let trace = &stream["trace"];
            let blocks = trace["blocks"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default();
            let detail = if !trace.is_null()
                && trace["blocks_truncated"] != true
                && stream["blocks"].as_u64() == Some(blocks.len() as u64)
            {
                "complete"
            } else if blocks.is_empty() {
                "unavailable"
            } else {
                "partial"
            };
            insert(
                &db,
                "stream_results",
                json!({
                    "run_id": self.run, "stream_id": stream_id, "profile_id": Self::profile(&db, &stream["parameters"])?,
                    "status": stream["status"], "verified": stream["verified"],
                    "signature_confidence": stream["signature_confidence"], "error_code": stream["error_code"],
                    "error": stream["error"], "reconstruction_bytes": stream["correction_bytes"],
                    "chunks": stream["chunks"], "block_count": stream["blocks"], "elapsed_ms": stream["elapsed_ms"],
                    "corrections_json": encoded(&stream["nonzero_corrections"], json!({})),
                    "token_mismatches": trace["token_mismatches"], "token_count": trace["token_count"],
                    "block_detail": detail,
                    "settings_source": if stream["parameters"].is_null() { "unavailable" } else { "stream_finalized" },
                }),
                false,
            )?;
            for block in blocks {
                insert(
                    &db,
                    "block_results",
                    json!({
                        "run_id": self.run, "stream_id": stream_id, "block_index": block["index"],
                        "chunk_index": block["chunk"], "plaintext_offset": block["plaintext_offset"],
                        "plaintext_bytes": block["plaintext_bytes"], "kind": block["kind"], "last": block["last"],
                        "literals": block["literals"], "references_count": block["references"],
                    }),
                    false,
                )?;
            }
            if let Some(chunks) = trace["chunks"].as_array() {
                for chunk in chunks {
                    insert(
                        &db,
                        "chunk_results",
                        json!({
                            "run_id": self.run, "stream_id": stream_id, "chunk_index": chunk["index"],
                            "deflate_offset": chunk["deflate_offset"], "deflate_bytes": chunk["deflate_bytes"],
                            "plaintext_offset": chunk["plaintext_offset"], "plaintext_bytes": chunk["plaintext_bytes"],
                            "reconstruction_bytes": chunk["correction_bytes"], "block_count": chunk["blocks"],
                            "block_profile": chunk["block_profile"], "elapsed_ms": chunk["elapsed_ms"],
                            "status": chunk["status"], "stage": chunk["stage"], "error": chunk["error"],
                            "corrections_json": encoded(&chunk["nonzero_corrections"], json!({})),
                        }),
                        false,
                    )?;
                }
            }
        }
        db.execute(
            "UPDATE runs SET imported_files=? WHERE id=?",
            params![i64::try_from(ordinal)?, self.run],
        )?;
        db.commit()?;
        self.ordinal = ordinal;
        Ok(())
    }

    pub fn finish(&self, summary: &Summary) -> Result<()> {
        let totals: (i64, i64, i64, i64, i64) = self.connection.query_row(
            "SELECT count(*),coalesce(sum(r.verified),0),coalesce(sum(s.deflate_bytes),0),\
             coalesce(sum(s.plaintext_bytes),0),coalesce(sum(r.reconstruction_bytes),0) \
             FROM stream_results r JOIN streams s ON s.id=r.stream_id \
             WHERE r.run_id=? AND r.status='ok'",
            [self.run],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        if self.ordinal != summary.entries
            || totals
                != (
                    i64::try_from(summary.successful_streams)?,
                    i64::try_from(summary.verified_streams)?,
                    i64::try_from(summary.successful_deflate_bytes)?,
                    i64::try_from(summary.successful_plaintext_bytes)?,
                    i64::try_from(summary.successful_correction_bytes)?,
                )
        {
            return Err("SQLite rows do not reconcile with scanner summary".into());
        }
        self.connection.execute(
            "UPDATE runs SET state='complete',summary_json=?,imported_summary_json=? WHERE id=?",
            params![
                serde_json::to_string(summary)?,
                serde_json::to_string(summary)?,
                self.run
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use miniz_oxide::deflate::compress_to_vec;
    use std::fs;

    fn cli(input: &Path, database: &Path, label: &str) -> Cli {
        Cli::try_parse_from([
            "preflate_scan",
            input.to_str().unwrap(),
            "--database",
            database.to_str().unwrap(),
            "--label",
            label,
        ])
        .unwrap()
    }

    #[test]
    fn private_directory_scans_append_runs_without_scanning_the_database() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::create_dir(root.join("nested")).unwrap();
        fs::write(
            root.join("nested").join("sample.deflate"),
            compress_to_vec(&b"private directory regression ".repeat(1000), 6),
        )
        .unwrap();
        fs::write(root.join("plain.txt"), b"no streams").unwrap();
        let path = root.join("private.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        for label in ["before", "after"] {
            let summary = crate::run(&cli(root, &path, label)).unwrap();
            assert_eq!(summary.entries, 2);
            assert_eq!(summary.successful_streams, 1);
            assert_eq!(summary.verified_streams, 1);
        }
        let count = |query: &str| db.query_row(query, [], |row| row.get::<_, i64>(0)).unwrap();
        assert_eq!(count("SELECT count(*) FROM runs WHERE state='complete'"), 2);
        assert_eq!(count("SELECT count(*) FROM files"), 2);
        assert_eq!(count("SELECT count(*) FROM streams"), 1);
        assert_eq!(count("SELECT count(*) FROM stream_results"), 2);
        assert_eq!(count("SELECT count(*) FROM pragma_foreign_key_check"), 0);
        assert!(crate::run(&cli(root, &path, "before")).is_err());
        assert_eq!(count("SELECT count(*) FROM runs"), 2);
    }

    #[test]
    fn trace_writes_real_block_and_chunk_rows() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("sample.deflate");
        fs::write(&input, compress_to_vec(&b"traced data ".repeat(1000), 6)).unwrap();
        let path = directory.path().join("trace.sqlite");
        let mut options = cli(&input, &path, "trace");
        options.trace = true;
        crate::run(&options).unwrap();
        let db = Connection::open(&path).unwrap();
        for table in ["block_results", "chunk_results"] {
            let count: i64 = db
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert!(count > 0, "{table}");
        }
        let detail: String = db
            .query_row("SELECT block_detail FROM stream_results", [], |r| r.get(0))
            .unwrap();
        assert_eq!(detail, "complete");
    }

    #[test]
    fn invalid_summary_leaves_run_incomplete() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unfinished.sqlite");
        let options = cli(directory.path(), &path, "unfinished");
        let mut database = ScanDatabase::create(&path, "unfinished", &options).unwrap();
        database
            .record(&FileReport::error(
                directory.path().join("missing"),
                "missing",
            ))
            .unwrap();
        assert!(database.finish(&Summary::default()).is_err());
        let state: String = database
            .connection
            .query_row("SELECT state FROM runs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(state, "importing");
        assert!(ScanDatabase::create(&path, "unfinished", &options).is_err());
    }

    #[test]
    fn refuses_unrelated_database_and_conflicting_output_options() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unrelated.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(
            "CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES('keep');",
        )
        .unwrap();
        assert!(
            ScanDatabase::create(&path, "test", &cli(directory.path(), &path, "test")).is_err()
        );
        let value: String = db
            .query_row("SELECT value FROM unrelated", [], |r| r.get(0))
            .unwrap();
        assert_eq!(value, "keep");
        for arguments in [
            vec!["preflate_scan", ".", "--database", "scan.sqlite"],
            vec![
                "preflate_scan",
                ".",
                "--database",
                "scan.sqlite",
                "--label",
                "test",
                "--perf-output",
                "perf.jsonl",
            ],
            vec![
                "preflate_scan",
                ".",
                "--database",
                "scan.sqlite",
                "--label",
                "test",
                "--output",
                "scan.json",
            ],
        ] {
            assert!(Cli::try_parse_from(arguments).is_err());
        }
        let options = cli(directory.path(), &path, "test");
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let sidecar = directory.path().join(format!("unrelated.sqlite{suffix}"));
            assert!(crate::is_scan_output(&sidecar, &path, &options));
        }
        assert!(!crate::is_scan_output(
            &directory.path().join("other.sqlite"),
            &path,
            &options
        ));
    }
}
