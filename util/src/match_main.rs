//! Command-line comparison of current estimates with a recorded corpus run.
//! Uses verified token-perfect streams and exact source ranges to report changes
//! in reconstruction settings and estimation metadata.

#![forbid(unsafe_code)]

mod scan_fs;

use std::{
    collections::{BTreeMap, HashMap, hash_map::DefaultHasher},
    fs::{self, File, OpenOptions},
    hash::{Hash, Hasher},
    io::{BufWriter, Read, Write},
    path::{Component, Path, PathBuf},
    time::{Instant, UNIX_EPOCH},
};

use clap::Parser;
use preflate_container::{DiagnosticParameters, diagnostic_deflate_payload};
use preflate_rs::{PreflateConfig, PreflateStreamProcessor, estimate_first_chunk_estimator_json};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MIB: u64 = 1024 * 1024;
const TOKEN_CORRECTIONS: [&str; 5] = [
    "LiteralPredictionWrong",
    "ReferencePredictionWrong",
    "LenCorrection",
    "DistOnlyCorrection",
    "DistAfterLenCorrection",
];
// Pin file-scoped streams before exact result lookups, not a full run scan per file.
const STREAMS_QUERY: &str = "SELECT s.signature_offset,s.deflate_offset,s.kind,s.deflate_bytes,s.plaintext_bytes,\
     r.status,r.verified,r.corrections_json,r.token_mismatches,p.settings_json \
     FROM streams s CROSS JOIN stream_results r ON r.stream_id=s.id \
     LEFT JOIN profiles p ON p.id=r.profile_id \
     WHERE s.file_version_id=? AND r.run_id=? ORDER BY s.signature_offset,s.id";

#[derive(Debug, Parser)]
#[command(about = "Check estimator parameters against token-perfect streams in a completed scan")]
struct Cli {
    /// Corpus SQLite database. Source files must still be available locally.
    baseline: PathBuf,
    /// Label of the completed scanner run to check.
    #[arg(long)]
    run: String,
    /// New JSON results file; existing files are never overwritten.
    #[arg(short, long)]
    output: PathBuf,
    /// Explicitly narrow coverage to streams at least this many DEFLATE bytes.
    #[arg(long, default_value_t = 0)]
    min_stream_bytes: u64,
    /// Allow cloud-only files to be downloaded. Disabled by default.
    #[arg(long)]
    hydrate: bool,
}

#[derive(Deserialize)]
struct ScanConfig {
    input: PathBuf,
    chunk_mib: u64,
    max_chain: u32,
    max_file_mib: u64,
}

impl ScanConfig {
    fn validate(&self) -> Result<()> {
        if !self.input.is_absolute()
            || self
                .input
                .components()
                .any(|part| part == Component::ParentDir)
        {
            return Err("baseline input must be an absolute path; create a new scan with the current scanner".into());
        }
        if !(1..=128).contains(&self.chunk_mib) || !(1..=4096).contains(&self.max_file_mib) {
            return Err("baseline has unsupported chunk/file memory limits".into());
        }
        Ok(())
    }

    fn preflate(&self) -> PreflateConfig {
        PreflateConfig {
            plain_text_limit: (self.chunk_mib * MIB) as usize,
            max_chain_length: self.max_chain,
            verify_compression: false,
        }
    }
}

struct ScanFile {
    path: PathBuf,
    size_bytes: Option<u64>,
    modified_unix_seconds: Option<u64>,
    streams: Vec<ScanStream>,
}

struct ScanStream {
    offset: usize,
    deflate_offset: Option<usize>,
    kind: String,
    status: String,
    verified: bool,
    deflate_bytes: u64,
    plaintext_bytes: u64,
    parameters: Option<DiagnosticParameters>,
    nonzero_corrections: BTreeMap<String, u64>,
    trace: Option<ScanTrace>,
}

struct ScanTrace {
    token_mismatches: u64,
}

impl ScanStream {
    fn perfect(&self) -> bool {
        self.status == "ok"
            && self.verified
            && self
                .trace
                .as_ref()
                .is_none_or(|trace| trace.token_mismatches == 0)
            && TOKEN_CORRECTIONS
                .iter()
                .all(|name| self.nonzero_corrections.get(*name).copied().unwrap_or(0) == 0)
    }
}

#[derive(Default, Debug, Deserialize, Eq, PartialEq)]
struct BaselineTotals {
    entries: u64,
    successful_streams: u64,
    successful_deflate_bytes: u64,
    successful_plaintext_bytes: u64,
    verified_streams: u64,
}

#[derive(Default, Debug, Serialize)]
struct Summary {
    baseline_files: u64,
    baseline_streams: u64,
    perfect_streams: u64,
    excluded_by_size: u64,
    eligible_streams: u64,
    files_read: u64,
    checked_streams: u64,
    unchanged_streams: u64,
    changed_streams: u64,
    failed_streams: u64,
    estimator_only_checks: u64,
    tiny_replay_checks: u64,
    cache_hits: u64,
    elapsed_ms: f64,
}

#[derive(Default)]
struct ParameterCache {
    entries: HashMap<u64, (Vec<u8>, DiagnosticParameters)>,
    bytes: usize,
}

impl ParameterCache {
    const MAX_BYTES: usize = 64 * 1024 * 1024;
    const MAX_ENTRIES: usize = 4096;

    fn key(payload: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        payload.hash(&mut hasher);
        hasher.finish()
    }

    fn get(&self, key: u64, payload: &[u8]) -> Option<DiagnosticParameters> {
        self.entries
            .get(&key)
            .filter(|(bytes, _)| bytes.as_slice() == payload)
            .map(|(_, parameters)| parameters.clone())
    }

    fn insert(&mut self, key: u64, payload: &[u8], parameters: DiagnosticParameters) {
        if payload.len() > Self::MAX_BYTES {
            return;
        }
        if self.bytes + payload.len() > Self::MAX_BYTES || self.entries.len() >= Self::MAX_ENTRIES {
            self.entries.clear();
            self.bytes = 0;
        }
        if let Some((bytes, _)) = self.entries.remove(&key) {
            self.bytes -= bytes.len();
        }
        self.bytes += payload.len();
        self.entries.insert(key, (payload.to_vec(), parameters));
    }
}

impl Summary {
    fn passed(&self) -> bool {
        self.eligible_streams > 0 && self.changed_streams == 0 && self.failed_streams == 0
    }
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Finding<'a> {
    ParametersChanged {
        path: &'a Path,
        offset: usize,
        kind: &'a str,
        changed_fields: Vec<String>,
        before: &'a DiagnosticParameters,
        after: DiagnosticParameters,
    },
    Error {
        path: &'a Path,
        offset: Option<usize>,
        affected_streams: u64,
        error: String,
    },
}

struct Checker<'a> {
    cli: &'a Cli,
    output: &'a mut BufWriter<File>,
    first: bool,
    totals: BaselineTotals,
    summary: Summary,
    cache: ParameterCache,
}

fn changed_parameter_paths(before: &serde_json::Value, after: &serde_json::Value) -> Vec<String> {
    fn collect(
        before: &serde_json::Value,
        after: &serde_json::Value,
        path: &str,
        changes: &mut Vec<String>,
    ) {
        if before == after {
            return;
        }
        if let (Some(before), Some(after)) = (before.as_object(), after.as_object()) {
            let keys: std::collections::BTreeSet<_> = before.keys().chain(after.keys()).collect();
            for key in keys {
                let path = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
                match (before.get(key), after.get(key)) {
                    (Some(before), Some(after)) => collect(before, after, &path, changes),
                    _ => changes.push(path),
                }
            }
        } else {
            changes.push(path.to_owned());
        }
    }
    let mut changes = Vec::new();
    collect(before, after, "", &mut changes);
    changes
}

impl Checker<'_> {
    fn finding(&mut self, finding: Finding<'_>) -> Result<()> {
        if !self.first {
            writeln!(self.output, ",")?;
        }
        self.first = false;
        serde_json::to_writer(&mut self.output, &finding)?;
        self.output.flush()?;
        Ok(())
    }

    fn file(&mut self, file: ScanFile, config: &ScanConfig, root: &Path) -> Result<()> {
        self.totals.entries += 1;
        self.summary.baseline_files += 1;
        let mut selected = Vec::new();
        for stream in &file.streams {
            self.summary.baseline_streams += 1;
            self.totals.verified_streams += u64::from(stream.verified);
            if stream.status == "ok" {
                self.totals.successful_streams += 1;
                self.totals.successful_deflate_bytes += stream.deflate_bytes;
                self.totals.successful_plaintext_bytes += stream.plaintext_bytes;
            }
            if stream.perfect() {
                self.summary.perfect_streams += 1;
                if stream.deflate_bytes < self.cli.min_stream_bytes {
                    self.summary.excluded_by_size += 1;
                } else {
                    selected.push(stream);
                }
            }
        }
        self.summary.eligible_streams += selected.len() as u64;
        if selected.is_empty() {
            return Ok(());
        }
        let contents = match read_source(&file, config, root, self.cli.hydrate) {
            Ok(contents) => contents,
            Err(error) => {
                self.summary.failed_streams += selected.len() as u64;
                return self.finding(Finding::Error {
                    path: &file.path,
                    offset: None,
                    affected_streams: selected.len() as u64,
                    error: error.to_string(),
                });
            }
        };
        self.summary.files_read += 1;
        for stream in selected {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                check_parameters(&contents, stream, config, &mut self.cache)
            }));
            let result = match result {
                Ok(result) => result,
                Err(_) => Err("parameter check panicked".into()),
            };
            match result {
                Ok((current, cached)) => {
                    self.summary.checked_streams += 1;
                    if cached {
                        self.summary.cache_hits += 1;
                    } else if stream.deflate_bytes < 1024 {
                        self.summary.tiny_replay_checks += 1;
                    } else {
                        self.summary.estimator_only_checks += 1;
                    }
                    let previous = stream
                        .parameters
                        .as_ref()
                        .expect("checked parameters exist");
                    if current == *previous {
                        self.summary.unchanged_streams += 1;
                    } else {
                        self.summary.changed_streams += 1;
                        let before = serde_json::to_value(previous)?;
                        let after = serde_json::to_value(&current)?;
                        let changed_fields = changed_parameter_paths(&before, &after);
                        self.finding(Finding::ParametersChanged {
                            path: &file.path,
                            offset: stream.offset,
                            kind: &stream.kind,
                            changed_fields,
                            before: previous,
                            after: current,
                        })?;
                    }
                }
                Err(error) => {
                    self.summary.failed_streams += 1;
                    self.finding(Finding::Error {
                        path: &file.path,
                        offset: Some(stream.offset),
                        affected_streams: 1,
                        error: error.to_string(),
                    })?;
                }
            }
        }
        if self.summary.files_read.is_multiple_of(100) {
            eprintln!(
                "{} files, {} streams checked, {} parameter changes, {} errors",
                self.summary.files_read,
                self.summary.checked_streams,
                self.summary.changed_streams,
                self.summary.failed_streams,
            );
        }
        Ok(())
    }
}

fn read_source(
    file: &ScanFile,
    config: &ScanConfig,
    root: &Path,
    hydrate: bool,
) -> Result<Vec<u8>> {
    if !file.path.is_absolute()
        || !file.path.starts_with(root)
        || file
            .path
            .components()
            .any(|part| part == Component::ParentDir)
    {
        return Err("source path is outside the baseline root".into());
    }
    let before = fs::symlink_metadata(&file.path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err("source is not a regular non-symlink file".into());
    }
    if !hydrate && scan_fs::cloud_only(&before) {
        return Err("cloud-only source; use --hydrate to explicitly allow downloading".into());
    }
    let modified = before.modified()?;
    let seconds = modified.duration_since(UNIX_EPOCH)?.as_secs();
    if file.size_bytes != Some(before.len()) || file.modified_unix_seconds != Some(seconds) {
        return Err("source size or modification time changed since the baseline scan".into());
    }
    let limit = config.max_file_mib * MIB;
    if before.len() > limit {
        return Err("source exceeds baseline file memory limit".into());
    }
    let mut contents = Vec::new();
    File::open(&file.path)?
        .take(limit + 1)
        .read_to_end(&mut contents)?;
    let after = fs::symlink_metadata(&file.path)?;
    if contents.len() as u64 != before.len()
        || after.len() != before.len()
        || after.modified()? != modified
        || after.file_type().is_symlink()
    {
        return Err("source changed while being read".into());
    }
    Ok(contents)
}

fn check_parameters(
    source: &[u8],
    stream: &ScanStream,
    config: &ScanConfig,
    cache: &mut ParameterCache,
) -> Result<(DiagnosticParameters, bool)> {
    if stream.parameters.is_none() || stream.deflate_bytes == 0 {
        return Err("perfect baseline stream has missing parameters or an empty payload".into());
    }
    if (stream.kind == "png_idat") != stream.deflate_offset.is_none() {
        return Err("baseline wrapper and payload offset disagree".into());
    }
    let payload = diagnostic_deflate_payload(
        source,
        stream.offset,
        stream.deflate_offset,
        usize::try_from(stream.deflate_bytes)?,
    )?;
    let key = (payload.len() <= ParameterCache::MAX_BYTES).then(|| ParameterCache::key(&payload));
    if let Some(parameters) = key.and_then(|key| cache.get(key, &payload)) {
        return Ok((parameters, true));
    }
    let parameters = if stream.deflate_bytes < 1024 {
        let mut processor = PreflateStreamProcessor::new(&config.preflate());
        processor
            .decompress(&payload)?
            .estimator_parameters_json()?
            .ok_or("first chunk did not return parameters")?
    } else {
        estimate_first_chunk_estimator_json(&payload, config.preflate().plain_text_limit)?
    };
    let parameters = DiagnosticParameters::from_json(&parameters)?;
    if let Some(key) = key {
        cache.insert(key, &payload, parameters.clone());
    }
    Ok((parameters, false))
}

fn baseline_run(db: &Connection, label: &str) -> Result<(i64, ScanConfig, BaselineTotals)> {
    let versions = db
        .prepare("SELECT version FROM schema_info")?
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if versions != [1] {
        return Err("unsupported corpus database schema".into());
    }
    let (run, state, configuration, summary, imported_files) = db
        .query_row(
            "SELECT id,state,configuration_json,summary_json,imported_files FROM runs WHERE label=?",
            [label],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| format!("no baseline run labelled {label:?}"))?;
    if state != "complete" {
        return Err("baseline run is incomplete".into());
    }
    let config: ScanConfig = serde_json::from_str(&configuration)?;
    config.validate()?;
    let summary: BaselineTotals =
        serde_json::from_str(&summary.ok_or("completed baseline has no summary")?)?;
    if u64::try_from(imported_files)? != summary.entries {
        return Err("baseline summary does not match its file count".into());
    }
    Ok((run, config, summary))
}

fn unsigned(row: &Row<'_>, column: &str) -> Result<u64> {
    Ok(u64::try_from(row.get::<_, i64>(column)?)?)
}

fn optional_unsigned(row: &Row<'_>, column: &str) -> Result<Option<u64>> {
    Ok(row
        .get::<_, Option<i64>>(column)?
        .map(u64::try_from)
        .transpose()?)
}

fn check_run(
    db: &Connection,
    run: i64,
    config: &ScanConfig,
    checker: &mut Checker<'_>,
) -> Result<()> {
    let mut files_statement = db.prepare(
        "SELECT rf.file_version_id,f.path,v.size_bytes,v.modified_unix_seconds \
         FROM run_files rf JOIN file_versions v ON v.id=rf.file_version_id \
         JOIN files f ON f.id=v.file_id WHERE rf.run_id=? ORDER BY rf.ordinal",
    )?;
    let mut streams_statement = db.prepare(STREAMS_QUERY)?;
    let mut files = files_statement.query([run])?;
    while let Some(row) = files.next()? {
        let version: i64 = row.get("file_version_id")?;
        let mut file = ScanFile {
            path: PathBuf::from(row.get::<_, String>("path")?),
            size_bytes: optional_unsigned(row, "size_bytes")?,
            modified_unix_seconds: optional_unsigned(row, "modified_unix_seconds")?,
            streams: Vec::new(),
        };
        let mut streams = streams_statement.query([version, run])?;
        while let Some(row) = streams.next()? {
            let parameters: Option<String> = row.get("settings_json")?;
            file.streams.push(ScanStream {
                offset: usize::try_from(unsigned(row, "signature_offset")?)?,
                deflate_offset: optional_unsigned(row, "deflate_offset")?
                    .map(usize::try_from)
                    .transpose()?,
                kind: row.get("kind")?,
                status: row.get("status")?,
                verified: row.get("verified")?,
                deflate_bytes: unsigned(row, "deflate_bytes")?,
                plaintext_bytes: unsigned(row, "plaintext_bytes")?,
                parameters: parameters
                    .map(|value| serde_json::from_str(&value))
                    .transpose()?,
                nonzero_corrections: serde_json::from_str(
                    &row.get::<_, String>("corrections_json")?,
                )?,
                trace: optional_unsigned(row, "token_mismatches")?
                    .map(|token_mismatches| ScanTrace { token_mismatches }),
            });
        }
        checker.file(file, config, &config.input)?;
    }
    Ok(())
}

fn run(cli: &Cli) -> Result<Summary> {
    let start = Instant::now();
    let mut database = Connection::open_with_flags(
        &cli.baseline,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    database.busy_timeout(std::time::Duration::from_secs(60))?;
    let snapshot = database.transaction()?;
    let (run, config, expected) = baseline_run(&snapshot, &cli.run)?;
    let mut output = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&cli.output)?,
    );
    write!(output, "{{\"schema_version\":1,\"tool_version\":")?;
    serde_json::to_writer(&mut output, env!("CARGO_PKG_VERSION"))?;
    write!(output, ",\"baseline\":")?;
    serde_json::to_writer(&mut output, &cli.baseline)?;
    write!(output, ",\"run\":")?;
    serde_json::to_writer(&mut output, &cli.run)?;
    write!(
        output,
        ",\"min_stream_bytes\":{},\"changes\":[",
        cli.min_stream_bytes
    )?;
    let mut checker = Checker {
        cli,
        output: &mut output,
        first: true,
        totals: BaselineTotals::default(),
        summary: Summary::default(),
        cache: ParameterCache::default(),
    };
    check_run(&snapshot, run, &config, &mut checker)?;
    if checker.totals != expected {
        return Err("baseline summary does not match its file/stream records".into());
    }
    let mut summary = checker.summary;
    summary.elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    write!(output, "],\"passed\":{},\"summary\":", summary.passed())?;
    serde_json::to_writer(&mut output, &summary)?;
    writeln!(output, "}}")?;
    output.flush()?;
    output.get_ref().sync_all()?;
    Ok(summary)
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(summary) => {
            eprintln!(
                "{} checked, {} unchanged, {} changed, {} failed; {} excluded by size",
                summary.checked_streams,
                summary.unchanged_streams,
                summary.changed_streams,
                summary.failed_streams,
                summary.excluded_by_size,
            );
            if summary.eligible_streams == 0 {
                eprintln!("No eligible streams: this run cannot establish regression coverage.");
            }

            if summary.passed() {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!(
                "Match check failed: {error}. An incomplete output is not a completed check."
            );
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_differences_identify_nested_settings_and_metadata() {
        let before = serde_json::json!({
            "reconstruction": {"behavior": {"Chain": {"common": {"search": {"nice_length": 128}}}}},
            "model": "custom"
        });
        let mut after = before.clone();
        after["reconstruction"]["behavior"]["Chain"]["common"]["search"]["nice_length"] =
            serde_json::json!(258);
        after["model"] = serde_json::json!("zlib");
        assert_eq!(
            changed_parameter_paths(&before, &after),
            [
                "/model",
                "/reconstruction/behavior/Chain/common/search/nice_length"
            ]
        );
    }

    fn parameters() -> DiagnosticParameters {
        let raw = miniz_oxide::deflate::compress_to_vec(b"synthetic", 0);
        DiagnosticParameters::from_json(&estimate_first_chunk_estimator_json(&raw, 1024).unwrap())
            .unwrap()
    }

    #[test]
    fn cache_requires_exact_bytes_even_when_hashes_collide() {
        let mut cache = ParameterCache::default();
        let parameters = parameters();
        cache.insert(7, b"first", parameters.clone());
        assert_eq!(cache.get(7, b"first"), Some(parameters.clone()));
        assert_eq!(cache.get(7, b"other"), None);
        cache.insert(7, b"other", parameters.clone());
        assert_eq!(cache.bytes, 5);
        assert_eq!(cache.get(7, b"first"), None);
        assert_eq!(cache.get(7, b"other"), Some(parameters));
    }

    #[test]
    fn cache_is_bounded_and_eviction_cannot_return_stale_parameters() {
        let mut cache = ParameterCache::default();
        let parameters = parameters();
        for key in 0..ParameterCache::MAX_ENTRIES as u64 {
            cache.insert(key, b"payload", parameters.clone());
        }
        cache.insert(99999, b"new", parameters);
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.bytes, 3);
        assert_eq!(cache.get(0, b"payload"), None);
    }

    #[test]
    fn cache_evicts_at_the_payload_byte_limit_before_the_entry_limit() {
        let mut cache = ParameterCache::default();
        let parameters = parameters();
        let payload = vec![0; ParameterCache::MAX_BYTES / 2048];
        for key in 0..2048 {
            cache.insert(key, &payload, parameters.clone());
        }
        assert_eq!(cache.bytes, ParameterCache::MAX_BYTES);
        assert!(cache.entries.len() < ParameterCache::MAX_ENTRIES);
        cache.insert(99999, b"x", parameters);
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.bytes, 1);
    }

    #[test]
    fn stream_queries_use_file_then_exact_result_indexes() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(include_str!("../../corpus/database/schema.sql"))
            .unwrap();
        let plan = db
            .prepare(&format!("EXPLAIN QUERY PLAN {STREAMS_QUERY}"))
            .unwrap()
            .query_map([1, 1], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            plan.iter().any(|step| step.contains("file_version_id=?")),
            "{plan:?}"
        );
        assert!(
            plan.iter()
                .any(|step| step.contains("run_id=? AND stream_id=?")),
            "{plan:?}"
        );
    }
}
