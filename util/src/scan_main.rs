//! Command-line DEFLATE scanning and diagnostic report generation.
//! Coordinates file or database-selected scans, limits, verification, and optional
//! tracing without subsequent Zstd compression.

#![forbid(unsafe_code)]

mod scan_baseline;
mod scan_database;
mod scan_fs;
mod scan_parallel;
mod scan_perf;
mod scan_progress;
mod scan_source;
use scan_fs::cloud_only;

use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata, OpenOptions},
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use preflate_container::{
    DeflateDiagnostic, DiagnosticScanOptions, scan_deflate_diagnostics_with_options,
};
use preflate_rs::PreflateConfig;
use serde::Serialize;

const MIB: u64 = 1024 * 1024;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Parser, Serialize)]
#[command(
    name = "preflate_scan",
    about = "Diagnose DEFLATE files or SQLite-selected sources without Zstd"
)]
struct Cli {
    /// File/directory, or SQLite database with a source/baseline selector. Sources are never modified.
    input: PathBuf,

    /// Read local file paths from a completed SQLite run instead of walking a directory.
    #[arg(long, conflicts_with = "from_crawl", conflicts_with_all = ["trace", "perf_output"])]
    from_run: Option<String>,

    /// Rescan a completed run ID and write JSON differences without recording a run.
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..), requires = "output",
        conflicts_with_all = ["from_run", "from_crawl", "source_root", "database", "trace", "perf_output", "no_verify"])]
    baseline_run: Option<i64>,

    /// Read distinct saved payload paths from a Common Crawl SQLite catalog.
    #[arg(long, conflicts_with_all = ["trace", "perf_output"])]
    from_crawl: bool,

    /// Storage root for --from-crawl; defaults to the catalog's parent directory.
    #[arg(long, requires = "from_crawl")]
    source_root: Option<PathBuf>,

    /// New JSON report to create (an existing file is never overwritten).
    #[arg(
        short,
        long,
        required_unless_present = "database",
        conflicts_with = "database"
    )]
    output: Option<PathBuf>,

    /// Write directly to a corpus SQLite database (existing databases are preserved).
    #[arg(long, requires = "label")]
    database: Option<PathBuf>,

    /// Unique run label for --database.
    #[arg(long, requires = "database")]
    label: Option<String>,

    /// Also write streaming JSONL whole-file CPU/wall measurements (no Zstd).
    #[arg(long, conflicts_with = "database")]
    perf_output: Option<PathBuf>,

    /// Attempts per regular file for --perf-output (first attempt plus warm repetitions).
    #[arg(long, default_value_t = 1, requires = "perf_output", value_parser = clap::value_parser!(u32).range(1..=1000))]
    perf_iterations: u32,

    /// Explicit binary/build label for performance provenance; never inferred from package version.
    #[arg(long)]
    build_identity: Option<String>,

    /// File workers (default: 4; performance repetitions and single-file traces default to 1).
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=64))]
    jobs: Option<u32>,

    #[arg(long, default_value_t = 4096)]
    max_chain: u32,

    /// Skip files larger than this, including files that grow while being read.
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u64).range(1..=4096))]
    max_file_mib: u64,

    /// Maximum plaintext per preflate chunk; a single larger block is a limit result.
    #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u64).range(1..=128))]
    chunk_mib: u64,

    /// Stop processing a stream after this plaintext budget (checked at chunk boundaries).
    #[arg(long, default_value_t = 512, value_parser = clap::value_parser!(u64).range(1..=1024))]
    max_stream_mib: u64,

    #[arg(long, default_value_t = 10000, value_parser = clap::value_parser!(u32).range(1..))]
    max_candidates: u32,

    /// Flag correction overhead above this percent of the original DEFLATE size.
    #[arg(long, default_value_t = 1.0, value_parser = parse_percent)]
    poor_ratio_percent: f64,

    /// Minimum DEFLATE size for poor-model flags and rankings (all streams are still recorded).
    #[arg(long, default_value_t = 1024)]
    min_stream_bytes: u64,

    /// Attempt all files as raw DEFLATE. Normally only .deflate files use raw mode.
    #[arg(long)]
    raw: bool,

    /// Disable bit-exact reconstruction verification (faster, but less diagnostic).
    #[arg(long)]
    no_verify: bool,

    /// Allow reading cloud-only files, which may download OneDrive contents.
    #[arg(long)]
    hydrate: bool,

    /// Include token-mismatch examples and per-chunk/block details. Input must be one file.
    #[arg(long)]
    trace: bool,

    /// Maximum mismatch examples and block descriptions retained per stream.
    #[arg(long, default_value_t = 64, requires = "trace", value_parser = clap::value_parser!(u32).range(1..=10000))]
    trace_limit: u32,

    /// Trace just this stream's signature offset from a previous scan report.
    #[arg(long, requires = "trace")]
    stream_offset: Option<usize>,

    /// Retain every rejected heuristic signature instead of counts and eight examples per file.
    #[arg(long)]
    include_rejected_candidates: bool,
}

impl Cli {
    fn worker_count(&self) -> usize {
        self.jobs
            .unwrap_or(if self.perf_output.is_some() || self.trace {
                1
            } else {
                4
            }) as usize
    }
}

fn parse_percent(value: &str) -> std::result::Result<f64, String> {
    let number: f64 = value
        .parse()
        .map_err(|_| "expected a percentage".to_string())?;
    if !number.is_finite() || number < 0.0 {
        return Err("percentage must be finite and nonnegative".into());
    }
    Ok(number)
}

#[derive(Serialize)]
struct StreamReport {
    #[serde(flatten)]
    diagnostic: DeflateDiagnostic,
    ranking_eligible: bool,
    poor_model: bool,
    plaintext_mib_per_second: Option<f64>,
}

#[derive(Serialize)]
struct FileReport {
    path: PathBuf,
    size_bytes: Option<u64>,
    modified_unix_seconds: Option<u64>,
    status: &'static str,
    error: Option<String>,
    elapsed_ms: f64,
    streams: Vec<StreamReport>,
    rejected_candidates: BTreeMap<String, u64>,
    rejected_candidate_examples: Vec<DeflateDiagnostic>,
}

impl FileReport {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            size_bytes: None,
            modified_unix_seconds: None,
            status: "error",
            error: None,
            elapsed_ms: 0.0,
            streams: Vec::new(),
            rejected_candidates: BTreeMap::new(),
            rejected_candidate_examples: Vec::new(),
        }
    }

    fn error(path: PathBuf, error: impl ToString) -> Self {
        let mut result = Self::new(path);
        result.error = Some(error.to_string());
        result
    }
}

#[derive(Serialize)]
struct RankedStream {
    path: PathBuf,
    offset: usize,
    kind: &'static str,
    member_name: Option<String>,
    correction_ratio: f64,
    deflate_bytes: u64,
    correction_bytes: u64,
    elapsed_ms: f64,
}

#[derive(Default, Serialize)]
struct Summary {
    entries: u64,
    files_read: u64,
    files_without_streams: u64,
    skipped_entries: u64,
    filesystem_errors: u64,
    trace_selection_errors: u64,
    panicked_files: u64,
    candidates: u64,
    successful_streams: u64,
    failed_candidates: u64,
    rejected_signature_candidates: u64,
    unsupported_candidates: u64,
    limited_candidates: u64,
    poor_model_streams: u64,
    verified_streams: u64,
    successful_deflate_bytes: u64,
    successful_plaintext_bytes: u64,
    successful_correction_bytes: u64,
    weighted_correction_ratio: Option<f64>,
    candidate_error_counts: BTreeMap<String, u64>,
    worst_streams: Vec<RankedStream>,
    elapsed_ms: f64,
}

impl Summary {
    fn record(&mut self, file: &FileReport) {
        self.entries += 1;
        match file.status {
            "skipped" => self.skipped_entries += 1,
            "error" => self.filesystem_errors += 1,
            "trace_selection_error" => {
                self.files_read += 1;
                self.trace_selection_errors += 1;
            }
            "panic" => {
                self.files_read += 1;
                self.panicked_files += 1;
            }
            _ => self.files_read += 1,
        }
        if file.status == "no_streams" {
            self.files_without_streams += 1;
        }
        for (code, count) in &file.rejected_candidates {
            self.candidates += count;
            self.failed_candidates += count;
            self.rejected_signature_candidates += count;
            *self.candidate_error_counts.entry(code.clone()).or_default() += count;
        }
        for stream in &file.streams {
            let d = &stream.diagnostic;
            self.candidates += 1;
            self.rejected_signature_candidates += u64::from(rejected_signature(d));
            match d.status {
                "ok" => {
                    self.successful_streams += 1;
                    self.successful_deflate_bytes += d.deflate_bytes;
                    self.successful_plaintext_bytes += d.plaintext_bytes;
                    self.successful_correction_bytes += d.correction_bytes;
                }
                "unsupported" => self.unsupported_candidates += 1,
                "limit" => self.limited_candidates += 1,
                _ => self.failed_candidates += 1,
            }
            self.verified_streams += u64::from(d.verified);
            self.poor_model_streams += u64::from(stream.poor_model);
            if let Some(code) = &d.error_code {
                *self.candidate_error_counts.entry(code.clone()).or_default() += 1;
            }
            if let Some(ratio) = d.correction_ratio.filter(|_| stream.ranking_eligible) {
                self.worst_streams.push(RankedStream {
                    path: file.path.clone(),
                    offset: d.offset,
                    kind: d.kind,
                    member_name: d.member_name.clone(),
                    correction_ratio: ratio,
                    deflate_bytes: d.deflate_bytes,
                    correction_bytes: d.correction_bytes,
                    elapsed_ms: d.elapsed_ms,
                });
                self.worst_streams
                    .sort_by(|a, b| b.correction_ratio.total_cmp(&a.correction_ratio));
                self.worst_streams.truncate(20);
            }
        }
    }
}

fn inspect_file(path: PathBuf, metadata: &Metadata, cli: &Cli) -> FileReport {
    let start = Instant::now();
    let mut report = FileReport::new(path);
    report.size_bytes = Some(metadata.len());
    report.modified_unix_seconds = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs());
    let limit = cli.max_file_mib * MIB;
    if metadata.len() > limit || (!cli.hydrate && cloud_only(metadata)) {
        report.status = "skipped";
        report.error = Some(if metadata.len() > limit {
            "file exceeds --max-file-mib".into()
        } else {
            "cloud-only file; use --hydrate to allow downloading".into()
        });
        return report;
    }

    let mut contents = Vec::new();
    let read =
        File::open(&report.path).and_then(|file| file.take(limit + 1).read_to_end(&mut contents));
    if let Err(error) = read {
        report.error = Some(format!("reading file: {error}"));
    } else if contents.len() as u64 > limit {
        report.status = "skipped";
        report.error = Some("file grew beyond --max-file-mib while reading".into());
    } else {
        let raw = cli.raw
            || report
                .path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("deflate"));
        let config = PreflateConfig {
            max_chain_length: cli.max_chain,
            plain_text_limit: (cli.chunk_mib * MIB) as usize,
            verify_compression: !cli.no_verify,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scan_deflate_diagnostics_with_options(
                &contents,
                &config,
                raw,
                cli.max_stream_mib * MIB,
                cli.max_candidates as usize,
                &DiagnosticScanOptions {
                    stream_offset: cli.stream_offset,
                    trace_limit: cli.trace.then_some(cli.trace_limit as usize),
                },
                |diagnostic| {
                    if !cli.trace
                        && !cli.include_rejected_candidates
                        && rejected_signature(&diagnostic)
                    {
                        let code = diagnostic
                            .error_code
                            .as_ref()
                            .expect("rejected signature has an error code");
                        *report.rejected_candidates.entry(code.clone()).or_default() += 1;
                        if report.rejected_candidate_examples.len() < 8 {
                            report.rejected_candidate_examples.push(diagnostic);
                        }
                        return;
                    }
                    let ranking_eligible = diagnostic.correction_ratio.is_some()
                        && diagnostic.deflate_bytes >= cli.min_stream_bytes;
                    let poor_model = ranking_eligible
                        && diagnostic
                            .correction_ratio
                            .is_some_and(|ratio| ratio > cli.poor_ratio_percent / 100.0);
                    let throughput = if diagnostic.elapsed_ms > 0.0 && diagnostic.status == "ok" {
                        Some(
                            diagnostic.plaintext_bytes as f64
                                / MIB as f64
                                / (diagnostic.elapsed_ms / 1000.0),
                        )
                    } else {
                        None
                    };
                    report.streams.push(StreamReport {
                        diagnostic,
                        ranking_eligible,
                        poor_model,
                        plaintext_mib_per_second: throughput,
                    });
                },
            );
        }));
        match result {
            Ok(()) => {
                report.status =
                    if let (true, Some(offset)) = (report.streams.is_empty(), cli.stream_offset) {
                        report.error = Some(format!(
                            "no supported stream signature at requested offset {offset}"
                        ));
                        "trace_selection_error"
                    } else if report.streams.is_empty() {
                        "no_streams"
                    } else if report.streams.iter().any(|s| s.diagnostic.status != "ok") {
                        "stream_issues"
                    } else {
                        "ok"
                    };
            }
            Err(payload) => {
                report.status = "panic";
                let message = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("non-string panic payload");
                report.error = Some(format!("preflate panicked: {message}"));
            }
        }
    }
    report.elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    report
}

fn rejected_signature(diagnostic: &DeflateDiagnostic) -> bool {
    diagnostic.signature_confidence == "heuristic"
        && diagnostic.status == "error"
        && matches!(
            diagnostic.error_code.as_deref(),
            Some("InvalidDeflate" | "NonZeroPadding" | "ShortRead")
        )
}

fn is_scan_output(path: &Path, output: &Path, cli: &Cli) -> bool {
    path == output
        || (cli.database.is_some()
            && ["-wal", "-shm", "-journal"].iter().any(|suffix| {
                let mut sidecar = output.as_os_str().to_os_string();
                sidecar.push(suffix);
                path == Path::new(&sidecar)
            }))
}

fn walk_tasks(
    root: &Path,
    output: &Path,
    cli: &Cli,
    perf: Option<&Path>,
    mut emit: impl FnMut(scan_parallel::Task) -> Result<()>,
) -> Result<()> {
    use scan_parallel::Task;
    let mut directories = vec![root.to_path_buf()];
    while let Some(path) = directories.pop() {
        if is_scan_output(&path, output, cli) || perf.is_some_and(|output| path == output) {
            continue;
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                emit(Task::Ready(FileReport::error(path, error)))?;
                continue;
            }
        };
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            let mut report = FileReport::new(path);
            report.status = "skipped";
            report.error = Some("symlink or non-regular filesystem entry".into());
            emit(Task::Ready(report))?;
        } else if metadata.is_dir() {
            let entries = match fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(error) => {
                    emit(Task::Ready(FileReport::error(
                        path,
                        format!("listing directory: {error}"),
                    )))?;
                    continue;
                }
            };
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        // Process files immediately rather than queueing an entire folder tree.
                        match entry.file_type() {
                            Ok(kind) if kind.is_dir() && !kind.is_symlink() => {
                                directories.push(entry.path())
                            }
                            Ok(_) => {
                                let child = entry.path();
                                if is_scan_output(&child, output, cli)
                                    || perf.is_some_and(|output| child == output)
                                {
                                    continue;
                                }
                                match fs::symlink_metadata(&child) {
                                    Ok(metadata)
                                        if metadata.is_file()
                                            && !metadata.file_type().is_symlink() =>
                                    {
                                        emit(Task::File(child, metadata))?
                                    }
                                    Ok(_) => {
                                        let mut report = FileReport::new(child);
                                        report.status = "skipped";
                                        report.error =
                                            Some("symlink or non-regular filesystem entry".into());
                                        emit(Task::Ready(report))?;
                                    }
                                    Err(error) => {
                                        emit(Task::Ready(FileReport::error(child, error)))?
                                    }
                                }
                            }
                            Err(error) => {
                                emit(Task::Ready(FileReport::error(entry.path(), error)))?
                            }
                        }
                    }
                    Err(error) => emit(Task::Ready(FileReport::error(
                        path.clone(),
                        format!("reading directory entry: {error}"),
                    )))?,
                }
            }
        } else {
            emit(Task::File(path, metadata))?;
        }
    }
    Ok(())
}

fn walk(
    root: &Path,
    output: &Path,
    cli: &Cli,
    perf: Option<&mut scan_perf::PerformanceWriter>,
    mut emit: impl FnMut(FileReport) -> Result<()>,
) -> Result<()> {
    if let Some(writer) = perf {
        let perf_path = writer.path.clone();
        return walk_tasks(root, output, cli, Some(&perf_path), |task| {
            let report = match task {
                scan_parallel::Task::File(path, metadata) => {
                    writer.inspect(path, &metadata, cli)?
                }
                task => task.inspect(cli),
            };
            emit(report)
        });
    }
    scan_parallel::run(
        cli,
        |pool| {
            walk_tasks(root, output, cli, None, |task| {
                pool.submit(task.path().to_path_buf(), task)
            })
        },
        |_, report| emit(report),
    )
}

fn run(cli: &Cli) -> Result<Summary> {
    if cli.perf_output.is_some() && cli.worker_count() != 1 {
        return Err(
            "--perf-output requires --jobs 1 so process CPU timings remain meaningful".into(),
        );
    }
    let source = (cli.from_run.is_some() || cli.from_crawl || cli.baseline_run.is_some())
        .then(|| scan_source::DatabaseSource::open(cli))
        .transpose()?;
    let root = match &source {
        Some(source) => source.root.clone(),
        None => fs::canonicalize(&cli.input)?,
    };
    let mut configuration = serde_json::to_value(cli)?;
    configuration["jobs"] = serde_json::json!(cli.worker_count());
    configuration["input"] = serde_json::to_value(&root)?;
    if let Some(source) = &source {
        configuration["source_database"] = serde_json::to_value(&source.path)?;
    }
    if cli.trace && !root.is_file() {
        return Err("--trace requires a single file, not a directory".into());
    }
    if cli.baseline_run.is_some() {
        return scan_baseline::run(
            source.as_ref().ok_or("missing baseline source")?,
            cli,
            &configuration,
        );
    }
    let total = source
        .as_ref()
        .map(|source| source.file_count)
        .or_else(|| root.is_file().then_some(1));
    let mut progress = scan_progress::Progress::new(total);
    let start = Instant::now();
    if let Some(path) = &cli.database {
        let label = cli.label.as_deref().ok_or("--database requires --label")?;
        let mut database = scan_database::ScanDatabase::create_with_configuration(
            path,
            label,
            cli,
            &configuration,
        )?;
        let output_path = fs::canonicalize(path)?;
        let mut summary = Summary::default();
        let mut emit = |report: FileReport| {
            database.record(&report)?;
            summary.record(&report);
            progress.update(&summary, false);
            Ok(())
        };
        if let Some(source) = &source {
            source.scan(&output_path, cli, &mut emit)?;
        } else {
            walk(&root, &output_path, cli, None, &mut emit)?;
        }
        finish_summary(&mut summary, start);
        database.finish(&summary)?;
        progress.update(&summary, true);
        return Ok(summary);
    }
    let output_name = cli.output.as_ref().ok_or("missing report output")?;
    let output_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_name)?;
    let output_path = fs::canonicalize(output_name)?;
    let mut perf = cli
        .perf_output
        .as_ref()
        .map(|path| scan_perf::PerformanceWriter::create(path, &output_path, cli))
        .transpose()?;
    let mut output = BufWriter::new(output_file);
    write!(output, "{{\"schema_version\":1,\"tool_version\":")?;
    serde_json::to_writer(&mut output, env!("CARGO_PKG_VERSION"))?;
    write!(
        output,
        ",\"started_unix_seconds\":{},\"configuration\":",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
    )?;
    serde_json::to_writer(&mut output, &configuration)?;
    write!(output, ",\"root\":")?;
    serde_json::to_writer(&mut output, &root)?;
    writeln!(output, ",\"files\":[")?;
    let mut first = true;
    let mut summary = Summary::default();
    let mut emit = |report: FileReport| {
        if !first {
            writeln!(output, ",")?;
        }
        first = false;
        serde_json::to_writer(&mut output, &report)?;
        output.flush()?;
        summary.record(&report);
        progress.update(&summary, false);
        Ok(())
    };
    if let Some(source) = &source {
        source.scan(&output_path, cli, &mut emit)?;
    } else {
        walk(&root, &output_path, cli, perf.as_mut(), &mut emit)?;
    }
    finish_summary(&mut summary, start);
    write!(output, "\n],\"summary\":")?;
    serde_json::to_writer(&mut output, &summary)?;
    writeln!(output, "}}")?;
    output.flush()?;
    output.get_ref().sync_all()?;
    progress.update(&summary, true);
    if let Some(writer) = &mut perf {
        writer.finish()?;
    }
    Ok(summary)
}

fn finish_summary(summary: &mut Summary, start: Instant) {
    summary.elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    if summary.successful_deflate_bytes != 0 {
        summary.weighted_correction_ratio = Some(
            summary.successful_correction_bytes as f64 / summary.successful_deflate_bytes as f64,
        );
    }
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(summary) => {
            eprintln!(
                "Report: {} | {} files read, {} streams OK, {} failed candidates, {} limited, {} poor models, {} filesystem errors",
                cli.database
                    .as_ref()
                    .or(cli.output.as_ref())
                    .expect("validated output")
                    .display(),
                summary.files_read,
                summary.successful_streams,
                summary.failed_candidates,
                summary.limited_candidates,
                summary.poor_model_streams,
                summary.filesystem_errors,
            );
            if summary.trace_selection_errors != 0 {
                eprintln!("The requested trace stream was not found; see the report for details.");
                std::process::ExitCode::FAILURE
            } else {
                std::process::ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!(
                "Scan failed: {error}. Any incomplete report must not be treated as a finished scan."
            );
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniz_oxide::deflate::compress_to_vec;
    use serde_json::Value;

    #[test]
    fn performance_jsonl_repeats_files_and_excludes_both_reports() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::write(
            root.join("good.deflate"),
            compress_to_vec(&b"benchmark benchmark ".repeat(1000), 6),
        )
        .unwrap();
        fs::write(root.join("plain.txt"), b"plain text").unwrap();
        File::create(root.join("large.bin"))
            .unwrap()
            .set_len(2 * MIB)
            .unwrap();
        let output = root.join("scan.json");
        let perf = root.join("perf.jsonl");
        let cli = Cli::try_parse_from([
            "preflate_scan",
            root.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--perf-output",
            perf.to_str().unwrap(),
            "--perf-iterations",
            "2",
            "--max-file-mib",
            "1",
            "--build-identity",
            "synthetic-test-build",
        ])
        .unwrap();
        let summary = run(&cli).unwrap();
        assert_eq!(summary.entries, 3);
        assert_eq!(summary.successful_streams, 1);
        let records: Vec<Value> = fs::read_to_string(&perf)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 7);
        assert_eq!(records[0]["schema"], "preflate_perf");
        assert_eq!(records[0]["verification_enabled"], true);
        assert_eq!(records[0]["build_identity"], "synthetic-test-build");
        for (index, record) in records[1..6].iter().enumerate() {
            assert_eq!(record["record"], "sample");
            assert_eq!(record["index"], index);
            assert!(record["cpu_seconds"].as_f64().unwrap() >= 0.0);
            assert!(record["wall_seconds"].as_f64().unwrap() >= 0.0);
            assert_eq!(record["successful_streams"], record["verified_streams"]);
        }
        assert_eq!(records[6]["samples"], 5);
        assert_eq!(records[6]["failed_samples"], 0);
        assert_eq!(records[6]["skipped_samples"], 1);
        let original = fs::read(&perf).unwrap();
        assert!(run(&cli).is_err());
        assert_eq!(fs::read(&perf).unwrap(), original);
    }

    #[test]
    fn performance_encode_only_is_explicit() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("good.deflate");
        fs::write(&input, compress_to_vec(&b"benchmark ".repeat(1000), 6)).unwrap();
        let output = directory.path().join("scan.json");
        let perf = directory.path().join("perf.jsonl");
        let cli = Cli::try_parse_from([
            "preflate_scan",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--perf-output",
            perf.to_str().unwrap(),
            "--no-verify",
        ])
        .unwrap();
        run(&cli).unwrap();
        let records: Vec<Value> = fs::read_to_string(perf)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records[0]["verification_enabled"], false);
        assert_eq!(records[1]["successful_streams"], 1);
        assert_eq!(records[1]["verified_streams"], 0);
    }

    #[test]
    fn recursive_report_includes_failures_and_excludes_itself() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::create_dir(root.join("nested")).unwrap();
        let text = b"document document document ".repeat(1000);
        fs::write(
            root.join("nested").join("good.deflate"),
            compress_to_vec(&text, 6),
        )
        .unwrap();
        fs::write(root.join("bad.deflate"), [7]).unwrap();
        fs::write(root.join("plain.txt"), b"plain document with no deflate").unwrap();
        File::create(root.join("large.bin"))
            .unwrap()
            .set_len(2 * MIB)
            .unwrap();
        let output = root.join("report.json");
        let cli = Cli::try_parse_from([
            "preflate_scan",
            root.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--max-file-mib",
            "1",
            "--poor-ratio-percent",
            "0",
            "--min-stream-bytes",
            "0",
        ])
        .unwrap();
        let summary = run(&cli).unwrap();
        let report: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["files"].as_array().unwrap().len(), 4);
        assert_eq!(summary.files_read, 3);
        assert_eq!(summary.files_without_streams, 1);
        assert_eq!(summary.successful_streams, 1);
        assert_eq!(summary.failed_candidates, 1);
        assert_eq!(summary.skipped_entries, 1);
        assert_eq!(summary.poor_model_streams, 1);
        assert_eq!(summary.verified_streams, 1);
        assert_eq!(summary.successful_plaintext_bytes, text.len() as u64);
        assert!(summary.weighted_correction_ratio.unwrap().is_finite());
        let original_report = fs::read(&output).unwrap();
        assert!(run(&cli).is_err());
        assert_eq!(fs::read(output).unwrap(), original_report);
    }

    #[test]
    fn empty_directory_has_null_ratio_and_valid_json() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("report.json");
        let cli = Cli::try_parse_from([
            "preflate_scan",
            directory.path().to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ])
        .unwrap();
        let summary = run(&cli).unwrap();
        assert_eq!(summary.entries, 0);
        let report: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert!(report["summary"]["weighted_correction_ratio"].is_null());
    }

    #[test]
    fn rejects_invalid_thresholds_and_limits() {
        for value in ["NaN", "inf", "-1"] {
            assert!(parse_percent(value).is_err());
        }
        assert!(
            Cli::try_parse_from(["preflate_scan", ".", "-o", "x", "--max-file-mib", "0"]).is_err()
        );
    }

    #[test]
    fn trace_rejects_directory_before_creating_report() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("trace.json");
        let cli = Cli::try_parse_from([
            "preflate_scan",
            directory.path().to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "--trace",
        ])
        .unwrap();
        assert!(run(&cli).err().unwrap().to_string().contains("single file"));
        assert!(!output.exists());
        assert!(
            Cli::try_parse_from(["preflate_scan", ".", "-o", "unused", "--stream-offset", "0"])
                .is_err()
        );
    }

    #[test]
    fn aggregates_rejected_signatures_and_trace_can_inspect_them() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data.bin");
        fs::write(&path, b"\x78\x9c\x07".repeat(20)).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let mut cli = Cli::try_parse_from(["preflate_scan", ".", "-o", "unused"]).unwrap();
        let report = inspect_file(path.clone(), &metadata, &cli);
        assert_eq!(report.status, "no_streams");
        assert!(report.streams.is_empty());
        assert_eq!(report.rejected_candidates.values().sum::<u64>(), 20);
        assert_eq!(report.rejected_candidate_examples.len(), 8);
        let mut summary = Summary::default();
        summary.record(&report);
        assert_eq!(summary.candidates, 20);
        assert_eq!(summary.rejected_signature_candidates, 20);
        cli.include_rejected_candidates = true;
        let full = inspect_file(path.clone(), &metadata, &cli);
        assert_eq!(full.streams.len(), 20);
        let mut full_summary = Summary::default();
        full_summary.record(&full);
        assert_eq!(
            full_summary.candidate_error_counts,
            summary.candidate_error_counts
        );
        assert_eq!(full_summary.rejected_signature_candidates, 20);
        cli.trace = true;
        cli.stream_offset = Some(3);
        let trace = inspect_file(path.clone(), &metadata, &cli);
        assert_eq!(trace.streams.len(), 1);
        assert_eq!(trace.streams[0].diagnostic.offset, 3);
        assert!(trace.streams[0].diagnostic.trace.is_some());
        cli.stream_offset = Some(1);
        let missing = inspect_file(path, &metadata, &cli);
        assert_eq!(missing.status, "trace_selection_error");
        assert!(missing.error.is_some());
    }

    #[test]
    fn file_size_option_skips_larger_than_twenty_mib() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large.bin");
        File::create(&path).unwrap().set_len(20 * MIB + 1).unwrap();
        let cli =
            Cli::try_parse_from(["preflate_scan", ".", "-o", "unused", "--max-file-mib", "20"])
                .unwrap();
        let report = inspect_file(path.clone(), &fs::metadata(&path).unwrap(), &cli);
        assert_eq!(report.status, "skipped");
        assert!(report.error.unwrap().contains("max-file-mib"));
        assert!(report.streams.is_empty());
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(20 * MIB)
            .unwrap();
        let report = inspect_file(path.clone(), &fs::metadata(&path).unwrap(), &cli);
        assert_eq!(report.status, "no_streams");
        assert_eq!(report.size_bytes, Some(20 * MIB));
    }

    #[test]
    fn rejected_gzip_magic_is_compact_but_confirmed_headers_keep_errors() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data.bin");
        let mut contents = vec![0x1f, 0x8b, 0, 0, 0, 0, 0, 0, 0, 0];
        contents.extend([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0, 7]);
        fs::write(&path, contents).unwrap();
        let cli = Cli::try_parse_from(["preflate_scan", ".", "-o", "unused"]).unwrap();
        let report = inspect_file(path.clone(), &fs::metadata(&path).unwrap(), &cli);
        assert_eq!(report.rejected_candidates.values().sum::<u64>(), 1);
        assert_eq!(report.streams.len(), 1);
        assert_eq!(report.streams[0].diagnostic.signature_confidence, "wrapper");
        assert_eq!(report.streams[0].diagnostic.status, "error");
        assert_eq!(report.streams[0].diagnostic.offset, 10);
    }

    #[test]
    fn unverified_raw_mode_is_explicit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data.bin");
        fs::write(&path, compress_to_vec(b"raw stream", 6)).unwrap();
        let cli =
            Cli::try_parse_from(["preflate_scan", ".", "-o", "unused", "--raw", "--no-verify"])
                .unwrap();
        let report = inspect_file(path.clone(), &fs::metadata(path).unwrap(), &cli);
        assert_eq!(report.status, "ok");
        assert!(!report.streams[0].diagnostic.verified);
    }

    #[test]
    fn ranking_size_threshold_is_inclusive() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data.deflate");
        let raw = compress_to_vec(&b"document content ".repeat(1000), 6);
        fs::write(&path, &raw).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let mut cli = Cli::try_parse_from([
            "preflate_scan",
            ".",
            "-o",
            "unused",
            "--poor-ratio-percent",
            "0",
        ])
        .unwrap();
        cli.min_stream_bytes = raw.len() as u64;
        let eligible = inspect_file(path.clone(), &metadata, &cli);
        assert!(eligible.streams[0].ranking_eligible);
        assert!(eligible.streams[0].poor_model);
        let mut summary = Summary::default();
        summary.record(&eligible);
        assert_eq!(summary.worst_streams.len(), 1);
        cli.min_stream_bytes += 1;
        let small = inspect_file(path, &metadata, &cli);
        assert!(!small.streams[0].ranking_eligible);
        assert!(!small.streams[0].poor_model);
        let mut summary = Summary::default();
        summary.record(&small);
        assert!(summary.worst_streams.is_empty());
        assert_eq!(summary.successful_streams, 1);
    }

    #[cfg(windows)]
    #[test]
    fn does_not_follow_junction_loops() {
        let directory = tempfile::tempdir().unwrap();
        let junction = directory.path().join("loop");
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&junction)
            .arg(directory.path())
            .status()
            .unwrap();
        assert!(status.success());
        let output = directory.path().join("report.json");
        let cli = Cli::try_parse_from([
            "preflate_scan",
            directory.path().to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ])
        .unwrap();
        let summary = run(&cli).unwrap();
        assert_eq!(summary.entries, 1);
        assert_eq!(summary.skipped_entries, 1);
        assert_eq!(summary.files_read, 0);
    }

    #[test]
    fn recognizes_cloud_only_attributes_without_hydration() {
        for attributes in [0x1000, 0x40000, 0x400000, 0x401020] {
            assert!(cloud_attributes(attributes));
        }
        for attributes in [0, 0x20, 0x400, 0x80000, 0x80420] {
            assert!(!cloud_attributes(attributes));
        }
    }

    use scan_fs::cloud_attributes;
}
