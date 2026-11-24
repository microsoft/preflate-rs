//! Per-file CPU and wall-time measurements for diagnostic scans.
//! Repeats scans and writes JSONL samples separately from the main scan report.

use std::{
    fs::{self, Metadata, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use cpu_time::ProcessTime;
use serde_json::json;

use crate::{Cli, FileReport, Result, Summary, inspect_file};

pub struct PerformanceWriter {
    pub path: PathBuf,
    output: BufWriter<std::fs::File>,
    samples: u64,
    failed_samples: u64,
    skipped_samples: u64,
}

impl PerformanceWriter {
    pub fn create(path: &Path, scan_report: &Path, cli: &Cli) -> Result<Self> {
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        let mut writer = Self {
            path: fs::canonicalize(path)?,
            output: BufWriter::new(file),
            samples: 0,
            failed_samples: 0,
            skipped_samples: 0,
        };
        writer.write(&json!({
            "record": "header",
            "schema": "preflate_perf",
            "schema_version": 1,
            "tool_version": env!("CARGO_PKG_VERSION"),
            "build_identity": cli.build_identity,
            "started_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "scan_report": scan_report,
            "configuration": cli,
            "verification_enabled": !cli.no_verify,
            "scope": "whole_file_preflate_scan",
            "timing_includes": ["file_read", "signature_scan", "preflate", "optional_exact_reconstruction"],
            "timing_excludes": ["directory_walk", "json_serialization", "source_metadata_checks"],
            "repetition_policy": "first_attempt_then_warm_per_file_no_warmup",
            "cpu_scope": "process_all_threads",
            "iterations": cli.perf_iterations,
        }))?;
        Ok(writer)
    }

    fn write(&mut self, value: &serde_json::Value) -> Result<()> {
        serde_json::to_writer(&mut self.output, value)?;
        writeln!(self.output)?;
        self.output.flush()?;
        Ok(())
    }

    fn attempt(
        &mut self,
        path: PathBuf,
        metadata: &Metadata,
        cli: &Cli,
        iteration: u32,
    ) -> Result<FileReport> {
        let before = fs::symlink_metadata(&path)?;
        if !before.is_file()
            || before.file_type().is_symlink()
            || before.len() != metadata.len()
            || metadata.modified().is_err()
            || before.modified().ok() != metadata.modified().ok()
        {
            return Err(format!("benchmark source metadata changed: {}", path.display()).into());
        }
        let cpu = ProcessTime::try_now()?;
        let wall = Instant::now();
        let report = inspect_file(path.clone(), &before, cli);
        let wall_seconds = wall.elapsed().as_secs_f64();
        let cpu_seconds = cpu.try_elapsed()?.as_secs_f64();
        let after = fs::symlink_metadata(&path)?;
        let stable = before.is_file()
            && !before.file_type().is_symlink()
            && after.is_file()
            && !after.file_type().is_symlink()
            && before.len() == metadata.len()
            && after.len() == metadata.len()
            && metadata.modified().is_ok()
            && before.modified().ok() == metadata.modified().ok()
            && after.modified().ok() == metadata.modified().ok();
        let mut totals = Summary::default();
        totals.record(&report);
        let status = if stable {
            report.status
        } else {
            "source_changed"
        };
        let error = if stable {
            report.error.as_deref()
        } else {
            Some("source metadata changed between or during benchmark attempts")
        };
        self.write(&json!({
            "record": "sample",
            "index": self.samples,
            "path": report.path,
            "size_bytes": report.size_bytes,
            "modified_unix_seconds": report.modified_unix_seconds,
            "modified_unix_ns": before.modified()?.duration_since(UNIX_EPOCH)?.as_nanos(),
            "iteration": iteration,
            "cpu_seconds": cpu_seconds,
            "wall_seconds": wall_seconds,
            "status": status,
            "error": error,
            "successful_streams": totals.successful_streams,
            "verified_streams": totals.verified_streams,
            "failed_candidates": totals.failed_candidates,
            "unsupported_candidates": totals.unsupported_candidates,
            "limited_candidates": totals.limited_candidates,
            "deflate_bytes": totals.successful_deflate_bytes,
            "plaintext_bytes": totals.successful_plaintext_bytes,
            "reconstruction_bytes": totals.successful_correction_bytes,
        }))?;
        self.samples += 1;
        self.skipped_samples += u64::from(status == "skipped");
        self.failed_samples += u64::from(!matches!(status, "ok" | "no_streams" | "skipped"));
        Ok(report)
    }

    pub fn inspect(&mut self, path: PathBuf, metadata: &Metadata, cli: &Cli) -> Result<FileReport> {
        let first = self.attempt(path.clone(), metadata, cli, 1)?;
        if first.status != "skipped" {
            for iteration in 2..=cli.perf_iterations {
                self.attempt(path.clone(), metadata, cli, iteration)?;
            }
        }
        Ok(first)
    }

    pub fn finish(&mut self) -> Result<()> {
        self.write(&json!({
            "record": "summary",
            "samples": self.samples,
            "failed_samples": self.failed_samples,
            "skipped_samples": self.skipped_samples,
        }))?;
        self.output.get_ref().sync_all()?;
        Ok(())
    }
}
