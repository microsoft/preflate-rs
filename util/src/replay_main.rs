//! JSON command-line interface for replaying explicit reconstruction settings.
//! Loads bounded file ranges or synthetic blocks and emits prediction diagnostics
//! with optional correction encoding and exact reconstruction verification.

#![forbid(unsafe_code)]

mod scan_fs;

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Parser;
use preflate_rs::{
    PreflateError,
    diagnostics::{ReplayBlock, ReplayOptions, encode_replay_blocks, replay_deflate},
};
use serde::Deserialize;
use serde_json::{Value, json};

const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Parser)]
#[command(about = "Replay explicit compressor parameters: JSON request to JSON result, no Zstd")]
struct Cli {
    /// JSON request file. If omitted, read a single request from stdin.
    request: Option<PathBuf>,
    /// Create a new JSON result file instead of writing to stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Permit opening cloud-only request/source files. Disabled by default.
    #[arg(long)]
    hydrate: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    source: Source,
    reconstruction_parameters: Box<serde_json::value::RawValue>,
    #[serde(default)]
    options: ReplayOptions,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Source {
    File {
        path: PathBuf,
        #[serde(default)]
        offset: u64,
        length: Option<u64>,
    },
    Deflate {
        bytes: Vec<u8>,
    },
    Blocks {
        blocks: Vec<ReplayBlock>,
    },
}

fn invalid(message: impl AsRef<str>) -> PreflateError {
    PreflateError::new(preflate_rs::ExitCode::InvalidParameter, message)
}

fn io_error(error: io::Error) -> PreflateError {
    PreflateError::new(preflate_rs::ExitCode::OsError, error.to_string())
}

fn bounded_read(reader: impl Read, maximum: u64) -> preflate_rs::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > maximum {
        return Err(invalid("input exceeds its configured byte limit"));
    }
    Ok(bytes)
}

fn open_source(path: &Path, hydrate: bool) -> preflate_rs::Result<(File, fs::Metadata)> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid("source must be a regular, non-symlink file"));
    }
    if !hydrate && scan_fs::cloud_only(&metadata) {
        return Err(invalid(
            "cloud-only source skipped; --hydrate is required to open it",
        ));
    }
    Ok((File::open(path).map_err(io_error)?, metadata))
}

fn run(cli: &Cli) -> preflate_rs::Result<Value> {
    let request = match &cli.request {
        Some(path) => bounded_read(open_source(path, cli.hydrate)?.0, MAX_REQUEST_BYTES)?,
        None => bounded_read(io::stdin().lock(), MAX_REQUEST_BYTES)?,
    };
    let request: Request =
        serde_json::from_slice(&request).map_err(|error| invalid(error.to_string()))?;
    request.options.validate()?;
    preflate_rs::diagnostics::validate_replay_parameters(request.reconstruction_parameters.get())?;
    let bytes = match request.source {
        Source::Deflate { bytes } => bytes,
        Source::Blocks { blocks } => encode_replay_blocks(blocks, &request.options)?,
        Source::File {
            path,
            offset,
            length,
        } => {
            let (mut file, before) = open_source(&path, cli.hydrate)?;
            let available = before
                .len()
                .checked_sub(offset)
                .ok_or_else(|| invalid("source offset is beyond EOF"))?;
            let length = length.unwrap_or(available);
            if length > available || length > request.options.max_input_bytes as u64 {
                return Err(invalid("source length exceeds EOF or max_input_bytes"));
            }
            file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
            let bytes = bounded_read(
                (&mut file).take(length),
                request.options.max_input_bytes as u64,
            )?;
            let after = file.metadata().map_err(io_error)?;
            if before.len() != after.len()
                || before.modified().map_err(io_error)? != after.modified().map_err(io_error)?
            {
                return Err(invalid("source metadata changed while reading"));
            }
            if bytes.len() as u64 != length {
                return Err(invalid("source ended before the requested length"));
            }
            bytes
        }
    };
    let result = replay_deflate(
        &bytes,
        request.reconstruction_parameters.get(),
        &request.options,
    )?;
    Ok(json!({"status": "ok", "result": result}))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (result, success) = match run(&cli) {
        Ok(result) => (result, true),
        Err(error) => (
            json!({
                "status": "error",
                "error": {"code": error.exit_code().to_string(), "message": error.to_string()}
            }),
            false,
        ),
    };
    let write = || -> Result<(), Box<dyn std::error::Error>> {
        let mut output: Box<dyn Write> = match &cli.output {
            Some(path) => Box::new(OpenOptions::new().write(true).create_new(true).open(path)?),
            None => Box::new(io::stdout().lock()),
        };
        serde_json::to_writer_pretty(&mut output, &result)?;
        writeln!(output)?;
        output.flush()?;
        Ok(())
    };
    if let Err(error) = write() {
        eprintln!("cannot write replay result: {error}");
        return ExitCode::FAILURE;
    }
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
