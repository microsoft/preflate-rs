use clap::{Parser, command};
use cpu_time::ProcessTime;
use env_logger::Builder;
use log::LevelFilter;

use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
};

use preflate_container::{
    PreflateContainerConfig, PreflateContainerProcessor, ProcessBuffer, RecreateContainerProcessor,
    ZstdCompressContext, ZstdDecompressContext,
};

#[derive(Parser)]
#[command(name = "preflate_util")]
#[command(about = "Tests preflate compression container", long_about = None)]
struct Cli {
    /// Directory to compress
    input: PathBuf,

    /// Maximum chain length to use for recreating the deflate stream. If a larger
    /// chain length is required, the stream will not be compressed.
    #[arg(long, default_value = "4096")]
    max_chain: u32,

    /// Compression level (0-14) to use for Zstandard compression
    #[arg(short = 'c', long, default_value = "9")]
    level: u32,

    /// level of logging to use
    #[arg(long, default_value = "Error")]
    #[arg(value_enum)]
    loglevel: LevelFilter,

    /// Whether to verify the compression by decompressing and comparing to original
    #[arg(long, default_value = "true")]
    verify: bool,

    /// Whether to output baseline zstd compression size
    #[arg(long, default_value = "false")]
    baseline: bool,
}

fn enumerate_directory_recursively(path: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut results = Vec::new();

    // Ensure the path exists and is a directory
    if path.is_dir() {
        let entries = fs::read_dir(path)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // If it's a directory, recursively enumerate its contents
                if let Ok(sub_dir_results) = enumerate_directory_recursively(&path) {
                    results.extend(sub_dir_results);
                }
            } else {
                // If it's a file, just add its path to the results
                results.push(path);
            }
        }
    } else {
        // If it's a file, just add its path to the results
        results.push(path.to_path_buf());
    }

    Ok(results)
}

fn main() {
    let cli = Cli::parse();

    Builder::new().filter_level(cli.loglevel).init();

    let config = PreflateContainerConfig {
        validate_compression: false,
        max_chain_length: cli.max_chain,
        ..PreflateContainerConfig::default()
    };

    let current_dir = cli.input;

    let mut totalseen = 0u64;
    let mut totalbaseline = 0u64;
    let mut totalzstd = 0u64;

    // Use WalkDir to recursively search for files in the directory
    for entry in enumerate_directory_recursively(Path::new(&current_dir)).unwrap() {
        // Check if the entry is a file (not a directory)
        // scan file for compressed data
        println!("Processing file: {:?}", entry);

        // open file for reading
        let original = fs::read(&entry).unwrap();

        let mut ctx = ZstdCompressContext::new(
            PreflateContainerProcessor::new(&config),
            cli.level as i32,
            cli.baseline,
        );

        let compress_start = ProcessTime::now();

        let mut preflate_compressed = Vec::new();
        if let Err(e) = ctx.copy_to_end_size(
            &mut Cursor::new(&original),
            &mut preflate_compressed,
            usize::MAX,
        ) {
            println!("Skipping due to error: {:?}", e);
            continue;
        };

        let stats = ctx.stats();

        println!(
            "compressed ratio: {:.1} cpu={:?}",
            (1f64 - (stats.zstd_compressed_size as f64 / stats.deflate_compressed_size as f64))
                * 100f64,
            compress_start.elapsed()
        );

        totalseen += stats.deflate_compressed_size as u64;
        totalbaseline += stats.zstd_baseline_size as u64;
        totalzstd += stats.zstd_compressed_size as u64;

        println!(
            "total seen ratio {totalzstd}:{totalbaseline}:{totalseen} {:.1}",
            (1f64 - totalzstd as f64 / totalbaseline as f64) * 100f64
        );

        // test expanding back to original and verifying
        if cli.verify {
            let start = ProcessTime::now();

            let mut recreated = Vec::new();
            let mut decomp = ZstdDecompressContext::new(RecreateContainerProcessor::new(
                config.chunk_plain_text_limit,
            ));

            if let Err(e) = decomp.copy_to_end_size(
                &mut Cursor::new(&preflate_compressed),
                &mut recreated,
                usize::MAX,
            ) {
                println!("Verification error: {:?}", e);
                continue;
            };

            println!("decompression cpu time: {:?}", start.elapsed());

            assert_eq_array(&original, &recreated);
        }
    }
}

/// handy function to compare two arrays, and print the first mismatch. Useful for debugging.
#[track_caller]
pub fn assert_eq_array<T: PartialEq + std::fmt::Debug>(a: &[T], b: &[T]) {
    use core::panic;

    if a.len() != b.len() {
        for i in 0..std::cmp::min(a.len(), b.len()) {
            assert_eq!(
                a[i],
                b[i],
                "length mismatch {},{} and first mismatch at offset {}",
                a.len(),
                b.len(),
                i
            );
        }
        panic!(
            "length mismatch {} and {}, but common prefix identical",
            a.len(),
            b.len()
        );
    } else {
        for i in 0..a.len() {
            assert_eq!(
                a[i],
                b[i],
                "length identical {}, but first mismatch at offset {}",
                a.len(),
                i
            );
        }
    }
}
