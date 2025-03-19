use std::{
    env, fs,
    io::Cursor,
    path::{Path, PathBuf},
};

use preflate_rs::{
    decompress_zstd, CompressionConfig, PreflateCompressionContext, ProcessBuffer,
    ZstdCompressContext,
};

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
    let current_dir = env::args().nth(1).unwrap_or_else(|| String::from("."));

    let mut totalseen = 0u64;
    let mut totalbaseline = 0u64;
    let mut totalzstd = 0u64;

    let loglevel = 0;

    // Use WalkDir to recursively search for files in the directory
    for entry in enumerate_directory_recursively(Path::new(&current_dir)).unwrap() {
        // Check if the entry is a file (not a directory)
        // scan file for compressed data
        println!("Processing file: {:?}", entry);

        let file = std::fs::read(entry).unwrap();

        let mut ctx = ZstdCompressContext::new(
            PreflateCompressionContext::new(CompressionConfig::default()),
            9,
            true,
        );

        let mut preflatecompressed = Vec::with_capacity(file.len());
        if let Err(e) = ctx.copy_to_end(&mut Cursor::new(&file), &mut preflatecompressed) {
            println!("Skipping due to error: {:?}", e);
            continue;
        }

        let stats = ctx.stats();

        totalseen += file.len() as u64;
        totalbaseline += stats.zstd_baseline_size as u64;
        totalzstd += stats.zstd_compressed_size as u64;

        println!(
            "total seen ratio {totalzstd}:{totalbaseline}:{totalseen} {}",
            totalzstd as f64 / totalseen as f64
        );
    }
}
