use std::{
    env, fs,
    path::{Path, PathBuf},
};

use preflate_rs::{compress_zstd, decompress_zstd};

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
    let mut totalzstd = 0u64;

    // Use WalkDir to recursively search for files in the directory
    for entry in enumerate_directory_recursively(Path::new(&current_dir)).unwrap() {
        // Check if the entry is a file (not a directory)
        // scan file for compressed data
        println!("Processing file: {:?}", entry);
        let file = std::fs::read(entry).unwrap();

        let zstdlen = zstd::bulk::compress(&file, 9).unwrap();

        let preflatecompressed = compress_zstd(&file, 1).unwrap();

        totalseen += zstdlen.len() as u64;
        totalzstd += preflatecompressed.len() as u64;

        let original = decompress_zstd(&preflatecompressed, 1024 * 1024 * 128).unwrap();

        assert!(original == file);

        println!("total seen ratio {}", totalzstd as f64 / totalseen as f64);
    }
}
