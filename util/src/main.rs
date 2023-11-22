use std::env;

use walkdir::WalkDir;

mod search_signature;
mod zip_structs;

fn main() {
    let current_dir = env::args().nth(1).unwrap_or_else(|| String::from("."));

    let mut totalseen = 0u64;
    let mut totalzstd = 0u64;

    // Use WalkDir to recursively search for files in the directory
    for entry in WalkDir::new(&current_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        // Check if the entry is a file (not a directory)
        if entry.file_type().is_file() {
            // scan file for compressed data
            let file_name = entry.path().to_str().unwrap();
            let file = std::fs::read(file_name).unwrap();

            println!("File: {}", entry.path().display());
            let mut results: Vec<search_signature::DeflateStreamLocation> = Vec::new();
            search_signature::search_for_deflate_streams(&file, &mut results);

            totalseen += file.len() as u64;
            totalzstd += file.len() as u64;

            if results.len() > 0 {
                for result in results {
                    totalzstd -= result.compressed_size as u64;
                    totalzstd += result.zstd + result.cabac_length as u64;
                    println!(
                        "  Found compressed data s={:?} c={} u={} zstd={} cabac={}",
                        result.signature,
                        result.compressed_size,
                        result.uncompressed_size,
                        result.zstd,
                        result.cabac_length,
                    );
                }
            }
        }
        println!("total seen ratio {}", totalzstd as f64 / totalseen as f64);
    }
}
