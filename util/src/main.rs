use std::{
    env, fs,
    io::BufReader,
    path::{Path, PathBuf},
};

use preflate_rs::{PreflateConfig, PreflateContainerProcessor, ProcessBuffer, ZstdCompressContext};

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
    simple_log::quick!();

    let current_dir = env::args().nth(1).unwrap_or_else(|| String::from("."));

    let mut totalseen = 0u64;
    let mut totalbaseline = 0u64;
    let mut totalzstd = 0u64;

    // Use WalkDir to recursively search for files in the directory
    for entry in enumerate_directory_recursively(Path::new(&current_dir)).unwrap() {
        // Check if the entry is a file (not a directory)
        // scan file for compressed data
        println!("Processing file: {:?}", entry);

        // open file for reading
        let mut filehandle = BufReader::new(fs::File::open(&entry).unwrap());

        let mut ctx = ZstdCompressContext::new(
            PreflateContainerProcessor::new(PreflateConfig::default()),
            9,
            true,
        );

        let mut preflatecompressed = Vec::new();
        if let Err(e) = ctx.copy_to_end(&mut filehandle, &mut preflatecompressed) {
            println!("Skipping due to error: {:?}", e);
            continue;
        }

        let stats = ctx.stats();

        println!(
            "compressed ratio: {:.1}",
            (1f64 - (stats.zstd_compressed_size as f64 / stats.deflate_compressed_size as f64))
                * 100f64
        );

        totalseen += stats.deflate_compressed_size as u64;
        totalbaseline += stats.zstd_baseline_size as u64;
        totalzstd += stats.zstd_compressed_size as u64;

        println!(
            "total seen ratio {totalzstd}:{totalbaseline}:{totalseen} {:.1}",
            (1f64 - totalzstd as f64 / totalbaseline as f64) * 100f64
        );
    }
}
