use std::fs::File;
use std::io::Read;
use std::{env, fs, path::Path};

use preflate_rs::{compress_zstd, decompress_zstd};

#[derive(Debug, Default)]
struct Results {
    original_size: u64,
    preflate_size: u64,
    zstd_size: u64,
    file_count_worked: u64,
    file_count_total: u64,
}

fn visit_dirs(item: &Path, results: &mut Results) {
    if item.is_dir() {
        if let Ok(dir_entries) = fs::read_dir(item) {
            for entry in dir_entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if entry.metadata().unwrap().len() > 1024 * 1024 * 4 {
                        continue;
                    }

                    visit_dirs(&path, results);
                }
            }
        }
    } else {
        if let Ok(contents) = read_file(item.to_str().unwrap()) {
            let comp_preflate = compress_zstd(&contents);

            let comp_plain_zstd = zstd::bulk::compress(&contents, 9).unwrap();

            let recreate = decompress_zstd(&comp_preflate).unwrap();

            assert_eq!(contents, recreate);

            // if preflate didn't help, then just use the plain zstd compression size
            if comp_preflate.len() > comp_plain_zstd.len() {
                results.preflate_size += comp_plain_zstd.len() as u64;
            } else {
                results.file_count_worked += 1;
                results.preflate_size += comp_preflate.len() as u64;
            }

            results.file_count_total += 1;
            results.zstd_size += comp_plain_zstd.len() as u64;
            results.original_size += contents.len() as u64;
        }
    }
}

fn read_file(filename: &str) -> Result<Vec<u8>, std::io::Error> {
    println!("reading {0}", filename);
    let mut f = File::open(filename)?;

    let mut content = Vec::new();
    f.read_to_end(&mut content)?;

    Ok(content)
}

fn main() {
    let current_dir = env::args().nth(1).unwrap_or_else(|| String::from("."));

    let mut results = Results::default();
    visit_dirs(Path::new(&current_dir), &mut results);

    println!("results:");
    println!("original size: {:>10}", results.original_size);
    println!("preflate size: {:>10}", results.preflate_size);
    println!("zstd size:     {:>10}", results.zstd_size);
    println!("file count:    {:>10}/{}", results.file_count_worked, results.file_count_total);
}
