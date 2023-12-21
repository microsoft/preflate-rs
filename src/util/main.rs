use std::fs::File;
use std::io::Read;
use std::{env, fs, path::Path};

use preflate_rs::{compress_zstd, decompress_zstd};

#[derive(Debug, Default)]
struct Results {
    original_size: u64,
    preflate_size: u64,
    zstd_size: u64,
    file_count: u64,
}

fn visit_dirs(item: &Path, results: &mut Results) {
    if item.is_dir() {
        for entry in fs::read_dir(item).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.metadata().unwrap().len() > 1024 * 1024 * 4 {
                continue;
            }

            visit_dirs(&path, results);
        }
    } else {
        let contents = read_file(item.to_str().unwrap());

        let comp_preflate = compress_zstd(&contents);

        let comp_plain = zstd::bulk::compress(&contents, 9).unwrap();

        let recreate = decompress_zstd(&comp_preflate, 40 * 1024 * 1024).unwrap();

        assert_eq!(contents, recreate);

        results.original_size += contents.len() as u64;
        results.preflate_size += comp_preflate.len() as u64;
        results.zstd_size += comp_plain.len() as u64;

        results.file_count += 1;
    }
}

fn read_file(filename: &str) -> Vec<u8> {
    println!("reading {0}", filename);
    let mut f = File::open(filename).unwrap();

    let mut content = Vec::new();
    f.read_to_end(&mut content).unwrap();

    content
}

fn main() {
    let current_dir = env::args().nth(1).unwrap_or_else(|| String::from("."));

    let mut results = Results::default();
    visit_dirs(Path::new(&current_dir), &mut results);

    println!("results:");
    println!("original size: {:>10}", results.original_size);
    println!("preflate size: {:>10}", results.preflate_size);
    println!("zstd size:     {:>10}", results.zstd_size);
    println!("file count:    {:>10}", results.file_count);
}
