#![no_main]

use std::io::Cursor;

use preflate_rs::decompress_deflate_stream;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {

    let _ = decompress_deflate_stream(data, true, 0);
});
