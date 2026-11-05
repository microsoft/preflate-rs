//! Fuzzes raw DEFLATE parsing and reconstruction with arbitrary input.
//! For accepted streams, checks that the plaintext and correction data can be
//! consumed by the reconstruction API.

#![no_main]

use preflate_rs::{preflate_whole_deflate_stream, recreate_whole_deflate_stream, PreflateConfig};

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let config = PreflateConfig::default();
    if let Ok((r, pt)) = preflate_whole_deflate_stream(data, &config) {
        recreate_whole_deflate_stream(pt.text(), &r.corrections).unwrap();
    }
});
