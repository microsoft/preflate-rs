#![no_main]

use preflate_container::{
    preflate_whole_into_container, recreate_whole_from_container, PreflateContainerConfig,
};
use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 {
        return;
    }

    let config = PreflateContainerConfig::default();

    let mut output = Vec::new();

    if let Ok(_r) = preflate_whole_into_container(&config, &mut Cursor::new(data), &mut output) {
        //println!("Compressed {} bytes into {} bytes", data.len(), output.len());
        let mut original = Vec::new();
        recreate_whole_from_container(&mut Cursor::new(&output), &mut original).unwrap();
        assert_eq!(data, &original[..]);
    }
});
