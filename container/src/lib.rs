/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

// forbid lints that we already have eliminated from the codebase so they don't show up in the future
#![forbid(unsafe_code)]
#![forbid(trivial_casts)]
#![forbid(trivial_numeric_casts)]
#![deny(clippy::cast_lossless)]
#![forbid(non_ascii_idents)]
#![forbid(redundant_lifetimes)]
#![forbid(single_use_lifetimes)]
#![forbid(missing_unsafe_on_extern)]
#![forbid(unused_import_braces)]
#![forbid(unused_lifetimes)]
#![warn(unused_extern_crates)]
#![warn(unused_macro_rules)]
#![warn(unused_crate_dependencies)]
#![warn(macro_use_extern_crate)]

use preflate_rs::Result;
use std::io::{BufReader, Read, Write};

mod container_common;
mod container_read;
mod container_write;
mod idat_parse;
mod scan_deflate;
mod scoped_read;
mod utils;

pub use container_common::{PreflateContainerConfig, PreflateStats, ProcessBuffer};
pub use container_read::RecreateContainerProcessor;
pub use container_write::PreflateContainerProcessor;

pub use utils::process_limited_buffer;

/// Convenience wrapper: compresses an entire input stream into the preflate container format.
pub fn preflate_whole_into_container(
    config: &PreflateContainerConfig,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<()> {
    let mut processor = PreflateContainerProcessor::new(config, 9, false);
    processor.copy_to_end(&mut BufReader::new(input), output)
}

/// Convenience wrapper: recreates the original data from a preflate container stream.
pub fn recreate_whole_from_container(input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    let mut processor = RecreateContainerProcessor::new(128 * 1024 * 1024);
    processor.copy_to_end(&mut BufReader::new(input), output)
}

#[cfg(test)]
static INIT: std::sync::Once = std::sync::Once::new();

/// Initialize the logger for tests. This is a no-op if the logger is already initialized.
#[cfg(test)]
pub fn init_logging() {
    INIT.call_once(|| {
        let _ = env_logger::builder().is_test(true).try_init();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    struct StreamingRead<R>(R);

    impl<R: Read> Read for StreamingRead<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            assert!(
                buffer.len() <= 8192,
                "Reader must not be used to buffer the whole input"
            );
            self.0.read(buffer)
        }
    }

    #[test]
    fn whole_stream_helpers_read_incrementally() {
        let input = (0u32..32_768)
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let mut encoded = Vec::new();
        preflate_whole_into_container(
            &PreflateContainerConfig::default(),
            &mut StreamingRead(Cursor::new(&input)),
            &mut encoded,
        )
        .unwrap();
        let mut restored = Vec::new();
        recreate_whole_from_container(&mut StreamingRead(Cursor::new(&encoded)), &mut restored)
            .unwrap();
        assert_eq!(restored, input);
    }
}
