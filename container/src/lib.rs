/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

//! Recompression of files containing embedded DEFLATE streams and images.
//! Provides streaming compression and reconstruction, with Zstd for shared
//! payloads and specialized handling for PNG and JPEG data.

// forbid lints that we already have eliminated from the codebase so they don't show up in the future
#![forbid(unsafe_code)]
#![forbid(trivial_casts)]
#![forbid(trivial_numeric_casts)]
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

mod container_common;
mod container_read;
mod container_write;
mod diagnostics;
mod idat_parse;
mod scan_deflate;
mod scoped_read;
mod utils;

pub use container_common::{PreflateContainerConfig, PreflateStats, ProcessBuffer};
pub use container_read::RecreateContainerProcessor;
pub use container_write::PreflateContainerProcessor;
#[cfg(feature = "diagnostics")]
pub use diagnostics::diagnostic_deflate_payload;
pub use diagnostics::{
    DeflateDiagnostic, DiagnosticParameters, DiagnosticScanOptions, scan_deflate_diagnostics,
    scan_deflate_diagnostics_with_options,
};
pub use utils::process_limited_buffer;

/// Compresses an entire input stream into the preflate container format.
///
/// This convenience helper buffers the entire input. Use [`PreflateContainerProcessor`]
/// with [`ProcessBuffer::copy_to_end`] for bounded input buffering.
pub fn preflate_whole_into_container(
    config: &PreflateContainerConfig,
    input: &mut impl std::io::Read,
    output: &mut impl std::io::Write,
) -> preflate_rs::Result<()> {
    let mut processor = PreflateContainerProcessor::new(config, 9, false);
    let mut buf = Vec::new();
    input.read_to_end(&mut buf).map_err(|e| {
        preflate_rs::PreflateError::new(preflate_rs::ExitCode::GeneralFailure, e.to_string())
    })?;
    processor.process_buffer(&buf, true, output)
}

/// Recreates the original data from a preflate container stream.
///
/// This convenience helper buffers the entire container. Use [`RecreateContainerProcessor`]
/// with [`ProcessBuffer::copy_to_end`] for bounded input buffering.
pub fn recreate_whole_from_container(
    input: &mut impl std::io::Read,
    output: &mut impl std::io::Write,
) -> preflate_rs::Result<()> {
    let mut processor = RecreateContainerProcessor::new(128 * 1024 * 1024);
    let mut buf = Vec::new();
    input.read_to_end(&mut buf).map_err(|e| {
        preflate_rs::PreflateError::new(preflate_rs::ExitCode::GeneralFailure, e.to_string())
    })?;
    processor.process_buffer(&buf, true, output)
}
