/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

// forbid lints that we already have eliminated from the codebase so they don't show up in the future
#![forbid(unsafe_code)]
#![forbid(trivial_casts)]
#![forbid(trivial_numeric_casts)]
#![forbid(non_ascii_idents)]
#![forbid(unused_extern_crates)]
#![forbid(unused_import_braces)]
#![forbid(redundant_lifetimes)]
#![forbid(single_use_lifetimes)]
#![forbid(unused_crate_dependencies)]
#![forbid(unused_extern_crates)]
#![forbid(unused_lifetimes)]
#![forbid(unused_macro_rules)]
#![forbid(macro_use_extern_crate)]
#![forbid(missing_unsafe_on_extern)]

mod container_processor;
mod idat_parse;
mod scan_deflate;
mod scoped_read;
mod utils;
mod zstd_compression;
pub use zstd_compression::{
    zstd_preflate_whole_deflate_stream, zstd_recreate_whole_deflate_stream,
};

pub use container_processor::{PreflateContainerConfig, PreflateStats};
pub use container_processor::{
    PreflateContainerProcessor, ProcessBuffer, RecreateContainerProcessor,
    preflate_whole_into_container, recreate_whole_from_container,
};

pub use zstd_compression::{ZstdCompressContext, ZstdDecompressContext};

#[cfg(test)]
static INIT: std::sync::Once = std::sync::Once::new();

/// Initialize the logger for tests. This is a no-op if the logger is already initialized.
#[cfg(test)]
pub fn init_logging() {
    INIT.call_once(|| {
        let _ = env_logger::builder().is_test(true).try_init();
    });
}
