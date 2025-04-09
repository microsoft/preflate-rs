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

mod bit_helper;
mod cabac_codec;
mod container_processor;
mod deflate;
mod estimator;
mod hash_algorithm;
mod hash_chain;
mod hash_chain_holder;
mod idat_parse;
mod preflate_error;
mod preflate_input;
mod scan_deflate;
mod scoped_read;
mod statistical_codec;
mod stream_processor;
mod token_predictor;
mod tree_predictor;
mod zstd_compression;

mod utils;

pub use stream_processor::{
    PreflateStreamChunkResult, PreflateStreamProcessor, RecreateStreamProcessor,
    preflate_whole_deflate_stream, recreate_whole_deflate_stream,
};

pub use zstd_compression::{
    zstd_preflate_whole_deflate_stream, zstd_recreate_whole_deflate_stream,
};

pub use preflate_error::ExitCode;
pub use preflate_error::{PreflateError, Result};

pub use container_processor::{PreflateConfig, PreflateStats};
pub use container_processor::{
    PreflateContainerProcessor, ProcessBuffer, RecreateContainerProcessor,
    preflate_whole_into_container, recreate_whole_from_container,
};

pub use zstd_compression::{ZstdCompressContext, ZstdDecompressContext};
