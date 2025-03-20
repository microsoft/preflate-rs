/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

#![doc = include_str!("../README.md")]

mod bit_helper;
mod cabac_codec;
mod chunk_processor;
mod deflate;
mod estimator;
mod hash_algorithm;
mod hash_chain;
mod hash_chain_holder;
mod idat_parse;
mod preflate_container;
mod preflate_error;
mod preflate_input;
mod scan_deflate;
mod scoped_read;
mod statistical_codec;
mod token_predictor;
mod tree_predictor;
mod zstd_compression;

mod utils;

pub mod unmanaged_api;

pub use chunk_processor::{
    preflate_whole_deflate_stream, recreate_whole_deflate_stream, PreflateChunkProcessor,
    PreflateChunkResult, RecreateChunkProcessor,
};

pub use zstd_compression::{
    zstd_preflate_whole_deflate_stream, zstd_recreate_whole_deflate_stream,
};

pub use preflate_error::ExitCode;
pub use preflate_error::{PreflateError, Result};

pub use preflate_container::{
    preflate_whole_into_container, recreate_whole_from_container, PreflateContainerProcessor,
    ProcessBuffer, RecreateContainerProcessor,
};
pub use preflate_container::{PreflateConfig, PreflateStats};

pub use zstd_compression::{ZstdCompressContext, ZstdDecompressContext};
