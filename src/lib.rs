/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

#![doc = include_str!("../README.md")]

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

pub mod unmanaged_api;

pub use stream_processor::{
    preflate_whole_deflate_stream, recreate_whole_deflate_stream, PreflateStreamChunkResult,
    PreflateStreamProcessor, RecreateStreamProcessor,
};

pub use zstd_compression::{
    zstd_preflate_whole_deflate_stream, zstd_recreate_whole_deflate_stream,
};

pub use preflate_error::ExitCode;
pub use preflate_error::{PreflateError, Result};

pub use container_processor::{
    preflate_whole_into_container, recreate_whole_from_container, PreflateContainerProcessor,
    ProcessBuffer, RecreateContainerProcessor,
};
pub use container_processor::{PreflateConfig, PreflateStats};

pub use zstd_compression::{ZstdCompressContext, ZstdDecompressContext};
