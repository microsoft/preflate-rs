/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

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
    decompress_whole_deflate_stream, recompress_whole_deflate_stream, PreflateChunkProcessor,
    PreflateChunkResult, RecreateChunkProcessor,
};

pub use zstd_compression::{compress_zstd, decompress_zstd};

pub use preflate_error::ExitCode;
pub use preflate_error::{PreflateError, Result};

pub use preflate_container::{
    prefate_container, recreated_container, PreflateContainerProcessor, ProcessBuffer,
    RecreateContainerProcessor,
};
pub use preflate_container::{CompressionConfig, CompressionStats};

pub use zstd_compression::{ZstdCompressContext, ZstdDecompressContext};
