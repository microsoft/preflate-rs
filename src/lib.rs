/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

mod bit_helper;
mod cabac_codec;
mod deflate;
mod estimator;
mod hash_algorithm;
mod hash_chain;
mod hash_chain_holder;
mod idat_parse;
mod preflate_container;
mod preflate_error;
mod preflate_input;
mod process;
mod scan_deflate;
mod scoped_read;
mod statistical_codec;
mod token_predictor;
mod tree_predictor;

pub mod unmanaged_api;

pub use preflate_container::{
    compress_zstd, decompress_deflate_stream, decompress_zstd, expand_zlib_chunks,
    recompress_deflate_stream, recreated_zlib_chunks,
};
pub use preflate_error::ExitCode;
pub use preflate_error::{PreflateError, Result};

pub use preflate_container::CompressionStats;
pub use preflate_container::{
    PreflateCompressionContext, ProcessBuffer, RecreateFromChunksContext, ZstdCompressContext,
    ZstdDecompressContext,
};
