/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

mod add_policy_estimator;
mod bit_helper;
mod bit_reader;
mod bit_writer;
mod cabac_codec;
mod complevel_estimator;
mod deflate_reader;
mod deflate_writer;
mod depth_estimator;
mod hash_algorithm;
mod hash_chain;
mod hash_chain_holder;
mod huffman_calc;
mod huffman_encoding;
mod huffman_helper;
mod idat_parse;
mod preflate_constants;
mod preflate_container;
mod preflate_error;
mod preflate_input;
mod preflate_parameter_estimator;
mod preflate_parse_config;
mod preflate_stream_info;
mod preflate_token;
mod process;
mod scan_deflate;
mod statistical_codec;
mod token_predictor;
mod tree_predictor;

pub mod unmanaged_api;

use hash_algorithm::HashAlgorithm;
pub use preflate_container::{
    compress_zstd, decompress_deflate_stream, decompress_zstd, expand_zlib_chunks,
    recompress_deflate_stream, recreated_zlib_chunks,
};
use preflate_error::ExitCode;
pub use preflate_error::{PreflateError, Result};

use std::io::Write;

pub struct PreflateCompressionContext {
    content: Vec<u8>,
    result: Option<Vec<u8>>,
    result_pos: usize,
    compression_stats: CompressionStats,
    test_baseline: bool,
}

#[derive(Debug, Copy, Clone, Default)]
pub struct CompressionStats {
    deflate_compressed_size: u64,
    zstd_compressed_size: u64,
    uncompressed_size: u64,
    overhead_bytes: u64,
    hash_algorithm: HashAlgorithm,
    zstd_baseline_size: u64,
}

impl PreflateCompressionContext {
    pub fn new(test_baseline: bool) -> Self {
        PreflateCompressionContext {
            content: Vec::new(),
            compression_stats: CompressionStats::default(),
            result: None,
            result_pos: 0,
            test_baseline,
        }
    }

    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
        max_output_write: usize,
    ) -> Result<bool> {
        self.content.extend_from_slice(input);

        if input_complete {
            if self.result.is_some() {
                if input.len() > 0 {
                    return Err(PreflateError::new(
                        ExitCode::InvalidParameter,
                        "more data provided after input_complete signaled",
                    ));
                }
            } else {
                if self.test_baseline {
                    self.compression_stats.zstd_baseline_size +=
                        zstd::bulk::compress(&self.content, 9)?.len() as u64;
                }

                self.result = Some(compress_zstd(
                    &self.content,
                    9,
                    &mut self.compression_stats,
                )?);
            }
        }

        if let Some(result) = &mut self.result {
            let amount_to_write = std::cmp::min(max_output_write, result.len() - self.result_pos);

            writer.write(&result[self.result_pos..self.result_pos + amount_to_write])?;
            self.result_pos += amount_to_write;
            Ok(self.result_pos == result.len())
        } else {
            Ok(false)
        }
    }

    pub fn stats(&self) -> CompressionStats {
        self.compression_stats
    }
}

struct PreflateDecompressionContext {
    capacity: usize,
    content: Vec<u8>,
    result: Option<Vec<u8>>,
    result_pos: usize,
}

impl PreflateDecompressionContext {
    fn new(capacity: usize) -> Self {
        PreflateDecompressionContext {
            content: Vec::new(),
            result: None,
            result_pos: 0,
            capacity,
        }
    }

    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
        max_output_write: usize,
    ) -> Result<bool> {
        self.content.extend_from_slice(input);
        if input_complete {
            if self.result.is_some() {
                if input.len() > 0 {
                    return Err(PreflateError::new(
                        ExitCode::InvalidParameter,
                        "more data provided after input_complete signaled",
                    ));
                }
            } else {
                self.result = Some(decompress_zstd(&self.content, self.capacity)?);
            }
        }

        if let Some(result) = &mut self.result {
            let amount_to_write = std::cmp::min(max_output_write, result.len() - self.result_pos);

            writer.write(&result[self.result_pos..self.result_pos + amount_to_write])?;
            self.result_pos += amount_to_write;
            Ok(self.result_pos == result.len())
        } else {
            Ok(false)
        }
    }
}
