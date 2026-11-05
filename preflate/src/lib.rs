/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

//! Split a DEFLATE stream into plaintext and corrections, then reconstruct its exact bytes.
//!
//! ```
//! use preflate_rs::{
//!     PreflateConfig, preflate_whole_deflate_stream, recreate_whole_deflate_stream,
//! };
//!
//! // A final stored block containing "abc".
//! let compressed = b"\x01\x03\x00\xfc\xffabc";
//! let (chunk, plaintext) = preflate_whole_deflate_stream(
//!     compressed, &PreflateConfig::default(),
//! )?;
//! assert_eq!(plaintext.text(), b"abc");
//! assert_eq!(chunk.compressed_size, compressed.len());
//! assert_eq!(
//!     recreate_whole_deflate_stream(plaintext.text(), &chunk.corrections)?,
//!     compressed,
//! );
//! # Ok::<(), preflate_rs::PreflateError>(())
//! ```
//!
//! The convenience helper analyzes one plaintext-limited chunk. For larger streams,
//! retain a [`PreflateStreamProcessor`] and [`RecreateStreamProcessor`] across chunks.
//! Parameter reports are available as JSON through [`PreflateStreamChunkResult::estimator_parameters_json`],
//! not as public estimator types:
//!
//! ```compile_fail
//! use preflate_rs::ReconstructionParameters;
//! ```

// forbid lints that we already have eliminated from the codebase so they don't show up in the future
#![forbid(unsafe_code)]
#![forbid(trivial_casts)]
#![forbid(trivial_numeric_casts)]
#![forbid(non_ascii_idents)]
#![forbid(redundant_lifetimes)]
#![forbid(single_use_lifetimes)]
#![forbid(macro_use_extern_crate)]
#![forbid(missing_unsafe_on_extern)]
#![forbid(unused_import_braces)]
#![warn(unused_crate_dependencies)]
#![warn(unused_extern_crates)]
#![warn(unused_lifetimes)]
#![warn(unused_macro_rules)]

mod bit_helper;
mod cabac;
mod cabac_codec;
mod compressors;
mod deflate;
#[cfg(feature = "diagnostics")]
pub mod diagnostics;
mod estimator;
mod hash_algorithm;
mod hash_chain;
mod hash_chain_holder;
mod parameters;

mod preflate_error;
mod preflate_input;

mod block_predictor;
mod configuration_access;
#[cfg(test)]
mod configuration_fixtures;
mod prediction_state;
mod reconstruction_parameters;
#[cfg(feature = "diagnostics")]
mod reconstruction_validation;
mod statistical_codec;
mod stream_processor;
mod token_predictor;
mod tree_predictor;
#[cfg(test)]
mod utils;

#[cfg(feature = "diagnostics")]
pub use deflate::deflate_token::{DeflateHuffmanType, DeflateToken, DeflateTokenBlockType};
pub use hash_algorithm::HashAlgorithm;
pub use preflate_error::{AddContext, ExitCode, PreflateError, Result, err_exit_code};
pub use preflate_input::{PlainText, PreflateInput};
pub use statistical_codec::{CodecCorrection, CountNonDefaultActions};
#[cfg(feature = "diagnostics")]
pub use stream_processor::estimate_first_chunk_estimator_json;
pub use stream_processor::{
    PreflateStreamChunkResult, PreflateStreamProcessor, RecreateStreamProcessor,
    preflate_whole_deflate_stream, recreate_whole_deflate_stream,
};
#[cfg(any(test, feature = "diagnostics"))]
pub use token_predictor::TokenPredictionTrace;

/// Configure the preflate stream processor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreflateConfig {
    /// Maximum number of lookups we will do in the hash chain. This will limit the
    /// amount of CPU time we spend on each chunk.
    pub max_chain_length: u32,

    /// The maximum size of the plain text that will be decompressed to memory before
    /// being recompressed. This limits memory usage and processing time, especially
    /// for files that are extremely compressed (eg zip bombs)
    pub plain_text_limit: usize,

    /// Decompress the data and verify that it can be recompressed to exactly the same bytes.
    /// This will slow down processing and isn't necessary if you are already doing end-to-end
    /// verification of the data.
    pub verify_compression: bool,
}

impl Default for PreflateConfig {
    fn default() -> Self {
        Self {
            max_chain_length: 4096,
            plain_text_limit: 128 * 1024 * 1024,
            verify_compression: true,
        }
    }
}
