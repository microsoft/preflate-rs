/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

//! Chunked DEFLATE analysis and exact reconstruction.
//!
//! Analysis parses compressed blocks into plaintext and records the corrections
//! needed to recreate their original encoding. The first chunk estimates the
//! compressor settings and stores them with its corrections; continuation chunks
//! reuse the predictor instead of repeating estimation.
//!
//! Analysis and reconstruction retain dictionary history across plaintext-limited
//! chunks, allowing long streams to be processed without keeping all plaintext
//! in memory. Reconstruction reads the settings and corrections, recovers the
//! original blocks, and writes their DEFLATE bytes. Optional verification checks
//! those bytes against the corresponding compressed input.

use std::io::{BufRead, Cursor};

use bitcode::{Decode, Encode};

use crate::{
    PreflateConfig, Result,
    cabac::vp8::{VP8Reader, VP8Writer},
    cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
    deflate::{
        deflate_reader::{DeflateContents, DeflateParser},
        deflate_token::DeflateTokenBlock,
        deflate_writer::DeflateWriter,
    },
    preflate_error::{AddContext, ExitCode, PreflateError},
    preflate_input::{PlainText, PreflateInput},
    reconstruction_parameters::ReconstructionParameters,
    statistical_codec::{CodecCorrection, PredictionDecoder, PredictionEncoder},
    token_predictor::TokenPredictor,
};

/// Version byte written in front of the serialized `ReconstructionData`.
/// The developing 0.8 format intentionally permits breaking changes under the same tag.
///
/// The high bit is set because unversioned blobs from 0.7 and earlier start with a small bitcode
/// byte (0x00 or 0x01 in practice), so they are rejected here instead of being misinterpreted.
pub(crate) const RECONSTRUCTION_DATA_VERSION: u8 = 0x84;

#[derive(Encode, Decode)]
struct ReconstructionData {
    parameters: ReconstructionParameters,
    corrections: Vec<u8>,
}

impl ReconstructionData {
    pub fn write(self) -> Vec<u8> {
        let mut data = vec![RECONSTRUCTION_DATA_VERSION];
        data.extend_from_slice(&bitcode::encode(&self));
        data
    }

    pub fn read(data: &[u8]) -> Result<Self> {
        match data.split_first() {
            Some((&RECONSTRUCTION_DATA_VERSION, payload)) => {
                bitcode::decode::<Self>(payload)
                    .map_err(|e| {
                        PreflateError::new(ExitCode::InvalidCompressedWrapper, format!("{e:?}"))
                    })
            }
            Some((&version, _)) => Err(PreflateError::new(
                ExitCode::InvalidCompressedWrapper,
                format!(
                    "unsupported corrections version {version:#04x}, expected {RECONSTRUCTION_DATA_VERSION:#04x}"
                )
                .as_str(),
            )),
            None => Err(PreflateError::new(
                ExitCode::InvalidCompressedWrapper,
                "empty corrections",
            )),
        }
    }
}

/// Result of a call to PreflateStreamProcessor::decompress
pub struct PreflateStreamChunkResult {
    /// the extra data that is needed to reconstruct the deflate stream exactly as it was written
    pub corrections: Vec<u8>,

    /// the number of bytes that were processed from the compressed stream (this will be exactly the
    /// data that will be recreated using the cabac_encoded data)
    pub compressed_size: usize,

    /// Parameter report retained only for the first chunk.
    parameters: Option<crate::estimator::EstimationResult>,

    pub blocks: Vec<DeflateTokenBlock>,
}

impl PreflateStreamChunkResult {
    /// Serialize the first chunk's parameter report, or return `None` for continuation chunks.
    ///
    /// ```compile_fail
    /// fn inspect(chunk: &preflate_rs::PreflateStreamChunkResult) {
    ///     let _ = &chunk.parameters;
    /// }
    /// ```
    pub fn estimator_parameters_json(&self) -> Result<Option<String>> {
        self.parameters
            .map(crate::estimator::EstimationResult::to_json)
            .transpose()
    }

    /// Serialize only the executable settings stored in the reconstruction record.
    pub fn reconstruction_parameters_json(&self) -> Result<Option<String>> {
        self.parameters
            .map(|report| report.reconstruction.to_json())
            .transpose()
    }

    /// Hash used by the first chunk, without serializing diagnostic metadata.
    pub fn hash_algorithm(&self) -> Option<crate::HashAlgorithm> {
        self.parameters
            .map(|report| report.reconstruction.hash_algorithm())
    }
}

pub(crate) fn encode_first_chunk(
    predictor: &mut TokenPredictor,
    contents: &DeflateContents,
    plain: &PlainText,
    complete: bool,
    counter: Option<&mut crate::CountNonDefaultActions>,
) -> Result<Vec<u8>> {
    encode_first_chunk_observed(
        predictor,
        contents,
        plain,
        complete,
        counter,
        |_, _, _, _| {},
    )
}

pub(crate) fn encode_first_chunk_observed(
    predictor: &mut TokenPredictor,
    contents: &DeflateContents,
    plain: &PlainText,
    complete: bool,
    counter: Option<&mut crate::CountNonDefaultActions>,
    observe: impl FnMut(usize, bool, &mut TokenPredictor, &PreflateInput),
) -> Result<Vec<u8>> {
    predictor.enable_parameter_normalization(contents.compressed_size, complete);
    let mut corrections = Vec::new();
    let mut encoder = (
        counter,
        PredictionEncoderCabac::new(VP8Writer::new(&mut corrections).unwrap()),
    );
    predict_blocks_observed(
        &contents.blocks,
        predictor,
        &mut encoder,
        &mut PreflateInput::new(plain),
        observe,
    )?;
    encoder.finish();
    Ok(ReconstructionData {
        parameters: predictor.finalize_reconstruction_parameters(),
        corrections,
    }
    .write())
}

/// Takes a stream of deflate compressed data removes the deflate compression, recording the data
/// that can be used to reconstruct it along with the plain-text.
#[derive(Debug)]
pub struct PreflateStreamProcessor {
    predictor: Option<TokenPredictor>,
    validator: Option<RecreateStreamProcessor>,
    parser: DeflateParser,
    max_chain_length: u32,
    #[cfg(any(test, feature = "diagnostics"))]
    trace: Option<crate::TokenPredictionTrace>,
}

impl PreflateStreamProcessor {
    /// Creates a processor with the plaintext, chain-depth and verification limits in `config`.
    pub fn new(config: &PreflateConfig) -> Self {
        Self {
            predictor: None,
            parser: DeflateParser::new(config.plain_text_limit),
            max_chain_length: config.max_chain_length,
            #[cfg(any(test, feature = "diagnostics"))]
            trace: None,
            validator: if config.verify_compression {
                Some(RecreateStreamProcessor::new())
            } else {
                None
            },
        }
    }

    /// Enable bounded mismatch sampling while counting all initial token predictions.
    #[cfg(any(test, feature = "diagnostics"))]
    pub fn enable_trace(&mut self, max_mismatches: usize) {
        self.trace = Some(crate::TokenPredictionTrace {
            max_mismatches,
            ..Default::default()
        });
    }

    #[cfg(any(test, feature = "diagnostics"))]
    pub fn prediction_trace(&self) -> Option<&crate::TokenPredictionTrace> {
        self.trace.as_ref()
    }

    pub fn is_done(&self) -> bool {
        self.parser.is_done()
    }

    pub fn plain_text(&self) -> &PlainText {
        self.parser.plain_text()
    }

    pub fn shrink_to_dictionary(&mut self) {
        self.parser.shrink_to_dictionary();
    }

    pub fn detach_plain_text(self) -> PlainText {
        self.parser.detach_plain_text()
    }

    /// Analyzes the next plaintext-limited chunk of a DEFLATE stream.
    ///
    /// Advance the compressed input by the returned `compressed_size`, consume the
    /// new plaintext through [`Self::plain_text`], then call [`Self::shrink_to_dictionary`]
    /// before the next chunk. Retain the processor until [`Self::is_done`] is true.
    pub fn decompress(&mut self, compressed_data: &[u8]) -> Result<PreflateStreamChunkResult> {
        self.decompress_counted(compressed_data, None)
    }

    /// Like `decompress`, also accumulating nonzero correction actions for diagnostics.
    /// Counts include structural actions; they are not token mismatch counts or bit costs.
    pub fn decompress_with_statistics(
        &mut self,
        compressed_data: &[u8],
        counts: &mut crate::CountNonDefaultActions,
    ) -> Result<PreflateStreamChunkResult> {
        self.decompress_counted(compressed_data, Some(counts))
    }

    fn decompress_counted(
        &mut self,
        compressed_data: &[u8],
        counter: Option<&mut crate::CountNonDefaultActions>,
    ) -> Result<PreflateStreamChunkResult> {
        #[cfg(any(test, feature = "diagnostics"))]
        if let Some(trace) = &mut self.trace {
            trace.stage = "parse";
            trace.block_profile = "Default";
        }
        let contents = self.parser.parse(compressed_data)?;

        if let Some(predictor) = &mut self.predictor {
            let mut cabac_encoded = Vec::new();
            let mut cabac_encoder = (
                counter,
                PredictionEncoderCabac::new(VP8Writer::new(&mut cabac_encoded).unwrap()),
            );
            let mut input = PreflateInput::new(self.parser.plain_text());

            // we are missing the last couple hashes in the dictionary since we didn't
            // have the full plaintext yet.
            predictor.add_missing_previous_hash(&input);

            #[cfg(any(test, feature = "diagnostics"))]
            {
                if let Some(trace) = &mut self.trace {
                    trace.stage = "predict";
                }
                predictor.trace = self.trace.take();
            }
            let prediction =
                predict_blocks(&contents.blocks, predictor, &mut cabac_encoder, &mut input);
            #[cfg(any(test, feature = "diagnostics"))]
            {
                self.trace = predictor.trace.take();
            }
            prediction?;

            cabac_encoder.finish();

            if let Some(validator) = &mut self.validator {
                #[cfg(any(test, feature = "diagnostics"))]
                if let Some(trace) = &mut self.trace {
                    trace.stage = "verify";
                }
                let (recompressed, _rec_blocks) = validator.recompress(
                    &mut Cursor::new(self.parser.plain_text().text()),
                    &cabac_encoded,
                )?;

                #[cfg(test)]
                for (i, block) in contents.blocks.iter().enumerate() {
                    crate::utils::assert_block_eq(block, &_rec_blocks[i]);
                }

                // we should always succeed here in test code
                #[cfg(test)]
                crate::utils::assert_eq_array(
                    &recompressed,
                    &compressed_data[..contents.compressed_size],
                );

                if recompressed[..] != compressed_data[..contents.compressed_size] {
                    return Err(PreflateError::new(
                        ExitCode::RoundtripMismatch,
                        "recompressed data does not match original",
                    ));
                }
            }

            #[cfg(any(test, feature = "diagnostics"))]
            if let Some(trace) = &mut self.trace {
                trace.stage = "complete";
            }
            Ok(PreflateStreamChunkResult {
                corrections: cabac_encoded,
                compressed_size: contents.compressed_size,
                parameters: None,
                blocks: contents.blocks,
            })
        } else {
            let (reconstruction_data, token_predictor, params) =
                crate::estimator::estimate_and_encode(
                    &contents,
                    self.parser.plain_text(),
                    self.parser.is_done(),
                    self.max_chain_length,
                    counter,
                    #[cfg(any(test, feature = "diagnostics"))]
                    &mut self.trace,
                )?;
            self.predictor = Some(token_predictor);

            if let Some(validator) = &mut self.validator {
                #[cfg(any(test, feature = "diagnostics"))]
                if let Some(trace) = &mut self.trace {
                    trace.stage = "verify";
                }
                let (recompressed, _rec_blocks) = validator.recompress(
                    &mut Cursor::new(self.parser.plain_text().text()),
                    &reconstruction_data,
                )?;

                #[cfg(test)]
                for (i, block) in contents.blocks.iter().enumerate() {
                    crate::utils::assert_block_eq(block, &_rec_blocks[i]);
                }

                // we should always succeed here in test code
                #[cfg(test)]
                crate::utils::assert_eq_array(
                    &recompressed,
                    &compressed_data[..contents.compressed_size],
                );

                if recompressed[..] != compressed_data[..contents.compressed_size] {
                    return Err(PreflateError::new(
                        ExitCode::RoundtripMismatch,
                        "recompressed data does not match original",
                    ));
                }
            }

            #[cfg(any(test, feature = "diagnostics"))]
            if let Some(trace) = &mut self.trace {
                trace.stage = "complete";
            }
            Ok(PreflateStreamChunkResult {
                corrections: reconstruction_data,
                compressed_size: contents.compressed_size,
                parameters: Some(params),
                blocks: contents.blocks,
            })
        }
    }
}

/// Parse and estimate the first chunk without correction coding or reconstruction.
/// Estimation may perform bounded candidate prediction scoring, not full-stream replay.
/// Tiny complete streams may normalize window/cutoff parameters during prediction;
/// this returns the estimator's original parameters as JSON, not those normalized values.
#[cfg(feature = "diagnostics")]
pub fn estimate_first_chunk_estimator_json(
    compressed_data: &[u8],
    plain_text_limit: usize,
) -> Result<String> {
    let mut parser = DeflateParser::new(plain_text_limit);
    let contents = parser.parse(compressed_data)?;
    crate::estimator::estimate_preflate_result(&contents, parser.plain_text())?.to_json()
}

/// Analyzes one plaintext-limited chunk and returns its plaintext and corrections.
///
/// If `compressed_size` is smaller than the supplied input, the remainder may be
/// another chunk or trailing wrapper data. Use [`PreflateStreamProcessor`] and its
/// completion state when processing streams larger than the configured plaintext limit.
pub fn preflate_whole_deflate_stream(
    compressed_data: &[u8],
    config: &PreflateConfig,
) -> Result<(PreflateStreamChunkResult, PlainText)> {
    let mut state = PreflateStreamProcessor::new(config);
    let r = state.decompress(compressed_data)?;

    Ok((r, state.parser.detach_plain_text()))
}

/// recreates the original deflate stream, piece-by-piece
#[derive(Debug)]
pub struct RecreateStreamProcessor {
    predictor: Option<TokenPredictor>,
    writer: DeflateWriter,
    plain_text: PlainText,
}

impl RecreateStreamProcessor {
    pub fn new() -> Self {
        Self {
            predictor: None,
            writer: DeflateWriter::new(),
            plain_text: PlainText::new(),
        }
    }

    pub fn recompress(
        &mut self,
        plain_text: &mut impl BufRead,
        corrections: &[u8],
    ) -> Result<(Vec<u8>, Vec<DeflateTokenBlock>)> {
        loop {
            let buf = plain_text.fill_buf().context()?;
            let buf_len = buf.len();
            if buf_len == 0 {
                break;
            }

            self.plain_text.append(buf);

            plain_text.consume(buf_len);
        }

        let mut input = PreflateInput::new(&self.plain_text);

        if let Some(predictor) = &mut self.predictor {
            let mut cabac_decoder =
                PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(corrections)).unwrap());

            predictor.add_missing_previous_hash(&input);

            let blocks =
                recreate_blocks(predictor, &mut cabac_decoder, &mut self.writer, &mut input)
                    .context()?;

            self.plain_text.shrink_to_dictionary();

            self.writer.flush();

            Ok((self.writer.detach_output(), blocks))
        } else {
            let r = ReconstructionData::read(corrections)?;
            let mut predictor = TokenPredictor::from_reconstruction_parameters(r.parameters);

            let mut cabac_decoder =
                PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(r.corrections)).unwrap());

            let blocks = recreate_blocks(
                &mut predictor,
                &mut cabac_decoder,
                &mut self.writer,
                &mut input,
            )
            .context()?;

            self.predictor = Some(predictor);

            self.plain_text.shrink_to_dictionary();

            self.writer.flush();

            Ok((self.writer.detach_output(), blocks))
        }
    }
}

impl Default for RecreateStreamProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// recompresses a deflate stream using the cabac_encoded data that was returned from decompress_deflate_stream
pub fn recreate_whole_deflate_stream(
    plain_text: &[u8],
    prediction_corrections: &[u8],
) -> Result<Vec<u8>> {
    let mut state = RecreateStreamProcessor::new();

    let (recompressed, _) =
        state.recompress(&mut Cursor::new(&plain_text), prediction_corrections)?;

    Ok(recompressed)
}

fn predict_blocks(
    blocks: &[DeflateTokenBlock],
    token_predictor: &mut TokenPredictor,
    encoder: &mut impl PredictionEncoder,
    input: &mut PreflateInput,
) -> Result<()> {
    predict_blocks_observed(blocks, token_predictor, encoder, input, |_, _, _, _| {})
}

pub(crate) fn predict_blocks_observed(
    blocks: &[DeflateTokenBlock],
    token_predictor: &mut TokenPredictor,
    encoder: &mut impl PredictionEncoder,
    input: &mut PreflateInput,
    mut observe: impl FnMut(usize, bool, &mut TokenPredictor, &PreflateInput),
) -> Result<()> {
    let tail_length = token_predictor.begin_chunk(blocks);
    for i in 0..blocks.len() {
        observe(i, true, token_predictor, input);
        token_predictor.predict_block(
            &blocks[i],
            encoder,
            input,
            i + tail_length + 1 == blocks.len(),
        )?;
        encoder.encode_correction_bool(
            CodecCorrection::EndOfChunk,
            i == blocks.len() - 1,
            token_predictor.predict_end_of_chunk(input),
        );
        observe(i, false, token_predictor, input);
    }
    assert!(input.remaining() == 0);
    Ok(())
}

fn recreate_blocks<D: PredictionDecoder>(
    token_predictor: &mut TokenPredictor,
    decoder: &mut D,
    deflate_writer: &mut DeflateWriter,
    input: &mut PreflateInput,
) -> Result<Vec<DeflateTokenBlock>> {
    token_predictor.begin_chunk(&[]);
    let mut output_blocks = Vec::new();
    loop {
        let block = token_predictor.recreate_block(decoder, input)?;

        deflate_writer.encode_block(&block)?;

        output_blocks.push(block);

        let last = decoder.decode_correction_bool(
            CodecCorrection::EndOfChunk,
            token_predictor.predict_end_of_chunk(input),
        );

        if last {
            break;
        }
    }
    Ok(output_blocks)
}

#[cfg(test)]
#[path = "prediction_diagnostics.rs"]
pub(crate) mod tests;
