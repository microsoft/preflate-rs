//! Bounded, explicit-parameter replay. JSON and file access belong to callers.

use serde::{Deserialize, Serialize};

use crate::{
    CountNonDefaultActions, ExitCode, HashAlgorithm, PreflateError, Result,
    TokenPredictorParameters,
    deflate::{
        deflate_reader::DeflateParser,
        deflate_token::{
            DeflateHuffmanType, DeflateToken, DeflateTokenBlock, DeflateTokenBlockType,
            DeflateTokenReference,
        },
        deflate_writer::DeflateWriter,
    },
    parameters::{DictionaryAddPolicy, LazyBehavior, MatchingType, PreflateStrategy},
    preflate_input::PreflateInput,
    stream_processor::{
        encode_first_chunk_observed, predict_blocks_observed, recreate_whole_deflate_stream,
    },
    token_predictor::{TokenPredictionTrace, TokenPredictor},
};

/// Limits apply to the entire first chunk, including context outside the reported range.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReplayOptions {
    pub max_input_bytes: usize,
    pub max_plaintext_bytes: usize,
    pub max_tokens: usize,
    pub max_blocks: usize,
    pub max_mismatches: usize,
    pub block_start: usize,
    pub block_count: Option<usize>,
    pub encode: bool,
    pub normalize_parameters: bool,
}

impl Default for ReplayOptions {
    fn default() -> Self {
        Self {
            max_input_bytes: 16 * 1024 * 1024,
            max_plaintext_bytes: 32 * 1024 * 1024,
            max_tokens: 2 * 1024 * 1024,
            max_blocks: 4096,
            max_mismatches: 0,
            block_start: 0,
            block_count: None,
            encode: true,
            normalize_parameters: false,
        }
    }
}

fn invalid(message: &str) -> PreflateError {
    PreflateError::new(ExitCode::InvalidParameter, message)
}

impl ReplayOptions {
    pub fn validate(&self) -> Result<()> {
        if !(1..=64 * 1024 * 1024).contains(&self.max_input_bytes)
            || !(1..=128 * 1024 * 1024).contains(&self.max_plaintext_bytes)
            || !(1..=4 * 1024 * 1024).contains(&self.max_tokens)
            || !(1..=65536).contains(&self.max_blocks)
            || self.max_mismatches > 1024
            || self.block_count == Some(0)
        {
            return Err(invalid("invalid replay limits or empty block range"));
        }
        Ok(())
    }
}

/// Synthetic JSON blocks use fixed Huffman coding; use original DEFLATE for exact dynamic trees.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReplayBlock {
    Huffman {
        tokens: Vec<ReplayToken>,
        last: bool,
    },
    Stored {
        bytes: Vec<u8>,
        last: bool,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReplayToken {
    Literal { value: u8 },
    Reference { length: u32, distance: u32 },
}

/// Create a synthetic stream, validating references before compact token conversion.
pub fn encode_replay_blocks(blocks: Vec<ReplayBlock>, options: &ReplayOptions) -> Result<Vec<u8>> {
    options.validate()?;
    if blocks.is_empty() || blocks.len() > options.max_blocks {
        return Err(invalid(
            "synthetic block count is empty or exceeds max_blocks",
        ));
    }
    let count = blocks.len();
    let mut position = 0usize;
    let mut token_count = 0usize;
    let mut writer = DeflateWriter::new();
    for (index, block) in blocks.into_iter().enumerate() {
        let (block_type, last) = match block {
            ReplayBlock::Stored { bytes, last } => {
                if bytes.len() > 65535 {
                    return Err(invalid("stored blocks may contain at most 65535 bytes"));
                }
                position += bytes.len();
                (
                    DeflateTokenBlockType::Stored {
                        uncompressed: bytes,
                    },
                    last,
                )
            }
            ReplayBlock::Huffman { tokens, last } => {
                token_count += tokens.len();
                if token_count > options.max_tokens {
                    return Err(invalid("synthetic input exceeds max_tokens"));
                }
                let mut converted = Vec::with_capacity(tokens.len());
                for token in tokens {
                    converted.push(match token {
                        ReplayToken::Literal { value } => {
                            position += 1;
                            DeflateToken::Literal(value)
                        }
                        ReplayToken::Reference { length, distance } => {
                            if !(3..=258).contains(&length)
                                || distance == 0
                                || distance > 32768
                                || distance as usize > position
                            {
                                return Err(invalid(
                                    "invalid synthetic reference length or distance",
                                ));
                            }
                            position += length as usize;
                            DeflateToken::Reference(DeflateTokenReference::new(length, distance))
                        }
                    });
                    if position > options.max_plaintext_bytes {
                        return Err(invalid("synthetic input exceeds max_plaintext_bytes"));
                    }
                }
                (
                    DeflateTokenBlockType::Huffman {
                        tokens: converted,
                        huffman_type: DeflateHuffmanType::Static,
                    },
                    last,
                )
            }
        };
        if position > options.max_plaintext_bytes || last != (index + 1 == count) {
            return Err(invalid(
                "synthetic plaintext limit or final-block flag is invalid",
            ));
        }
        writer.encode_block(&DeflateTokenBlock { block_type, last })?;
    }
    writer.flush();
    let bytes = writer.detach_output();
    if bytes.len() > options.max_input_bytes {
        return Err(invalid("synthetic stream exceeds max_input_bytes"));
    }
    Ok(bytes)
}

/// Validate explicit experimental settings before constructing hash/search state.
pub fn validate_replay_parameters(parameters: &TokenPredictorParameters) -> Result<()> {
    let dictionary = matches!(
        parameters.strategy,
        PreflateStrategy::Default | PreflateStrategy::RleOnly
    );
    if parameters.max_token_count == 0
        || parameters.max_chain > 4096
        || parameters.max_dist_3_matches > 32768
        || (dictionary
            && (!(9..=15).contains(&parameters.window_bits)
                || !(3..=258).contains(&parameters.nice_length)
                || parameters.max_chain == 0
                || parameters.hash_algorithm == HashAlgorithm::None))
        || (!dictionary && parameters.hash_algorithm != HashAlgorithm::None)
    {
        return Err(invalid(
            "invalid dictionary, window, search or token-buffer parameters",
        ));
    }
    if let HashAlgorithm::Zlib {
        hash_mask,
        hash_shift,
    } = parameters.hash_algorithm
        && (hash_mask == 0
            || !u32::from(hash_mask).saturating_add(1).is_power_of_two()
            || !(1..=15).contains(&hash_shift))
    {
        return Err(invalid("invalid zlib hash mask or shift"));
    }
    if let HashAlgorithm::Chromium { hash_mask } = parameters.hash_algorithm
        && ![32767, 65535].contains(&hash_mask)
    {
        return Err(invalid("invalid Chromium hash mask"));
    }
    if matches!(parameters.add_policy, DictionaryAddPolicy::AddFirst(n) | DictionaryAddPolicy::AddFirstAndLast(n) if n > 258)
        || matches!(parameters.matching_type,
            MatchingType::Lazy { max_lazy, .. } | MatchingType::WindowsLazy { max_lazy } if max_lazy > 258)
        || matches!(parameters.matching_type, MatchingType::Lazy { behavior: LazyBehavior::Zlib { good_length }, .. } if good_length > 258)
        || matches!(parameters.matching_type, MatchingType::MiniZ { max_probes, .. } if max_probes == 0 || max_probes > 4096)
    {
        return Err(invalid("invalid insertion or parser parameters"));
    }
    Ok(())
}

/// Literal contents are deliberately omitted from output.
#[derive(Debug, Serialize)]
pub struct TokenShape {
    pub kind: &'static str,
    pub length: u32,
    pub distance: Option<u32>,
}

impl From<DeflateToken> for TokenShape {
    fn from(token: DeflateToken) -> Self {
        match token {
            DeflateToken::Literal(_) => Self {
                kind: "literal",
                length: 1,
                distance: None,
            },
            DeflateToken::Reference(reference) => Self {
                kind: "reference",
                length: reference.len(),
                distance: Some(reference.dist()),
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ReplayMismatch {
    pub block: usize,
    pub plaintext_offset: u32,
    pub actual: TokenShape,
    pub predicted: TokenShape,
}

#[derive(Debug, Serialize)]
pub struct ReplayBlockResult {
    pub index: usize,
    pub kind: &'static str,
    pub last: bool,
    pub plaintext_offset: u32,
    pub plaintext_bytes: u32,
    pub tokens: usize,
    pub mismatches: usize,
    pub mismatch_percent: f64,
    pub block_profile: &'static str,
    pub lookahead_limit: Option<u32>,
    pub dictionary_reset: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ReplayResult {
    pub parameters: TokenPredictorParameters,
    pub effective_parameters: TokenPredictorParameters,
    pub stream_complete: bool,
    pub compressed_bytes: usize,
    pub plaintext_bytes: usize,
    pub total_blocks: usize,
    pub total_tokens: usize,
    pub total_mismatches: usize,
    pub total_mismatch_percent: f64,
    pub reported_tokens: usize,
    pub reported_mismatches: usize,
    pub reported_mismatch_percent: f64,
    pub reconstruction_bytes: Option<usize>,
    pub verified: Option<bool>,
    pub nonzero_corrections: std::collections::BTreeMap<String, u32>,
    pub blocks: Vec<ReplayBlockResult>,
    pub mismatches: Vec<ReplayMismatch>,
    pub mismatches_truncated: bool,
}

fn percent(errors: usize, tokens: usize) -> f64 {
    if tokens == 0 {
        0.0
    } else {
        100.0 * errors as f64 / tokens as f64
    }
}

/// Replay the whole first plaintext-limited chunk, reporting only the requested block range.
/// Encoding verifies the exact consumed DEFLATE bytes and never invokes model selection/retry.
pub fn replay_deflate(
    compressed: &[u8],
    parameters: &TokenPredictorParameters,
    options: &ReplayOptions,
) -> Result<ReplayResult> {
    options.validate()?;
    validate_replay_parameters(parameters)?;
    if compressed.len() > options.max_input_bytes {
        return Err(invalid("DEFLATE input exceeds max_input_bytes"));
    }
    let mut parser = DeflateParser::new(options.max_plaintext_bytes);
    let contents = parser.parse_limited(compressed, options.max_tokens, options.max_blocks)?;
    let total_tokens: usize = contents
        .blocks
        .iter()
        .map(|block| match &block.block_type {
            DeflateTokenBlockType::Huffman { tokens, .. } => tokens.len(),
            DeflateTokenBlockType::Stored { .. } => 0,
        })
        .sum();
    if total_tokens > options.max_tokens || contents.blocks.len() > options.max_blocks {
        return Err(invalid("parsed chunk exceeds max_tokens or max_blocks"));
    }
    let end = options
        .block_count
        .map_or(Some(contents.blocks.len()), |count| {
            options.block_start.checked_add(count)
        })
        .filter(|&end| options.block_start < end && end <= contents.blocks.len())
        .ok_or_else(|| invalid("block range is outside the parsed first chunk"))?;
    let range = options.block_start..end;
    let mut result = ReplayResult {
        parameters: *parameters,
        effective_parameters: *parameters,
        stream_complete: parser.is_done(),
        compressed_bytes: contents.compressed_size,
        plaintext_bytes: parser.plain_text().len(),
        total_blocks: contents.blocks.len(),
        total_tokens,
        total_mismatches: 0,
        total_mismatch_percent: 0.0,
        reported_tokens: 0,
        reported_mismatches: 0,
        reported_mismatch_percent: 0.0,
        reconstruction_bytes: None,
        verified: None,
        nonzero_corrections: Default::default(),
        blocks: Vec::new(),
        mismatches: Vec::new(),
        mismatches_truncated: false,
    };
    let mut predictor = TokenPredictor::new(parameters);
    predictor.trace = Some(TokenPredictionTrace::default());
    let mut before = (0, 0, 0);
    let mut observe =
        |index: usize, beginning: bool, predictor: &mut TokenPredictor, input: &PreflateInput| {
            if beginning {
                before = (
                    predictor.trace.as_ref().expect("replay trace").token_count,
                    predictor
                        .trace
                        .as_ref()
                        .expect("replay trace")
                        .mismatch_count,
                    input.pos(),
                );
                if let Some(trace) = &mut predictor.trace {
                    trace.first_mismatches.clear();
                    trace.max_mismatches = if range.contains(&index) {
                        options.max_mismatches - result.mismatches.len()
                    } else {
                        0
                    };
                }
            } else if range.contains(&index) {
                let trace = predictor.trace.as_ref().expect("replay trace");
                let tokens = trace.token_count - before.0;
                let errors = trace.mismatch_count - before.1;
                result.reported_tokens += tokens;
                result.reported_mismatches += errors;
                if let Some(trace) = &predictor.trace {
                    result.blocks.push(ReplayBlockResult {
                        index,
                        kind: match &contents.blocks[index].block_type {
                            DeflateTokenBlockType::Stored { .. } => "stored",
                            DeflateTokenBlockType::Huffman {
                                huffman_type: DeflateHuffmanType::Static,
                                ..
                            } => "static",
                            DeflateTokenBlockType::Huffman { .. } => "dynamic",
                        },
                        last: contents.blocks[index].last,
                        plaintext_offset: before.2,
                        plaintext_bytes: input.pos() - before.2,
                        tokens,
                        mismatches: errors,
                        mismatch_percent: percent(errors, tokens),
                        block_profile: trace.block_profile,
                        lookahead_limit: trace.block_limit,
                        dictionary_reset: trace.dictionary_reset,
                    });
                    result.mismatches.extend(trace.first_mismatches.iter().map(
                        |&(offset, actual, predicted)| ReplayMismatch {
                            block: index,
                            plaintext_offset: offset,
                            actual: actual.into(),
                            predicted: predicted.into(),
                        },
                    ));
                }
            }
        };
    let mut counts = CountNonDefaultActions::default();
    if options.encode {
        let data = encode_first_chunk_observed(
            &mut predictor,
            &contents,
            parser.plain_text(),
            options.normalize_parameters && parser.is_done(),
            Some(&mut counts),
            &mut observe,
        )?;
        let recreated = recreate_whole_deflate_stream(parser.plain_text().text(), &data)?;
        if recreated != compressed[..contents.compressed_size] {
            return Err(PreflateError::new(
                ExitCode::RoundtripMismatch,
                "diagnostic replay did not reconstruct original bytes",
            ));
        }
        result.reconstruction_bytes = Some(data.len());
        result.verified = Some(true);
    } else {
        predictor.enable_parameter_normalization(
            contents.compressed_size,
            options.normalize_parameters && parser.is_done(),
        );
        predict_blocks_observed(
            &contents.blocks,
            &mut predictor,
            &mut &mut counts,
            &mut PreflateInput::new(parser.plain_text()),
            &mut observe,
        )?;
    }
    result.total_mismatches = predictor
        .trace
        .as_ref()
        .expect("replay trace")
        .mismatch_count;
    result.total_mismatch_percent = percent(result.total_mismatches, result.total_tokens);
    result.effective_parameters = predictor.reconstruction_parameters();
    result.reported_mismatch_percent = percent(result.reported_mismatches, result.reported_tokens);
    result.mismatches_truncated = result.reported_mismatches > result.mismatches.len();
    use crate::CodecCorrection::*;
    for action in [
        TokenCount,
        BlockTypeCorrection,
        LenCorrection,
        DistOnlyCorrection,
        DistAfterLenCorrection,
        TreeCodeBitLengthCorrection,
        LDTypeCorrection,
        RepeatCountCorrection,
        LDBitLengthCorrection,
        TreeProfile,
        LiteralCountCorrection,
        DistanceCountCorrection,
        UncompressBlockLenCorrection,
        Last,
        EndOfChunk,
        LiteralPredictionWrong,
        ReferencePredictionWrong,
    ] {
        let count = counts.corrections_count[action as usize];
        if count != 0 {
            result
                .nonzero_corrections
                .insert(format!("{action:?}"), count);
        }
    }
    Ok(result)
}
