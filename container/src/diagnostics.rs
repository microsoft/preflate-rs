//! Offline DEFLATE diagnostics. Unlike the compression scanner, failed candidates
//! are reported, including possible signature false positives.

use std::{collections::BTreeMap, io::Cursor, time::Instant};

use preflate_rs::{
    CodecCorrection, CountNonDefaultActions, ExitCode, PreflateConfig, PreflateError,
    PreflateStreamProcessor, TokenPredictorParameters,
};
#[cfg(feature = "diagnostics")]
use preflate_rs::{DeflateHuffmanType, DeflateToken, DeflateTokenBlockType};
use serde::Serialize;

use crate::{
    idat_parse::parse_idat,
    scan_deflate::{Signature, ZipLocalFileHeader, next_signature, skip_gzip_header},
};

#[derive(Default)]
pub struct DiagnosticScanOptions {
    /// Select a signature offset from a previous report, rather than scanning other candidates.
    pub stream_offset: Option<usize>,
    #[cfg(feature = "diagnostics")]
    /// Capture at most this many mismatch examples and block descriptions per stream.
    pub trace_limit: Option<usize>,
}

#[cfg(feature = "diagnostics")]
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DiagnosticToken {
    Literal { value: u8 },
    Reference { length: u32, distance: u32 },
}

#[cfg(feature = "diagnostics")]
impl From<DeflateToken> for DiagnosticToken {
    fn from(token: DeflateToken) -> Self {
        match token {
            DeflateToken::Literal(value) => Self::Literal { value },
            DeflateToken::Reference(reference) => Self::Reference {
                length: reference.len(),
                distance: reference.dist(),
            },
        }
    }
}

#[cfg(feature = "diagnostics")]
#[derive(Debug, Serialize)]
pub struct TokenMismatch {
    pub plaintext_offset: u32,
    pub actual: DiagnosticToken,
    pub predicted: DiagnosticToken,
}

#[cfg(feature = "diagnostics")]
#[derive(Debug, Serialize)]
pub struct BlockDiagnostic {
    pub index: u64,
    pub chunk: u64,
    pub plaintext_offset: u64,
    pub plaintext_bytes: u64,
    pub kind: &'static str,
    pub last: bool,
    pub literals: u64,
    pub references: u64,
}

#[cfg(feature = "diagnostics")]
#[derive(Debug, Serialize)]
pub struct ChunkDiagnostic {
    pub index: u64,
    pub block_profile: &'static str,
    /// Relative to the raw DEFLATE payload, not the wrapper/file.
    pub deflate_offset: usize,
    pub plaintext_offset: u64,
    pub deflate_bytes: usize,
    pub plaintext_bytes: usize,
    pub correction_bytes: usize,
    pub blocks: usize,
    pub elapsed_ms: f64,
    pub status: &'static str,
    pub stage: &'static str,
    pub error: Option<String>,
    pub nonzero_corrections: BTreeMap<String, u64>,
}

#[cfg(feature = "diagnostics")]
#[derive(Debug, Default, Serialize)]
pub struct StreamTrace {
    pub last_stage: &'static str,
    pub token_count: usize,
    pub token_mismatches: usize,
    pub first_mismatches: Vec<TokenMismatch>,
    pub mismatches_truncated: bool,
    pub chunks: Vec<ChunkDiagnostic>,
    pub blocks: Vec<BlockDiagnostic>,
    pub blocks_truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct DiagnosticParameters {
    hash_algorithm: String,
    matching_type: String,
    strategy: String,
    add_policy: String,
    block_type_strategy: String,
    window_bits: u32,
    nice_length: u32,
    max_chain: u32,
    max_token_count: u16,
    max_dist_3_matches: u32,
    matches_to_start_detected: bool,
    very_far_matches_detected: bool,
}

impl From<TokenPredictorParameters> for DiagnosticParameters {
    fn from(p: TokenPredictorParameters) -> Self {
        Self {
            hash_algorithm: format!("{:?}", p.hash_algorithm),
            matching_type: format!("{:?}", p.matching_type),
            strategy: format!("{:?}", p.strategy),
            add_policy: format!("{:?}", p.add_policy),
            block_type_strategy: format!("{:?}", p.block_type_strategy),
            window_bits: p.window_bits,
            nice_length: p.nice_length,
            max_chain: p.max_chain,
            max_token_count: p.max_token_count,
            max_dist_3_matches: p.max_dist_3_matches,
            matches_to_start_detected: p.matches_to_start_detected,
            very_far_matches_detected: p.very_far_matches_detected,
        }
    }
}

/// One candidate, including partial measurements when modelling fails.
#[derive(Debug, Serialize)]
pub struct DeflateDiagnostic {
    /// Signature offset in the source file (first chunk length for PNG).
    pub offset: usize,
    /// Absolute raw payload offset, or None for concatenated PNG IDAT data.
    pub deflate_offset: Option<usize>,
    pub kind: &'static str,
    pub signature_confidence: &'static str,
    pub member_name: Option<String>,
    pub status: &'static str,
    pub error_code: Option<String>,
    pub error: Option<String>,
    /// Successfully processed raw DEFLATE bytes, excluding wrappers.
    pub deflate_bytes: u64,
    pub plaintext_bytes: u64,
    /// Includes serialized reconstruction parameters in the first chunk.
    pub correction_bytes: u64,
    pub chunks: u64,
    pub blocks: u64,
    pub correction_ratio: Option<f64>,
    pub verified: bool,
    pub elapsed_ms: f64,
    pub parameters: Option<DiagnosticParameters>,
    pub nonzero_corrections: BTreeMap<String, u64>,
    #[cfg(feature = "diagnostics")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<StreamTrace>,
}

impl DeflateDiagnostic {
    fn new(offset: usize, kind: &'static str) -> Self {
        Self {
            offset,
            deflate_offset: None,
            kind,
            signature_confidence: match kind {
                "raw" => "explicit",
                "zlib" | "gzip" => "heuristic",
                _ => "wrapper",
            },
            member_name: None,
            status: "ok",
            error_code: None,
            error: None,
            deflate_bytes: 0,
            plaintext_bytes: 0,
            correction_bytes: 0,
            chunks: 0,
            blocks: 0,
            correction_ratio: None,
            verified: false,
            elapsed_ms: 0.0,
            parameters: None,
            nonzero_corrections: BTreeMap::new(),
            #[cfg(feature = "diagnostics")]
            trace: None,
        }
    }

    fn fail(&mut self, error: PreflateError) {
        self.status = if error.exit_code() == ExitCode::PlainTextLimit {
            "limit"
        } else {
            "error"
        };
        self.error_code = Some(error.exit_code().to_string());
        self.error = Some(error.to_string());
        self.verified = false;
    }
}

fn analyze(
    input: &[u8],
    config: &PreflateConfig,
    max_plaintext: u64,
    diagnostic: &mut DeflateDiagnostic,
    _options: &DiagnosticScanOptions,
) -> usize {
    use CodecCorrection::*;
    let actions = [
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
    ];
    let start = Instant::now();
    let mut state = PreflateStreamProcessor::new(config);
    #[cfg(feature = "diagnostics")]
    if let Some(limit) = _options.trace_limit {
        state.enable_trace(limit);
        diagnostic.trace = Some(StreamTrace::default());
    }
    let mut position = 0;
    loop {
        let mut counts = CountNonDefaultActions::default();
        #[cfg(feature = "diagnostics")]
        let chunk_start = Instant::now();
        let result = state.decompress_with_statistics(&input[position..], &mut counts);
        #[cfg(feature = "diagnostics")]
        if let Some(trace) = &mut diagnostic.trace {
            let mut chunk = ChunkDiagnostic {
                index: diagnostic.chunks,
                block_profile: state
                    .prediction_trace()
                    .map(|trace| trace.block_profile)
                    .unwrap_or("Default"),
                deflate_offset: position,
                plaintext_offset: diagnostic.plaintext_bytes,
                deflate_bytes: 0,
                plaintext_bytes: state.plain_text().len(),
                correction_bytes: 0,
                blocks: 0,
                elapsed_ms: chunk_start.elapsed().as_secs_f64() * 1000.0,
                status: "error",
                stage: state
                    .prediction_trace()
                    .map(|trace| trace.stage)
                    .unwrap_or("not_traced"),
                error: None,
                nonzero_corrections: BTreeMap::new(),
            };
            for action in actions {
                let count = counts.corrections_count[action as usize];
                if count != 0 {
                    chunk
                        .nonzero_corrections
                        .insert(format!("{action:?}"), u64::from(count));
                }
            }
            match &result {
                Ok(result) => {
                    chunk.status = "ok";
                    chunk.deflate_bytes = result.compressed_size;
                    chunk.correction_bytes = result.corrections.len();
                    chunk.blocks = result.blocks.len();
                    let mut plaintext_offset = diagnostic.plaintext_bytes;
                    for (index, block) in result.blocks.iter().enumerate() {
                        if trace.blocks.len() >= _options.trace_limit.unwrap_or(0) {
                            trace.blocks_truncated = true;
                            break;
                        }
                        let (kind, bytes, literals, references) = match &block.block_type {
                            DeflateTokenBlockType::Stored { uncompressed } => {
                                ("stored", uncompressed.len() as u64, 0, 0)
                            }
                            DeflateTokenBlockType::Huffman {
                                tokens,
                                huffman_type,
                            } => {
                                let mut literals = 0;
                                let mut references = 0;
                                let mut bytes = 0;
                                for token in tokens {
                                    match token {
                                        DeflateToken::Literal(_) => {
                                            literals += 1;
                                            bytes += 1;
                                        }
                                        DeflateToken::Reference(r) => {
                                            references += 1;
                                            bytes += u64::from(r.len());
                                        }
                                    }
                                }
                                let kind = match huffman_type {
                                    DeflateHuffmanType::Static => "static_huffman",
                                    DeflateHuffmanType::Dynamic { .. } => "dynamic_huffman",
                                };
                                (kind, bytes, literals, references)
                            }
                        };
                        trace.blocks.push(BlockDiagnostic {
                            index: diagnostic.blocks + index as u64,
                            chunk: diagnostic.chunks,
                            plaintext_offset,
                            plaintext_bytes: bytes,
                            kind,
                            last: block.last,
                            literals,
                            references,
                        });
                        plaintext_offset += bytes;
                    }
                }
                Err(error) => {
                    chunk.error = Some(error.to_string());
                }
            }
            trace.chunks.push(chunk);
        }
        match result {
            Ok(chunk) => {
                if let Some(parameters) = chunk.parameters {
                    diagnostic.parameters = Some(parameters.into());
                }
                diagnostic.deflate_bytes += chunk.compressed_size as u64;
                diagnostic.plaintext_bytes += state.plain_text().len() as u64;
                diagnostic.correction_bytes += chunk.corrections.len() as u64;
                diagnostic.chunks += 1;
                diagnostic.blocks += chunk.blocks.len() as u64;
                for action in actions {
                    let count = counts.corrections_count[action as usize];
                    if count != 0 {
                        *diagnostic
                            .nonzero_corrections
                            .entry(format!("{action:?}"))
                            .or_default() += u64::from(count);
                    }
                }
                position += chunk.compressed_size;
                if diagnostic.plaintext_bytes > max_plaintext {
                    diagnostic.fail(PreflateError::new(
                        ExitCode::PlainTextLimit,
                        "diagnostic stream plaintext budget exceeded",
                    ));
                    break;
                }
                if state.is_done() {
                    diagnostic.verified = config.verify_compression;
                    break;
                }
                if chunk.compressed_size == 0 {
                    diagnostic.fail(PreflateError::new(
                        ExitCode::InvalidDeflate,
                        "DEFLATE parser made no progress",
                    ));
                    break;
                }
                state.shrink_to_dictionary();
            }
            Err(error) => {
                diagnostic.fail(error);
                break;
            }
        }
    }
    #[cfg(feature = "diagnostics")]
    if let (Some(trace), Some(predictions)) = (&mut diagnostic.trace, state.prediction_trace()) {
        trace.last_stage = predictions.stage;
        if diagnostic.parameters.is_none() {
            diagnostic.parameters = predictions.parameters.map(Into::into);
        }
        trace.token_count = predictions.token_count;
        trace.token_mismatches = predictions.mismatch_count;
        trace.first_mismatches = predictions
            .first_mismatches
            .iter()
            .map(|&(plaintext_offset, actual, predicted)| TokenMismatch {
                plaintext_offset,
                actual: actual.into(),
                predicted: predicted.into(),
            })
            .collect();
        trace.mismatches_truncated = predictions.mismatch_count > trace.first_mismatches.len();
    }
    if diagnostic.status == "ok" && diagnostic.deflate_bytes != 0 {
        diagnostic.correction_ratio =
            Some(diagnostic.correction_bytes as f64 / diagnostic.deflate_bytes as f64);
    }
    diagnostic.elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    position
}

/// Scans wrapper signatures without Zstd, JPEG or WebP processing. Raw mode
/// attempts a single DEFLATE stream at offset zero instead of signature scanning.
/// `max_candidates` also bounds false-positive attempts in arbitrary binary data.
pub fn scan_deflate_diagnostics(
    src: &[u8],
    config: &PreflateConfig,
    raw: bool,
    max_stream_plaintext: u64,
    max_candidates: usize,
    emit: impl FnMut(DeflateDiagnostic),
) {
    scan_deflate_diagnostics_with_options(
        src,
        config,
        raw,
        max_stream_plaintext,
        max_candidates,
        &DiagnosticScanOptions::default(),
        emit,
    );
}

/// Like `scan_deflate_diagnostics`, optionally selecting a stream and capturing bounded traces.
pub fn scan_deflate_diagnostics_with_options(
    src: &[u8],
    config: &PreflateConfig,
    raw: bool,
    max_stream_plaintext: u64,
    max_candidates: usize,
    options: &DiagnosticScanOptions,
    mut emit: impl FnMut(DeflateDiagnostic),
) {
    if raw {
        if options.stream_offset.is_some_and(|offset| offset != 0) {
            return;
        }
        let mut diagnostic = DeflateDiagnostic::new(0, "raw");
        diagnostic.deflate_offset = Some(0);
        analyze(src, config, max_stream_plaintext, &mut diagnostic, options);
        emit(diagnostic);
        return;
    }

    let mut index = options.stream_offset.unwrap_or(0);
    let mut attempts = 0;
    while let Some(signature) = next_signature(src, &mut index) {
        let kind = match signature {
            Signature::Zlib(_) => "zlib",
            Signature::Gzip => "gzip",
            Signature::ZipLocalFileHeader => {
                // Only complete local-header signatures are candidates.
                if !src[index..].starts_with(b"PK\x03\x04") {
                    index += 1;
                    continue;
                }
                "zip"
            }
            Signature::IDAT if index >= 4 && src[index..].starts_with(b"IDAT") => "png_idat",
            _ => {
                index += 1;
                continue;
            }
        };
        let candidate_offset = if kind == "png_idat" { index - 4 } else { index };
        if let Some(target) = options.stream_offset {
            if candidate_offset > target {
                break;
            }
            if candidate_offset != target {
                index += 1;
                continue;
            }
        }
        if attempts == max_candidates {
            let mut diagnostic = DeflateDiagnostic::new(candidate_offset, kind);
            diagnostic.status = "limit";
            diagnostic.error_code = Some("CandidateLimit".into());
            diagnostic.error =
                Some("per-file candidate limit reached; remaining bytes not scanned".into());
            emit(diagnostic);
            break;
        }
        attempts += 1;
        let mut diagnostic = DeflateDiagnostic::new(candidate_offset, kind);
        let mut next = index + 1;
        let result = match signature {
            Signature::Zlib(_) => {
                let start = index + 2;
                diagnostic.deflate_offset = Some(start);
                next = next.max(
                    start
                        + analyze(
                            &src[start..],
                            config,
                            max_stream_plaintext,
                            &mut diagnostic,
                            options,
                        ),
                );
                if diagnostic.status == "ok" {
                    next = next.saturating_add(4).min(src.len());
                }
                Ok(())
            }
            Signature::Gzip => {
                if src[index..].len() >= 10 && src[index + 2] == 8 && src[index + 3] & 0xe0 == 0 {
                    diagnostic.signature_confidence = "wrapper";
                }
                let mut header = Cursor::new(&src[index..]);
                skip_gzip_header(&mut header).map(|()| {
                    let start = index + header.position() as usize;
                    diagnostic.deflate_offset = Some(start);
                    next = next.max(
                        start
                            + analyze(
                                &src[start..],
                                config,
                                max_stream_plaintext,
                                &mut diagnostic,
                                options,
                            ),
                    );
                    if diagnostic.status == "ok" {
                        next = next.saturating_add(8).min(src.len());
                    }
                })
            }
            Signature::ZipLocalFileHeader => {
                let mut cursor = Cursor::new(&src[index..]);
                ZipLocalFileHeader::create_and_load(&mut cursor).and_then(|header| {
                    let name_start = index + cursor.position() as usize;
                    let name_end = name_start + usize::from(header.file_name_length);
                    let start = name_end + usize::from(header.extra_field_length);
                    if start > src.len() {
                        return Err(PreflateError::new(
                            ExitCode::ShortRead,
                            "truncated ZIP header",
                        ));
                    }
                    diagnostic.member_name =
                        Some(String::from_utf8_lossy(&src[name_start..name_end]).into_owned());
                    if header.general_purpose_bit_flag & 0x41 != 0 || header.compression_method != 8
                    {
                        diagnostic.status = "unsupported";
                        diagnostic.error_code = Some("UnsupportedZipEntry".into());
                        diagnostic.error = Some(format!(
                            "ZIP method {}, flags {:#x}",
                            header.compression_method, header.general_purpose_bit_flag
                        ));
                        // With a data descriptor or ZIP64, the local size is not reliable.
                        next = if header.general_purpose_bit_flag & 8 == 0
                            && header.compressed_size != u64::from(u32::MAX)
                        {
                            start
                                .saturating_add(header.compressed_size as usize)
                                .min(src.len())
                        } else {
                            start
                        };
                    } else {
                        diagnostic.deflate_offset = Some(start);
                        next = next.max(
                            start
                                + analyze(
                                    &src[start..],
                                    config,
                                    max_stream_plaintext,
                                    &mut diagnostic,
                                    options,
                                ),
                        );
                    }
                    Ok(())
                })
            }
            Signature::IDAT => {
                diagnostic.offset = index - 4;
                parse_idat(None, &src[index - 4..]).map(|(idat, payload)| {
                    next = index - 4 + idat.total_chunk_length;
                    analyze(
                        &payload,
                        config,
                        max_stream_plaintext,
                        &mut diagnostic,
                        options,
                    );
                })
            }
            _ => unreachable!(),
        };
        if let Err(error) = result {
            diagnostic.fail(error);
        }
        emit(diagnostic);
        if options.stream_offset.is_some() {
            break;
        }
        index = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniz_oxide::deflate::{compress_to_vec, compress_to_vec_zlib};

    fn scan(src: &[u8], raw: bool) -> Vec<DeflateDiagnostic> {
        let mut results = Vec::new();
        scan_deflate_diagnostics(
            src,
            &PreflateConfig::default(),
            raw,
            1024 * 1024,
            100,
            |d| results.push(d),
        );
        results
    }

    fn check_bounded_diagnostics(src: &[u8], raw: bool, context: &str) {
        let config = PreflateConfig {
            plain_text_limit: 4096,
            ..PreflateConfig::default()
        };
        let mut results = Vec::new();
        scan_deflate_diagnostics(src, &config, raw, 8192, 16, |d| results.push(d));
        assert!(results.len() <= 17, "{context}");
        for d in &results {
            assert!(d.offset <= src.len(), "{context}: {d:?}");
            assert!(d.deflate_bytes <= src.len() as u64, "{context}: {d:?}");
            if d.status == "ok" {
                assert!(d.verified, "{context}: {d:?}");
                assert!(d.plaintext_bytes <= 8192, "{context}: {d:?}");
                let ratio = d.correction_ratio.unwrap();
                assert!(ratio.is_finite(), "{context}: {d:?}");
                assert_eq!(
                    ratio,
                    d.correction_bytes as f64 / d.deflate_bytes as f64,
                    "{context}"
                );
                assert!(d.error_code.is_none(), "{context}: {d:?}");
            } else {
                assert!(
                    !d.verified && d.correction_ratio.is_none(),
                    "{context}: {d:?}"
                );
                assert!(
                    d.error_code.is_some() && d.error.is_some(),
                    "{context}: {d:?}"
                );
            }
        }
        #[cfg(feature = "diagnostics")]
        {
            let mut traced = Vec::new();
            scan_deflate_diagnostics_with_options(
                src,
                &config,
                raw,
                8192,
                16,
                &DiagnosticScanOptions {
                    trace_limit: Some(4),
                    stream_offset: None,
                },
                |d| traced.push(d),
            );
            assert_eq!(results.len(), traced.len(), "{context}");
            for (normal, detailed) in results.iter().zip(&traced) {
                assert_eq!(normal.offset, detailed.offset, "{context}");
                assert_eq!(normal.status, detailed.status, "{context}");
                assert_eq!(normal.error_code, detailed.error_code, "{context}");
                assert_eq!(normal.deflate_bytes, detailed.deflate_bytes, "{context}");
                assert_eq!(
                    normal.plaintext_bytes, detailed.plaintext_bytes,
                    "{context}"
                );
                assert_eq!(
                    normal.correction_bytes, detailed.correction_bytes,
                    "{context}"
                );
                assert_eq!(
                    normal.nonzero_corrections, detailed.nonzero_corrections,
                    "{context}"
                );
                if let Some(trace) = &detailed.trace {
                    assert!(
                        trace.first_mismatches.len() <= 4 && trace.blocks.len() <= 4,
                        "{context}"
                    );
                    assert!(trace.chunks.len() as u64 >= detailed.chunks, "{context}");
                    assert!(
                        trace.chunks.len() as u64 <= detailed.chunks + 1,
                        "{context}"
                    );
                    assert_eq!(
                        trace.first_mismatches.len(),
                        trace.token_mismatches.min(4),
                        "{context}"
                    );
                }
            }
        }
    }

    #[test]
    fn malformed_signatures_and_seeded_inputs_keep_bounded_diagnostics() {
        let signatures: &[&[u8]] = &[
            b"",
            b"\x78\x9c",
            b"\x1f\x8b",
            b"PK\x03\x04",
            b"\xff\xff\xff\xffIDAT",
            b"\0\0\0\0IDAT",
        ];
        let mut seed = 0x5eed_u32;
        for case in 0..256 {
            let mut input = signatures[case % signatures.len()].to_vec();
            for _ in 0..case {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                input.push((seed >> 24) as u8);
            }
            for raw in [false, true] {
                check_bounded_diagnostics(&input, raw, &format!("seeded case {case}, raw={raw}"));
            }
        }
    }

    #[test]
    fn truncated_and_bit_flipped_streams_keep_bounded_diagnostics() {
        let raw = compress_to_vec(&b"repeated diagnostic content ".repeat(80), 6);
        for end in 0..raw.len() {
            check_bounded_diagnostics(&raw[..end], true, &format!("truncated at {end}"));
            let result = scan(&raw[..end], true);
            assert_ne!(result[0].status, "ok", "truncated at {end}");
        }
        for index in 0..raw.len() {
            for bit in 0..8 {
                let mut mutated = raw.clone();
                mutated[index] ^= 1 << bit;
                check_bounded_diagnostics(&mutated, true, &format!("byte {index}, bit {bit}"));
            }
        }
    }

    #[test]
    fn gzip_optional_headers_preserve_payload_offsets_and_report_truncation() {
        let text = b"example document content ".repeat(80);
        let raw = compress_to_vec(&text, 6);
        let mut gzip = vec![0x1f, 0x8b, 8, 0x1e, 0, 0, 0, 0, 0, 0];
        gzip.extend(3u16.to_le_bytes());
        gzip.extend([1, 2, 3]);
        gzip.extend(b"document.xml\0test comment\0");
        gzip.extend([0, 0]);
        let payload_offset = gzip.len();
        gzip.extend(&raw);
        gzip.extend([0; 8]);
        let results = scan(&gzip, false);
        let stream = results.iter().find(|d| d.kind == "gzip").unwrap();
        assert_eq!(stream.status, "ok", "{stream:?}");
        assert!(stream.verified);
        assert_eq!(stream.signature_confidence, "wrapper");
        assert_eq!(stream.deflate_offset, Some(payload_offset));
        assert_eq!(stream.deflate_bytes, raw.len() as u64);
        assert_eq!(stream.plaintext_bytes, text.len() as u64);
        for end in 0..payload_offset {
            check_bounded_diagnostics(
                &gzip[..end],
                false,
                &format!("gzip header truncated at {end}"),
            );
            assert!(scan(&gzip[..end], false).iter().all(|d| d.status != "ok"));
        }
    }

    #[test]
    fn zip_data_descriptors_do_not_hide_following_streams() {
        let text = b"example document content ".repeat(80);
        let raw = compress_to_vec(&text, 6);
        let name = b"document.xml";
        let mut zip = vec![0; 30];
        zip[..4].copy_from_slice(b"PK\x03\x04");
        zip[4..6].copy_from_slice(&20u16.to_le_bytes());
        zip[6..8].copy_from_slice(&8u16.to_le_bytes());
        zip[8..10].copy_from_slice(&8u16.to_le_bytes());
        zip[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend(name);
        let zip_payload = zip.len();
        zip.extend(&raw);
        zip.extend(b"PK\x07\x08");
        zip.extend(0u32.to_le_bytes());
        zip.extend((raw.len() as u32).to_le_bytes());
        zip.extend((text.len() as u32).to_le_bytes());
        let gzip_offset = zip.len();
        zip.extend([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0]);
        zip.extend(&raw);
        zip.extend([0; 8]);
        let results = scan(&zip, false);
        let streams: Vec<_> = results.iter().filter(|d| d.status == "ok").collect();
        assert_eq!(streams.len(), 2, "{results:?}");
        assert_eq!(streams[0].kind, "zip");
        assert_eq!(streams[0].deflate_offset, Some(zip_payload));
        assert_eq!(streams[0].member_name.as_deref(), Some("document.xml"));
        assert_eq!(streams[1].kind, "gzip");
        assert_eq!(streams[1].offset, gzip_offset);
        assert_eq!(streams[1].deflate_offset, Some(gzip_offset + 10));
        assert!(
            streams
                .iter()
                .all(|d| d.verified && d.deflate_bytes == raw.len() as u64)
        );
        for end in 0..zip_payload {
            check_bounded_diagnostics(
                &zip[..end],
                false,
                &format!("ZIP header truncated at {end}"),
            );
        }
    }

    #[test]
    fn reports_raw_and_wrapped_streams_with_verification() {
        let text = b"example document content and repeated text ".repeat(100);
        let raw = compress_to_vec(&text, 6);
        let results = scan(&raw, true);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, "ok");
        assert!(results[0].verified);
        assert_eq!(results[0].plaintext_bytes, text.len() as u64);
        assert_eq!(results[0].deflate_bytes, raw.len() as u64);
        assert!(results[0].correction_ratio.unwrap() > 0.0);
        let expected = preflate_rs::preflate_whole_deflate_stream(&raw, &PreflateConfig::default())
            .unwrap()
            .0;
        assert_eq!(
            results[0].correction_bytes,
            expected.corrections.len() as u64
        );
        assert_eq!(
            results[0].correction_ratio,
            Some(expected.corrections.len() as f64 / raw.len() as f64)
        );
        let zlib = compress_to_vec_zlib(&text, 6);
        let mut file = b"prefix".to_vec();
        file.extend(&zlib);
        file.extend(&zlib);
        let results = scan(&file, false);
        assert_eq!(results.iter().filter(|d| d.status == "ok").count(), 2);
        assert_eq!(results[0].offset, 6);
    }

    #[test]
    fn reports_bad_candidates_and_plaintext_limits() {
        let results = scan(b"\x78\x9c\x07", false);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, "error");
        assert!(results[0].error_code.is_some());
        assert!(!results[0].verified);
        let mut results = Vec::new();
        scan_deflate_diagnostics(
            &compress_to_vec(&[42; 5000], 6),
            &PreflateConfig::default(),
            true,
            10,
            100,
            |d| results.push(d),
        );
        assert_eq!(results[0].status, "limit");
        assert!(results[0].correction_ratio.is_none());
    }

    #[test]
    fn scans_document_and_image_fixtures() {
        let samples = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("samples");
        for (name, kind, expected) in [
            ("test_zip_3entries.zip", "zip", 3),
            ("test_two_gzip_streams.bin", "gzip", 2),
            ("figma.png", "png_idat", 1),
            ("file-sample_1MB.docx", "zip", 1),
            ("samplepptx.pptx", "zip", 1),
        ] {
            let contents = std::fs::read(samples.join(name)).unwrap();
            let mut results = Vec::new();
            scan_deflate_diagnostics(
                &contents,
                &PreflateConfig::default(),
                false,
                512 * 1024 * 1024,
                1000,
                |d| results.push(d),
            );
            let successful: Vec<_> = results
                .iter()
                .filter(|d| d.status == "ok" && d.kind == kind)
                .collect();
            assert!(successful.len() >= expected, "{name}: {results:?}");
            assert!(successful.iter().all(|d| d.verified), "{name}");
            if kind == "zip" {
                assert!(successful.iter().all(|d| d.member_name.is_some()), "{name}");
                assert!(
                    successful
                        .iter()
                        .all(|d| d.deflate_offset.is_some_and(|offset| offset > d.offset)),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn stored_blocks_respect_chunk_limits_and_continue() {
        let mut raw = Vec::new();
        for block in 0..4 {
            let length = 600u16;
            raw.push(u8::from(block == 3));
            raw.extend(length.to_le_bytes());
            raw.extend((!length).to_le_bytes());
            raw.extend(vec![b'x'; usize::from(length)]);
        }
        let config = PreflateConfig {
            plain_text_limit: 1000,
            ..PreflateConfig::default()
        };
        let mut results = Vec::new();
        scan_deflate_diagnostics(&raw, &config, true, 10000, 100, |d| results.push(d));
        assert_eq!(results[0].status, "ok", "{results:?}");
        assert_eq!(results[0].chunks, 4);
        assert_eq!(results[0].blocks, 4);
        assert_eq!(results[0].deflate_bytes, raw.len() as u64);
        assert_eq!(results[0].plaintext_bytes, 2400);
        assert!(results[0].verified);

        let config = PreflateConfig {
            plain_text_limit: 500,
            ..config
        };
        let mut results = Vec::new();
        scan_deflate_diagnostics(&raw, &config, true, 10000, 100, |d| results.push(d));
        assert_eq!(results[0].status, "limit");
        assert_eq!(results[0].plaintext_bytes, 0);
    }

    #[test]
    fn correction_counting_preserves_the_encoded_bytes() {
        let raw = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("samples")
                .join("compressed_libdeflate_level9.deflate"),
        )
        .unwrap();
        let config = PreflateConfig::default();
        let mut normal = PreflateStreamProcessor::new(&config);
        let baseline = normal.decompress(&raw).unwrap();
        let mut counted = PreflateStreamProcessor::new(&config);
        #[cfg(feature = "diagnostics")]
        counted.enable_trace(3);
        let mut counts = CountNonDefaultActions::default();
        let diagnostic = counted
            .decompress_with_statistics(&raw, &mut counts)
            .unwrap();
        assert_eq!(baseline.corrections, diagnostic.corrections);
        assert_eq!(baseline.compressed_size, diagnostic.compressed_size);
        assert_eq!(baseline.parameters, diagnostic.parameters);
        assert!(counts.total_non_default > 0);
        assert_eq!(
            counts.total_non_default,
            counts.corrections_count.iter().sum::<u32>()
        );
        assert_eq!(normal.plain_text().text(), counted.plain_text().text());
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    fn trace_is_bounded_and_preserves_measurements() {
        let raw = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("samples")
                .join("savegame.deflate"),
        )
        .unwrap();
        let mut baseline = Vec::new();
        let mut traced = Vec::new();
        let config = PreflateConfig::default();
        scan_deflate_diagnostics(&raw, &config, true, 512 * 1024 * 1024, 100, |d| {
            baseline.push(d)
        });
        scan_deflate_diagnostics_with_options(
            &raw,
            &config,
            true,
            512 * 1024 * 1024,
            100,
            &DiagnosticScanOptions {
                trace_limit: Some(3),
                stream_offset: None,
            },
            |d| traced.push(d),
        );
        assert!(baseline[0].trace.is_none());
        let d = &traced[0];
        assert_eq!(d.status, "ok");
        assert!(d.verified);
        assert_eq!(d.correction_bytes, baseline[0].correction_bytes);
        assert_eq!(d.deflate_bytes, baseline[0].deflate_bytes);
        assert_eq!(d.nonzero_corrections, baseline[0].nonzero_corrections);
        let trace = d.trace.as_ref().unwrap();
        assert!(trace.token_count > 0);
        assert!(trace.token_mismatches > 3);
        assert_eq!(trace.first_mismatches.len(), 3);
        assert!(trace.mismatches_truncated);
        assert!(trace.blocks.len() <= 3);
        assert_eq!(
            trace
                .chunks
                .iter()
                .map(|c| c.deflate_bytes as u64)
                .sum::<u64>(),
            d.deflate_bytes
        );
        assert_eq!(
            trace
                .chunks
                .iter()
                .map(|c| c.correction_bytes as u64)
                .sum::<u64>(),
            d.correction_bytes
        );
        assert!(
            trace
                .first_mismatches
                .iter()
                .all(|m| u64::from(m.plaintext_offset) < d.plaintext_bytes)
        );
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    fn trace_carries_offsets_across_chunks_and_bounds_block_details() {
        let mut raw = b"\x00\x01\x00\xfe\xffx".repeat(4);
        raw[18] = 1;
        let mut results = Vec::new();
        let config = PreflateConfig {
            plain_text_limit: 1,
            ..PreflateConfig::default()
        };
        scan_deflate_diagnostics_with_options(
            &raw,
            &config,
            true,
            1024,
            100,
            &DiagnosticScanOptions {
                trace_limit: Some(2),
                stream_offset: None,
            },
            |d| results.push(d),
        );
        let d = &results[0];
        assert_eq!(d.status, "ok");
        assert!(d.verified);
        let trace = d.trace.as_ref().unwrap();
        assert_eq!(trace.last_stage, "complete");
        assert_eq!(trace.blocks.len(), 2);
        assert!(trace.blocks_truncated);
        assert_eq!(trace.blocks[1].plaintext_offset, 1);
        assert_eq!(trace.chunks.len(), 4);
        for (index, chunk) in trace.chunks.iter().enumerate() {
            assert_eq!(chunk.deflate_offset, index * 6);
            assert_eq!(chunk.plaintext_offset, index as u64);
            assert_eq!(chunk.plaintext_bytes, 1);
        }
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    fn trace_retains_estimated_parameters_when_chain_limit_rejects_stream() {
        let raw = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("samples")
                .join("savegame.deflate"),
        )
        .unwrap();
        let mut results = Vec::new();
        let config = PreflateConfig {
            max_chain_length: 0,
            ..PreflateConfig::default()
        };
        scan_deflate_diagnostics_with_options(
            &raw,
            &config,
            true,
            512 * 1024 * 1024,
            100,
            &DiagnosticScanOptions {
                trace_limit: Some(2),
                stream_offset: None,
            },
            |d| results.push(d),
        );
        let d = &results[0];
        assert_eq!(d.error_code.as_deref(), Some("NoCompressionCandidates"));
        assert!(d.parameters.is_some());
        let trace = d.trace.as_ref().unwrap();
        assert_eq!(trace.last_stage, "chain_limit");
        assert_eq!(trace.chunks[0].stage, "chain_limit");
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    fn trace_selects_reported_offsets_including_png_and_failed_streams() {
        let zlib = compress_to_vec_zlib(&b"text ".repeat(1000), 6);
        let mut src = zlib.clone();
        src.extend(&zlib);
        let options = DiagnosticScanOptions {
            trace_limit: Some(2),
            stream_offset: Some(zlib.len()),
        };
        let mut results = Vec::new();
        scan_deflate_diagnostics_with_options(
            &src,
            &PreflateConfig::default(),
            false,
            1024 * 1024,
            100,
            &options,
            |d| results.push(d),
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, zlib.len());
        assert_eq!(results[0].status, "ok");
        let png = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("samples")
                .join("figma.png"),
        )
        .unwrap();
        let baseline = scan(&png, false);
        let offset = baseline
            .iter()
            .find(|d| d.kind == "png_idat")
            .unwrap()
            .offset;
        let mut results = Vec::new();
        scan_deflate_diagnostics_with_options(
            &png,
            &PreflateConfig::default(),
            false,
            512 * 1024 * 1024,
            100,
            &DiagnosticScanOptions {
                stream_offset: Some(offset),
                ..options
            },
            |d| results.push(d),
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, offset);
        assert_eq!(results[0].status, "ok");
        let mut results = Vec::new();
        scan_deflate_diagnostics_with_options(
            b"\x78\x9c\x07",
            &PreflateConfig::default(),
            false,
            1024 * 1024,
            100,
            &DiagnosticScanOptions {
                trace_limit: Some(2),
                stream_offset: Some(0),
            },
            |d| results.push(d),
        );
        let trace = results[0].trace.as_ref().unwrap();
        assert_eq!(trace.chunks.len(), 1);
        assert_eq!(trace.chunks[0].status, "error");
        assert!(trace.chunks[0].error.is_some());
        assert_eq!(trace.chunks[0].deflate_offset, 0);
    }

    #[test]
    fn reports_candidate_limit_and_ignores_empty_input() {
        assert!(scan(&[], false).is_empty());
        let mut results = Vec::new();
        scan_deflate_diagnostics(
            b"\x78\x9c\x07\x78\x9c\x07",
            &PreflateConfig::default(),
            false,
            1000,
            1,
            |d| results.push(d),
        );
        assert_eq!(results.len(), 2);
        assert_eq!(results[1].error_code.as_deref(), Some("CandidateLimit"));
    }
}
