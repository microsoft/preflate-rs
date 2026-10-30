/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Offline diagnostics only: sweeps do not affect production parameter selection.
//! Baselines and improving candidates are checked by exact bitstream reconstruction.

use super::*;
use crate::{
    HashAlgorithm,
    deflate::deflate_reader::{DeflateContents, parse_deflate_whole},
    deflate::deflate_token::{DeflateHuffmanType, DeflateToken, DeflateTokenBlockType},
    estimator::add_policy_estimator::DictionaryAddPolicy,
    estimator::preflate_parameter_estimator::BlockTypeStrategy,
    estimator::preflate_parse_config::{LazyBehavior, MatchingType, SLOW_PREFLATE_PARSER_SETTINGS},
    estimator::{extract_preflate_info, zlib_compatible},
    statistical_codec::CountNonDefaultActions,
    token_predictor::TokenPredictionTrace,
};
use std::path::{Path, PathBuf};

#[test]
fn bounded_parameter_scores_match_full_prediction_traces() {
    for name in [
        "compressed_zlib_level6.deflate",
        "compressed_libdeflate_level1.deflate",
        "compressed_libdeflate_level5.deflate",
        "compressed_flate2_level3.deflate",
    ] {
        let compressed = crate::utils::read_file(name);
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        let params = estimate_preflate_parameters(&contents, &plain).unwrap();
        let measurement = measure(&contents, &plain, &params).unwrap();
        let score = TokenPredictor::new(&params).score_predictions(
            &contents.blocks,
            &plain,
            usize::MAX,
            u32::MAX,
        );
        assert_eq!(
            score,
            (
                measurement.trace.mismatch_count,
                measurement.trace.token_count
            ),
            "{name}"
        );
        for limit in [0, 1, 257, 1024] {
            let (mismatches, tokens) = TokenPredictor::new(&params).score_predictions(
                &contents.blocks,
                &plain,
                limit,
                262144,
            );
            assert!(tokens <= limit);
            assert!(mismatches <= tokens);
        }
        assert_eq!(
            TokenPredictor::new(&params).score_predictions(&contents.blocks, &plain, 1024, 0),
            (0, 0)
        );
    }
}

#[test]
fn chromium_three_byte_matches_round_trip_without_a_secondary_hash() {
    for (fourth, tail) in [(0x10, Some(0x90)), (0x80, None), (0, None)] {
        let mut tokens: Vec<_> = [
            b'@', b'a', b'b', b'c', fourth, b'a', b'b', b'c', 0x11, b'z', b'z', b'z', b'.',
        ]
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
        tokens.push(DeflateToken::new_ref(3, 12));
        if let Some(byte) = tail {
            tokens.push(DeflateToken::Literal(byte));
        }
        let (compressed, contents, plain) = synthetic_stream(tokens);
        for matching_type in [
            MatchingType::Greedy,
            MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: false,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            },
        ] {
            let params = TokenPredictorParameters {
                hash_algorithm: HashAlgorithm::Chromium { hash_mask: 0x7fff },
                matching_type,
                max_dist_3_matches: 4096,
                ..synthetic_params()
            };
            let measured = measure(&contents, &plain, &params).unwrap();
            verify(&measured, &plain, &compressed);
            assert_eq!(measured.trace.mismatch_count, 0);
            assert_eq!(
                TokenPredictor::new(&params).score_predictions(
                    &contents.blocks,
                    &plain,
                    usize::MAX,
                    u32::MAX,
                ),
                (measured.trace.mismatch_count, measured.trace.token_count)
            );
        }
    }
}

#[test]
fn native_chromium_all_levels_select_and_reconstruct() {
    use crate::{estimator::preflate_parameter_estimator::PreflateStrategy, utils::read_file};

    let expected_plain = read_file("chromium_model_input.bin");
    for level in 0..=9 {
        let compressed = read_file(&format!("compressed_chromium_level{level}.deflate"));
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len());
        assert_eq!(plain.text(), expected_plain);
        let automatic = estimate_preflate_parameters(&contents, &plain).unwrap();
        let measured = measure(&contents, &plain, &automatic).unwrap();
        verify(&measured, &plain, &compressed);
        println!(
            "CHROMIUM_AUTO level={level} bytes={} mismatches={} params={automatic:?}",
            measured.corrections.len(),
            measured.trace.mismatch_count
        );
        assert_eq!(measured.trace.mismatch_count, 0, "automatic level={level}");
        assert!(measured.corrections.len() <= 32, "automatic level={level}");
        if level == 0 {
            assert_eq!(automatic.strategy, PreflateStrategy::Store);
            continue;
        }
        assert_eq!(
            automatic.hash_algorithm,
            HashAlgorithm::Chromium { hash_mask: 0x7fff }
        );
        let config = if level < 4 {
            &crate::estimator::preflate_parse_config::ZLIB_PREFLATE_PARSER_SETTINGS[level - 1]
        } else {
            &SLOW_PREFLATE_PARSER_SETTINGS[level - 4]
        };
        let canonical = TokenPredictorParameters {
            matching_type: config.match_type,
            add_policy: config.dictionary_add_policy,
            nice_length: config.nice_length,
            max_chain: config.max_chain,
            max_dist_3_matches: if level < 4 { 32768 } else { 4096 },
            window_bits: 15,
            very_far_matches_detected: false,
            ..automatic
        };
        let known = measure(&contents, &plain, &canonical).unwrap();
        verify(&known, &plain, &compressed);
        println!(
            "CHROMIUM_NATIVE level={level} bytes={} mismatches={}",
            known.corrections.len(),
            known.trace.mismatch_count
        );
        assert_eq!(known.trace.mismatch_count, 0, "native level={level}");
    }
}

#[test]
fn adaptive_libdeflate_scores_match_encoding_and_reconstruction() {
    let tokens = (0..30000)
        .map(|i| DeflateToken::Literal(if i < 4096 { i as u8 } else { b'a' }))
        .collect();
    let (compressed, contents, plain) = synthetic_stream(tokens);
    for two_positions in [false, true] {
        let params = TokenPredictorParameters {
            hash_algorithm: HashAlgorithm::Libdeflate4,
            matching_type: MatchingType::LibdeflateLazy { two_positions },
            max_chain: 101,
            ..synthetic_params()
        };
        let measurement = measure(&contents, &plain, &params).unwrap();
        verify(&measurement, &plain, &compressed);
        assert_eq!(
            TokenPredictor::new(&params).score_predictions(
                &contents.blocks,
                &plain,
                usize::MAX,
                u32::MAX,
            ),
            (
                measurement.trace.mismatch_count,
                measurement.trace.token_count,
            )
        );
    }
}

#[test]
fn match_length_filter_projects_evidence_without_changing_other_parsers() {
    let lazy = MatchingType::Lazy {
        max_lazy: 16,
        filtered_matching: false,
        behavior: LazyBehavior::Zlib { good_length: 8 },
    };
    for (matching_type, hash_algorithm, accepts_filter, compatible) in [
        (lazy, synthetic_params().hash_algorithm, true, true),
        (lazy, synthetic_params().hash_algorithm, true, false),
        (
            MatchingType::Greedy,
            synthetic_params().hash_algorithm,
            false,
            true,
        ),
        (lazy, HashAlgorithm::RandomVector, false, true),
        (lazy, HashAlgorithm::RandomVector, false, false),
    ] {
        for length in 3..=6 {
            let pattern = &b"abcdef"[..length];
            let mut text = vec![b'@'];
            text.extend_from_slice(pattern);
            text.push(b'X');
            text.extend_from_slice(pattern);
            text.push(b'Y');
            let (compressed, contents, plain) =
                synthetic_stream(text.into_iter().map(DeflateToken::Literal).collect());
            let base = TokenPredictorParameters {
                matching_type,
                hash_algorithm,
                ..synthetic_params()
            };
            let mut records: [Option<Vec<u8>>; 2] = [None, None];
            for (observed_min_len, selects_filter) in [
                (3, false),
                (4, false),
                (5, false),
                (6, true),
                (7, true),
                (258, true),
                (u32::MAX, true),
            ] {
                let params = base.with_lazy_behavior(compatible, observed_min_len);
                let measurement = measure(&contents, &plain, &params).unwrap();
                verify(&measurement, &plain, &compressed);
                let filtered = accepts_filter && selects_filter;
                let expected_mismatches = if filtered {
                    usize::from(length == 6)
                } else {
                    length - 2
                };
                assert_eq!(
                    measurement.trace.mismatch_count, expected_mismatches,
                    "length={length}, observed={observed_min_len}, {params:?}",
                );
                if expected_mismatches != 0 {
                    assert_eq!(
                        measurement.trace.first_mismatches[0],
                        (
                            (length + 2) as u32,
                            DeflateToken::Literal(b'a'),
                            DeflateToken::new_ref(length as u32, (length + 1) as u32),
                        )
                    );
                }
                let record = &mut records[usize::from(filtered)];
                if let Some(previous) = record {
                    assert_eq!(previous, &measurement.corrections);
                } else {
                    *record = Some(measurement.corrections);
                }
            }
        }
    }
}

#[test]
fn legacy_filtered_parameters_keep_original_predictions() {
    let tokens = b"@abcdXabcdYabcdZabcdW"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    let (compressed, contents, plain) = synthetic_stream(tokens);
    let params = TokenPredictorParameters {
        matching_type: MatchingType::Lazy {
            max_lazy: 16,
            filtered_matching: true,
            behavior: LazyBehavior::Zlib { good_length: 8 },
        },
        ..synthetic_params()
    };
    let mut buffer = Vec::new();
    let mut encoder = PredictionEncoderCabac::new(VP8Writer::new(&mut buffer).unwrap());
    let mut predictor = TokenPredictor::new_legacy(&params);
    predict_blocks(
        &contents.blocks,
        &mut predictor,
        &mut encoder,
        &mut PreflateInput::new(&plain),
    )
    .unwrap();
    encoder.finish();
    drop(encoder);
    let mut legacy = ReconstructionData {
        parameters: params,
        corrections: buffer,
    }
    .write();
    legacy[0] = LEGACY_RECONSTRUCTION_DATA_VERSION;
    assert_eq!(
        recreate_whole_deflate_stream(plain.text(), &legacy).unwrap(),
        compressed
    );
    let modern = measure(&contents, &plain, &params).unwrap();
    verify(&modern, &plain, &compressed);
    assert_ne!(&legacy[1..], &modern.corrections[1..]);
    assert_eq!(modern.trace.mismatch_count, 0);

    let mut predictor = TokenPredictor::new_legacy(&params);
    let mut plain = PlainText::new();
    let mut writer = DeflateWriter::new();
    let mut decoder = RecreateStreamProcessor::new();
    for (index, text) in [b"@abcdXabcdYabcdZabcdW", b"@abcdPabcdQabcdRabcdS"]
        .into_iter()
        .enumerate()
    {
        plain.append(text);
        let block = DeflateTokenBlock {
            last: index == 1,
            block_type: DeflateTokenBlockType::Huffman {
                tokens: text.iter().copied().map(DeflateToken::Literal).collect(),
                huffman_type: DeflateHuffmanType::Static,
            },
        };
        let mut input = PreflateInput::new(&plain);
        if index != 0 {
            predictor.add_missing_previous_hash(&input);
        }
        let mut buffer = Vec::new();
        let mut encoder = PredictionEncoderCabac::new(VP8Writer::new(&mut buffer).unwrap());
        predict_blocks(
            std::slice::from_ref(&block),
            &mut predictor,
            &mut encoder,
            &mut input,
        )
        .unwrap();
        encoder.finish();
        drop(encoder);
        let corrections = if index == 0 {
            let mut first = ReconstructionData {
                parameters: params,
                corrections: buffer,
            }
            .write();
            first[0] = LEGACY_RECONSTRUCTION_DATA_VERSION;
            first
        } else {
            buffer
        };
        writer.encode_block(&block).unwrap();
        writer.flush();
        let (recreated, _) = decoder
            .recompress(&mut Cursor::new(text), &corrections)
            .unwrap();
        assert_eq!(recreated, writer.detach_output());
        plain.shrink_to_dictionary();
    }
}

#[derive(Default)]
struct CorrectionCounter(CountNonDefaultActions);

impl PredictionEncoder for CorrectionCounter {
    fn encode_correction(&mut self, action: CodecCorrection, value: u32) {
        self.0.record_correction(action, value);
    }

    fn encode_verify_state(&mut self, _message: &'static str, _checksum: u64) {}

    fn finish(&mut self) {}
}

struct Measurement {
    corrections: Vec<u8>,
    cabac_size: usize,
    count: CountNonDefaultActions,
    trace: TokenPredictionTrace,
    short_match_distance_bounds: Option<(u32, u32)>,
}

fn measure(
    contents: &DeflateContents,
    plain_text: &PlainText,
    params: &TokenPredictorParameters,
) -> Result<Measurement> {
    measure_with_short_match_bounds(contents, plain_text, params, false)
}

fn measure_with_short_match_bounds(
    contents: &DeflateContents,
    plain_text: &PlainText,
    params: &TokenPredictorParameters,
    track_bounds: bool,
) -> Result<Measurement> {
    measure_with_tracking(contents, plain_text, params, track_bounds, false, 8)
}

fn measure_normalized(
    contents: &DeflateContents,
    plain_text: &PlainText,
    params: &TokenPredictorParameters,
) -> Result<Measurement> {
    measure_with_tracking(contents, plain_text, params, false, true, 8)
}

fn measure_with_tracking(
    contents: &DeflateContents,
    plain_text: &PlainText,
    params: &TokenPredictorParameters,
    track_bounds: bool,
    normalize_parameters: bool,
    trace_limit: usize,
) -> Result<Measurement> {
    let mut buffer = Vec::new();
    let mut encoder = (
        CorrectionCounter::default(),
        PredictionEncoderCabac::new(VP8Writer::new(&mut buffer).unwrap()),
    );
    let mut predictor = TokenPredictor::new(params);
    if normalize_parameters {
        predictor.enable_parameter_normalization(
            contents.compressed_size,
            contents.blocks.last().is_some_and(|block| block.last),
        );
    }
    if track_bounds {
        predictor.short_match_distance_bounds = Some((0, 32768));
    }
    predictor.trace = Some(TokenPredictionTrace {
        max_mismatches: trace_limit,
        ..Default::default()
    });
    predict_blocks(
        &contents.blocks,
        &mut predictor,
        &mut encoder,
        &mut PreflateInput::new(plain_text),
    )?;
    encoder.finish();
    let (counter, cabac) = encoder;
    drop(cabac);
    let cabac_size = buffer.len();
    let corrections = ReconstructionData {
        parameters: if normalize_parameters {
            predictor.reconstruction_parameters()
        } else {
            *params
        },
        corrections: buffer,
    }
    .write();
    Ok(Measurement {
        corrections,
        cabac_size,
        count: counter.0,
        trace: predictor.trace.unwrap(),
        short_match_distance_bounds: predictor.short_match_distance_bounds,
    })
}

fn canonical_short_match_limits(bounds: (u32, u32), original: u32) -> impl Iterator<Item = u32> {
    assert!(bounds.0 <= original && original <= bounds.1);
    [0, 4096, 32768]
        .into_iter()
        .chain((1..=15).map(|bits| (1 << bits) - 1))
        .filter(move |&limit| bounds.0 <= limit && limit <= bounds.1)
        .chain(std::iter::once(original))
}

fn standard_short_match_cutoff(
    params: TokenPredictorParameters,
) -> (&'static str, Option<u32>, TokenPredictorParameters) {
    let (profile, default) = match (params.hash_algorithm, params.matching_type) {
        (
            HashAlgorithm::Zlib { .. },
            MatchingType::Lazy {
                behavior: LazyBehavior::Zlib { .. },
                ..
            },
        ) => ("zlib_style_lazy", Some(4096)),
        (HashAlgorithm::Zlib { .. }, MatchingType::Greedy) => ("zlib_style_greedy", Some(32768)),
        _ => ("unclassified_unchanged", None),
    };
    let candidate = TokenPredictorParameters {
        max_dist_3_matches: default.map_or(params.max_dist_3_matches, |limit| {
            limit.max(params.max_dist_3_matches)
        }),
        ..params
    };
    (profile, default, candidate)
}

#[test]
fn standard_short_match_cutoff_exposes_extra_candidates_without_breaking_recovery() {
    let tokens = b"@abcXabcY#defX12345defY"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    let (compressed, contents, plain) = synthetic_stream(tokens);
    for matching_type in [
        MatchingType::Greedy,
        SLOW_PREFLATE_PARSER_SETTINGS[2].match_type,
    ] {
        let params = TokenPredictorParameters {
            max_dist_3_matches: 0,
            matching_type,
            ..synthetic_params()
        };
        let baseline = measure(&contents, &plain, &params).unwrap();
        verify(&baseline, &plain, &compressed);
        assert_eq!(baseline.trace.mismatch_count, 0);
        let (_, _, candidate) = standard_short_match_cutoff(params);
        let measurement = measure(&contents, &plain, &candidate).unwrap();
        verify(&measurement, &plain, &compressed);
        assert!(measurement.trace.mismatch_count > 0);
        assert!(measurement.cabac_size > baseline.cabac_size);
    }

    let mut tokens: Vec<_> = b"@abcX"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.push(DeflateToken::new_ref(3, 4));
    tokens.push(DeflateToken::Literal(b'Y'));
    let (compressed, contents, plain) = synthetic_stream(tokens);
    let params = TokenPredictorParameters {
        max_dist_3_matches: 4,
        matching_type: SLOW_PREFLATE_PARSER_SETTINGS[2].match_type,
        ..synthetic_params()
    };
    let baseline = measure(&contents, &plain, &params).unwrap();
    let (_, _, candidate) = standard_short_match_cutoff(params);
    let measurement = measure(&contents, &plain, &candidate).unwrap();
    verify(&baseline, &plain, &compressed);
    verify(&measurement, &plain, &compressed);
    assert_eq!(baseline.trace.mismatch_count, 0);
    assert_eq!(measurement.trace.mismatch_count, 0);
    assert_eq!(
        ReconstructionData::read(&baseline.corrections)
            .unwrap()
            .corrections,
        ReconstructionData::read(&measurement.corrections)
            .unwrap()
            .corrections,
    );
}

#[test]
fn standard_short_match_cutoff_retains_emitted_matches_beyond_the_default() {
    let mut tokens: Vec<_> = b"@abcX"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    let mut remaining = 4098 - tokens.len() as u32;
    while remaining > 0 {
        let length = remaining.min(258);
        assert!(length >= 3);
        tokens.push(DeflateToken::new_ref(length, 1));
        remaining -= length;
    }
    tokens.push(DeflateToken::new_ref(3, 4097));
    let (compressed, contents, plain) = synthetic_stream(tokens);
    assert_eq!(
        extract_preflate_info(&contents.blocks).max_dist_3_matches,
        4097
    );
    let params = TokenPredictorParameters {
        max_dist_3_matches: 4097,
        matching_type: SLOW_PREFLATE_PARSER_SETTINGS[2].match_type,
        ..synthetic_params()
    };
    let (_, default, candidate) = standard_short_match_cutoff(params);
    assert_eq!(default, Some(4096));
    let normalized = measure_normalized(&contents, &plain, &params).unwrap();
    verify(&normalized, &plain, &compressed);
    let normalized_record = ReconstructionData::read(&normalized.corrections).unwrap();
    assert!(normalized_record.parameters.max_dist_3_matches >= 4097);
    assert_eq!(
        normalized_record.corrections,
        ReconstructionData::read(&measure(&contents, &plain, &params).unwrap().corrections)
            .unwrap()
            .corrections,
    );
    let retained = measure(&contents, &plain, &candidate).unwrap();
    let clamped = measure(
        &contents,
        &plain,
        &TokenPredictorParameters {
            max_dist_3_matches: 4096,
            ..params
        },
    )
    .unwrap();
    verify(&retained, &plain, &compressed);
    verify(&clamped, &plain, &compressed);
    assert!(clamped.trace.mismatch_count > retained.trace.mismatch_count);
}

#[test]
fn short_match_distance_bounds_preserve_decisions_and_exclude_counterexamples() {
    let tokens = b"@abcXabcY#defX12345defY"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    let (compressed, contents, plain) = synthetic_stream(tokens);
    let params = TokenPredictorParameters {
        max_dist_3_matches: 4,
        ..synthetic_params()
    };
    let baseline = measure_with_short_match_bounds(&contents, &plain, &params, true).unwrap();
    verify(&baseline, &plain, &compressed);
    let bounds = baseline.short_match_distance_bounds.unwrap();
    assert_eq!(bounds, (4, 8));
    let normalized = measure_normalized(&contents, &plain, &params).unwrap();
    verify(&normalized, &plain, &compressed);
    let normalized_record = ReconstructionData::read(&normalized.corrections).unwrap();
    assert_eq!(normalized_record.parameters.max_dist_3_matches, 7);
    assert_eq!(
        normalized_record.corrections,
        ReconstructionData::read(&baseline.corrections)
            .unwrap()
            .corrections,
    );
    let canonical = canonical_short_match_limits(bounds, params.max_dist_3_matches)
        .next()
        .unwrap();
    assert_eq!(canonical, 7);
    for (limit, expected_mismatches) in [(canonical, 1), (3, 0), (9, 2)] {
        let candidate = TokenPredictorParameters {
            max_dist_3_matches: limit,
            ..params
        };
        let measurement = measure(&contents, &plain, &candidate).unwrap();
        verify(&measurement, &plain, &compressed);
        assert_eq!(measurement.trace.mismatch_count, expected_mismatches);
        if limit == canonical {
            assert_eq!(
                ReconstructionData::read(&measurement.corrections)
                    .unwrap()
                    .corrections,
                ReconstructionData::read(&baseline.corrections)
                    .unwrap()
                    .corrections,
            );
        }
    }
}

#[test]
fn cutoff_normalization_preserves_decisions_across_families_and_deferred_matches() {
    let tokens = b"@abcXabcY#defX12345defY"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    let (compressed, contents, plain) = synthetic_stream(tokens);
    let zlib = synthetic_params().hash_algorithm;
    for (hash_algorithm, matching_type) in [
        (zlib, MatchingType::Greedy),
        (zlib, SLOW_PREFLATE_PARSER_SETTINGS[2].match_type),
        (
            zlib,
            MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: true,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            },
        ),
        (HashAlgorithm::RandomVector, MatchingType::Greedy),
        (
            HashAlgorithm::RandomVector,
            SLOW_PREFLATE_PARSER_SETTINGS[2].match_type,
        ),
        (HashAlgorithm::Libdeflate4, MatchingType::Greedy),
        (HashAlgorithm::Libdeflate4, MatchingType::LibdeflateGreedy),
        (
            HashAlgorithm::Libdeflate4,
            MatchingType::LibdeflateLazy {
                two_positions: false,
            },
        ),
        (
            HashAlgorithm::Libdeflate4,
            MatchingType::LibdeflateLazy {
                two_positions: true,
            },
        ),
        (
            zlib,
            MatchingType::MiniZ {
                max_probes: 16,
                greedy: false,
            },
        ),
    ] {
        for cutoff in [0, 4, 8, 255, 256, 4096, 8192, 32768] {
            let params = TokenPredictorParameters {
                hash_algorithm,
                matching_type,
                max_dist_3_matches: cutoff,
                ..synthetic_params()
            };
            let baseline = measure(&contents, &plain, &params).unwrap();
            let normalized = measure_normalized(&contents, &plain, &params).unwrap();
            verify(&baseline, &plain, &compressed);
            verify(&normalized, &plain, &compressed);
            let after = ReconstructionData::read(&normalized.corrections).unwrap();
            assert_eq!(
                after.corrections,
                ReconstructionData::read(&baseline.corrections)
                    .unwrap()
                    .corrections
            );
            assert_eq!(
                baseline.trace.mismatch_count,
                normalized.trace.mismatch_count
            );
            assert_eq!(
                baseline.count.total_non_default,
                normalized.count.total_non_default
            );
            assert!(normalized.corrections.len() <= baseline.corrections.len());
            let bounds = normalized.short_match_distance_bounds.unwrap();
            assert!((bounds.0..=bounds.1).contains(&after.parameters.max_dist_3_matches));
            if cutoff == 0 {
                assert_eq!(after.parameters.max_dist_3_matches, 0);
            }
        }
    }
}

fn verify(measurement: &Measurement, plain_text: &PlainText, compressed: &[u8]) {
    let recreated = recreate_whole_deflate_stream(plain_text.text(), &measurement.corrections)
        .expect("diagnostic parameters must reconstruct successfully");
    crate::utils::assert_eq_array(compressed, &recreated);
}

#[derive(Default)]
struct RecordedCorrections(Vec<(CodecCorrection, u32)>);

impl PredictionEncoder for RecordedCorrections {
    fn encode_correction(&mut self, action: CodecCorrection, value: u32) {
        self.0.push((action, value));
    }

    fn encode_verify_state(&mut self, _message: &'static str, _checksum: u64) {}

    fn finish(&mut self) {}
}

fn overhead_family(action: CodecCorrection) -> usize {
    use CodecCorrection::*;
    match action {
        LenCorrection
        | DistOnlyCorrection
        | DistAfterLenCorrection
        | LiteralPredictionWrong
        | ReferencePredictionWrong => 0,
        TreeProfile => 1,
        TreeCodeBitLengthCorrection
        | LDTypeCorrection
        | RepeatCountCorrection
        | LDBitLengthCorrection
        | LiteralCountCorrection
        | DistanceCountCorrection => 2,
        TokenCount | BlockTypeCorrection | UncompressBlockLenCorrection | Last | EndOfChunk => 3,
        MAX => unreachable!("MAX is not a correction action"),
    }
}

fn replay_correction_families(actions: &RecordedCorrections, families: u8) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut encoder = PredictionEncoderCabac::new(VP8Writer::new(&mut buffer).unwrap());
    for &(action, value) in &actions.0 {
        encoder.encode_correction(
            action,
            if families & (1 << overhead_family(action)) != 0 {
                value
            } else {
                0
            },
        );
    }
    encoder.finish();
    drop(encoder);
    buffer
}

// Average each family's marginal coding cost over all 24 family orders. Contexts,
// the shared action mask and byte rounding make single-removal costs non-additive.
// Zeroing events is a coding-cost attribution, not a decodable alternative model.
fn overhead_contributions(actions: &RecordedCorrections) -> (Vec<u8>, usize, [i64; 4]) {
    let subsets: Vec<_> = (0..16)
        .map(|mask| replay_correction_families(actions, mask))
        .collect();
    let mut contributions = [0; 4];
    for (family, contribution) in contributions.iter_mut().enumerate() {
        for mask in 0u8..16 {
            if mask & (1 << family) == 0 {
                let weight = match mask.count_ones() {
                    0 | 3 => 6,
                    1 | 2 => 2,
                    _ => unreachable!(),
                };
                *contribution += weight
                    * (subsets[usize::from(mask | (1 << family))].len() as i64
                        - subsets[usize::from(mask)].len() as i64);
            }
        }
    }
    let baseline = subsets[0].len();
    assert_eq!(
        contributions.iter().sum::<i64>(),
        24 * (subsets[15].len() as i64 - baseline as i64),
    );
    (subsets.into_iter().last().unwrap(), baseline, contributions)
}

#[test]
fn overhead_attribution_matches_real_encoder_and_isolates_a_tree_profile() {
    use crate::deflate::deflate_token::DeflateToken;

    let (compressed, contents, plain) = synthetic_stream(
        b"@abcdefabcdefabcdef"
            .iter()
            .copied()
            .map(DeflateToken::Literal)
            .collect(),
    );
    let params = synthetic_params();
    let actual = measure(&contents, &plain, &params).unwrap();
    verify(&actual, &plain, &compressed);
    let mut actions = RecordedCorrections::default();
    predict_blocks(
        &contents.blocks,
        &mut TokenPredictor::new(&params),
        &mut actions,
        &mut PreflateInput::new(&plain),
    )
    .unwrap();
    let (replayed, _, _) = overhead_contributions(&actions);
    assert_eq!(
        replayed,
        ReconstructionData::read(&actual.corrections)
            .unwrap()
            .corrections
    );

    let only_tree_profile = RecordedCorrections(vec![
        (CodecCorrection::TreeProfile, 3),
        (CodecCorrection::TreeProfile, 0),
        (CodecCorrection::TokenCount, 0),
    ]);
    let (encoded, baseline, contributions) = overhead_contributions(&only_tree_profile);
    assert!(encoded.len() > baseline);
    assert_eq!(contributions[0], 0);
    assert_eq!(contributions[2], 0);
    assert_eq!(contributions[3], 0);
    assert_eq!(contributions[1], 24 * (encoded.len() - baseline) as i64);

    let defaults = RecordedCorrections(vec![
        (CodecCorrection::TokenCount, 0),
        (CodecCorrection::TreeProfile, 0),
        (CodecCorrection::ReferencePredictionWrong, 0),
    ]);
    let (encoded, baseline, contributions) = overhead_contributions(&defaults);
    assert!(encoded.is_empty());
    assert_eq!(baseline, 0);
    assert_eq!(contributions, [0; 4]);
}

#[test]
#[ignore = "offline tiny-stream byte attribution; requires local .deflate fixtures"]
fn profile_tiny_overhead() {
    use std::io::Write;

    let path = std::env::var_os("PREFLATE_TINY_PROFILE_RESULTS")
        .expect("set PREFLATE_TINY_PROFILE_RESULTS to a new TSV output file");
    let mut output = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap(),
    );
    writeln!(output, "case\tdeflate\tplaintext\tblocks\tbytes\tcabac\tparameter_bytes\twrapper_bytes\tzero_cabac\tcomponents_x24\tmismatches\tcounts\tblock_profile\tparams").unwrap();
    let mut files: Vec<_> = std::fs::read_dir(fixture_directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "deflate"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .deflate fixtures found");
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy();
        let compressed = std::fs::read(&file).unwrap();
        assert!(compressed.len() < 1024, "{name}: not a tiny stream");
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len(), "{name}");
        let params = estimate_preflate_parameters(&contents, &plain).unwrap();
        let baseline = measure(&contents, &plain, &params).unwrap();
        verify(&baseline, &plain, &compressed);
        let mut actions = RecordedCorrections::default();
        predict_blocks(
            &contents.blocks,
            &mut TokenPredictor::new(&params),
            &mut actions,
            &mut PreflateInput::new(&plain),
        )
        .unwrap();
        let (replayed, zero_cabac, components) = overhead_contributions(&actions);
        assert_eq!(
            replayed,
            ReconstructionData::read(&baseline.corrections)
                .unwrap()
                .corrections,
            "{name}"
        );
        let parameter_bytes = bitcode::encode(&params).len();
        let wrapper_bytes =
            baseline.corrections.len() as i64 - baseline.cabac_size as i64 - parameter_bytes as i64;
        writeln!(
            output,
            "{name}\t{}\t{}\t{}\t{}\t{}\t{parameter_bytes}\t{wrapper_bytes}\t{zero_cabac}\t{components:?}\t{}\t{:?}\t{}\t{params:?}",
            compressed.len(), plain.len(), contents.blocks.len(), baseline.corrections.len(),
            baseline.cabac_size, baseline.trace.mismatch_count, baseline.count.corrections_count,
            baseline.trace.block_profile,
        ).unwrap();
        output.flush().unwrap();
    }
}

#[test]
#[ignore = "offline tiny-state equivalence study; requires local .deflate fixtures"]
fn profile_tiny_state_collapse() {
    use std::io::Write;

    let path = std::env::var_os("PREFLATE_TINY_STATE_RESULTS")
        .expect("set PREFLATE_TINY_STATE_RESULTS to a new TSV output file");
    let mut output = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap(),
    );
    writeln!(output, "case\tdeflate\tplaintext\tperfect\tbytes\toriginal_limit\tlower\tupper\tcanonical_limit\tcanonical_bytes\tnongrowing_limit\tnongrowing_bytes\tparams\tcanonical_params\tnongrowing_params\tcommon_perfect\tcommon_bytes\tcommon_error\tcommon_params").unwrap();
    let mut files: Vec<_> = std::fs::read_dir(fixture_directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "deflate"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .deflate fixtures found");
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy();
        let compressed = std::fs::read(&file).unwrap();
        assert!(compressed.len() < 1024, "{name}: not a tiny stream");
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len(), "{name}");
        let params = estimate_preflate_parameters(&contents, &plain).unwrap();
        let baseline = measure_with_short_match_bounds(&contents, &plain, &params, true).unwrap();
        verify(&baseline, &plain, &compressed);
        let perfect = baseline.count.total_non_default == 0;
        let bounds = baseline.short_match_distance_bounds.unwrap();
        let canonical_limit = canonical_short_match_limits(bounds, params.max_dist_3_matches)
            .next()
            .unwrap();
        let canonical = TokenPredictorParameters {
            max_dist_3_matches: canonical_limit,
            ..params
        };
        let canonical_measurement = measure(&contents, &plain, &canonical).unwrap();
        verify(&canonical_measurement, &plain, &compressed);
        let baseline_cabac = ReconstructionData::read(&baseline.corrections)
            .unwrap()
            .corrections;
        assert_eq!(
            ReconstructionData::read(&canonical_measurement.corrections)
                .unwrap()
                .corrections,
            baseline_cabac,
            "{name}: interval canonicalization changed correction coding"
        );
        assert_eq!(
            canonical_measurement.count.corrections_count, baseline.count.corrections_count,
            "{name}"
        );
        let mut nongrowing = params;
        let mut nongrowing_bytes = baseline.corrections.len();
        for limit in canonical_short_match_limits(bounds, params.max_dist_3_matches) {
            let candidate = TokenPredictorParameters {
                max_dist_3_matches: limit,
                ..params
            };
            if bitcode::encode(&candidate).len() > bitcode::encode(&params).len() {
                continue;
            }
            let measurement = measure(&contents, &plain, &candidate).unwrap();
            verify(&measurement, &plain, &compressed);
            assert_eq!(
                ReconstructionData::read(&measurement.corrections)
                    .unwrap()
                    .corrections,
                baseline_cabac,
                "{name}: size-constrained canonicalization changed correction coding"
            );
            if measurement.corrections.len() <= baseline.corrections.len() {
                nongrowing = candidate;
                nongrowing_bytes = measurement.corrections.len();
                break;
            }
        }
        let common = TokenPredictorParameters {
            matches_to_start_detected: false,
            very_far_matches_detected: false,
            window_bits: 15,
            nice_length: 128,
            add_policy: DictionaryAddPolicy::AddAll,
            max_dist_3_matches: 4096,
            matching_type: SLOW_PREFLATE_PARSER_SETTINGS[2].match_type,
            max_chain: 128,
            hash_algorithm: HashAlgorithm::Zlib {
                hash_mask: 32767,
                hash_shift: 5,
            },
            ..params
        }
        .with_lazy_behavior(true, extract_preflate_info(&contents.blocks).min_len);
        let (common_perfect, common_bytes, common_error) = match measure(&contents, &plain, &common)
        {
            Ok(measurement) => {
                verify(&measurement, &plain, &compressed);
                (
                    measurement.count.total_non_default == 0,
                    measurement.corrections.len(),
                    String::new(),
                )
            }
            Err(error) => (false, 0, format!("{:?}", error.exit_code())),
        };
        writeln!(
            output,
            "{name}\t{}\t{}\t{perfect}\t{}\t{}\t{}\t{}\t{canonical_limit}\t{}\t{}\t{nongrowing_bytes}\t{params:?}\t{canonical:?}\t{nongrowing:?}\t{common_perfect}\t{common_bytes}\t{common_error}\t{common:?}",
            compressed.len(), plain.len(), baseline.corrections.len(),
            params.max_dist_3_matches, bounds.0, bounds.1,
            canonical_measurement.corrections.len(), nongrowing.max_dist_3_matches,
        ).unwrap();
        output.flush().unwrap();
    }
}

#[test]
#[ignore = "offline standard-cutoff study; requires local .deflate fixtures"]
fn profile_tiny_standard_cutoffs() {
    use std::io::Write;

    let path = std::env::var_os("PREFLATE_TINY_DEFAULT_RESULTS")
        .expect("set PREFLATE_TINY_DEFAULT_RESULTS to a new TSV output file");
    let mut output = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap(),
    );
    writeln!(output, "case\tdeflate\tplaintext\tblocks\tperfect\tbytes\tcabac\tcorrections\tmismatches\toriginal_limit\tprofile\tdefault_limit\tparams\tdefault_params\tdefault_bytes\tdefault_cabac\tdefault_corrections\tdefault_mismatches\tdefault_perfect\terror").unwrap();
    let mut files: Vec<_> = std::fs::read_dir(fixture_directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "deflate"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .deflate fixtures found");
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy();
        let compressed = std::fs::read(&file).unwrap();
        assert!(compressed.len() < 1024, "{name}: not a tiny stream");
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len(), "{name}");
        let params = estimate_preflate_parameters(&contents, &plain).unwrap();
        let baseline = measure(&contents, &plain, &params).unwrap();
        verify(&baseline, &plain, &compressed);
        let (profile, default, candidate) = standard_short_match_cutoff(params);
        write!(
            output,
            "{name}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{profile}\t{}\t{params:?}\t{candidate:?}\t",
            compressed.len(), plain.len(), contents.blocks.len(),
            baseline.count.total_non_default == 0, baseline.corrections.len(),
            baseline.cabac_size, baseline.count.total_non_default,
            baseline.trace.mismatch_count, params.max_dist_3_matches,
            default.map_or(String::new(), |limit| limit.to_string()),
        ).unwrap();
        match measure(&contents, &plain, &candidate) {
            Ok(measurement) => {
                verify(&measurement, &plain, &compressed);
                writeln!(
                    output,
                    "{}\t{}\t{}\t{}\t{}\t",
                    measurement.corrections.len(),
                    measurement.cabac_size,
                    measurement.count.total_non_default,
                    measurement.trace.mismatch_count,
                    measurement.count.total_non_default == 0,
                )
                .unwrap();
            }
            Err(error) => {
                writeln!(output, "\t\t\t\t\t{:?}", error.exit_code()).unwrap();
            }
        }
        output.flush().unwrap();
    }
}

fn distance_window_variants(
    params: TokenPredictorParameters,
    plaintext_length: usize,
) -> Vec<(&'static str, TokenPredictorParameters)> {
    let mut control = standard_short_match_cutoff(params).2;
    if params.max_dist_3_matches == 0 {
        control.max_dist_3_matches = 0;
    }
    let mut libdeflate = control;
    if params.hash_algorithm == HashAlgorithm::Libdeflate4 && params.max_dist_3_matches != 0 {
        let cutoff = match params.matching_type {
            MatchingType::Greedy | MatchingType::LibdeflateGreedy => 4096,
            _ => 8192,
        };
        libdeflate.max_dist_3_matches = params.max_dist_3_matches.max(cutoff);
    }
    let windows = |cutoff| TokenPredictorParameters {
        max_dist_3_matches: if params.hash_algorithm == HashAlgorithm::RandomVector
            && params.max_dist_3_matches != 0
        {
            params.max_dist_3_matches.max(cutoff)
        } else {
            libdeflate.max_dist_3_matches
        },
        ..libdeflate
    };
    let window = |mut candidate: TokenPredictorParameters, inert_only: bool| {
        if candidate.window_bits != 0
            && (!inert_only
                || plaintext_length
                    <= ((1usize << candidate.window_bits)
                        .saturating_sub(crate::deflate::deflate_constants::MIN_LOOKAHEAD as usize)))
        {
            candidate.window_bits = 15;
        }
        candidate
    };
    vec![
        ("baseline", params),
        ("guarded_zlib", control),
        ("libdeflate_defaults", libdeflate),
        ("windows_4096", windows(4096)),
        ("windows_8192", windows(8192)),
        ("windows_full", windows(32768)),
        ("window15", window(control, false)),
        ("window15_inert_only", window(control, true)),
        ("libdeflate_window15", window(libdeflate, false)),
        ("libdeflate_window15_inert_only", window(libdeflate, true)),
        ("windows_4096_window15", window(windows(4096), false)),
        ("windows_8192_window15", window(windows(8192), false)),
        ("windows_full_window15", window(windows(32768), false)),
    ]
}

#[test]
fn distance_window_normalization_exposes_unobserved_history() {
    let mut tokens: Vec<_> = b"@abcdefX"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.extend([
        DeflateToken::new_ref(258, 1),
        DeflateToken::new_ref(258, 1),
        DeflateToken::new_ref(84, 1),
    ]);
    tokens.extend(b"abcdefY".iter().copied().map(DeflateToken::Literal));
    let (compressed, contents, plain) = synthetic_stream(tokens);
    for hash_algorithm in [
        synthetic_params().hash_algorithm,
        HashAlgorithm::RandomVector,
    ] {
        let params = TokenPredictorParameters {
            hash_algorithm,
            window_bits: 9,
            max_dist_3_matches: 0,
            ..synthetic_params()
        };
        let baseline = measure(&contents, &plain, &params).unwrap();
        verify(&baseline, &plain, &compressed);
        let normalized = measure_normalized(&contents, &plain, &params).unwrap();
        verify(&normalized, &plain, &compressed);
        assert_eq!(
            ReconstructionData::read(&normalized.corrections)
                .unwrap()
                .corrections,
            ReconstructionData::read(&baseline.corrections)
                .unwrap()
                .corrections,
        );
        for (name, candidate) in distance_window_variants(params, plain.len()) {
            let measurement = measure(&contents, &plain, &candidate).unwrap();
            verify(&measurement, &plain, &compressed);
            assert_eq!(candidate.max_dist_3_matches, 0, "{name}");
            if name == "window15" {
                assert!(measurement.trace.mismatch_count > baseline.trace.mismatch_count);
            } else if name == "window15_inert_only" {
                assert_eq!(candidate, params);
                assert_eq!(measurement.corrections, baseline.corrections);
            }
        }
    }
}

#[test]
fn distance_window_normalization_preserves_inert_windows_and_above_default_references() {
    for (length, expected_bits) in [(250, 15), (251, 9)] {
        let tokens = (0..length)
            .map(|value| DeflateToken::Literal(value as u8))
            .collect();
        let (compressed, contents, plain) = synthetic_stream(tokens);
        let params = TokenPredictorParameters {
            window_bits: 9,
            max_dist_3_matches: 0,
            ..synthetic_params()
        };
        let candidate = distance_window_variants(params, plain.len())[7].1;
        assert_eq!(candidate.window_bits, expected_bits);
        let baseline = measure(&contents, &plain, &params).unwrap();
        let measurement = measure(&contents, &plain, &candidate).unwrap();
        verify(&baseline, &plain, &compressed);
        verify(&measurement, &plain, &compressed);
        assert_eq!(
            ReconstructionData::read(&measurement.corrections)
                .unwrap()
                .corrections,
            ReconstructionData::read(&baseline.corrections)
                .unwrap()
                .corrections,
        );
    }
    let mut tokens: Vec<_> = b"@abcX"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.push(DeflateToken::new_ref(3, 4));
    tokens.push(DeflateToken::Literal(b'Y'));
    let (compressed, contents, plain) = synthetic_stream(tokens);
    for hash_algorithm in [
        synthetic_params().hash_algorithm,
        HashAlgorithm::RandomVector,
        HashAlgorithm::Libdeflate4,
    ] {
        let params = TokenPredictorParameters {
            hash_algorithm,
            window_bits: 9,
            max_dist_3_matches: 4,
            ..synthetic_params()
        };
        let baseline = measure(&contents, &plain, &params).unwrap();
        let candidate = distance_window_variants(params, plain.len())
            .into_iter()
            .find(|(name, _)| *name == "window15_inert_only")
            .unwrap()
            .1;
        assert_eq!(candidate.window_bits, 15);
        let measurement = measure(&contents, &plain, &candidate).unwrap();
        verify(&baseline, &plain, &compressed);
        verify(&measurement, &plain, &compressed);
        assert_eq!(
            ReconstructionData::read(&measurement.corrections)
                .unwrap()
                .corrections,
            ReconstructionData::read(&baseline.corrections)
                .unwrap()
                .corrections,
        );
        for (_, candidate) in distance_window_variants(
            TokenPredictorParameters {
                max_dist_3_matches: 9000,
                ..params
            },
            plain.len(),
        ) {
            assert!(candidate.max_dist_3_matches >= 9000);
        }
    }
}

#[test]
#[ignore = "offline distance/window normalization study; requires local tiny .deflate fixtures"]
fn profile_tiny_distance_windows() {
    use std::io::Write;

    let path = std::env::var_os("PREFLATE_TINY_DISTANCE_WINDOW_RESULTS")
        .expect("set PREFLATE_TINY_DISTANCE_WINDOW_RESULTS to a new TSV output file");
    let mut output = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap(),
    );
    writeln!(output, "case\tvariant\tdeflate\tplaintext\tblocks\tbytes\tcabac\tcorrections\tmismatches\tperfect\tparams\tcabac_unchanged\terror").unwrap();
    let mut files: Vec<_> = std::fs::read_dir(fixture_directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "deflate"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .deflate fixtures found");
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy();
        let compressed = std::fs::read(&file).unwrap();
        assert!(compressed.len() < 1024, "{name}: not a tiny stream");
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len(), "{name}");
        let params = estimate_preflate_parameters(&contents, &plain).unwrap();
        let baseline = measure(&contents, &plain, &params).unwrap();
        verify(&baseline, &plain, &compressed);
        let baseline_cabac = ReconstructionData::read(&baseline.corrections)
            .unwrap()
            .corrections;
        for (variant, candidate) in distance_window_variants(params, plain.len()) {
            write!(
                output,
                "{name}\t{variant}\t{}\t{}\t{}\t",
                compressed.len(),
                plain.len(),
                contents.blocks.len()
            )
            .unwrap();
            match measure(&contents, &plain, &candidate) {
                Ok(measurement) => {
                    verify(&measurement, &plain, &compressed);
                    let unchanged = ReconstructionData::read(&measurement.corrections)
                        .unwrap()
                        .corrections
                        == baseline_cabac;
                    if variant == "window15_inert_only" {
                        let control = distance_window_variants(params, plain.len())[1].1;
                        let control_measurement = measure(&contents, &plain, &control).unwrap();
                        assert_eq!(
                            ReconstructionData::read(&control_measurement.corrections)
                                .unwrap()
                                .corrections,
                            ReconstructionData::read(&measurement.corrections)
                                .unwrap()
                                .corrections,
                            "{name}: inert window changed prediction",
                        );
                    }
                    writeln!(
                        output,
                        "{}\t{}\t{}\t{}\t{}\t{candidate:?}\t{unchanged}\t",
                        measurement.corrections.len(),
                        measurement.cabac_size,
                        measurement.count.total_non_default,
                        measurement.trace.mismatch_count,
                        measurement.count.total_non_default == 0
                    )
                    .unwrap();
                }
                Err(error) => {
                    writeln!(output, "\t\t\t\t\t{candidate:?}\t\t{:?}", error.exit_code()).unwrap();
                }
            }
        }
        output.flush().unwrap();
    }
}

#[test]
fn admissible_window_normalization_preserves_records_and_skips_partial_streams() {
    let mut tokens: Vec<_> = b"@abcX"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.push(DeflateToken::new_ref(3, 4));
    tokens.push(DeflateToken::Literal(b'Y'));
    let (compressed, mut contents, plain) = synthetic_stream(tokens);
    let params = TokenPredictorParameters {
        window_bits: 9,
        max_dist_3_matches: 4,
        ..synthetic_params()
    };
    let baseline = measure(&contents, &plain, &params).unwrap();
    let normalized = measure_normalized(&contents, &plain, &params).unwrap();
    verify(&normalized, &plain, &compressed);
    assert_eq!(
        ReconstructionData::read(&normalized.corrections)
            .unwrap()
            .parameters
            .window_bits,
        15
    );
    assert_eq!(baseline.cabac_size, normalized.cabac_size);
    assert_eq!(baseline.corrections.len(), normalized.corrections.len());

    contents.compressed_size = 1024;
    let large = measure_normalized(&contents, &plain, &params).unwrap();
    verify(&large, &plain, &compressed);
    assert_eq!(large.corrections, baseline.corrections);
    contents.compressed_size = compressed.len();
    contents.blocks.last_mut().unwrap().last = false;
    let mut writer = DeflateWriter::new();
    writer.encode_block(&contents.blocks[0]).unwrap();
    writer.flush();
    let partial = measure_normalized(&contents, &plain, &params).unwrap();
    verify(&partial, &plain, &writer.detach_output());
    assert_eq!(
        ReconstructionData::read(&partial.corrections)
            .unwrap()
            .parameters,
        params
    );
}

#[test]
#[ignore = "offline safe-parameter study; requires local tiny .deflate fixtures"]
fn profile_tiny_parameter_normalization() {
    use std::io::Write;
    let path = std::env::var_os("PREFLATE_TINY_NORMALIZATION_RESULTS")
        .expect("set PREFLATE_TINY_NORMALIZATION_RESULTS to a new TSV file");
    let mut output = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap(),
    );
    writeln!(
        output,
        "case\tpolicy\tperfect\tbytes\tcabac\tparams\tnormalized_bytes\tnormalized_params\tlower\tupper"
    )
    .unwrap();
    let mut files: Vec<_> = std::fs::read_dir(fixture_directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "deflate"))
        .collect();
    files.sort();
    assert!(!files.is_empty());
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy();
        let compressed = std::fs::read(&file).unwrap();
        assert!(compressed.len() < 1024, "{name}");
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len(), "{name}");
        let original = estimate_preflate_parameters(&contents, &plain).unwrap();
        let guarded = distance_window_variants(original, plain.len())[1].1;
        for (policy, params) in [("production", original), ("guarded_zlib", guarded)] {
            let baseline = measure(&contents, &plain, &params).unwrap();
            let normalized = measure_normalized(&contents, &plain, &params).unwrap();
            verify(&baseline, &plain, &compressed);
            verify(&normalized, &plain, &compressed);
            let before = ReconstructionData::read(&baseline.corrections).unwrap();
            let after = ReconstructionData::read(&normalized.corrections).unwrap();
            assert_eq!(
                before.corrections, after.corrections,
                "{name}/{policy}: CABAC changed"
            );
            assert_eq!(
                baseline.count.total_non_default, normalized.count.total_non_default,
                "{name}"
            );
            assert_eq!(
                baseline.trace.mismatch_count, normalized.trace.mismatch_count,
                "{name}"
            );
            assert_eq!(
                TokenPredictorParameters {
                    window_bits: params.window_bits,
                    max_dist_3_matches: params.max_dist_3_matches,
                    ..after.parameters
                },
                params
            );
            assert!(after.parameters.window_bits >= params.window_bits, "{name}");
            assert!(
                normalized.corrections.len() <= baseline.corrections.len(),
                "{name}"
            );
            if policy == "production" {
                let (production, _) =
                    preflate_whole_deflate_stream(&compressed, &PreflateConfig::default()).unwrap();
                assert_eq!(
                    production.corrections, normalized.corrections,
                    "{name}: production differs"
                );
                assert_eq!(production.parameters, Some(after.parameters), "{name}");
            }
            writeln!(
                output,
                "{name}\t{policy}\t{}\t{}\t{}\t{params:?}\t{}\t{:?}\t{}\t{}",
                baseline.count.total_non_default == 0,
                baseline.corrections.len(),
                baseline.cabac_size,
                normalized.corrections.len(),
                after.parameters,
                normalized.short_match_distance_bounds.unwrap().0,
                normalized.short_match_distance_bounds.unwrap().1,
            )
            .unwrap();
        }
        output.flush().unwrap();
    }
}

fn print_measurement(label: &str, measurement: &Measurement, compressed_size: usize) {
    println!(
        "{label}: overhead={} ({:.3}% of deflate), cabac={}, tokens={}, token_mismatches={}, corrections={}",
        measurement.corrections.len(),
        100.0 * measurement.corrections.len() as f64 / compressed_size as f64,
        measurement.cabac_size,
        measurement.trace.token_count,
        measurement.trace.mismatch_count,
        measurement.count.total_non_default,
    );
}

fn print_details(measurement: &Measurement) {
    measurement.count.print();
    for (offset, actual, predicted) in &measurement.trace.first_mismatches {
        println!("  plaintext offset {offset}: actual={actual:?}, predicted={predicted:?}");
    }
}

fn parameter_variants(
    params: TokenPredictorParameters,
    observed_min_len: u32,
    combined: bool,
) -> Vec<TokenPredictorParameters> {
    let mut variants = Vec::new();
    let compatible = zlib_compatible(&params);
    let mut add = |candidate: TokenPredictorParameters| {
        let candidate = candidate.with_lazy_behavior(compatible, observed_min_len);
        if candidate != params && !variants.contains(&candidate) {
            variants.push(candidate);
        }
    };
    let matching_types = std::iter::once(MatchingType::Greedy).chain(
        SLOW_PREFLATE_PARSER_SETTINGS
            .iter()
            .map(|config| config.match_type),
    );
    for matching_type in matching_types {
        add(TokenPredictorParameters {
            matching_type,
            ..params
        });
        if combined {
            for nice_length in [8, 10, 14, 16, 30, 32, 64, 65, 128, 130, 258] {
                for max_chain in [
                    params.max_chain,
                    params.max_chain.saturating_sub(1).max(1),
                    params.max_chain.next_power_of_two(),
                ] {
                    add(TokenPredictorParameters {
                        matching_type,
                        nice_length,
                        max_chain,
                        ..params
                    });
                }
            }
        }
    }
    for nice_length in [8, 10, 14, 16, 30, 32, 64, 65, 128, 130, 258] {
        add(TokenPredictorParameters {
            nice_length,
            ..params
        });
    }
    // A chain depth inferred from observed matches is a lower bound, not a search budget.
    for max_chain in [
        params.max_chain.saturating_sub(1).max(1),
        params.max_chain.next_power_of_two(),
    ] {
        add(TokenPredictorParameters {
            max_chain,
            ..params
        });
    }
    variants
}

fn fixture_directory() -> PathBuf {
    std::env::var_os("PREFLATE_DIAGNOSTICS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("target")
                .join("prediction-diagnostics")
        })
}

struct DefaultPredictionDecoder;

impl PredictionDecoder for DefaultPredictionDecoder {
    fn decode_correction(&mut self, _correction: CodecCorrection) -> u32 {
        0
    }

    fn decode_verify_state(&mut self, _message: &'static str, _checksum: u64) {}
}

// Test a hypothetical layout preset: only trailer types and final bits are supplied.
// The data block, including its Huffman tree, is reconstructed with zero corrections.
fn reconstruct_with_empty_tail(
    contents: &DeflateContents,
    plain: &PlainText,
    params: &TokenPredictorParameters,
) -> Result<Option<Vec<u8>>> {
    if !(2..=4).contains(&contents.blocks.len()) {
        return Ok(None);
    }
    let first_type = match &contents.blocks[0].block_type {
        DeflateTokenBlockType::Huffman {
            huffman_type: DeflateHuffmanType::Static,
            ..
        } => BlockTypeStrategy::Static,
        DeflateTokenBlockType::Huffman {
            huffman_type: DeflateHuffmanType::Dynamic { .. },
            ..
        } => BlockTypeStrategy::Dynamic,
        _ => return Ok(None),
    };
    if contents.blocks[0].last
        || contents.blocks[1..]
            .iter()
            .enumerate()
            .any(|(index, block)| {
                block.last != (index + 2 == contents.blocks.len())
                    || match &block.block_type {
                        DeflateTokenBlockType::Stored { uncompressed } => !uncompressed.is_empty(),
                        DeflateTokenBlockType::Huffman {
                            tokens,
                            huffman_type: DeflateHuffmanType::Static,
                        } => !tokens.is_empty(),
                        _ => true,
                    }
            })
    {
        return Ok(None);
    }
    let parameters = TokenPredictorParameters {
        block_type_strategy: first_type,
        ..*params
    };
    let mut input = PreflateInput::new(plain);
    let mut first = TokenPredictor::new(&parameters)
        .recreate_block(&mut DefaultPredictionDecoder, &mut input)?;
    if input.remaining() != 0 {
        return Ok(None);
    }
    first.last = false;
    let mut writer = DeflateWriter::new();
    writer.encode_block(&first)?;
    for block in &contents.blocks[1..] {
        writer.encode_block(block)?;
    }
    writer.flush();
    Ok(Some(writer.detach_output()))
}

#[test]
#[ignore = "release-mode production validation using local Huffman outlier fixtures"]
fn verify_huffman_profile_selection() {
    use std::io::Write;

    let output = std::env::var_os("PREFLATE_HUFFMAN_RESULTS")
        .expect("set PREFLATE_HUFFMAN_RESULTS to a new TSV output file");
    let mut output = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .unwrap(),
    );
    writeln!(
        output,
        "case\tdeflate\tplaintext\tcorrection_bytes\tchunks\tprofile_actions\ttree_actions\tcounts\telapsed_us"
    )
    .unwrap();
    let mut files: Vec<_> = std::fs::read_dir(fixture_directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "deflate"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .deflate fixtures found");
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy();
        let compressed = std::fs::read(&file).unwrap();
        let start = std::time::Instant::now();
        let mut processor = PreflateStreamProcessor::new(&PreflateConfig {
            verify_compression: true,
            plain_text_limit: 32 * 1024 * 1024,
            ..PreflateConfig::default()
        });
        let mut counts = CountNonDefaultActions::default();
        let mut position = 0;
        let mut plaintext = 0;
        let mut bytes = 0;
        let mut chunks = 0;
        while !processor.is_done() {
            let chunk = processor
                .decompress_with_statistics(&compressed[position..], &mut counts)
                .unwrap_or_else(|error| panic!("{name} at {position}: {error:?}"));
            assert!(chunk.compressed_size > 0);
            position += chunk.compressed_size;
            plaintext += processor.plain_text().len();
            bytes += chunk.corrections.len();
            chunks += 1;
            processor.shrink_to_dictionary();
        }
        assert_eq!(position, compressed.len());
        let tree_actions: u32 = [
            CodecCorrection::TreeCodeBitLengthCorrection,
            CodecCorrection::LDTypeCorrection,
            CodecCorrection::RepeatCountCorrection,
            CodecCorrection::LDBitLengthCorrection,
            CodecCorrection::LiteralCountCorrection,
            CodecCorrection::DistanceCountCorrection,
        ]
        .iter()
        .map(|&action| counts.corrections_count[action as usize])
        .sum();
        writeln!(
            output,
            "{name}\t{position}\t{plaintext}\t{bytes}\t{chunks}\t{}\t{tree_actions}\t{:?}\t{}",
            counts.corrections_count[CodecCorrection::TreeProfile as usize],
            counts.corrections_count,
            start.elapsed().as_micros(),
        )
        .unwrap();
        output.flush().unwrap();
    }
}

#[test]
fn selected_huffman_profiles_survive_block_and_chunk_boundaries() {
    use crate::{
        deflate::{deflate_token::TokenFrequency, huffman_calc::HufftreeBitCalc},
        statistical_codec::AssertDefaultOnlyDecoder,
        tree_predictor::recreate_tree_with_rules,
    };

    let mut writer = DeflateWriter::new();
    let mut expected = Vec::new();
    for index in 0..4 {
        let tokens: Vec<_> = (0..96)
            .map(|position| DeflateToken::Literal(b'A' + ((position + index * 3) % 5) as u8))
            .collect();
        let mut freq = TokenFrequency::default();
        for token in &tokens {
            freq.commit_token(token);
            if let DeflateToken::Literal(byte) = token {
                expected.push(*byte);
            }
        }
        let calc = [
            HufftreeBitCalc::Floyd,
            HufftreeBitCalc::Miniz,
            HufftreeBitCalc::ZlibCorrected,
            HufftreeBitCalc::Zlib,
        ][index];
        // The source is allowed to include an unused distance symbol.
        freq.distance_codes[0] = 1;
        let encoding = recreate_tree_with_rules(
            &freq,
            &mut AssertDefaultOnlyDecoder {},
            calc,
            index % 2 == 0,
        )
        .unwrap();
        writer
            .encode_block(&DeflateTokenBlock {
                block_type: DeflateTokenBlockType::Huffman {
                    tokens,
                    huffman_type: DeflateHuffmanType::Dynamic {
                        huffman_encoding: encoding,
                    },
                },
                last: index == 3,
            })
            .unwrap();
    }
    writer.flush();
    let compressed = writer.detach_output();
    let mut processor = PreflateStreamProcessor::new(&PreflateConfig {
        plain_text_limit: 128,
        verify_compression: true,
        ..PreflateConfig::default()
    });
    let mut decoder = RecreateStreamProcessor::new();
    let mut position = 0;
    let mut chunks = 0;
    let mut recreated = Vec::new();
    let mut plaintext = Vec::new();
    while !processor.is_done() {
        let chunk = processor.decompress(&compressed[position..]).unwrap();
        position += chunk.compressed_size;
        let plain = processor.plain_text().text();
        plaintext.extend_from_slice(plain);
        recreated.extend(
            decoder
                .recompress(&mut Cursor::new(plain), &chunk.corrections)
                .unwrap()
                .0,
        );
        processor.shrink_to_dictionary();
        chunks += 1;
    }
    assert_eq!(chunks, 4);
    assert_eq!(plaintext, expected);
    assert_eq!(recreated, compressed);
}

#[test]
fn block_tails_roundtrip_across_chunk_boundaries_and_fallback_layouts() {
    use crate::deflate::deflate_token::TokenFrequency;

    for kind in 0..3 {
        for tail_length in 0..=5 {
            for pattern in 0..1 << tail_length {
                for internal_flush in [false, true] {
                    let mut writer = DeflateWriter::new();
                    let mut expected = Vec::new();
                    for index in 0..3 {
                        let bytes: Vec<_> = (0..96)
                            .map(|pos| b'A' + ((pos + index) % 23) as u8)
                            .collect();
                        expected.extend_from_slice(&bytes);
                        let block_type = if kind == 0 {
                            DeflateTokenBlockType::Stored {
                                uncompressed: bytes,
                            }
                        } else {
                            let tokens: Vec<_> =
                                bytes.into_iter().map(DeflateToken::Literal).collect();
                            let huffman_type = if kind == 1 {
                                DeflateHuffmanType::Static
                            } else {
                                let mut freq = TokenFrequency::default();
                                for token in &tokens {
                                    freq.commit_token(token);
                                }
                                freq.distance_codes[0] = 1;
                                DeflateHuffmanType::Dynamic {
                                huffman_encoding: crate::tree_predictor::recreate_tree_with_rules(
                                    &freq,
                                    &mut crate::statistical_codec::AssertDefaultOnlyDecoder {},
                                    crate::deflate::huffman_calc::HufftreeBitCalc::ZlibCorrected,
                                    true,
                                )
                                .unwrap(),
                            }
                            };
                            DeflateTokenBlockType::Huffman {
                                tokens,
                                huffman_type,
                            }
                        };
                        writer
                            .encode_block(&DeflateTokenBlock {
                                block_type,
                                last: index == 2 && tail_length == 0,
                            })
                            .unwrap();
                        if internal_flush && index < 2 {
                            writer
                                .encode_block(&DeflateTokenBlock {
                                    block_type: DeflateTokenBlockType::Stored {
                                        uncompressed: Vec::new(),
                                    },
                                    last: false,
                                })
                                .unwrap();
                        }
                    }
                    for index in 0..tail_length {
                        writer
                            .encode_block(&DeflateTokenBlock {
                                block_type: if pattern & (1 << index) != 0 {
                                    DeflateTokenBlockType::Stored {
                                        uncompressed: Vec::new(),
                                    }
                                } else {
                                    DeflateTokenBlockType::Huffman {
                                        tokens: Vec::new(),
                                        huffman_type: DeflateHuffmanType::Static,
                                    }
                                },
                                last: index + 1 == tail_length,
                            })
                            .unwrap();
                    }
                    writer.flush();
                    let compressed = writer.detach_output();
                    for limit in [128, 4096] {
                        let mut processor = PreflateStreamProcessor::new(&PreflateConfig {
                            plain_text_limit: limit,
                            verify_compression: true,
                            ..PreflateConfig::default()
                        });
                        let mut decoder = RecreateStreamProcessor::new();
                        let mut position = 0;
                        let mut plaintext = Vec::new();
                        let mut recreated = Vec::new();
                        while !processor.is_done() {
                            let chunk = processor.decompress(&compressed[position..]).unwrap();
                            position += chunk.compressed_size;
                            let plain = processor.plain_text().text();
                            plaintext.extend_from_slice(plain);
                            recreated.extend(
                                decoder
                                    .recompress(&mut Cursor::new(plain), &chunk.corrections)
                                    .unwrap()
                                    .0,
                            );
                            processor.shrink_to_dictionary();
                        }
                        assert_eq!(position, compressed.len());
                        assert_eq!(plaintext, expected);
                        assert_eq!(
                            recreated, compressed,
                            "kind={kind} tail={tail_length}/{pattern} limit={limit} internal={internal_flush}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn legacy_stored_block_lengths_remain_readable() {
    let mut writer = DeflateWriter::new();
    writer
        .encode_block(&DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Stored {
                uncompressed: b"legacy stored block".to_vec(),
            },
            last: true,
        })
        .unwrap();
    writer.flush();
    let compressed = writer.detach_output();
    let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
    let params = estimate_preflate_parameters(&contents, &plain).unwrap();
    let mut bytes = Vec::new();
    let mut encoder = PredictionEncoderCabac::new(VP8Writer::new(&mut bytes).unwrap());
    predict_blocks(
        &contents.blocks,
        &mut TokenPredictor::new_legacy(&params),
        &mut encoder,
        &mut PreflateInput::new(&plain),
    )
    .unwrap();
    encoder.finish();
    drop(encoder);
    let mut corrections = ReconstructionData {
        parameters: params,
        corrections: bytes,
    }
    .write();
    corrections[0] = LEGACY_RECONSTRUCTION_DATA_VERSION;
    assert_eq!(
        recreate_whole_deflate_stream(plain.text(), &corrections).unwrap(),
        compressed
    );
}

#[test]
#[ignore = "offline Huffman investigation; requires local .deflate fixtures"]
fn diagnose_huffman_trees() {
    use crate::{
        deflate::{
            deflate_token::TokenFrequency,
            huffman_calc::{HufftreeBitCalc, calc_bit_lengths},
        },
        statistical_codec::{VerifyPredictionDecoder, VerifyPredictionEncoder},
        tree_predictor::{predict_tree_with_rules, recreate_tree_with_rules},
    };
    use std::io::Write;

    let output = std::env::var_os("PREFLATE_HUFFMAN_RESULTS")
        .expect("set PREFLATE_HUFFMAN_RESULTS to a new TSV output file");
    let mut output = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .unwrap(),
    );
    writeln!(
        output,
        "case\tblock\ttokens\tzlib_counts\tminiz_counts\tliteral_frequencies\tdistance_frequencies\tactual_literals\tactual_distances\tactual_rle\tactual_code_lengths\tactual_code_count\tzlib_literals\tzlib_distances\tzlib_code_lengths\tminiz_literals\tminiz_distances\tminiz_code_lengths\tcorrected_counts\tcorrected_literals\tcorrected_distances\tcorrected_code_lengths\tfloyd_counts\tfloyd_literals\tfloyd_distances\tfloyd_code_lengths\tzlib_split_counts\tminiz_split_counts\tcorrected_split_counts\tfloyd_split_counts"
    )
    .unwrap();
    let mut files: Vec<_> = std::fs::read_dir(fixture_directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "deflate"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .deflate fixtures found");
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy();
        let compressed = std::fs::read(&file).unwrap();
        let (contents, _) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len(), "{name}");
        let mut writer = DeflateWriter::new();
        for (index, block) in contents.blocks.iter().enumerate() {
            let mut reconstructed = None;
            if let DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type: DeflateHuffmanType::Dynamic { huffman_encoding },
            } = &block.block_type
            {
                let mut freq = TokenFrequency::default();
                for token in tokens {
                    freq.commit_token(token);
                }
                let (literal_lengths, distance_lengths) =
                    huffman_encoding.get_literal_distance_lengths();
                let codes: Vec<_> = huffman_encoding
                    .lengths
                    .iter()
                    .map(|&(kind, data)| (kind as u8, data))
                    .collect();
                let mut code_freq = [0u16; 19];
                for &(kind, data) in &huffman_encoding.lengths {
                    let symbol = match kind {
                        crate::deflate::huffman_encoding::TreeCodeType::Code => usize::from(data),
                        crate::deflate::huffman_encoding::TreeCodeType::Repeat => 16,
                        crate::deflate::huffman_encoding::TreeCodeType::ZeroShort => 17,
                        crate::deflate::huffman_encoding::TreeCodeType::ZeroLong => 18,
                    };
                    code_freq[symbol] += 1;
                }
                let mut measurements = Vec::new();
                let mut split_counts = Vec::new();
                for calc in [
                    HufftreeBitCalc::Zlib,
                    HufftreeBitCalc::Miniz,
                    HufftreeBitCalc::ZlibCorrected,
                    HufftreeBitCalc::Floyd,
                ] {
                    let mut count = CountNonDefaultActions::default();
                    let mut encoder = (&mut count, VerifyPredictionEncoder::new());
                    predict_tree_with_rules(huffman_encoding, &freq, &mut encoder, calc, false)
                        .unwrap();
                    let mut decoder = VerifyPredictionDecoder::new(encoder.1.actions());
                    let recreated =
                        recreate_tree_with_rules(&freq, &mut decoder, calc, false).unwrap();
                    assert_eq!(
                        &recreated, huffman_encoding,
                        "{name} block {index} {calc:?}"
                    );
                    reconstructed = Some(DeflateTokenBlock {
                        block_type: DeflateTokenBlockType::Huffman {
                            tokens: tokens.clone(),
                            huffman_type: DeflateHuffmanType::Dynamic {
                                huffman_encoding: recreated,
                            },
                        },
                        last: block.last,
                    });
                    measurements.push((
                        count.corrections_count,
                        calc_bit_lengths(calc, &freq.literal_codes, 15),
                        calc_bit_lengths(calc, &freq.distance_codes, 15),
                        calc_bit_lengths(calc, &code_freq, 7),
                    ));
                    let mut count = CountNonDefaultActions::default();
                    let mut encoder = (&mut count, VerifyPredictionEncoder::new());
                    predict_tree_with_rules(huffman_encoding, &freq, &mut encoder, calc, true)
                        .unwrap();
                    let mut decoder = VerifyPredictionDecoder::new(encoder.1.actions());
                    let recreated =
                        recreate_tree_with_rules(&freq, &mut decoder, calc, true).unwrap();
                    assert_eq!(
                        &recreated, huffman_encoding,
                        "{name} block {index} split {calc:?}"
                    );
                    split_counts.push(count.corrections_count);
                }
                writeln!(
                    output,
                    "{name}\t{index}\t{}\t{:?}\t{:?}\t{:?}\t{:?}\t{literal_lengths:?}\t{distance_lengths:?}\t{codes:?}\t{:?}\t{}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}\t{:?}",
                    tokens.len(),
                    measurements[0].0,
                    measurements[1].0,
                    freq.literal_codes,
                    freq.distance_codes,
                    huffman_encoding.code_lengths,
                    huffman_encoding.num_code_lengths,
                    measurements[0].1,
                    measurements[0].2,
                    measurements[0].3,
                    measurements[1].1,
                    measurements[1].2,
                    measurements[1].3,
                    measurements[2].0,
                    measurements[2].1,
                    measurements[2].2,
                    measurements[2].3,
                    measurements[3].0,
                    measurements[3].1,
                    measurements[3].2,
                    measurements[3].3,
                    split_counts[0],
                    split_counts[1],
                    split_counts[2],
                    split_counts[3],
                )
                .unwrap();
            }
            writer
                .encode_block(reconstructed.as_ref().unwrap_or(block))
                .unwrap();
        }
        writer.flush();
        crate::utils::assert_eq_array(&compressed, &writer.detach_output());
        output.flush().unwrap();
    }
}

#[test]
fn diagnostic_reconstructs_empty_tails_without_corrections() {
    for tail in [
        &[false][..],
        &[false, false],
        &[true, false],
        &[true, true, false],
        &[true],
        &[true, true],
    ] {
        let (_, contents, _) = synthetic_stream(
            b"@0123456789ABCDEF"
                .iter()
                .copied()
                .map(DeflateToken::Literal)
                .collect(),
        );
        let mut blocks = contents.blocks;
        blocks[0].last = false;
        for (index, &stored) in tail.iter().enumerate() {
            blocks.push(DeflateTokenBlock {
                block_type: if stored {
                    DeflateTokenBlockType::Stored {
                        uncompressed: Vec::new(),
                    }
                } else {
                    DeflateTokenBlockType::Huffman {
                        tokens: Vec::new(),
                        huffman_type: DeflateHuffmanType::Static,
                    }
                },
                last: index + 1 == tail.len(),
            });
        }
        let mut writer = DeflateWriter::new();
        for block in &blocks {
            writer.encode_block(block).unwrap();
        }
        writer.flush();
        let compressed = writer.detach_output();
        let (mut contents, plain) = parse_deflate_whole(&compressed).unwrap();
        let params = synthetic_params();
        let baseline = measure(&contents, &plain, &params).unwrap();
        assert_eq!(
            baseline.count.total_non_default, 1,
            "{tail:?}: {:?}",
            baseline.count.corrections_count
        );
        assert_eq!(
            baseline.count.corrections_count[CodecCorrection::BlockTypeCorrection as usize],
            1
        );
        verify(&baseline, &plain, &compressed);
        assert_eq!(
            reconstruct_with_empty_tail(&contents, &plain, &params)
                .unwrap()
                .unwrap(),
            compressed,
        );
        contents.blocks[1].block_type = DeflateTokenBlockType::Huffman {
            tokens: vec![DeflateToken::Literal(b'X')],
            huffman_type: DeflateHuffmanType::Static,
        };
        assert!(
            reconstruct_with_empty_tail(&contents, &plain, &params)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
#[ignore = "offline tiny-stream investigation; requires local .deflate fixtures"]
fn diagnose_tiny_streams() {
    use std::io::Write;

    let output = std::env::var_os("PREFLATE_TINY_RESULTS")
        .expect("set PREFLATE_TINY_RESULTS to a new TSV output file");
    let mut output = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .unwrap(),
    );
    writeln!(
        output,
        "case\tdeflate\tplaintext\tlayout\tbaseline_bytes\tbaseline_cabac\tbaseline_actions\tbaseline_counts\tbaseline_params\tbest_bytes\tbest_cabac\tbest_actions\tbest_counts\tbest_params\ttrials\trejected\tbaseline_tail_zero\tbest_tail_zero"
    )
    .unwrap();
    let mut files: Vec<_> = std::fs::read_dir(fixture_directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "deflate"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .deflate fixtures found");
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy();
        let compressed = std::fs::read(&file).unwrap();
        assert!(compressed.len() < 1024, "{name}: not a tiny stream");
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len(), "{name}");
        let params = estimate_preflate_parameters(&contents, &plain).unwrap();
        let baseline = measure(&contents, &plain, &params).unwrap();
        verify(&baseline, &plain, &compressed);
        let layout: Vec<_> = contents
            .blocks
            .iter()
            .map(|block| {
                let (kind, size) = match &block.block_type {
                    DeflateTokenBlockType::Stored { uncompressed } => {
                        ("stored", uncompressed.len())
                    }
                    DeflateTokenBlockType::Huffman {
                        tokens,
                        huffman_type,
                    } => (
                        match huffman_type {
                            DeflateHuffmanType::Static => "static",
                            DeflateHuffmanType::Dynamic { .. } => "dynamic",
                        },
                        tokens.len(),
                    ),
                };
                format!("{kind}:{size}:{}", block.last)
            })
            .collect();
        let baseline_fields = format!(
            "{}\t{}\t{}\t{:?}\t{params:?}",
            baseline.corrections.len(),
            baseline.cabac_size,
            baseline.count.total_non_default,
            baseline.count.corrections_count,
        );
        let has_token_corrections = [
            CodecCorrection::LenCorrection,
            CodecCorrection::DistOnlyCorrection,
            CodecCorrection::DistAfterLenCorrection,
            CodecCorrection::LiteralPredictionWrong,
            CodecCorrection::ReferencePredictionWrong,
        ]
        .iter()
        .any(|&action| baseline.count.corrections_count[action as usize] != 0);
        let mut candidates = Vec::new();
        if has_token_corrections {
            let observed_min_len = extract_preflate_info(&contents.blocks).min_len;
            candidates = parameter_variants(params, observed_min_len, false);
            for (hash_mask, hash_shift) in [(511, 3), (2047, 4), (32767, 5)] {
                for settings in
                    crate::estimator::preflate_parse_config::ZLIB_PREFLATE_PARSER_SETTINGS
                        .iter()
                        .chain(SLOW_PREFLATE_PARSER_SETTINGS.iter())
                {
                    for min_len in [3, observed_min_len] {
                        let candidate = TokenPredictorParameters {
                            hash_algorithm: HashAlgorithm::Zlib {
                                hash_mask,
                                hash_shift,
                            },
                            matching_type: settings.match_type,
                            add_policy: settings.dictionary_add_policy,
                            nice_length: settings.nice_length,
                            max_chain: settings.max_chain,
                            window_bits: 15,
                            very_far_matches_detected: false,
                            ..params
                        }
                        .with_lazy_behavior(true, min_len);
                        if candidate != params && !candidates.contains(&candidate) {
                            candidates.push(candidate);
                        }
                    }
                }
            }
        }
        let trials = candidates.len();
        let mut rejected = 0;
        let mut best = baseline;
        let mut best_params = params;
        for candidate in candidates {
            match measure(&contents, &plain, &candidate) {
                Ok(measurement) => {
                    if (
                        measurement.count.total_non_default,
                        measurement.corrections.len(),
                    ) < (best.count.total_non_default, best.corrections.len())
                    {
                        verify(&measurement, &plain, &compressed);
                        best = measurement;
                        best_params = candidate;
                    }
                }
                Err(error) => {
                    rejected += 1;
                    println!("REJECTED {name}: {candidate:?}: {error:?}");
                }
            }
        }
        let baseline_tail_zero = reconstruct_with_empty_tail(&contents, &plain, &params)
            .unwrap()
            .is_some_and(|recreated| recreated == compressed);
        let best_tail_zero = reconstruct_with_empty_tail(&contents, &plain, &best_params)
            .unwrap()
            .is_some_and(|recreated| recreated == compressed);
        writeln!(
            output,
            "{name}\t{}\t{}\t{}\t{baseline_fields}\t{}\t{}\t{}\t{:?}\t{best_params:?}\t{trials}\t{rejected}\t{baseline_tail_zero}\t{best_tail_zero}",
            compressed.len(),
            plain.len(),
            layout.join(","),
            best.corrections.len(),
            best.cabac_size,
            best.count.total_non_default,
            best.count.corrections_count,
        )
        .unwrap();
        output.flush().unwrap();
    }
}

#[test]
#[ignore = "offline PDF overhead investigation; requires local .deflate fixtures"]
fn diagnose_pdf_overhead() {
    use std::io::Write;

    let probes: std::collections::BTreeSet<_> = std::env::var_os("PREFLATE_PDF_PROBES")
        .map(|value| {
            value
                .into_string()
                .expect("PREFLATE_PDF_PROBES must be valid Unicode")
        })
        .unwrap_or_default()
        .split(',')
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect();
    let mut remaining_probes = probes.clone();
    let path = std::env::var_os("PREFLATE_PDF_RESULTS")
        .expect("set PREFLATE_PDF_RESULTS to a new TSV output file");
    let mut output = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap(),
    );
    writeln!(output, "case\tdeflate\tplaintext\tblocks\tbytes\tcabac\tframing\tparameter_bytes\ttokens\tmismatches\treferences\tdistance_one\tmax_distance\tcounts\tprofile\tparams\ttrials\trejected\tbest_bytes\tbest_mismatches\tbest_counts\tbest_params").unwrap();
    let mut files: Vec<_> = std::fs::read_dir(fixture_directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "deflate"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .deflate fixtures found");
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy();
        let compressed = std::fs::read(&file).unwrap();
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len(), "{name}");
        let params = estimate_preflate_parameters(&contents, &plain).unwrap();
        let baseline = measure(&contents, &plain, &params).unwrap();
        verify(&baseline, &plain, &compressed);
        let mut references = 0;
        let mut distance_one = 0;
        let mut max_distance = 0;
        for block in &contents.blocks {
            if let DeflateTokenBlockType::Huffman { tokens, .. } = &block.block_type {
                for token in tokens {
                    if let DeflateToken::Reference(reference) = token {
                        references += 1;
                        distance_one += usize::from(reference.dist() == 1);
                        max_distance = max_distance.max(reference.dist());
                    }
                }
            }
        }
        let mut trials = 0;
        let mut rejected = 0;
        let mut best = None;
        let mut best_params = params;
        if remaining_probes.remove(name.as_ref()) {
            let baseline_score = TokenPredictor::new(&params)
                .score_predictions(&contents.blocks, &plain, 4096, 524288)
                .0;
            let observed_min_len = extract_preflate_info(&contents.blocks).min_len;
            let mut candidates: Vec<_> = pdf_parameter_variants(params, observed_min_len)
                .into_iter()
                .map(|candidate| {
                    let score = TokenPredictor::new(&candidate)
                        .score_predictions(&contents.blocks, &plain, 4096, 524288)
                        .0;
                    (score, candidate)
                })
                .filter(|(score, _)| *score <= baseline_score)
                .collect();
            candidates.sort_by_key(|(score, _)| *score);
            let mut families = Vec::new();
            for (_, candidate) in candidates {
                let family = (candidate.hash_algorithm, candidate.matching_type);
                if families.contains(&family) {
                    continue;
                }
                families.push(family);
                trials += 1;
                let trial = match measure(&contents, &plain, &candidate) {
                    Ok(trial) => trial,
                    Err(error)
                        if matches!(
                            error.exit_code(),
                            ExitCode::PredictionFailure | ExitCode::MatchNotFound
                        ) =>
                    {
                        rejected += 1;
                        eprintln!("{name}: rejected {candidate:?}: {error:?}");
                        if trials == 8 {
                            break;
                        }
                        continue;
                    }
                    Err(error) => panic!("{name}: {candidate:?}: {error:?}"),
                };
                verify(&trial, &plain, &compressed);
                if trial.corrections.len() < best.as_ref().unwrap_or(&baseline).corrections.len() {
                    best = Some(trial);
                    best_params = candidate;
                }
                if trials == 8 {
                    break;
                }
            }
        }
        let best = best.as_ref().unwrap_or(&baseline);
        writeln!(
            output,
            "{name}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{references}\t{distance_one}\t{max_distance}\t{:?}\t{}\t{params:?}\t{trials}\t{rejected}\t{}\t{}\t{:?}\t{best_params:?}",
            compressed.len(), plain.len(), contents.blocks.len(), baseline.corrections.len(),
            baseline.cabac_size, baseline.corrections.len() - baseline.cabac_size,
            bitcode::encode(&params).len(), baseline.trace.token_count,
            baseline.trace.mismatch_count, baseline.count.corrections_count,
            baseline.trace.block_profile,
            best.corrections.len(), best.trace.mismatch_count, best.count.corrections_count,
        ).unwrap();
        output.flush().unwrap();
    }
    assert!(
        remaining_probes.is_empty(),
        "missing PDF probe fixtures: {remaining_probes:?}"
    );
}

#[test]
#[ignore = "offline bounded family-profile investigation; requires local .deflate fixtures"]
fn diagnose_fixed_family_profiles() {
    use std::io::Write;

    let filter = std::env::var("PREFLATE_DIAGNOSTICS_FILTER").unwrap_or_default();
    let path = std::env::var_os("PREFLATE_FAMILY_RESULTS")
        .expect("set PREFLATE_FAMILY_RESULTS to a new TSV output file");
    let mut output = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap(),
    );
    writeln!(
        output,
        "case\ttrial\tbytes\tcabac\tmismatches\tprefix_errors\tprefix_tokens\tparams\terror"
    )
    .unwrap();
    let mut files: Vec<_> = std::fs::read_dir(fixture_directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "deflate"))
        .collect();
    files.sort();
    files.retain(|file| {
        file.file_stem()
            .unwrap()
            .to_string_lossy()
            .contains(&filter)
    });
    assert!(!files.is_empty(), "no .deflate fixtures matched");
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy();
        let compressed = std::fs::read(&file).unwrap();
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len());
        let params = estimate_preflate_parameters(&contents, &plain).unwrap();
        let mut lengths = std::collections::BTreeMap::<u32, usize>::new();
        for block in &contents.blocks {
            if let DeflateTokenBlockType::Huffman { tokens, .. } = &block.block_type {
                for token in tokens {
                    if let DeflateToken::Reference(reference) = token {
                        *lengths.entry(reference.len()).or_default() += 1;
                    }
                }
            }
        }
        println!("{name}: reference_lengths={lengths:?}");
        let mut candidates = vec![params];
        if matches!(params.hash_algorithm, HashAlgorithm::Zlib { .. }) {
            for config in SLOW_PREFLATE_PARSER_SETTINGS {
                for filtered in [false, true] {
                    let mut matching_type = config.match_type;
                    if let MatchingType::Lazy {
                        filtered_matching, ..
                    } = &mut matching_type
                    {
                        *filtered_matching = filtered;
                    }
                    candidates.push(TokenPredictorParameters {
                        matching_type,
                        nice_length: config.nice_length,
                        max_chain: config.max_chain,
                        ..params
                    });
                }
            }
            candidates.push(TokenPredictorParameters {
                matching_type: MatchingType::Greedy,
                ..params
            });
            candidates.push(TokenPredictorParameters {
                matching_type: MatchingType::Lazy {
                    max_lazy: 258,
                    filtered_matching: false,
                    behavior: LazyBehavior::RecomputeAfterLiteral,
                },
                ..params
            });
            for max_probes in [32, 128, 512, 1500] {
                for greedy in [false, true] {
                    candidates.push(TokenPredictorParameters {
                        matching_type: MatchingType::MiniZ { max_probes, greedy },
                        max_chain: u32::from(max_probes).div_ceil(3) * 3,
                        ..params
                    });
                }
            }
        } else {
            for hash_algorithm in [params.hash_algorithm, HashAlgorithm::RandomVector] {
                for filtered_matching in [false, true] {
                    candidates.push(TokenPredictorParameters {
                        hash_algorithm,
                        matching_type: MatchingType::Lazy {
                            max_lazy: 16,
                            filtered_matching,
                            behavior: LazyBehavior::RecomputeAfterLiteral,
                        },
                        ..params
                    });
                }
            }
            for (max_chain, nice_length, matching_type) in [
                (17, 30, MatchingType::LibdeflateGreedy),
                (
                    17,
                    30,
                    MatchingType::LibdeflateLazy {
                        two_positions: false,
                    },
                ),
                (
                    36,
                    65,
                    MatchingType::LibdeflateLazy {
                        two_positions: false,
                    },
                ),
                (
                    101,
                    130,
                    MatchingType::LibdeflateLazy {
                        two_positions: false,
                    },
                ),
                (
                    301,
                    258,
                    MatchingType::LibdeflateLazy {
                        two_positions: true,
                    },
                ),
                (
                    601,
                    258,
                    MatchingType::LibdeflateLazy {
                        two_positions: true,
                    },
                ),
            ] {
                candidates.push(TokenPredictorParameters {
                    hash_algorithm: HashAlgorithm::Libdeflate4,
                    matching_type,
                    max_chain,
                    nice_length,
                    max_dist_3_matches: 4096,
                    ..params
                });
            }
        }
        for (index, candidate) in candidates.iter().enumerate() {
            if candidates[..index].contains(candidate) {
                continue;
            }
            let (prefix_errors, prefix_tokens) = TokenPredictor::new(candidate).score_predictions(
                &contents.blocks,
                &plain,
                1024,
                262144,
            );
            match measure(&contents, &plain, candidate) {
                Ok(measurement) => {
                    verify(&measurement, &plain, &compressed);
                    println!("{name}: trial={index} params={candidate:?}");
                    print_measurement("VERIFIED", &measurement, compressed.len());
                    print_details(&measurement);
                    writeln!(
                        output,
                        "{name}\t{index}\t{}\t{}\t{}\t{prefix_errors}\t{prefix_tokens}\t{candidate:?}\t",
                        measurement.corrections.len(),
                        measurement.cabac_size,
                        measurement.trace.mismatch_count,
                    )
                    .unwrap();
                }
                Err(error)
                    if matches!(
                        error.exit_code(),
                        ExitCode::PredictionFailure | ExitCode::MatchNotFound
                    ) =>
                {
                    writeln!(
                        output,
                        "{name}\t{index}\t\t\t\t{prefix_errors}\t{prefix_tokens}\t{candidate:?}\t{error:?}"
                    )
                    .unwrap();
                }
                Err(error) => panic!("{name}: {candidate:?}: {error:?}"),
            }
            output.flush().unwrap();
        }
    }
}

#[test]
#[ignore = "offline residual classification; requires selected raw .deflate fixtures"]
fn diagnose_prediction_residual_shapes() {
    let filter = std::env::var("PREFLATE_DIAGNOSTICS_FILTER").unwrap_or_default();
    let mut matched = 0;
    for entry in std::fs::read_dir(fixture_directory()).unwrap() {
        let file = entry.unwrap().path();
        if !file.extension().is_some_and(|ext| ext == "deflate") {
            continue;
        }
        let name = file.file_stem().unwrap().to_string_lossy();
        if !name.contains(&filter) {
            continue;
        }
        matched += 1;
        let compressed = std::fs::read(&file).unwrap();
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len());
        let estimated = estimate_preflate_parameters(&contents, &plain).unwrap();
        let params = if matches!(estimated.hash_algorithm, HashAlgorithm::Zlib { .. }) {
            estimated
        } else {
            TokenPredictorParameters {
                hash_algorithm: HashAlgorithm::Libdeflate4,
                matching_type: MatchingType::LibdeflateLazy {
                    two_positions: false,
                },
                nice_length: 130,
                max_chain: 101,
                max_dist_3_matches: 4096,
                ..estimated
            }
        };
        let measurement =
            measure_with_tracking(&contents, &plain, &params, false, false, 1_000_000).unwrap();
        verify(&measurement, &plain, &compressed);
        assert_eq!(
            measurement.trace.first_mismatches.len(),
            measurement.trace.mismatch_count,
            "{name}: residual sample truncated"
        );
        let mut lengths = std::collections::BTreeMap::<(u32, u32), usize>::new();
        let length = |token: &DeflateToken| match token {
            DeflateToken::Literal(_) => 0,
            DeflateToken::Reference(reference) => reference.len(),
        };
        for (_, actual, predicted) in &measurement.trace.first_mismatches {
            *lengths
                .entry((length(actual), length(predicted)))
                .or_default() += 1;
        }
        let mut ranked: Vec<_> = lengths.into_iter().collect();
        ranked.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        println!("{name}: params={params:?}");
        print_measurement("RESIDUAL", &measurement, compressed.len());
        println!(
            "Residual length pairs (actual,predicted; zero means literal): {:?}",
            &ranked[..ranked.len().min(12)]
        );
        for (offset, actual, predicted) in measurement.trace.first_mismatches.iter().take(8) {
            println!(
                "  offset={offset} actual_length={} predicted_length={}",
                length(actual),
                length(predicted)
            );
        }
        let mut probes = Vec::new();
        if matches!(params.hash_algorithm, HashAlgorithm::Zlib { .. }) {
            for cutoff in [0, 16, 64, 256, 1024] {
                probes.push(TokenPredictorParameters {
                    max_dist_3_matches: cutoff,
                    ..params
                });
            }
        } else {
            for max_chain in [99, 100, 101, 102] {
                for nice_length in [128, 130] {
                    probes.push(TokenPredictorParameters {
                        max_chain,
                        nice_length,
                        ..params
                    });
                }
            }
        }
        for candidate in probes {
            let trial = measure(&contents, &plain, &candidate).unwrap();
            verify(&trial, &plain, &compressed);
            println!(
                "NEIGHBOR {name}: chain={} nice={} cutoff={} bytes={} mismatches={}",
                candidate.max_chain,
                candidate.nice_length,
                candidate.max_dist_3_matches,
                trial.corrections.len(),
                trial.trace.mismatch_count,
            );
        }
    }
    assert!(matched > 0, "no .deflate fixtures matched");
}

#[test]
fn sparse_short_references_select_suppression_and_round_trip() {
    let original = crate::utils::read_file("compressed_zlib_level6.deflate");
    let (contents, plain) = parse_deflate_whole(&original).unwrap();
    let original_info = extract_preflate_info(&contents.blocks);
    let short_budget = (original_info.reference_count / 1024).min(64);
    let mut prefix = Vec::new();
    for suffix in 0..64 {
        prefix.extend_from_slice(b"abc");
        prefix.push(suffix);
    }
    prefix.extend_from_slice(b"qrs0qrs1");
    let mut prefix_tokens: Vec<_> = prefix.into_iter().map(DeflateToken::Literal).collect();
    prefix_tokens.push(DeflateToken::new_ref(3, 8));
    prefix_tokens.push(DeflateToken::Literal(b'!'));
    let mut writer = DeflateWriter::new();
    writer
        .encode_block(&DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens: prefix_tokens,
                huffman_type: DeflateHuffmanType::Static,
            },
            last: false,
        })
        .unwrap();
    let mut position = 0;
    let mut kept_short = 1;
    for block in contents.blocks {
        let block_type = match block.block_type {
            DeflateTokenBlockType::Stored { uncompressed } => {
                position += uncompressed.len();
                DeflateTokenBlockType::Stored { uncompressed }
            }
            DeflateTokenBlockType::Huffman { tokens, .. } => {
                let mut filtered = Vec::new();
                for token in tokens {
                    match token {
                        DeflateToken::Reference(reference) => {
                            if reference.len() == 3 && kept_short >= short_budget {
                                filtered.extend(
                                    plain.text()[position..position + 3]
                                        .iter()
                                        .copied()
                                        .map(DeflateToken::Literal),
                                );
                            } else {
                                kept_short += u32::from(reference.len() == 3);
                                filtered.push(token);
                            }
                            position += reference.len() as usize;
                        }
                        DeflateToken::Literal(_) => {
                            filtered.push(token);
                            position += 1;
                        }
                    }
                }
                DeflateTokenBlockType::Huffman {
                    tokens: filtered,
                    huffman_type: DeflateHuffmanType::Static,
                }
            }
        };
        writer
            .encode_block(&DeflateTokenBlock {
                block_type,
                last: block.last,
            })
            .unwrap();
    }
    assert!(kept_short > 0);
    writer.flush();
    let compressed = writer.detach_output();
    let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
    let info = extract_preflate_info(&contents.blocks);
    assert_eq!(info.short_reference_count, kept_short);
    assert!(
        info.reference_count >= 4096,
        "references={}",
        info.reference_count
    );
    let params = estimate_preflate_parameters(&contents, &plain).unwrap();
    assert_eq!(params.max_dist_3_matches, 0, "{params:?}");
    let measurement = measure(&contents, &plain, &params).unwrap();
    verify(&measurement, &plain, &compressed);
    let baseline = measure(
        &contents,
        &plain,
        &TokenPredictorParameters {
            max_dist_3_matches: info.max_dist_3_matches,
            ..params
        },
    )
    .unwrap();
    verify(&baseline, &plain, &compressed);
    assert!(
        measurement.corrections.len() < baseline.corrections.len(),
        "{} >= {}",
        measurement.corrections.len(),
        baseline.corrections.len(),
    );
    let (production, plaintext) =
        preflate_whole_deflate_stream(&compressed, &PreflateConfig::default()).unwrap();
    assert_eq!(production.parameters.unwrap().max_dist_3_matches, 0);
    assert_eq!(
        recreate_whole_deflate_stream(plaintext.text(), &production.corrections).unwrap(),
        compressed,
    );
}

#[test]
#[ignore = "offline short-match policy investigation; requires selected raw .deflate fixtures"]
fn diagnose_short_match_policy() {
    let filter = std::env::var("PREFLATE_DIAGNOSTICS_FILTER").unwrap_or_default();
    let mut matched = 0;
    for entry in std::fs::read_dir(fixture_directory()).unwrap() {
        let file = entry.unwrap().path();
        if !file.extension().is_some_and(|ext| ext == "deflate") {
            continue;
        }
        let name = file.file_stem().unwrap().to_string_lossy();
        if !name.contains(&filter) {
            continue;
        }
        matched += 1;
        let compressed = std::fs::read(&file).unwrap();
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len());
        let params = estimate_preflate_parameters(&contents, &plain).unwrap();
        let mut lengths = std::collections::BTreeMap::<u32, usize>::new();
        let short_disabled = TokenPredictorParameters {
            max_dist_3_matches: 0,
            ..params
        };
        let residual =
            measure_with_tracking(&contents, &plain, &short_disabled, false, false, 1_000_000)
                .unwrap();
        verify(&residual, &plain, &compressed);
        let missed_references: std::collections::BTreeMap<_, _> = residual
            .trace
            .first_mismatches
            .iter()
            .filter_map(|(offset, actual, predicted)| match (actual, predicted) {
                (DeflateToken::Reference(reference), DeflateToken::Literal(_)) => {
                    Some((*offset, *reference))
                }
                _ => None,
            })
            .take(8)
            .collect();
        let mut short_distances = std::collections::BTreeMap::<u32, usize>::new();
        let mut short_blocks = Vec::new();
        let mut short_extendable = 0;
        let mut short_window_tail = 0;
        let mut short_at_head = 0;
        let mut literal_run_samples = 0;
        let mut rejected_short_heads = 0;
        let mut state = crate::hash_chain_holder::new_hash_chain_holder(&params);
        let mut input = PreflateInput::new(&plain);
        let mut position = 0;
        for (index, block) in contents.blocks.iter().enumerate() {
            let mut short_count = 0;
            match &block.block_type {
                DeflateTokenBlockType::Stored { uncompressed } => {
                    position += uncompressed.len() as u32;
                    for batch in uncompressed.chunks(258) {
                        state.update_hash(batch.len() as u32, &input);
                        input.advance(batch.len() as u32);
                    }
                }
                DeflateTokenBlockType::Huffman { tokens, .. } => {
                    for (token_index, token) in tokens.iter().enumerate() {
                        match token {
                            DeflateToken::Literal(_) => {
                                if literal_run_samples < 256
                                    && matches!(
                                        tokens.get(token_index + 1),
                                        Some(DeflateToken::Literal(_))
                                    )
                                    && matches!(
                                        tokens.get(token_index + 2),
                                        Some(DeflateToken::Literal(_))
                                    )
                                {
                                    literal_run_samples += 1;
                                    if matches!(
                                        state.match_token_0(2, 1, &input),
                                        crate::hash_chain_holder::MatchResult::Success(head)
                                            if head.len() == 3 && head.dist() <= params.max_dist_3_matches
                                    ) {
                                        rejected_short_heads += 1;
                                    }
                                }
                                position += 1;
                                state.update_hash(1, &input);
                                input.advance(1);
                            }
                            DeflateToken::Reference(reference) => {
                                if missed_references.contains_key(&position) {
                                    println!(
                                        "SHORT_MISS {name}: offset={position} actual={reference:?} current={:?} full={:?}",
                                        state.match_token_0(0, params.max_chain, &input),
                                        state.match_token_0(0, 65535, &input),
                                    );
                                }
                                *lengths.entry(reference.len()).or_default() += 1;
                                if reference.len() == 3 {
                                    short_count += 1;
                                    if matches!(
                                        state.match_token_0(2, 1, &input),
                                        crate::hash_chain_holder::MatchResult::Success(head)
                                            if head == *reference
                                    ) {
                                        short_at_head += 1;
                                    }
                                    if position as usize + 3 < plain.len()
                                        && plain.text()[position as usize + 3]
                                            == plain.text()
                                                [(position - reference.dist()) as usize + 3]
                                    {
                                        short_extendable += 1;
                                    }
                                    if position % 32768 >= 32768 - 262 {
                                        short_window_tail += 1;
                                    }
                                    *short_distances
                                        .entry(reference.dist().next_power_of_two())
                                        .or_default() += 1;
                                }
                                position += reference.len();
                                state.update_hash(reference.len(), &input);
                                input.advance(reference.len());
                            }
                        }
                    }
                }
            }
            if short_count > 0 {
                short_blocks.push((index, short_count, position));
            }
        }
        assert_eq!(position as usize, plain.len());
        println!(
            "SHORT {name}: lengths_3_to_10={:?} distances_3={short_distances:?} extendable_3={short_extendable} window_tail_3={short_window_tail} head_3={short_at_head} run_samples={literal_run_samples} rejected_heads={rejected_short_heads} blocks_with_3={} first_blocks={:?}",
            lengths.range(3..=10).collect::<Vec<_>>(),
            short_blocks.len(),
            &short_blocks[..short_blocks.len().min(12)],
        );
        let level8 = &SLOW_PREFLATE_PARSER_SETTINGS[4];
        let mut candidates = vec![
            params,
            short_disabled,
            TokenPredictorParameters {
                matching_type: level8.match_type,
                max_chain: level8.max_chain,
                nice_length: level8.nice_length,
                ..short_disabled
            },
            TokenPredictorParameters {
                max_chain: 1024,
                matching_type: MatchingType::Lazy {
                    max_lazy: 16,
                    filtered_matching: false,
                    behavior: LazyBehavior::Zlib { good_length: 8 },
                },
                ..short_disabled
            },
        ];
        for limit in [30, 32, 64] {
            for base in [params, candidates[3]] {
                for cutoff in [0, params.max_dist_3_matches] {
                    candidates.push(TokenPredictorParameters {
                        add_policy: DictionaryAddPolicy::AddFirst(limit),
                        max_dist_3_matches: cutoff,
                        ..base
                    });
                }
            }
            for nice_length in [32, 64, 128] {
                candidates.push(TokenPredictorParameters {
                    nice_length,
                    ..params
                });
            }
            for config in &SLOW_PREFLATE_PARSER_SETTINGS[2..5] {
                candidates.push(TokenPredictorParameters {
                    nice_length: 128,
                    matching_type: config.match_type,
                    ..params
                });
            }
        }
        let four_byte_config = SLOW_PREFLATE_PARSER_SETTINGS
            .iter()
            .find(|config| config.max_chain == 128)
            .unwrap();
        for hash_algorithm in [
            HashAlgorithm::Libdeflate4,
            HashAlgorithm::Chromium { hash_mask: 0x7fff },
        ] {
            candidates.extend(sweep_neighborhood(TokenPredictorParameters {
                hash_algorithm,
                matching_type: four_byte_config.match_type,
                max_chain: four_byte_config.max_chain,
                nice_length: four_byte_config.nice_length,
                add_policy: DictionaryAddPolicy::AddAll,
                max_dist_3_matches: 0,
                ..params
            }));
        }
        let mut measured = std::collections::HashSet::new();
        for candidate in candidates {
            if !measured.insert(bitcode::encode(&candidate)) {
                continue;
            }
            let trial =
                match measure_with_tracking(&contents, &plain, &candidate, false, false, 1_000_000)
                {
                    Ok(trial) => trial,
                    Err(error)
                        if matches!(
                            error.exit_code(),
                            ExitCode::MatchNotFound | ExitCode::PredictionFailure
                        ) =>
                    {
                        println!("SHORT_REJECTED {name}: params={candidate:?} error={error:?}");
                        continue;
                    }
                    Err(error) => panic!("{name}: {candidate:?}: {error:?}"),
                };
            verify(&trial, &plain, &compressed);
            let length = |token: &DeflateToken| match token {
                DeflateToken::Literal(_) => 0,
                DeflateToken::Reference(reference) => reference.len(),
            };
            let mut pairs = std::collections::BTreeMap::<(u32, u32), usize>::new();
            for (_, actual, predicted) in &trial.trace.first_mismatches {
                *pairs
                    .entry((length(actual), length(predicted)))
                    .or_default() += 1;
            }
            let mut ranked: Vec<_> = pairs.into_iter().collect();
            ranked.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
            let first: Vec<_> = trial
                .trace
                .first_mismatches
                .iter()
                .take(8)
                .map(|(offset, actual, predicted)| {
                    let distance = |token: &DeflateToken| match token {
                        DeflateToken::Literal(_) => 0,
                        DeflateToken::Reference(reference) => reference.dist(),
                    };
                    (
                        *offset,
                        length(actual),
                        distance(actual),
                        length(predicted),
                        distance(predicted),
                    )
                })
                .collect();
            println!(
                "SHORT_TRIAL {name}: bytes={} mismatches={} params={candidate:?} pairs={:?} first={first:?}",
                trial.corrections.len(),
                trial.trace.mismatch_count,
                &ranked[..ranked.len().min(10)],
            );
        }
    }
    assert!(matched > 0, "no .deflate fixtures matched");
}

#[test]
#[ignore = "offline Chromium hash/profile comparison; requires selected raw .deflate fixtures"]
fn diagnose_chromium_profiles() {
    let filter = std::env::var("PREFLATE_DIAGNOSTICS_FILTER").unwrap_or_default();
    let mut matched = 0;
    for entry in std::fs::read_dir(fixture_directory()).unwrap() {
        let file = entry.unwrap().path();
        if !file.extension().is_some_and(|ext| ext == "deflate") {
            continue;
        }
        let name = file.file_stem().unwrap().to_string_lossy();
        if !name.contains(&filter) {
            continue;
        }
        matched += 1;
        let compressed = std::fs::read(&file).unwrap();
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len());
        let baseline = estimate_preflate_parameters(&contents, &plain).unwrap();
        for hash_mask in [0x7fff, 0xffff] {
            for config in &SLOW_PREFLATE_PARSER_SETTINGS {
                let parameters = TokenPredictorParameters {
                    hash_algorithm: HashAlgorithm::Chromium { hash_mask },
                    matching_type: config.match_type,
                    nice_length: config.nice_length,
                    max_chain: config.max_chain,
                    add_policy: DictionaryAddPolicy::AddAll,
                    max_dist_3_matches: 4096,
                    ..baseline
                };
                let trial =
                    match measure_with_tracking(&contents, &plain, &parameters, false, false, 4096)
                    {
                        Ok(trial) => trial,
                        Err(error)
                            if matches!(
                                error.exit_code(),
                                ExitCode::MatchNotFound | ExitCode::PredictionFailure
                            ) =>
                        {
                            println!(
                                "CHROMIUM_REJECTED {name}: params={parameters:?} error={error:?}"
                            );
                            continue;
                        }
                        Err(error) => panic!("{name}: {parameters:?}: {error:?}"),
                    };
                verify(&trial, &plain, &compressed);
                let shape = |token: DeflateToken| match token {
                    DeflateToken::Literal(_) => (0, 0),
                    DeflateToken::Reference(reference) => (reference.len(), reference.dist()),
                };
                let first: Vec<_> = trial
                    .trace
                    .first_mismatches
                    .iter()
                    .take(8)
                    .map(|&(offset, actual, predicted)| (offset, shape(actual), shape(predicted)))
                    .collect();
                println!(
                    "CHROMIUM {name}: bytes={} mismatches={} params={parameters:?} first={first:?}",
                    trial.corrections.len(),
                    trial.trace.mismatch_count
                );
            }
        }
    }
    assert!(matched > 0, "no .deflate fixtures matched");
}

#[test]
#[ignore = "offline three-byte insertion audit; requires PREFLATE_REFERENCE"]
fn diagnose_three_byte_backup_insertion() {
    use crate::{
        hash_algorithm::{
            HashImplementation, LibdeflateHash3Secondary, RandomVectorHash, ZlibRotatingHashFixed,
        },
        hash_chain::{HashChain, HashChainDefault},
    };

    fn audit<H: HashImplementation + Copy>(
        name: &str,
        hash: H,
        contents: &DeflateContents,
        plain: &PlainText,
    ) {
        let policies = [
            ("all", DictionaryAddPolicy::AddAll, false),
            ("token_starts", DictionaryAddPolicy::AddFirst(1), false),
            ("literals_only", DictionaryAddPolicy::AddAll, true),
            (
                "first_and_last",
                DictionaryAddPolicy::AddFirstAndLast(1),
                false,
            ),
            ("first_four", DictionaryAddPolicy::AddFirst(4), false),
            ("first_eight", DictionaryAddPolicy::AddFirst(8), false),
        ];
        let mut chains = policies.map(|_| HashChainDefault::new(hash));
        let mut counts = [[0usize; 4]; 6];
        let mut previous_context = [0usize; 8];
        let mut short_previous_context = [0usize; 8];
        let mut short_next_bit_matches = [0usize; 8];
        let mut short_next_pairs = std::collections::BTreeSet::new();
        let mut short_next_zeroes = [0usize; 2];
        let mut context_references = 0;
        let mut short_context_references = 0;
        let mut input = PreflateInput::new(plain);
        let mut visit = |token: DeflateToken| {
            if let DeflateToken::Reference(reference) = token {
                if input.bytes_before() > reference.dist() {
                    context_references += 1;
                    short_context_references += usize::from(reference.len() == 3);
                    let difference =
                        input.cur_char(-1) ^ input.cur_char(-(reference.dist() as i32) - 1);
                    for bits in 1..=8 {
                        let matches = u32::from(difference) & ((1 << bits) - 1) == 0;
                        previous_context[bits - 1] += usize::from(matches);
                        short_previous_context[bits - 1] +=
                            usize::from(matches && reference.len() == 3);
                    }
                }
                if reference.len() == 3 {
                    if input.remaining() > 3 {
                        let next = input.cur_char(3);
                        let source_next = input.cur_char(3 - reference.dist() as i32);
                        short_next_pairs.insert((next, source_next));
                        short_next_zeroes[0] += usize::from(next == 0);
                        short_next_zeroes[1] += usize::from(source_next == 0);
                        for (bit, matches) in short_next_bit_matches.iter_mut().enumerate() {
                            *matches += usize::from((next ^ source_next) & (1 << bit) == 0);
                        }
                    }
                    for (chain, count) in chains.iter().zip(&mut counts) {
                        count[0] += 1;
                        let mut candidates = chain
                            .iterate::<0>(&input)
                            .take(0xffff)
                            .take_while(|&distance| distance <= 32768);
                        let head = candidates.next();
                        count[1] += usize::from(head == Some(reference.dist()));
                        let mut nearest = None;
                        let mut inserted = false;
                        for distance in head.into_iter().chain(candidates) {
                            if nearest.is_none()
                                && input.cur_chars(-(distance as i32))[..3]
                                    == input.cur_chars(0)[..3]
                            {
                                nearest = Some(distance);
                            }
                            inserted |= distance == reference.dist();
                        }
                        count[2] += usize::from(nearest == Some(reference.dist()));
                        count[3] += usize::from(inserted);
                    }
                }
            }
            let length = match token {
                DeflateToken::Literal(_) => 1,
                DeflateToken::Reference(reference) => reference.len(),
            };
            for ((_, policy, literals_only), chain) in policies.iter().zip(&mut chains) {
                if *literals_only && matches!(token, DeflateToken::Reference(_)) {
                    continue;
                }
                policy.update_hash(
                    input.cur_chars(0),
                    input.pos(),
                    length,
                    |bytes, position, length| chain.update_hash(bytes, position, length),
                );
            }
            input.advance(length);
        };
        for block in &contents.blocks {
            match &block.block_type {
                DeflateTokenBlockType::Stored { uncompressed } => {
                    uncompressed
                        .iter()
                        .copied()
                        .map(DeflateToken::Literal)
                        .for_each(&mut visit);
                }
                DeflateTokenBlockType::Huffman { tokens, .. } => {
                    tokens.iter().copied().for_each(&mut visit);
                }
            }
        }
        for ((policy, _, _), count) in policies.iter().zip(counts) {
            println!(
                "BACKUP hash={name} policy={policy} short_references={} actual_at_raw_head={} actual_at_nearest_prefix={} actual_source_inserted={}",
                count[0], count[1], count[2], count[3],
            );
        }
        println!(
            "LEFT_CONTEXT hash={name} eligible_references={context_references} eligible_short_references={short_context_references} equal_previous_low_bits_1_to_8={previous_context:?} short_equal_previous_low_bits_1_to_8={short_previous_context:?}"
        );
        println!(
            "SHORT_NEXT_CONTEXT hash={name} distinct_next_byte_pairs={} equal_next_bits_0_to_7={short_next_bit_matches:?} target_and_source_next_zeroes={short_next_zeroes:?}",
            short_next_pairs.len(),
        );
    }

    let path = std::env::var_os("PREFLATE_REFERENCE").expect("set PREFLATE_REFERENCE");
    let compressed = std::fs::read(path).unwrap();
    let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
    assert_eq!(contents.compressed_size, compressed.len());
    audit(
        "libdeflate3",
        LibdeflateHash3Secondary {},
        &contents,
        &plain,
    );
    audit(
        "zlib3",
        ZlibRotatingHashFixed::<5, 0x7fff> {},
        &contents,
        &plain,
    );
    audit("windows3", RandomVectorHash {}, &contents, &plain);
}

#[test]
#[ignore = "offline structural compressor constraints; requires selected raw .deflate fixtures"]
fn diagnose_compressor_constraints() {
    let filter = std::env::var("PREFLATE_DIAGNOSTICS_FILTER").unwrap_or_default();
    let mut matched = 0;
    for entry in std::fs::read_dir(fixture_directory()).unwrap() {
        let file = entry.unwrap().path();
        if !file.extension().is_some_and(|ext| ext == "deflate") {
            continue;
        }
        let name = file.file_stem().unwrap().to_string_lossy();
        if !name.contains(&filter) {
            continue;
        }
        matched += 1;
        let compressed = std::fs::read(&file).unwrap();
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len());
        let info = extract_preflate_info(&contents.blocks);
        let mut position = 0;
        let mut crossing_references = 0;
        let mut first_crossings = Vec::new();
        let mut token_counts = std::collections::BTreeMap::new();
        for block in &contents.blocks {
            match &block.block_type {
                DeflateTokenBlockType::Stored { uncompressed } => {
                    position += uncompressed.len() as u32;
                }
                DeflateTokenBlockType::Huffman { tokens, .. } => {
                    *token_counts.entry(tokens.len()).or_insert(0) += 1;
                    for token in tokens {
                        match token {
                            DeflateToken::Literal(_) => position += 1,
                            DeflateToken::Reference(reference) => {
                                if position % 32768 + reference.len() > 32768 {
                                    crossing_references += 1;
                                    if first_crossings.len() < 8 {
                                        first_crossings.push((position, reference.len()));
                                    }
                                }
                                position += reference.len();
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(position as usize, plain.len());
        println!(
            "CONSTRAINT {name}: plain={} deflate={} min_length={} max_distance={} max_block_bytes={} crossing_32k={} blocks={token_counts:?} first_crossings={first_crossings:?}",
            plain.len(),
            compressed.len(),
            info.min_len,
            info.max_dist,
            info.max_huffman_block_bytes,
            crossing_references,
        );
    }
    assert!(matched > 0, "no .deflate fixtures matched");
}

fn sweep_neighborhood(base: TokenPredictorParameters) -> Vec<TokenPredictorParameters> {
    let mut candidates = vec![base];
    for delta in 1..=8 {
        for max_chain in [
            base.max_chain.saturating_sub(delta).max(1),
            base.max_chain.saturating_add(delta).min(32768),
        ] {
            candidates.push(TokenPredictorParameters { max_chain, ..base });
        }
    }
    for max_chain in [
        1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 768, 1024, 1200, 1536, 2048, 3072, 4096, 8192,
        16384, 32768,
    ] {
        candidates.push(TokenPredictorParameters { max_chain, ..base });
    }
    for nice_length in [3, 4, 5, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 258] {
        candidates.push(TokenPredictorParameters {
            nice_length,
            ..base
        });
    }
    for max_dist_3_matches in [0, 1, 16, 64, 256, 1024, 2048, 4096, 8192, 32768] {
        candidates.push(TokenPredictorParameters {
            max_dist_3_matches,
            ..base
        });
    }
    for add_policy in [
        DictionaryAddPolicy::AddAll,
        DictionaryAddPolicy::AddFirst(0),
        DictionaryAddPolicy::AddFirst(4),
        DictionaryAddPolicy::AddFirst(8),
        DictionaryAddPolicy::AddFirst(16),
        DictionaryAddPolicy::AddFirst(32),
        DictionaryAddPolicy::AddFirst(64),
        DictionaryAddPolicy::AddFirst(128),
        DictionaryAddPolicy::AddFirstAndLast(0),
        DictionaryAddPolicy::AddFirstAndLast(16),
        DictionaryAddPolicy::AddFirstAndLast(32),
        DictionaryAddPolicy::AddFirstAndLast(64),
        DictionaryAddPolicy::AddFirstAndLast(128),
    ] {
        candidates.push(TokenPredictorParameters { add_policy, ..base });
    }
    for very_far_matches_detected in [false, true] {
        for matches_to_start_detected in [false, true] {
            candidates.push(TokenPredictorParameters {
                very_far_matches_detected,
                matches_to_start_detected,
                ..base
            });
        }
    }
    if let MatchingType::Lazy {
        filtered_matching,
        behavior,
        ..
    } = base.matching_type
    {
        for max_lazy in [0, 4, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 258] {
            candidates.push(TokenPredictorParameters {
                matching_type: MatchingType::Lazy {
                    max_lazy,
                    filtered_matching,
                    behavior,
                },
                ..base
            });
        }
        if let LazyBehavior::Zlib { .. } = behavior {
            for good_length in [0, 4, 8, 12, 16, 24, 32, 64, 128, 258] {
                if let MatchingType::Lazy { max_lazy, .. } = base.matching_type {
                    candidates.push(TokenPredictorParameters {
                        matching_type: MatchingType::Lazy {
                            max_lazy,
                            filtered_matching,
                            behavior: LazyBehavior::Zlib { good_length },
                        },
                        ..base
                    });
                }
            }
        }
    }
    candidates
}

#[test]
fn sweep_neighborhood_preserves_parser_hash_pairings() {
    for matching_type in [
        MatchingType::LibdeflateLazy {
            two_positions: true,
        },
        MatchingType::LibdeflateGreedy,
        SLOW_PREFLATE_PARSER_SETTINGS[2].match_type,
    ] {
        let base = TokenPredictorParameters {
            hash_algorithm: HashAlgorithm::Libdeflate4,
            matching_type,
            ..synthetic_params()
        };
        let candidates = sweep_neighborhood(base);
        assert!(candidates.contains(&base));
        if (2..32768).contains(&base.max_chain) {
            for max_chain in [base.max_chain - 1, base.max_chain + 1] {
                assert!(candidates.contains(&TokenPredictorParameters { max_chain, ..base }));
            }
        }
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.hash_algorithm == base.hash_algorithm)
        );
        assert!(candidates.iter().all(|candidate| {
            match (matching_type, candidate.matching_type) {
                (MatchingType::Lazy { .. }, MatchingType::Lazy { .. }) => true,
                (original, candidate) => original == candidate,
            }
        }));
    }
}

#[test]
#[ignore = "offline whole-stream sweep; requires PREFLATE_REFERENCE and PREFLATE_SWEEP_RESULTS"]
fn sweep_compressor_parameters() {
    use std::{collections::HashSet, io::Write};

    fn representatives(
        ranked: &[(usize, TokenPredictorParameters)],
    ) -> Vec<TokenPredictorParameters> {
        let mut hashes = Vec::new();
        let mut parsers = Vec::new();
        let mut result = Vec::new();
        for &(_, parameters) in ranked {
            let parser = std::mem::discriminant(&parameters.matching_type);
            if !hashes.contains(&parameters.hash_algorithm) || !parsers.contains(&parser) {
                hashes.push(parameters.hash_algorithm);
                parsers.push(parser);
                result.push(parameters);
            }
        }
        result
    }

    let path = std::env::var_os("PREFLATE_REFERENCE").expect("set PREFLATE_REFERENCE");
    let prefix = PathBuf::from(
        std::env::var_os("PREFLATE_SWEEP_RESULTS").expect("set PREFLATE_SWEEP_RESULTS"),
    );
    let new_output = |extension| {
        std::io::BufWriter::new(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(prefix.with_extension(extension))
                .unwrap(),
        )
    };
    let mut scores = new_output("scores.tsv");
    let mut verified = new_output("verified.tsv");
    let mut residuals = new_output("residuals.tsv");
    writeln!(scores, "stage\tmismatches\ttokens\tparameters").unwrap();
    writeln!(
        verified,
        "status\tmismatches\trecord_bytes\tcabac_bytes\tparameters\terror"
    )
    .unwrap();
    writeln!(
        residuals,
        "offset\tactual_length\tactual_distance\tpredicted_length\tpredicted_distance"
    )
    .unwrap();
    let compressed = std::fs::read(path).unwrap();
    let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
    assert_eq!(contents.compressed_size, compressed.len());
    let baseline = estimate_preflate_parameters(&contents, &plain).unwrap();
    let expected_tokens: usize = contents
        .blocks
        .iter()
        .map(|block| match &block.block_type {
            DeflateTokenBlockType::Stored { .. } => 0,
            DeflateTokenBlockType::Huffman { tokens, .. } => tokens.len(),
        })
        .sum();
    let hashes = [
        HashAlgorithm::RandomVector,
        HashAlgorithm::Zlib {
            hash_mask: 32767,
            hash_shift: 5,
        },
        HashAlgorithm::Zlib {
            hash_mask: 2047,
            hash_shift: 4,
        },
        HashAlgorithm::Zlib {
            hash_mask: 8191,
            hash_shift: 5,
        },
        HashAlgorithm::Zlib {
            hash_mask: 16383,
            hash_shift: 5,
        },
        HashAlgorithm::Zlib {
            hash_mask: 65535,
            hash_shift: 6,
        },
        HashAlgorithm::MiniZFast,
    ];
    let mut parsers = vec![MatchingType::Greedy];
    for (max_lazy, good_length) in [(4, 4), (16, 8), (32, 8), (128, 32), (258, 32)] {
        parsers.push(MatchingType::Lazy {
            max_lazy,
            filtered_matching: false,
            behavior: LazyBehavior::Zlib { good_length },
        });
    }
    for max_lazy in [16, 258] {
        parsers.push(MatchingType::Lazy {
            max_lazy,
            filtered_matching: false,
            behavior: LazyBehavior::RecomputeAfterLiteral,
        });
    }
    let mut candidates = vec![baseline];
    candidates.extend(pdf_parameter_variants(
        baseline,
        extract_preflate_info(&contents.blocks).min_len,
    ));
    for hash_algorithm in hashes.into_iter().chain([
        HashAlgorithm::Libdeflate4,
        HashAlgorithm::Libdeflate4Fast,
        HashAlgorithm::Libdeflate4Fast15,
        HashAlgorithm::ZlibNG,
        HashAlgorithm::Chromium { hash_mask: 0x7fff },
        HashAlgorithm::Crc32cHash,
    ]) {
        let family_parsers = if hash_algorithm == HashAlgorithm::Libdeflate4 {
            vec![
                MatchingType::Greedy,
                MatchingType::LibdeflateGreedy,
                MatchingType::LibdeflateLazy {
                    two_positions: false,
                },
                MatchingType::LibdeflateLazy {
                    two_positions: true,
                },
                parsers[2],
            ]
        } else if hashes.contains(&hash_algorithm) {
            parsers.clone()
        } else {
            vec![MatchingType::Greedy, parsers[2]]
        };
        for max_chain in [16, 64, 256, 1024, 4096] {
            for nice_length in [16, 64, 128, 258] {
                for &matching_type in &family_parsers {
                    for max_dist_3_matches in [0, 4096] {
                        candidates.push(TokenPredictorParameters {
                            hash_algorithm,
                            matching_type,
                            max_chain,
                            nice_length,
                            max_dist_3_matches,
                            add_policy: DictionaryAddPolicy::AddAll,
                            ..baseline
                        });
                    }
                }
            }
        }
    }
    for max_probes in [1, 6, 16, 32, 128, 512, 1024, 4096] {
        for greedy in [false, true] {
            for max_dist_3_matches in [0, 4096] {
                candidates.push(TokenPredictorParameters {
                    hash_algorithm: crate::models::zlib::DEFAULT_HASH,
                    matching_type: MatchingType::MiniZ { max_probes, greedy },
                    max_dist_3_matches,
                    add_policy: DictionaryAddPolicy::AddAll,
                    ..baseline
                });
            }
        }
    }
    let mut seen = HashSet::new();
    let mut ranked = Vec::new();
    for stage in 0..3 {
        for candidate in candidates.drain(..) {
            if !seen.insert(bitcode::encode(&candidate)) {
                continue;
            }
            let (mismatches, tokens) = TokenPredictor::new(&candidate).score_predictions(
                &contents.blocks,
                &plain,
                usize::MAX,
                u32::MAX,
            );
            assert_eq!(tokens, expected_tokens);
            ranked.push((mismatches, candidate));
            writeln!(scores, "{stage}\t{mismatches}\t{tokens}\t{candidate:?}").unwrap();
            if seen.len() % 128 == 0 {
                scores.flush().unwrap();
                println!(
                    "SWEEP_PROGRESS stage={stage} trials={} best_mismatches={}",
                    seen.len(),
                    ranked.iter().map(|row| row.0).min().unwrap()
                );
            }
        }
        ranked.sort_by_key(|row| row.0);
        let seeds: Vec<_> = ranked
            .iter()
            .take(8)
            .map(|row| row.1)
            .chain(representatives(&ranked))
            .collect();
        for seed in seeds {
            candidates.extend(sweep_neighborhood(seed));
        }
    }
    scores.flush().unwrap();
    let finalists: Vec<_> = representatives(&ranked)
        .into_iter()
        .chain([baseline])
        .chain(ranked.iter().map(|row| row.1))
        .collect();
    let mut measured = HashSet::new();
    let mut verified_count = 0;
    let mut rejected_count = 0;
    let mut best: Option<(TokenPredictorParameters, Measurement)> = None;
    for candidate in finalists {
        if verified_count >= 64 {
            break;
        }
        if !measured.insert(bitcode::encode(&candidate)) {
            continue;
        }
        let score = ranked.iter().find(|row| row.1 == candidate).unwrap().0;
        let trial =
            match measure_with_tracking(&contents, &plain, &candidate, false, false, 1_000_000) {
                Ok(trial) => trial,
                Err(error)
                    if matches!(
                        error.exit_code(),
                        ExitCode::MatchNotFound | ExitCode::PredictionFailure
                    ) =>
                {
                    writeln!(
                        verified,
                        "rejected\t{score}\t\t\t{candidate:?}\t{}",
                        error.to_string().replace('\n', " ").replace('\t', " ")
                    )
                    .unwrap();
                    rejected_count += 1;
                    continue;
                }
                Err(error) => panic!("{candidate:?}: {error:?}"),
            };
        verify(&trial, &plain, &compressed);
        verified_count += 1;
        assert_eq!(trial.trace.mismatch_count, score);
        writeln!(
            verified,
            "verified\t{score}\t{}\t{}\t{candidate:?}\t",
            trial.corrections.len(),
            trial.cabac_size
        )
        .unwrap();
        if best
            .as_ref()
            .is_none_or(|(_, previous)| trial.corrections.len() < previous.corrections.len())
        {
            println!(
                "SWEEP_BEST bytes={} mismatches={score} params={candidate:?}",
                trial.corrections.len()
            );
            best = Some((candidate, trial));
        }
    }
    let (parameters, best) = best.expect("no encodable finalist");
    assert!(best.trace.mismatch_count <= best.trace.max_mismatches);
    let shape = |token: DeflateToken| match token {
        DeflateToken::Literal(_) => (0, 0),
        DeflateToken::Reference(reference) => (reference.len(), reference.dist()),
    };
    let mut pairs = std::collections::BTreeMap::new();
    for (index, &(offset, actual, predicted)) in best.trace.first_mismatches.iter().enumerate() {
        let (actual_length, actual_distance) = shape(actual);
        let (predicted_length, predicted_distance) = shape(predicted);
        *pairs
            .entry((actual_length, predicted_length))
            .or_insert(0usize) += 1;
        if index < 4096 {
            writeln!(residuals, "{offset}\t{actual_length}\t{actual_distance}\t{predicted_length}\t{predicted_distance}").unwrap();
        }
    }
    println!(
        "SWEEP_FINAL trials={} verified={verified_count} rejected={rejected_count} record_bytes={} mismatches={} params={parameters:?} pairs={pairs:?}",
        seen.len(),
        best.corrections.len(),
        best.trace.mismatch_count
    );
    verified.flush().unwrap();
    residuals.flush().unwrap();
}

#[test]
#[ignore = "offline native token comparison; requires reference and comparison raw streams"]
fn compare_compressor_tokens() {
    fn positioned_tokens(contents: &DeflateContents) -> Vec<(u32, DeflateToken)> {
        let mut result = Vec::new();
        let mut position = 0;
        for block in &contents.blocks {
            match &block.block_type {
                DeflateTokenBlockType::Stored { uncompressed } => {
                    for &byte in uncompressed {
                        result.push((position, DeflateToken::Literal(byte)));
                        position += 1;
                    }
                }
                DeflateTokenBlockType::Huffman { tokens, .. } => {
                    for &token in tokens {
                        result.push((position, token));
                        position += shape(token).0;
                    }
                }
            }
        }
        result
    }

    fn shape(token: DeflateToken) -> (u32, u32) {
        match token {
            DeflateToken::Literal(_) => (1, 0),
            DeflateToken::Reference(reference) => (reference.len(), reference.dist()),
        }
    }

    let reference = std::env::var_os("PREFLATE_REFERENCE")
        .expect("set PREFLATE_REFERENCE to the original raw .deflate stream");
    let compressed = std::fs::read(reference).unwrap();
    let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
    assert_eq!(contents.compressed_size, compressed.len());
    let reference = positioned_tokens(&contents);
    let reference_short_references = reference
        .iter()
        .filter(|(_, token)| shape(*token).0 == 3)
        .count();
    let filter = std::env::var("PREFLATE_DIAGNOSTICS_FILTER").unwrap_or_default();
    let mut matched = 0;
    for entry in std::fs::read_dir(fixture_directory()).unwrap() {
        let file = entry.unwrap().path();
        if !file.extension().is_some_and(|ext| ext == "deflate") {
            continue;
        }
        let name = file.file_stem().unwrap().to_string_lossy();
        if !name.contains(&filter) {
            continue;
        }
        matched += 1;
        let candidate_compressed = std::fs::read(&file).unwrap();
        let (candidate, candidate_plain) = parse_deflate_whole(&candidate_compressed).unwrap();
        assert_eq!(candidate.compressed_size, candidate_compressed.len());
        assert!(
            plain.text() == candidate_plain.text(),
            "{name}: different plaintext"
        );
        let candidate = positioned_tokens(&candidate);
        let candidate_short_references = candidate
            .iter()
            .filter(|(_, token)| shape(*token).0 == 3)
            .count();
        let mut candidate_tokens = candidate.iter().peekable();
        let mut matching_tokens = 0;
        let mut matching_bytes = 0;
        let mut matching_short_references = 0;
        let mut first_differences = Vec::new();
        let mut first_short_differences = Vec::new();
        for &(position, token) in &reference {
            while candidate_tokens
                .peek()
                .is_some_and(|next| next.0 < position)
            {
                candidate_tokens.next();
            }
            let other = candidate_tokens.peek().filter(|next| next.0 == position);
            if other.is_some_and(|next| next.1 == token) {
                matching_tokens += 1;
                matching_bytes += shape(token).0;
                matching_short_references += usize::from(shape(token).0 == 3);
            } else {
                let difference = (position, shape(token), other.map(|next| shape(next.1)));
                if first_differences.len() < 8 {
                    first_differences.push(difference);
                }
                if shape(token).0 == 3 && first_short_differences.len() < 8 {
                    first_short_differences.push(difference);
                }
            }
        }
        println!(
            "COMPARISON {name}: exact_bitstream={} reference_tokens={} candidate_tokens={} matching_tokens={matching_tokens} matching_bytes={matching_bytes} plain_bytes={} reference_short_references={reference_short_references} candidate_short_references={candidate_short_references} matching_short_references={matching_short_references} first_differences={first_differences:?} first_short_differences={first_short_differences:?}",
            compressed == candidate_compressed,
            reference.len(),
            candidate.len(),
            plain.len(),
        );
    }
    assert!(matched > 0, "no .deflate fixtures matched");
}

fn pdf_parameter_variants(
    params: TokenPredictorParameters,
    observed_min_len: u32,
) -> Vec<TokenPredictorParameters> {
    use crate::estimator::preflate_parse_config::ZLIB_PREFLATE_PARSER_SETTINGS;

    let mut variants = parameter_variants(params, observed_min_len, false);
    let compatible = zlib_compatible(&params);
    let mut add = |candidate: TokenPredictorParameters| {
        let candidate = candidate.with_lazy_behavior(compatible, observed_min_len);
        if candidate != params && !variants.contains(&candidate) {
            variants.push(candidate);
        }
    };
    for hash_algorithm in [
        params.hash_algorithm,
        HashAlgorithm::RandomVector,
        HashAlgorithm::Libdeflate4,
        HashAlgorithm::Libdeflate4Fast,
        HashAlgorithm::ZlibNG,
        HashAlgorithm::Chromium { hash_mask: 0x7fff },
        HashAlgorithm::Crc32cHash,
        HashAlgorithm::Zlib {
            hash_mask: 32767,
            hash_shift: 5,
        },
        HashAlgorithm::Zlib {
            hash_mask: 2047,
            hash_shift: 4,
        },
    ] {
        add(TokenPredictorParameters {
            hash_algorithm,
            ..params
        });
        for config in ZLIB_PREFLATE_PARSER_SETTINGS
            .iter()
            .chain(SLOW_PREFLATE_PARSER_SETTINGS.iter())
        {
            add(TokenPredictorParameters {
                hash_algorithm,
                matching_type: config.match_type,
                nice_length: config.nice_length,
                max_chain: config.max_chain,
                add_policy: config.dictionary_add_policy,
                ..params
            });
        }
    }
    for (depth, nice_length, matching_type) in [
        (7, 10, MatchingType::LibdeflateGreedy),
        (13, 14, MatchingType::LibdeflateGreedy),
        (17, 30, MatchingType::LibdeflateGreedy),
        (
            17,
            30,
            MatchingType::LibdeflateLazy {
                two_positions: false,
            },
        ),
        (
            36,
            65,
            MatchingType::LibdeflateLazy {
                two_positions: false,
            },
        ),
        (
            101,
            130,
            MatchingType::LibdeflateLazy {
                two_positions: false,
            },
        ),
        (
            301,
            258,
            MatchingType::LibdeflateLazy {
                two_positions: true,
            },
        ),
        (
            601,
            258,
            MatchingType::LibdeflateLazy {
                two_positions: true,
            },
        ),
    ] {
        add(TokenPredictorParameters {
            hash_algorithm: HashAlgorithm::Libdeflate4,
            matching_type,
            nice_length,
            max_chain: depth,
            add_policy: DictionaryAddPolicy::AddAll,
            window_bits: 15,
            max_dist_3_matches: 4096,
            ..params
        });
    }
    for max_probes in [6, 16, 32, 128, 256, 512, 768, 1500] {
        for greedy in [false, true] {
            add(TokenPredictorParameters {
                hash_algorithm: HashAlgorithm::Zlib {
                    hash_mask: 32767,
                    hash_shift: 5,
                },
                matching_type: MatchingType::MiniZ { max_probes, greedy },
                nice_length: 258,
                max_chain: u32::from(max_probes).div_ceil(3) * 3,
                add_policy: DictionaryAddPolicy::AddAll,
                window_bits: 15,
                ..params
            });
        }
    }
    variants.retain(|candidate| match candidate.matching_type {
        MatchingType::LibdeflateGreedy | MatchingType::LibdeflateLazy { .. } => {
            candidate.hash_algorithm == HashAlgorithm::Libdeflate4
        }
        MatchingType::MiniZ { .. } => {
            candidate.hash_algorithm
                == HashAlgorithm::Zlib {
                    hash_mask: 32767,
                    hash_shift: 5,
                }
        }
        _ => true,
    });
    variants
}

#[test]
fn pdf_probe_variants_keep_coupled_parsers_and_hashes() {
    for name in [
        "compressed_zlib_level6.deflate",
        "compressed_libdeflate_level5.deflate",
        "compressed_minizoxide_level1.deflate",
    ] {
        let compressed = crate::utils::read_file(name);
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        let params = estimate_preflate_parameters(&contents, &plain).unwrap();
        let observed_min_len = extract_preflate_info(&contents.blocks).min_len;
        let variants = pdf_parameter_variants(params, observed_min_len);
        assert!(!variants.is_empty());
        for (index, candidate) in variants.iter().enumerate() {
            assert_ne!(candidate, &params);
            assert!(!variants[..index].contains(candidate));
            match candidate.matching_type {
                MatchingType::LibdeflateGreedy | MatchingType::LibdeflateLazy { .. } => {
                    assert_eq!(candidate.hash_algorithm, HashAlgorithm::Libdeflate4);
                }
                MatchingType::MiniZ { .. } => {
                    assert_eq!(
                        candidate.hash_algorithm,
                        HashAlgorithm::Zlib {
                            hash_mask: 32767,
                            hash_shift: 5
                        }
                    );
                }
                _ => {}
            }
            TokenPredictor::new(candidate).score_predictions(&contents.blocks, &plain, 128, 65536);
        }
    }
}

#[test]
#[ignore = "release-mode model refactor comparison; requires a separate snapshot directory"]
fn compare_model_family_snapshots() {
    use std::io::Write;

    let destination = PathBuf::from(
        std::env::var_os("PREFLATE_MODEL_SNAPSHOTS")
            .expect("set PREFLATE_MODEL_SNAPSHOTS to a snapshot directory"),
    );
    let capture = std::env::var_os("PREFLATE_CAPTURE_MODEL_BASELINE").is_some();
    let mut files: Vec<_> = std::fs::read_dir(fixture_directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "deflate"))
        .collect();
    files.sort();
    assert!(!files.is_empty());
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy();
        let compressed = std::fs::read(&file).unwrap();
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        let compressed = &compressed[..contents.compressed_size];
        let snapshot = match estimate_preflate_parameters(&contents, &plain) {
            Ok(parameters) => {
                let measurement = measure(&contents, &plain, &parameters).unwrap();
                verify(&measurement, &plain, compressed);
                let mut snapshot = format!("{parameters:?}\n").into_bytes();
                snapshot.extend(measurement.corrections);
                snapshot
            }
            Err(error) if error.exit_code() == ExitCode::NoCompressionCandidates => {
                format!("UNSUPPORTED: {:?}\n", error.exit_code()).into_bytes()
            }
            Err(error) => panic!("{name}: {error:?}"),
        };
        let path = destination.join(format!("{name}.model"));
        if capture {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap()
                .write_all(&snapshot)
                .unwrap();
        } else {
            assert_eq!(std::fs::read(path).unwrap(), snapshot, "{name}");
        }
        println!("MODEL SNAPSHOT {name}: {} bytes", snapshot.len());
    }
}

// Separate encoding costs from fixture generation and optional round-trip validation.
// This manual benchmark reports throughput and correction sizes, not a pass/fail speed limit.
#[test]
#[ignore = "throughput measurement using exported fixtures; run in release mode"]
fn benchmark_prediction_throughput() {
    let names = [
        "zlib_6",
        "miniz_2",
        "miniz_3",
        "libdeflate_1",
        "libdeflate_2",
        "libdeflate_3",
        "libdeflate_4",
        "libdeflate_5",
    ];
    let config = PreflateConfig {
        verify_compression: false,
        ..PreflateConfig::default()
    };
    for name in names {
        let compressed =
            std::fs::read(fixture_directory().join(format!("{name}.deflate"))).unwrap();
        let (_, plain_text) = preflate_whole_deflate_stream(&compressed, &config).unwrap();
        let start = std::time::Instant::now();
        let mut iterations = 0;
        let mut corrections = 0;
        while start.elapsed().as_millis() < 1000 {
            let result =
                preflate_whole_deflate_stream(std::hint::black_box(&compressed), &config).unwrap();
            corrections = result.0.corrections.len();
            std::hint::black_box(result);
            iterations += 1;
        }
        let elapsed = start.elapsed().as_secs_f64();
        println!(
            "THROUGHPUT {name}: {:.2} MiB/s plaintext, {:.3} ms/stream, corrections={corrections}, iterations={iterations}",
            iterations as f64 * plain_text.len() as f64 / (1024.0 * 1024.0 * elapsed),
            elapsed * 1000.0 / iterations as f64
        );
    }
}

// Poor ratios need attributable token/tree diagnostics rather than blind parameter changes.
// This manual harness verifies supported baselines and accepted trials before reporting them.
#[test]
#[ignore = "run export_compression_diagnostics first; optionally filter or sweep parameters"]
fn diagnose_compression() {
    let directory = fixture_directory();
    let filter = std::env::var("PREFLATE_DIAGNOSTICS_FILTER").unwrap_or_default();
    let sweep = std::env::var_os("PREFLATE_DIAGNOSTICS_SWEEP").is_some();
    let mut files: Vec<_> = std::fs::read_dir(&directory)
        .expect("run the root export_compression_diagnostics test first")
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "deflate")
                && path
                    .file_stem()
                    .unwrap()
                    .to_string_lossy()
                    .contains(&filter)
        })
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no .deflate fixtures matched in {}",
        directory.display()
    );
    let mut ranking = Vec::new();
    let mut unsupported = 0;
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy();
        let compressed = std::fs::read(&file).unwrap();
        let (contents, plain_text) = parse_deflate_whole(&compressed)
            .unwrap_or_else(|error| panic!("{}: {error:?}", file.display()));
        assert_eq!(contents.compressed_size, compressed.len());
        let params = match estimate_preflate_parameters(&contents, &plain_text) {
            Ok(params) => params,
            Err(error) if error.exit_code() == ExitCode::NoCompressionCandidates => {
                println!("UNSUPPORTED {name}: {error:?}");
                unsupported += 1;
                continue;
            }
            Err(error) => panic!("{name}: {error:?}"),
        };
        let baseline = measure(&contents, &plain_text, &params)
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        verify(&baseline, &plain_text, &compressed);
        println!(
            "\n{name}: plaintext={}, deflate={}, blocks={}, params={params:?}",
            plain_text.len(),
            compressed.len(),
            contents.blocks.len()
        );
        print_measurement("BASELINE", &baseline, compressed.len());
        print_details(&baseline);
        ranking.push((
            name.into_owned(),
            baseline.corrections.len(),
            compressed.len(),
        ));
        if !sweep || params.max_chain == 0 {
            continue;
        }
        let mut best = baseline;
        let mut best_params = params;
        let observed_min_len = extract_preflate_info(&contents.blocks).min_len;
        for candidate in parameter_variants(params, observed_min_len, false) {
            match measure(&contents, &plain_text, &candidate) {
                Ok(measurement) => {
                    verify(&measurement, &plain_text, &compressed);
                    println!(
                        "  ISOLATED match={:?} nice={} chain={}",
                        candidate.matching_type, candidate.nice_length, candidate.max_chain
                    );
                    print_measurement("  RESULT", &measurement, compressed.len());
                    if measurement.corrections.len() < best.corrections.len() {
                        best = measurement;
                        best_params = candidate;
                    }
                }
                Err(error) => println!("  REJECTED {candidate:?}: {error:?}"),
            }
        }
        for candidate in parameter_variants(params, observed_min_len, true) {
            match measure(&contents, &plain_text, &candidate) {
                Ok(measurement) => {
                    if measurement.corrections.len() < best.corrections.len() {
                        verify(&measurement, &plain_text, &compressed);
                        best = measurement;
                        best_params = candidate;
                    }
                }
                Err(error) => println!("  REJECTED {candidate:?}: {error:?}"),
            }
        }
        println!("BEST TESTED params={best_params:?}");
        print_measurement("BEST TESTED", &best, compressed.len());
        print_details(&best);
    }
    ranking.sort_by(|a, b| (b.1 as u128 * a.2 as u128).cmp(&(a.1 as u128 * b.2 as u128)));
    println!("\nOverhead ranking (corrections / original deflate bytes):");
    for (name, corrections, compressed) in ranking {
        println!(
            "{name}: {corrections}/{compressed} = {:.3}%",
            100.0 * corrections as f64 / compressed as f64
        );
    }
    println!("Unsupported streams: {unsupported}");
}

// The isolation harness must measure the real format without changing predictor behavior.
// Verify production-byte parity, exact reconstruction and zero fastest-profile token errors.
#[test]
fn diagnostic_measurement_matches_production() {
    for name in [
        "compressed_zlib_level1.deflate",
        "compressed_libdeflate_level1.deflate",
        "compressed_libdeflate_level2.deflate",
        "compressed_libdeflate_level4.deflate",
        "compressed_zlib_level0.deflate",
        "compressed_minizoxide_level1.deflate",
        "compressed_flate2_level3.deflate",
        "compressed_zlibng_level3.deflate",
    ] {
        let compressed = crate::utils::read_file(name);
        let (contents, plain_text) = parse_deflate_whole(&compressed).unwrap();
        let params = estimate_preflate_parameters(&contents, &plain_text).unwrap();
        let measurement = measure_normalized(&contents, &plain_text, &params).unwrap();
        if name == "compressed_libdeflate_level1.deflate" {
            assert_eq!(
                params.hash_algorithm,
                crate::HashAlgorithm::Libdeflate4Fast15
            );
            assert_eq!(measurement.trace.mismatch_count, 0);
        }
        verify(&measurement, &plain_text, &compressed);
        let (production, _) =
            preflate_whole_deflate_stream(&compressed, &PreflateConfig::default()).unwrap();
        assert_eq!(measurement.corrections, production.corrections);
        assert_eq!(
            measurement.trace.first_mismatches.len(),
            measurement.trace.mismatch_count.min(8)
        );
        assert!(measurement.trace.mismatch_count <= measurement.trace.token_count);
        for (offset, actual, predicted) in &measurement.trace.first_mismatches {
            assert_ne!(actual, predicted);
            assert!((*offset as usize) < plain_text.len());
        }
    }
}

// A diagnostic sweep cannot attribute improvements if unrelated settings change together.
// Derived filter behavior follows the parser; other axes stay isolated, without duplicates.
#[test]
fn isolated_variants_change_one_parameter() {
    for name in [
        "compressed_zlib_level1.deflate",
        "compressed_libdeflate_level1.deflate",
        "compressed_libdeflate_level4.deflate",
        "compressed_minizoxide_level1.deflate",
        "compressed_zlibng_level3.deflate",
    ] {
        let compressed = crate::utils::read_file(name);
        let (contents, plain_text) = parse_deflate_whole(&compressed).unwrap();
        let params = estimate_preflate_parameters(&contents, &plain_text).unwrap();
        let observed_min_len = extract_preflate_info(&contents.blocks).min_len;
        for combined in [false, true] {
            let variants = parameter_variants(params, observed_min_len, combined);
            assert!(!variants.is_empty(), "{name}");
            for (index, candidate) in variants.iter().enumerate() {
                let changes = usize::from(candidate.matching_type != params.matching_type)
                    + usize::from(candidate.nice_length != params.nice_length)
                    + usize::from(candidate.max_chain != params.max_chain);
                assert!((1..=3).contains(&changes), "{name}");
                if !combined {
                    assert_eq!(changes, 1, "{name}");
                }
                let expected = TokenPredictorParameters {
                    matching_type: candidate.matching_type,
                    nice_length: candidate.nice_length,
                    max_chain: candidate.max_chain,
                    ..params
                }
                .with_lazy_behavior(zlib_compatible(&params), observed_min_len);
                assert_eq!(*candidate, expected, "{name}");
                assert!(!variants[..index].contains(candidate), "{name}");
            }
        }
    }
}

fn synthetic_stream(tokens: Vec<DeflateToken>) -> (Vec<u8>, DeflateContents, PlainText) {
    let mut writer = DeflateWriter::new();
    writer
        .encode_block(&DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type: DeflateHuffmanType::Static,
            },
            last: true,
        })
        .unwrap();
    writer.flush();
    let compressed = writer.detach_output();
    let (contents, plain_text) = parse_deflate_whole(&compressed).unwrap();
    (compressed, contents, plain_text)
}

fn synthetic_params() -> TokenPredictorParameters {
    TokenPredictorParameters {
        add_policy: DictionaryAddPolicy::AddAll,
        nice_length: 258,
        max_chain: 32,
        block_type_strategy: BlockTypeStrategy::Static,
        ..crate::token_predictor::zlib_level_1_params()
    }
}

// Greedy/lazy misclassification should have a distinct, reproducible diagnostic signature.
// Verify one known lookahead decision causes exactly one traced and coded literal mismatch.
#[test]
fn diagnostic_isolates_greedy_from_lazy_matching() {
    let mut tokens: Vec<_> = b"@abcdX"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.push(DeflateToken::new_ref(3, 4));
    tokens.extend(b"efY".iter().copied().map(DeflateToken::Literal));
    tokens.push(DeflateToken::new_ref(4, 11));
    tokens.extend(b"ef".iter().copied().map(DeflateToken::Literal));
    let (compressed, contents, plain_text) = synthetic_stream(tokens);
    assert_eq!(plain_text.text(), b"@abcdXbcdefYabcdef");
    let params = synthetic_params();
    let greedy = measure(&contents, &plain_text, &params).unwrap();
    let lazy = measure(
        &contents,
        &plain_text,
        &TokenPredictorParameters {
            matching_type: MatchingType::Lazy {
                max_lazy: 258,
                filtered_matching: false,
                behavior: LazyBehavior::Zlib { good_length: 32 },
            },
            ..params
        },
    )
    .unwrap();
    verify(&greedy, &plain_text, &compressed);
    verify(&lazy, &plain_text, &compressed);
    assert_eq!(greedy.trace.mismatch_count, 0);
    assert_eq!(lazy.trace.mismatch_count, 1);
    assert_eq!(
        lazy.trace.first_mismatches,
        vec![(
            12,
            DeflateToken::new_ref(4, 11),
            DeflateToken::Literal(b'a')
        )]
    );
    assert_eq!(
        lazy.count.corrections_count[CodecCorrection::LiteralPredictionWrong as usize],
        1
    );
}

// An early nice-length exit can hide a longer match despite the correct hash and parser.
// Verify changing only that cutoff produces the expected single length-correction mismatch.
#[test]
fn diagnostic_isolates_nice_length_cutoff() {
    let mut tokens: Vec<_> = b"@abcdefX"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.push(DeflateToken::new_ref(3, 7));
    tokens.push(DeflateToken::Literal(b'Y'));
    tokens.push(DeflateToken::new_ref(6, 11));
    let (compressed, contents, plain_text) = synthetic_stream(tokens);
    assert_eq!(plain_text.text(), b"@abcdefXabcYabcdef");
    let params = synthetic_params();
    let full_search = measure(&contents, &plain_text, &params).unwrap();
    let early_exit = measure(
        &contents,
        &plain_text,
        &TokenPredictorParameters {
            nice_length: 3,
            ..params
        },
    )
    .unwrap();
    verify(&full_search, &plain_text, &compressed);
    verify(&early_exit, &plain_text, &compressed);
    assert_eq!(full_search.trace.mismatch_count, 0);
    assert_eq!(early_exit.trace.mismatch_count, 1);
    assert_eq!(
        early_exit.trace.first_mismatches,
        vec![(
            12,
            DeflateToken::new_ref(6, 11),
            DeflateToken::new_ref(3, 4)
        )]
    );
    assert_eq!(
        early_exit.count.corrections_count[CodecCorrection::LenCorrection as usize],
        1
    );
}

// Mismatch tracing must bound memory without undercounting errors on badly matched streams.
// Verify counts continue beyond the sample cap while only eight ordered samples are retained.
#[test]
fn diagnostic_trace_bounds_samples_not_counts() {
    for length in [0, 1, 4, 8, 12, 16, 32, 128] {
        let bytes: Vec<_> = (0..length).map(|i| b"abcd"[i % 4]).collect();
        let tokens = bytes.iter().copied().map(DeflateToken::Literal).collect();
        let (compressed, contents, plain_text) = synthetic_stream(tokens);
        let measurement = measure(&contents, &plain_text, &synthetic_params()).unwrap();
        verify(&measurement, &plain_text, &compressed);
        assert_eq!(measurement.trace.token_count, length);
        assert_eq!(
            measurement.trace.first_mismatches.len(),
            measurement.trace.mismatch_count.min(8)
        );
        if length == 128 {
            assert!(measurement.trace.mismatch_count > 8);
        }
        for (offset, actual, predicted) in &measurement.trace.first_mismatches {
            assert_eq!(*actual, DeflateToken::Literal(bytes[*offset as usize]));
            assert_ne!(actual, predicted);
        }
        for pair in measurement.trace.first_mismatches.windows(2) {
            assert!(pair[0].0 < pair[1].0);
        }
    }
}
