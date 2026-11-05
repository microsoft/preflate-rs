/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Streaming reconstruction tests, prediction regressions, and offline diagnostics.
//! Measures token and tree mismatches, compares parameter variants, and verifies
//! correction data through exact bitstream reconstruction.

use std::path::{Path, PathBuf};

use super::*;
use crate::{
    HashAlgorithm,
    deflate::{
        deflate_reader::{DeflateContents, tests::parse_deflate_whole},
        deflate_token::{DeflateHuffmanType, DeflateToken, DeflateTokenBlockType},
    },
    estimator::test_support::{
        extract_preflate_info, zlib::SLOW_PREFLATE_PARSER_SETTINGS, zlib_compatible,
    },
    hash_chain_holder::SearchPurpose,
    parameters::{BlockTypeStrategy, DictionaryAddPolicy, LazyBehavior, tests::MatchingType},
    statistical_codec::CountNonDefaultActions,
    token_predictor::TokenPredictionTrace,
};

#[test]
fn filtered_six_table_hash_parameters_and_corrections_roundtrip() {
    let mut tokens: Vec<_> = b"@abcdeXabcdeYabcdefZ"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.push(DeflateToken::new_ref(6, 7));
    tokens.extend([DeflateToken::Literal(b'!'), DeflateToken::Literal(b'$')]);
    let (compressed, contents, plain) = synthetic_stream(tokens);
    let filtered = {
        let mut canonical_configuration = synthetic_params();
        canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
        canonical_configuration.set_nice_length(128);
        canonical_configuration.set_max_chain(128);
        canonical_configuration.set_matching_type(MatchingType::Lazy {
            max_lazy: 16,
            filtered_matching: true,
            behavior: LazyBehavior::Zlib { good_length: 8 },
        });
        canonical_configuration.max_token_count = 16383;
        canonical_configuration
    };
    let unfiltered = {
        let mut canonical_configuration = filtered;
        canonical_configuration.set_matching_type(MatchingType::Lazy {
            max_lazy: 16,
            filtered_matching: false,
            behavior: LazyBehavior::Zlib { good_length: 8 },
        });
        canonical_configuration
    };
    assert!(
        measure(&contents, &plain, &unfiltered)
            .unwrap()
            .trace
            .mismatch_count
            >= 2
    );
    for measurement in [
        measure(&contents, &plain, &filtered).unwrap(),
        measure_normalized(&contents, &plain, &filtered).unwrap(),
    ] {
        assert_eq!(measurement.trace.mismatch_count, 0);
        verify(&measurement, &plain, &compressed);
    }
}

#[test]
fn sparse_first_only_insertion_does_not_invent_slide_boundary_matches() {
    let mut tokens = vec![DeflateToken::Literal(b'@'), DeflateToken::Literal(b'a')];
    tokens.push(DeflateToken::new_ref(258, 1));
    tokens.extend(std::iter::repeat_n(DeflateToken::new_ref(258, 258), 299));
    let (compressed, contents, plain) = synthetic_stream(tokens);
    let parameters = {
        let mut canonical_configuration = synthetic_params();
        canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
        canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(0));
        canonical_configuration.set_max_chain(4);
        canonical_configuration.set_matching_type(MatchingType::Greedy);
        canonical_configuration
    };
    let unsupported_boundary = {
        let mut canonical_configuration = parameters;
        canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirstWith32KBoundary);
        canonical_configuration
    };
    let before = measure(&contents, &plain, &unsupported_boundary).unwrap();
    assert!(before.trace.mismatch_count >= 2);
    verify(&before, &plain, &compressed);
    for after in [
        measure(&contents, &plain, &parameters).unwrap(),
        measure_normalized(&contents, &plain, &parameters).unwrap(),
    ] {
        assert_eq!(after.trace.mismatch_count, 0);
        assert!(after.corrections.len() < before.corrections.len());
        verify(&after, &plain, &compressed);
    }
}

#[test]
fn generic_search_depth_does_not_imply_a_short_nice_length() {
    let prefix = b"@abcdefghijklmnopqrstu#";
    let mut tokens: Vec<_> = prefix.iter().copied().map(DeflateToken::Literal).collect();
    tokens.push(DeflateToken::new_ref(3, prefix.len() as u32 - 1));
    tokens.push(DeflateToken::Literal(b'%'));
    tokens.push(DeflateToken::new_ref(11, prefix.len() as u32 + 3));
    tokens.extend([DeflateToken::Literal(b'!'), DeflateToken::Literal(b'$')]);
    tokens.push(DeflateToken::new_ref(21, prefix.len() as u32 + 16));
    let (compressed, contents, plain) = synthetic_stream(tokens);
    let parameters = estimate_preflate_parameters(&contents, &plain).unwrap();
    assert_eq!(parameters.matching_type(), MatchingType::Greedy);
    assert_eq!(parameters.max_chain(), 3);
    assert_eq!(parameters.nice_length(), 255);
    let measured = measure(&contents, &plain, &parameters).unwrap();
    verify(&measured, &plain, &compressed);
    assert_eq!(measured.trace.mismatch_count, 0);
}

#[test]
fn ambiguous_prefix_insertion_keeps_later_four_byte_match_interiors() {
    for endpoint_observed in [false, true] {
        let mut tokens: Vec<_> = b"@abc".iter().copied().map(DeflateToken::Literal).collect();
        tokens.extend([DeflateToken::new_ref(3, 3), DeflateToken::new_ref(3, 2)]);
        tokens.extend(b"@abcdef".iter().copied().map(DeflateToken::Literal));
        tokens.push(DeflateToken::new_ref(4, 6));
        if endpoint_observed {
            tokens.push(DeflateToken::new_ref(3, 1));
        }
        let (_, mut prefix, prefix_plain) = synthetic_stream(tokens.clone());
        prefix.blocks.last_mut().unwrap().last = false;
        let policy = estimate_preflate_parameters(&prefix, &prefix_plain)
            .unwrap()
            .add_policy();
        assert_eq!(policy, DictionaryAddPolicy::AddFirst(4));
        tokens.push(DeflateToken::new_ref(
            3,
            if endpoint_observed { 6 } else { 3 },
        ));
        tokens.extend([DeflateToken::Literal(b'!'), DeflateToken::Literal(b'$')]);
        let (compressed, contents, plain) = synthetic_stream(tokens);
        for hash in [
            HashAlgorithm::RandomVector,
            HashAlgorithm::Zlib {
                hash_mask: 32767,
                hash_shift: 5,
            },
        ] {
            let parameters = {
                let mut canonical_configuration = synthetic_params();
                canonical_configuration.set_hash_algorithm(hash);
                canonical_configuration.set_insertion(policy);
                canonical_configuration.set_matching_type(MatchingType::Greedy);
                canonical_configuration
            };
            let measured = measure(&contents, &plain, &parameters).unwrap();
            verify(&measured, &plain, &compressed);
        }
    }
}

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
        let measurement =
            measure_with_tracking(&contents, &plain, &params, false, false, 32768).unwrap();
        let score = crate::estimator::test_support::score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                (&params).into(),
            ),
            &contents.blocks,
            &plain,
            usize::MAX,
            u32::MAX,
        );
        assert!(score.1 <= 32768);
        let mut remaining = score.1;
        let mut end = 0;
        'blocks: for block in &contents.blocks {
            match &block.block_type {
                DeflateTokenBlockType::Stored { uncompressed } => {
                    end += uncompressed.len() as u32;
                }
                DeflateTokenBlockType::Huffman { tokens, .. } => {
                    for token in tokens {
                        if remaining == 0 {
                            break 'blocks;
                        }
                        end += match token {
                            DeflateToken::Literal(_) => 1,
                            DeflateToken::Reference(reference) => reference.len(),
                        };
                        remaining -= 1;
                    }
                }
            }
        }
        assert_eq!(remaining, 0);
        assert_eq!(
            score.0,
            measurement
                .trace
                .first_mismatches
                .iter()
                .filter(|(position, _, _)| *position < end)
                .count(),
            "{name}"
        );
        if score.1 == measurement.trace.token_count {
            assert_eq!(score.0, measurement.trace.mismatch_count, "{name}");
        }
        for limit in [0, 1, 257, 1024] {
            let (mismatches, tokens) = crate::estimator::test_support::score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    (&params).into(),
                ),
                &contents.blocks,
                &plain,
                limit,
                262144,
            );
            let informative = contents
                .blocks
                .iter()
                .flat_map(|block| match &block.block_type {
                    DeflateTokenBlockType::Huffman { tokens, .. } => tokens.as_slice(),
                    DeflateTokenBlockType::Stored { .. } => &[],
                })
                .take(tokens)
                .filter(|token| !matches!(token, DeflateToken::Reference(reference) if reference.dist() == 1 && reference.len() == 258))
                .count();
            assert!(informative <= limit);
            assert!(tokens <= 32768);
            assert!(mismatches <= tokens);
        }
        assert_eq!(
            crate::estimator::test_support::score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    (&params).into()
                ),
                &contents.blocks,
                &plain,
                1024,
                0
            ),
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
            let params = {
                let mut canonical_configuration = synthetic_params();
                canonical_configuration
                    .set_hash_algorithm(HashAlgorithm::Chromium { hash_mask: 0x7fff });
                canonical_configuration.set_short_match_cutoff(4096);
                canonical_configuration.set_matching_type(matching_type);
                canonical_configuration
            };
            let measured = measure(&contents, &plain, &params).unwrap();
            verify(&measured, &plain, &compressed);
            assert_eq!(measured.trace.mismatch_count, 0);
            assert_eq!(
                crate::estimator::test_support::score_predictions(
                    &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                        (&params).into()
                    ),
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
fn native_chromium_without_three_byte_aliases_is_considered() {
    use crate::{estimator::test_support::extract_preflate_info, utils::read_file};

    let expected_plain = read_file("chromium_no_short_input.bin");
    for level in [1, 6] {
        let compressed = read_file(&format!(
            "compressed_chromium_no_short_level{level}.deflate"
        ));
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(plain.text(), expected_plain);
        let info = extract_preflate_info(&contents.blocks);
        assert_eq!(info.short_reference_count, 0);
        let parameters = estimate_preflate_parameters(&contents, &plain).unwrap();
        assert_eq!(
            parameters.hash_algorithm(),
            HashAlgorithm::Chromium { hash_mask: 0x7fff },
            "level={level}"
        );
        let ambiguous = {
            let mut canonical_configuration = parameters;
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4Fast);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(4));
            canonical_configuration.set_nice_length(16);
            canonical_configuration.set_max_chain(6);
            canonical_configuration.set_matching_type(MatchingType::Greedy);
            canonical_configuration
        };
        assert!(
            crate::estimator::test_support::score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    (&ambiguous).into()
                ),
                &contents.blocks,
                &plain,
                4096,
                524288
            )
            .0 >= 2
        );
        assert_eq!(
            crate::estimator::test_support::refine_ambiguous_profile(
                ambiguous, &info, &contents, &plain
            ),
            parameters
        );
        let measured = measure(&contents, &plain, &parameters).unwrap();
        verify(&measured, &plain, &compressed);
        assert_eq!(measured.trace.mismatch_count, 0, "level={level}");
        assert!(measured.corrections.len() <= 32, "level={level}");
        assert_eq!(
            crate::estimator::test_support::refine_ambiguous_profile(
                parameters, &info, &contents, &plain
            ),
            parameters
        );
    }
}

#[test]
fn native_chromium_all_levels_select_and_reconstruct() {
    use crate::{parameters::PreflateStrategy, utils::read_file};

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
        // Explicit lazy/window settings need one more header byte at levels 8 and 9.
        let max_correction_bytes = if level >= 8 { 33 } else { 32 };
        assert!(
            measured.corrections.len() <= max_correction_bytes,
            "automatic level={level}: {} correction bytes",
            measured.corrections.len()
        );
        if level == 0 {
            assert_eq!(automatic.strategy(), PreflateStrategy::Store);
            continue;
        }
        assert_eq!(
            automatic.hash_algorithm(),
            HashAlgorithm::Chromium { hash_mask: 0x7fff }
        );
        let config = if level < 4 {
            &crate::estimator::test_support::zlib::ZLIB_PREFLATE_PARSER_SETTINGS[level - 1]
        } else {
            &SLOW_PREFLATE_PARSER_SETTINGS[level - 4]
        };
        let canonical = {
            let mut canonical_configuration = automatic;
            canonical_configuration.set_full_window(false);
            canonical_configuration.set_window_bits(15);
            canonical_configuration.set_insertion(config.dictionary_add_policy);
            canonical_configuration.set_nice_length(config.nice_length);
            canonical_configuration.set_max_chain(config.max_chain);
            canonical_configuration.set_short_match_cutoff(if level < 4 { 32768 } else { 4096 });
            canonical_configuration.set_matching_type(config.parser.matching_type());
            canonical_configuration
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
        let params = {
            let mut canonical_configuration = synthetic_params();
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4);
            canonical_configuration.set_max_chain(101);
            canonical_configuration
                .set_matching_type(MatchingType::LibdeflateLazy { two_positions });
            canonical_configuration
        };
        let measurement = measure(&contents, &plain, &params).unwrap();
        verify(&measurement, &plain, &compressed);
        assert_eq!(
            crate::estimator::test_support::score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    (&params).into()
                ),
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
        (lazy, synthetic_params().hash_algorithm(), true, true),
        (lazy, synthetic_params().hash_algorithm(), true, false),
        (
            MatchingType::Greedy,
            synthetic_params().hash_algorithm(),
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
            let base = {
                let mut canonical_configuration = synthetic_params();
                canonical_configuration.set_hash_algorithm(hash_algorithm);
                canonical_configuration.set_matching_type(matching_type);
                canonical_configuration
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
fn filtered_parameters_roundtrip_across_chunks() {
    let tokens = b"@abcdXabcdYabcdZabcdW"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    let (compressed, contents, plain) = synthetic_stream(tokens);
    let params = {
        let mut canonical_configuration = synthetic_params();
        canonical_configuration.set_matching_type(MatchingType::Lazy {
            max_lazy: 16,
            filtered_matching: true,
            behavior: LazyBehavior::Zlib { good_length: 8 },
        });
        canonical_configuration
    };
    let modern = measure(&contents, &plain, &params).unwrap();
    verify(&modern, &plain, &compressed);
    assert_eq!(modern.trace.mismatch_count, 0);

    let mut predictor = TokenPredictor::from_parameters(&params);
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
            ReconstructionData {
                parameters: predictor.finalize_reconstruction_parameters(),
                corrections: buffer,
            }
            .write()
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
    params: &ReconstructionParameters,
) -> Result<Measurement> {
    measure_with_short_match_bounds(contents, plain_text, params, false)
}

fn measure_with_short_match_bounds(
    contents: &DeflateContents,
    plain_text: &PlainText,
    params: &ReconstructionParameters,
    track_bounds: bool,
) -> Result<Measurement> {
    measure_with_tracking(contents, plain_text, params, track_bounds, false, 8)
}

fn measure_normalized(
    contents: &DeflateContents,
    plain_text: &PlainText,
    params: &ReconstructionParameters,
) -> Result<Measurement> {
    measure_with_tracking(contents, plain_text, params, false, true, 8)
}

fn measure_with_tracking(
    contents: &DeflateContents,
    plain_text: &PlainText,
    params: &ReconstructionParameters,
    track_bounds: bool,
    normalize_parameters: bool,
    trace_limit: usize,
) -> Result<Measurement> {
    let mut buffer = Vec::new();
    let mut encoder = (
        CorrectionCounter::default(),
        PredictionEncoderCabac::new(VP8Writer::new(&mut buffer).unwrap()),
    );
    let mut predictor = TokenPredictor::from_parameters(params);
    if normalize_parameters {
        predictor.enable_parameter_normalization(
            contents.compressed_size,
            contents.blocks.last().is_some_and(|block| block.last),
        );
    }
    if track_bounds {
        predictor.track_short_match_distance();
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
    let short_match_distance_bounds = predictor.short_match_distance_bounds();
    let corrections = ReconstructionData {
        parameters: if normalize_parameters {
            predictor.finalize_reconstruction_parameters()
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
        short_match_distance_bounds,
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
    params: ReconstructionParameters,
) -> (&'static str, Option<u32>, ReconstructionParameters) {
    let (profile, default) = match (params.hash_algorithm(), params.matching_type()) {
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
    let candidate = {
        let mut canonical_configuration = params;
        canonical_configuration.set_short_match_cutoff(
            default.map_or(params.max_dist_3_matches(), |limit| {
                limit.max(params.max_dist_3_matches())
            }),
        );
        canonical_configuration
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
        SLOW_PREFLATE_PARSER_SETTINGS[2].parser.matching_type(),
    ] {
        let params = {
            let mut canonical_configuration = synthetic_params();
            canonical_configuration.set_short_match_cutoff(0);
            canonical_configuration.set_matching_type(matching_type);
            canonical_configuration
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
    let params = {
        let mut canonical_configuration = synthetic_params();
        canonical_configuration.set_short_match_cutoff(4);
        canonical_configuration
            .set_matching_type(SLOW_PREFLATE_PARSER_SETTINGS[2].parser.matching_type());
        canonical_configuration
    };
    let baseline = measure(&contents, &plain, &params).unwrap();
    let (_, _, candidate) = standard_short_match_cutoff(params);
    let measurement = measure(&contents, &plain, &candidate).unwrap();
    verify(&baseline, &plain, &compressed);
    verify(&measurement, &plain, &compressed);
    assert_eq!(baseline.trace.mismatch_count, 0);
    assert_eq!(measurement.trace.mismatch_count, 0);
    assert_eq!(
        InspectedReconstructionData::read(&baseline.corrections)
            .unwrap()
            .corrections,
        InspectedReconstructionData::read(&measurement.corrections)
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
    let params = {
        let mut canonical_configuration = synthetic_params();
        canonical_configuration.set_short_match_cutoff(4097);
        canonical_configuration
            .set_matching_type(SLOW_PREFLATE_PARSER_SETTINGS[2].parser.matching_type());
        canonical_configuration
    };
    let (_, default, candidate) = standard_short_match_cutoff(params);
    assert_eq!(default, Some(4096));
    let normalized = measure_normalized(&contents, &plain, &params).unwrap();
    verify(&normalized, &plain, &compressed);
    let normalized_record = InspectedReconstructionData::read(&normalized.corrections).unwrap();
    assert!(normalized_record.parameters.max_dist_3_matches() >= 4097);
    assert_eq!(
        normalized_record.corrections,
        InspectedReconstructionData::read(
            &measure(&contents, &plain, &params).unwrap().corrections
        )
        .unwrap()
        .corrections,
    );
    let retained = measure(&contents, &plain, &candidate).unwrap();
    let clamped = measure(&contents, &plain, &{
        let mut canonical_configuration = params;
        canonical_configuration.set_short_match_cutoff(4096);
        canonical_configuration
    })
    .unwrap();
    verify(&retained, &plain, &compressed);
    verify(&clamped, &plain, &compressed);
    assert!(clamped.trace.mismatch_count > retained.trace.mismatch_count);
}

#[test]
fn lazy_cutoff_equivalence_reuses_the_next_fresh_search() {
    let mut tokens: Vec<_> = b"@abcX"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.push(DeflateToken::new_ref(3, 4));
    tokens.extend(b"Y#bcZ12345!a".iter().copied().map(DeflateToken::Literal));
    tokens.push(DeflateToken::new_ref(8, 10));
    let (compressed, contents, plain) = synthetic_stream(tokens);
    for hash_algorithm in [
        HashAlgorithm::Zlib {
            hash_mask: 2047,
            hash_shift: 4,
        },
        crate::estimator::test_support::zlib::DEFAULT_HASH,
        HashAlgorithm::RandomVector,
    ] {
        for behavior in [
            LazyBehavior::Zlib { good_length: 8 },
            LazyBehavior::RecomputeAfterLiteral,
        ] {
            let parameters = {
                let mut canonical_configuration = synthetic_params();
                canonical_configuration.set_hash_algorithm(hash_algorithm);
                canonical_configuration.set_short_match_cutoff(4);
                canonical_configuration.set_matching_type(MatchingType::Lazy {
                    max_lazy: 16,
                    filtered_matching: false,
                    behavior,
                });
                canonical_configuration
            };
            let before =
                measure_with_short_match_bounds(&contents, &plain, &parameters, true).unwrap();
            assert_eq!(before.short_match_distance_bounds, Some((4, 13)));
            let after = measure_normalized(&contents, &plain, &parameters).unwrap();
            verify(&after, &plain, &compressed);
            assert_eq!(after.short_match_distance_bounds, Some((4, 32768)));
            let record = InspectedReconstructionData::read(&after.corrections).unwrap();
            assert_eq!(record.parameters.max_dist_3_matches(), 128);
            let original = InspectedReconstructionData::read(&before.corrections)
                .unwrap()
                .corrections;
            assert_eq!(record.corrections, original);
            assert!(after.corrections.len() <= before.corrections.len());
            for cutoff in 4..=255 {
                let candidate = {
                    let mut canonical_configuration = parameters;
                    canonical_configuration.set_short_match_cutoff(cutoff);
                    canonical_configuration
                };
                let measured = measure(&contents, &plain, &candidate).unwrap();
                verify(&measured, &plain, &compressed);
                assert_eq!(
                    InspectedReconstructionData::read(&measured.corrections)
                        .unwrap()
                        .corrections,
                    original
                );
            }
            let repeated = measure_normalized(&contents, &plain, &record.parameters).unwrap();
            assert_eq!(repeated.corrections, after.corrections);
        }
    }
}

#[test]
fn lazy_cutoff_equivalence_preserves_randomized_collision_streams() {
    for seed in 0..6u32 {
        let mut random = seed + 1;
        let mut next = || {
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            random
        };
        let mut tokens = vec![DeflateToken::Literal(b'@')];
        tokens.extend((0..32).map(|_| DeflateToken::Literal(b'a' + (next() % 4) as u8)));
        let mut position = 33;
        for _ in 0..80 {
            if next() % 3 == 0 {
                tokens.push(DeflateToken::Literal(b'a' + (next() % 4) as u8));
                position += 1;
            } else {
                let length = 3 + next() % 12;
                let distance = 1 + next() % (position - 1).min(128);
                tokens.push(DeflateToken::new_ref(length, distance));
                position += length;
            }
        }
        let (compressed, contents, plain) = synthetic_stream(tokens);
        assert!(compressed.len() < 1024);
        for hash_algorithm in [
            HashAlgorithm::Zlib {
                hash_mask: 15,
                hash_shift: 2,
            },
            crate::estimator::test_support::zlib::DEFAULT_HASH,
            HashAlgorithm::RandomVector,
        ] {
            for cutoff in [0, 4, 128] {
                for behavior in [
                    LazyBehavior::Zlib { good_length: 4 },
                    LazyBehavior::RecomputeAfterLiteral,
                ] {
                    let parameters = {
                        let mut canonical_configuration = synthetic_params();
                        canonical_configuration.set_hash_algorithm(hash_algorithm);
                        canonical_configuration.set_window_bits(9);
                        canonical_configuration.set_nice_length([3, 4, 128][seed as usize % 3]);
                        canonical_configuration.set_max_chain([1, 4, 128][seed as usize % 3]);
                        canonical_configuration.set_short_match_cutoff(cutoff);
                        canonical_configuration.set_matching_type(MatchingType::Lazy {
                            max_lazy: 16,
                            filtered_matching: false,
                            behavior,
                        });
                        canonical_configuration
                    };
                    let before = measure(&contents, &plain, &parameters).unwrap();
                    let after = measure_normalized(&contents, &plain, &parameters).unwrap();
                    verify(&after, &plain, &compressed);
                    let before = InspectedReconstructionData::read(&before.corrections).unwrap();
                    let record = InspectedReconstructionData::read(&after.corrections).unwrap();
                    assert_eq!(record.corrections, before.corrections);
                    let repeated =
                        measure_normalized(&contents, &plain, &record.parameters).unwrap();
                    assert_eq!(repeated.corrections, after.corrections);
                }
            }
        }
    }
}

#[test]
fn lazy_cutoff_equivalence_retains_constraints_at_block_boundaries() {
    use crate::deflate::deflate_token::DeflateTokenBlock;
    let mut tokens: Vec<_> = b"@abcX"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.push(DeflateToken::new_ref(3, 4));
    tokens.extend(b"Y#bcZ12345!a".iter().copied().map(DeflateToken::Literal));
    let mut writer = DeflateWriter::new();
    for (tokens, last) in [(tokens, false), (vec![DeflateToken::new_ref(8, 10)], true)] {
        writer
            .encode_block(&DeflateTokenBlock {
                block_type: DeflateTokenBlockType::Huffman {
                    tokens,
                    huffman_type: DeflateHuffmanType::Static,
                },
                last,
            })
            .unwrap();
    }
    writer.flush();
    let compressed = writer.detach_output();
    let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
    let parameters = {
        let mut canonical_configuration = synthetic_params();
        canonical_configuration.set_short_match_cutoff(4);
        canonical_configuration
            .set_matching_type(SLOW_PREFLATE_PARSER_SETTINGS[2].parser.matching_type());
        canonical_configuration
    };
    let before = measure(&contents, &plain, &parameters).unwrap();
    let after = measure_normalized(&contents, &plain, &parameters).unwrap();
    verify(&after, &plain, &compressed);
    assert_eq!(after.short_match_distance_bounds, Some((4, 13)));
    assert_eq!(
        InspectedReconstructionData::read(&before.corrections)
            .unwrap()
            .corrections,
        InspectedReconstructionData::read(&after.corrections)
            .unwrap()
            .corrections
    );
}

#[test]
fn short_match_distance_bounds_preserve_decisions_and_exclude_counterexamples() {
    let tokens = b"@abcXabcY#defX12345defY"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    let (compressed, contents, plain) = synthetic_stream(tokens);
    let params = {
        let mut canonical_configuration = synthetic_params();
        canonical_configuration.set_short_match_cutoff(4);
        canonical_configuration
    };
    let baseline = measure_with_short_match_bounds(&contents, &plain, &params, true).unwrap();
    verify(&baseline, &plain, &compressed);
    let bounds = baseline.short_match_distance_bounds.unwrap();
    assert_eq!(bounds, (4, 8));
    let normalized = measure_normalized(&contents, &plain, &params).unwrap();
    verify(&normalized, &plain, &compressed);
    let normalized_record = InspectedReconstructionData::read(&normalized.corrections).unwrap();
    assert_eq!(normalized_record.parameters.max_dist_3_matches(), 8);
    assert_eq!(
        normalized_record.corrections,
        InspectedReconstructionData::read(&baseline.corrections)
            .unwrap()
            .corrections,
    );
    let canonical = params.canonical_short_match_cutoff(bounds);
    assert_eq!(canonical, 8);
    for (limit, expected_mismatches) in [(canonical, 1), (3, 0), (9, 2)] {
        let candidate = {
            let mut canonical_configuration = params;
            canonical_configuration.set_short_match_cutoff(limit);
            canonical_configuration
        };
        let measurement = measure(&contents, &plain, &candidate).unwrap();
        verify(&measurement, &plain, &compressed);
        assert_eq!(measurement.trace.mismatch_count, expected_mismatches);
        if limit == canonical {
            assert_eq!(
                InspectedReconstructionData::read(&measurement.corrections)
                    .unwrap()
                    .corrections,
                InspectedReconstructionData::read(&baseline.corrections)
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
    let zlib = synthetic_params().hash_algorithm();
    for (hash_algorithm, matching_type) in [
        (zlib, MatchingType::Greedy),
        (
            zlib,
            SLOW_PREFLATE_PARSER_SETTINGS[2].parser.matching_type(),
        ),
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
            SLOW_PREFLATE_PARSER_SETTINGS[2].parser.matching_type(),
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
            let params = {
                let mut canonical_configuration = synthetic_params();
                canonical_configuration.set_hash_algorithm(hash_algorithm);
                canonical_configuration.set_short_match_cutoff(cutoff);
                canonical_configuration.set_matching_type(matching_type);
                canonical_configuration
            };
            let baseline = measure(&contents, &plain, &params).unwrap();
            let normalized = measure_normalized(&contents, &plain, &params).unwrap();
            verify(&baseline, &plain, &compressed);
            verify(&normalized, &plain, &compressed);
            let after = InspectedReconstructionData::read(&normalized.corrections).unwrap();
            assert_eq!(
                after.corrections,
                InspectedReconstructionData::read(&baseline.corrections)
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
            assert!((bounds.0..=bounds.1).contains(&after.parameters.max_dist_3_matches()));
            if cutoff == 0 {
                assert_eq!(after.parameters.max_dist_3_matches(), 0);
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
        &mut TokenPredictor::from_parameters(&params),
        &mut actions,
        &mut PreflateInput::new(&plain),
    )
    .unwrap();
    let (replayed, _, _) = overhead_contributions(&actions);
    assert_eq!(
        replayed,
        InspectedReconstructionData::read(&actual.corrections)
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
            &mut TokenPredictor::from_parameters(&params),
            &mut actions,
            &mut PreflateInput::new(&plain),
        )
        .unwrap();
        let (replayed, zero_cabac, components) = overhead_contributions(&actions);
        assert_eq!(
            replayed,
            InspectedReconstructionData::read(&baseline.corrections)
                .unwrap()
                .corrections,
            "{name}"
        );
        let parameter_bytes = params.serialized_size();
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
        let canonical_limit = params.canonical_short_match_cutoff(bounds);
        let canonical = {
            let mut canonical_configuration = params;
            canonical_configuration.set_short_match_cutoff(canonical_limit);
            canonical_configuration
        };
        let canonical_measurement = measure(&contents, &plain, &canonical).unwrap();
        verify(&canonical_measurement, &plain, &compressed);
        let baseline_cabac = InspectedReconstructionData::read(&baseline.corrections)
            .unwrap()
            .corrections;
        assert_eq!(
            InspectedReconstructionData::read(&canonical_measurement.corrections)
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
        for limit in canonical_short_match_limits(bounds, params.max_dist_3_matches()) {
            let candidate = {
                let mut canonical_configuration = params;
                canonical_configuration.set_short_match_cutoff(limit);
                canonical_configuration
            };
            if candidate.serialized_size() > params.serialized_size() {
                continue;
            }
            let measurement = measure(&contents, &plain, &candidate).unwrap();
            verify(&measurement, &plain, &compressed);
            assert_eq!(
                InspectedReconstructionData::read(&measurement.corrections)
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
        let common = {
            let mut canonical_configuration = params;
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Zlib {
                hash_mask: 32767,
                hash_shift: 5,
            });
            canonical_configuration.set_full_window(false);
            canonical_configuration.set_matches_to_start(false);
            canonical_configuration.set_window_bits(15);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(128);
            canonical_configuration.set_max_chain(128);
            canonical_configuration.set_short_match_cutoff(4096);
            canonical_configuration
                .set_matching_type(SLOW_PREFLATE_PARSER_SETTINGS[2].parser.matching_type());
            canonical_configuration
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
            params.max_dist_3_matches(), bounds.0, bounds.1,
            canonical_measurement.corrections.len(), nongrowing.max_dist_3_matches(),
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
            baseline.trace.mismatch_count, params.max_dist_3_matches(),
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
    params: ReconstructionParameters,
    plaintext_length: usize,
) -> Vec<(&'static str, ReconstructionParameters)> {
    let mut control = standard_short_match_cutoff(params).2;
    if params.max_dist_3_matches() == 0 {
        control.set_short_match_cutoff(0);
    }
    let mut libdeflate = control;
    if params.hash_algorithm() == HashAlgorithm::Libdeflate4 && params.max_dist_3_matches() != 0 {
        let cutoff = match params.matching_type() {
            MatchingType::Greedy | MatchingType::LibdeflateGreedy => 4096,
            _ => 8192,
        };
        libdeflate.set_short_match_cutoff(params.max_dist_3_matches().max(cutoff));
    }
    let windows = |cutoff| {
        let mut canonical_configuration = libdeflate;
        canonical_configuration.set_short_match_cutoff(
            if params.hash_algorithm() == HashAlgorithm::RandomVector
                && params.max_dist_3_matches() != 0
            {
                params.max_dist_3_matches().max(cutoff)
            } else {
                libdeflate.max_dist_3_matches()
            },
        );
        canonical_configuration
    };
    let window = |mut candidate: ReconstructionParameters, inert_only: bool| {
        if candidate.window_bits() != 0
            && (!inert_only
                || plaintext_length
                    <= ((1usize << candidate.window_bits())
                        .saturating_sub(crate::deflate::deflate_constants::MIN_LOOKAHEAD as usize)))
        {
            candidate.set_window_bits(15);
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
        synthetic_params().hash_algorithm(),
        HashAlgorithm::RandomVector,
    ] {
        let params = {
            let mut canonical_configuration = synthetic_params();
            canonical_configuration.set_hash_algorithm(hash_algorithm);
            canonical_configuration.set_window_bits(9);
            canonical_configuration.set_short_match_cutoff(0);
            canonical_configuration
        };
        let baseline = measure(&contents, &plain, &params).unwrap();
        verify(&baseline, &plain, &compressed);
        let normalized = measure_normalized(&contents, &plain, &params).unwrap();
        verify(&normalized, &plain, &compressed);
        assert_eq!(
            InspectedReconstructionData::read(&normalized.corrections)
                .unwrap()
                .corrections,
            InspectedReconstructionData::read(&baseline.corrections)
                .unwrap()
                .corrections,
        );
        for (name, candidate) in distance_window_variants(params, plain.len()) {
            let measurement = measure(&contents, &plain, &candidate).unwrap();
            verify(&measurement, &plain, &compressed);
            assert_eq!(candidate.max_dist_3_matches(), 0, "{name}");
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
        let params = {
            let mut canonical_configuration = synthetic_params();
            canonical_configuration.set_window_bits(9);
            canonical_configuration.set_short_match_cutoff(0);
            canonical_configuration
        };
        let candidate = distance_window_variants(params, plain.len())[7].1;
        assert_eq!(candidate.window_bits(), expected_bits);
        let baseline = measure(&contents, &plain, &params).unwrap();
        let measurement = measure(&contents, &plain, &candidate).unwrap();
        verify(&baseline, &plain, &compressed);
        verify(&measurement, &plain, &compressed);
        assert_eq!(
            InspectedReconstructionData::read(&measurement.corrections)
                .unwrap()
                .corrections,
            InspectedReconstructionData::read(&baseline.corrections)
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
        synthetic_params().hash_algorithm(),
        HashAlgorithm::RandomVector,
        HashAlgorithm::Libdeflate4,
    ] {
        let params = {
            let mut canonical_configuration = synthetic_params();
            canonical_configuration.set_hash_algorithm(hash_algorithm);
            canonical_configuration.set_window_bits(9);
            canonical_configuration.set_short_match_cutoff(4);
            canonical_configuration
        };
        let baseline = measure(&contents, &plain, &params).unwrap();
        let candidate = distance_window_variants(params, plain.len())
            .into_iter()
            .find(|(name, _)| *name == "window15_inert_only")
            .unwrap()
            .1;
        assert_eq!(candidate.window_bits(), 15);
        let measurement = measure(&contents, &plain, &candidate).unwrap();
        verify(&baseline, &plain, &compressed);
        verify(&measurement, &plain, &compressed);
        assert_eq!(
            InspectedReconstructionData::read(&measurement.corrections)
                .unwrap()
                .corrections,
            InspectedReconstructionData::read(&baseline.corrections)
                .unwrap()
                .corrections,
        );
        for (_, candidate) in distance_window_variants(
            {
                let mut canonical_configuration = params;
                canonical_configuration.set_short_match_cutoff(9000);
                canonical_configuration
            },
            plain.len(),
        ) {
            assert!(candidate.max_dist_3_matches() >= 9000);
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
        let baseline_cabac = InspectedReconstructionData::read(&baseline.corrections)
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
                    let unchanged = InspectedReconstructionData::read(&measurement.corrections)
                        .unwrap()
                        .corrections
                        == baseline_cabac;
                    if variant == "window15_inert_only" {
                        let control = distance_window_variants(params, plain.len())[1].1;
                        let control_measurement = measure(&contents, &plain, &control).unwrap();
                        assert_eq!(
                            InspectedReconstructionData::read(&control_measurement.corrections)
                                .unwrap()
                                .corrections,
                            InspectedReconstructionData::read(&measurement.corrections)
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
fn unobserved_insertion_normalization_preserves_predictions_across_parsers() {
    let mut tokens: Vec<_> = b"@abcX"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.push(DeflateToken::new_ref(3, 4));
    tokens.push(DeflateToken::Literal(b'Y'));
    let (compressed, contents, plain) = synthetic_stream(tokens);
    for matching_type in [
        MatchingType::Greedy,
        SLOW_PREFLATE_PARSER_SETTINGS[2].parser.matching_type(),
        MatchingType::MiniZ {
            max_probes: 3,
            greedy: true,
        },
        MatchingType::LibdeflateGreedy,
        MatchingType::LibdeflateLazy {
            two_positions: true,
        },
        MatchingType::WindowsLazy { max_lazy: 128 },
    ] {
        for add_policy in [
            DictionaryAddPolicy::AddFirst(2),
            DictionaryAddPolicy::AddFirst(3),
            DictionaryAddPolicy::AddFirstAndLast(2),
            DictionaryAddPolicy::AddFirstAndLast(3),
        ] {
            let parameters = {
                let mut canonical_configuration = synthetic_params();
                canonical_configuration.set_insertion(add_policy);
                canonical_configuration.set_short_match_cutoff(4);
                canonical_configuration.set_matching_type(matching_type);
                canonical_configuration
            };
            let mut profile = crate::estimator::test_support::CompressorProfile::Custom
                .with_parameters(parameters);
            crate::estimator::test_support::canonicalize_unobserved_insertion(
                &mut profile.reconstruction,
                extract_preflate_info(&contents.blocks).max_len,
            );
            let before = measure(&contents, &plain, &parameters).unwrap();
            let after = measure_normalized(&contents, &plain, &profile.reconstruction).unwrap();
            verify(&after, &plain, &compressed);
            assert_eq!(
                InspectedReconstructionData::read(&before.corrections)
                    .unwrap()
                    .corrections,
                InspectedReconstructionData::read(&after.corrections)
                    .unwrap()
                    .corrections
            );
            assert!(after.corrections.len() <= before.corrections.len());
        }
    }
}

#[test]
fn reconstruction_token_reservation_is_bounded_by_available_plaintext() {
    let (compressed, contents, plain) = synthetic_stream(vec![DeflateToken::Literal(b'a'); 127]);
    let parameters = {
        let mut canonical_configuration = synthetic_params();
        canonical_configuration.max_token_count = u16::MAX;
        canonical_configuration
    };
    let measured = measure(&contents, &plain, &parameters).unwrap();
    let record = InspectedReconstructionData::read(&measured.corrections).unwrap();
    let mut decoder =
        PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&record.corrections)).unwrap());
    let (recreated, blocks) = decode_mispredictions(
        &record.parameters,
        &mut PreflateInput::new(&plain),
        &mut decoder,
    )
    .unwrap();
    assert_eq!(recreated, compressed);
    let DeflateTokenBlockType::Huffman { tokens, .. } = &blocks[0].block_type else {
        panic!("expected Huffman block");
    };
    assert_eq!(tokens.len(), 127);
    assert!(tokens.capacity() <= plain.len());
}

#[test]
fn token_limit_normalization_merges_equivalent_final_block_profiles() {
    let (compressed, contents, plain) = synthetic_stream(vec![DeflateToken::Literal(b'a'); 127]);
    let mut shared = None;
    for max_token_count in [511, 1023, 2047, 8191, 16383] {
        let parameters = {
            let mut canonical_configuration = synthetic_params();
            canonical_configuration.max_token_count = max_token_count;
            canonical_configuration
        };
        let before = measure(&contents, &plain, &parameters).unwrap();
        let after = measure_normalized(&contents, &plain, &parameters).unwrap();
        verify(&after, &plain, &compressed);
        let normalized = InspectedReconstructionData::read(&after.corrections).unwrap();
        assert_eq!(normalized.parameters.max_token_count, 1023);
        assert_eq!(
            normalized.corrections,
            InspectedReconstructionData::read(&before.corrections)
                .unwrap()
                .corrections
        );
        assert!(after.corrections.len() <= before.corrections.len());
        if let Some(shared) = &shared {
            assert_eq!(&after.corrections, shared);
        } else {
            shared = Some(after.corrections);
        }
    }
}

#[test]
fn token_limit_normalization_preserves_nonfinal_boundaries_and_windows_parsing() {
    use crate::deflate::deflate_token::DeflateTokenBlock;
    for (count, final_block, matching_type, expected) in [
        (126, false, MatchingType::Greedy, 255),
        (127, false, MatchingType::Greedy, 127),
        (128, false, MatchingType::Greedy, 127),
        (127, true, MatchingType::Greedy, 255),
        (127, true, MatchingType::WindowsLazy { max_lazy: 128 }, 127),
    ] {
        let mut writer = DeflateWriter::new();
        writer
            .encode_block(&DeflateTokenBlock {
                block_type: DeflateTokenBlockType::Huffman {
                    tokens: vec![DeflateToken::Literal(b'a'); count],
                    huffman_type: DeflateHuffmanType::Static,
                },
                last: final_block,
            })
            .unwrap();
        if !final_block {
            writer
                .encode_block(&DeflateTokenBlock {
                    block_type: DeflateTokenBlockType::Huffman {
                        tokens: vec![DeflateToken::Literal(b'b'); 3],
                        huffman_type: DeflateHuffmanType::Static,
                    },
                    last: true,
                })
                .unwrap();
        }
        writer.flush();
        let compressed = writer.detach_output();
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        let parameters = {
            let mut canonical_configuration = synthetic_params();
            canonical_configuration.set_matching_type(matching_type);
            canonical_configuration.max_token_count = 127;
            canonical_configuration
        };
        let before = measure(&contents, &plain, &parameters).unwrap();
        let after = measure_normalized(&contents, &plain, &parameters).unwrap();
        verify(&after, &plain, &compressed);
        let normalized = InspectedReconstructionData::read(&after.corrections).unwrap();
        assert_eq!(normalized.parameters.max_token_count, expected);
        assert_eq!(
            normalized.corrections,
            InspectedReconstructionData::read(&before.corrections)
                .unwrap()
                .corrections
        );
        assert!(after.corrections.len() <= before.corrections.len());
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
    let params = {
        let mut canonical_configuration = synthetic_params();
        canonical_configuration.set_window_bits(9);
        canonical_configuration.set_short_match_cutoff(4);
        canonical_configuration
    };
    let baseline = measure(&contents, &plain, &params).unwrap();
    let normalized = measure_normalized(&contents, &plain, &params).unwrap();
    verify(&normalized, &plain, &compressed);
    assert_eq!(
        InspectedReconstructionData::read(&normalized.corrections)
            .unwrap()
            .parameters
            .window_bits(),
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
        InspectedReconstructionData::read(&partial.corrections)
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
            let before = InspectedReconstructionData::read(&baseline.corrections).unwrap();
            let after = InspectedReconstructionData::read(&normalized.corrections).unwrap();
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
                {
                    let mut canonical_configuration = after.parameters;
                    canonical_configuration.set_window_bits(params.window_bits());
                    canonical_configuration.set_short_match_cutoff(params.max_dist_3_matches());
                    canonical_configuration
                },
                params
            );
            assert!(
                after.parameters.window_bits() >= params.window_bits(),
                "{name}"
            );
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
                assert_eq!(
                    production.parameters.map(|report| report.reconstruction),
                    Some(after.parameters),
                    "{name}"
                );
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
    params: ReconstructionParameters,
    observed_min_len: u32,
    combined: bool,
) -> Vec<ReconstructionParameters> {
    let mut variants = Vec::new();
    let compatible = zlib_compatible(&params);
    let mut add = |candidate: ReconstructionParameters| {
        let candidate = candidate.with_lazy_behavior(compatible, observed_min_len);
        if candidate != params && !variants.contains(&candidate) {
            variants.push(candidate);
        }
    };
    let matching_types = std::iter::once(MatchingType::Greedy).chain(
        SLOW_PREFLATE_PARSER_SETTINGS
            .iter()
            .map(|config| config.parser.matching_type()),
    );
    for matching_type in matching_types {
        add({
            let mut canonical_configuration = params;
            canonical_configuration.set_matching_type(matching_type);
            canonical_configuration
        });
        if combined {
            for nice_length in [8, 10, 14, 16, 30, 32, 64, 65, 128, 130, 258] {
                for max_chain in [
                    params.max_chain(),
                    params.max_chain().saturating_sub(1).max(1),
                    params.max_chain().next_power_of_two(),
                ] {
                    add({
                        let mut canonical_configuration = params;
                        canonical_configuration.set_nice_length(nice_length);
                        canonical_configuration.set_max_chain(max_chain);
                        canonical_configuration.set_matching_type(matching_type);
                        canonical_configuration
                    });
                }
            }
        }
    }
    for nice_length in [8, 10, 14, 16, 30, 32, 64, 65, 128, 130, 258] {
        add({
            let mut canonical_configuration = params;
            canonical_configuration.set_nice_length(nice_length);
            canonical_configuration
        });
    }
    // A chain depth inferred from observed matches is a lower bound, not a search budget.
    for max_chain in [
        params.max_chain().saturating_sub(1).max(1),
        params.max_chain().next_power_of_two(),
    ] {
        add({
            let mut canonical_configuration = params;
            canonical_configuration.set_max_chain(max_chain);
            canonical_configuration
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
    params: &ReconstructionParameters,
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
    let parameters = {
        let mut canonical_configuration = *params;
        canonical_configuration.block_type_strategy = first_type;
        canonical_configuration
    };
    let mut input = PreflateInput::new(plain);
    let mut first = TokenPredictor::from_parameters(&parameters)
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
        statistical_codec::tests::AssertDefaultOnlyDecoder,
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
                                    &mut crate::statistical_codec::tests::AssertDefaultOnlyDecoder {},
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
fn stored_block_lengths_roundtrip() {
    let mut writer = DeflateWriter::new();
    writer
        .encode_block(&DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Stored {
                uncompressed: b"stored block".to_vec(),
            },
            last: true,
        })
        .unwrap();
    writer.flush();
    let compressed = writer.detach_output();
    let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
    let params = estimate_preflate_parameters(&contents, &plain).unwrap();
    let mut predictor = TokenPredictor::from_parameters(&params);
    let mut bytes = Vec::new();
    let mut encoder = PredictionEncoderCabac::new(VP8Writer::new(&mut bytes).unwrap());
    predict_blocks(
        &contents.blocks,
        &mut predictor,
        &mut encoder,
        &mut PreflateInput::new(&plain),
    )
    .unwrap();
    encoder.finish();
    drop(encoder);
    let corrections = ReconstructionData {
        parameters: predictor.finalize_reconstruction_parameters(),
        corrections: bytes,
    }
    .write();
    assert_eq!(
        recreate_whole_deflate_stream(plain.text(), &corrections).unwrap(),
        compressed
    );
}

#[test]
#[ignore = "offline Huffman investigation; requires local .deflate fixtures"]
fn diagnose_huffman_trees() {
    use std::io::Write;

    use crate::{
        deflate::{
            deflate_token::TokenFrequency,
            huffman_calc::{HufftreeBitCalc, calc_bit_lengths},
        },
        statistical_codec::{VerifyPredictionDecoder, VerifyPredictionEncoder},
        tree_predictor::{predict_tree_with_rules, recreate_tree_with_rules},
    };

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
        &[false, true, false],
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
                for settings in crate::estimator::test_support::zlib::ZLIB_PREFLATE_PARSER_SETTINGS
                    .iter()
                    .chain(SLOW_PREFLATE_PARSER_SETTINGS.iter())
                {
                    for min_len in [3, observed_min_len] {
                        let candidate = {
                            let mut canonical_configuration = params;
                            canonical_configuration.set_hash_algorithm(HashAlgorithm::Zlib {
                                hash_mask,
                                hash_shift,
                            });
                            canonical_configuration.set_full_window(false);
                            canonical_configuration.set_window_bits(15);
                            canonical_configuration.set_insertion(settings.dictionary_add_policy);
                            canonical_configuration.set_nice_length(settings.nice_length);
                            canonical_configuration.set_max_chain(settings.max_chain);
                            canonical_configuration
                                .set_matching_type(settings.parser.matching_type());
                            canonical_configuration
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
            let baseline_score = crate::estimator::test_support::score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    (&params).into(),
                ),
                &contents.blocks,
                &plain,
                4096,
                524288,
            )
            .0;
            let observed_min_len = extract_preflate_info(&contents.blocks).min_len;
            let mut candidates: Vec<_> = pdf_parameter_variants(params, observed_min_len)
                .into_iter()
                .map(|candidate| {
                    let score = crate::estimator::test_support::score_predictions(
                        &mut crate::prediction_state::PredictionState::from_reconstruction_parameters((&candidate).into()),
                        &contents.blocks,
                        &plain,
                        4096,
                        524288,
                    )
                    .0;
                    (score, candidate)
                })
                .filter(|(score, _)| *score <= baseline_score)
                .collect();
            candidates.sort_by_key(|(score, _)| *score);
            let mut families = Vec::new();
            for (_, candidate) in candidates {
                let family = (candidate.hash_algorithm(), candidate.matching_type());
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
            params.serialized_size(), baseline.trace.token_count,
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
        if matches!(params.hash_algorithm(), HashAlgorithm::Zlib { .. }) {
            for config in SLOW_PREFLATE_PARSER_SETTINGS {
                for filtered in [false, true] {
                    let mut matching_type = config.parser.matching_type();
                    if let MatchingType::Lazy {
                        filtered_matching, ..
                    } = &mut matching_type
                    {
                        *filtered_matching = filtered;
                    }
                    candidates.push({
                        let mut canonical_configuration = params;
                        canonical_configuration.set_nice_length(config.nice_length);
                        canonical_configuration.set_max_chain(config.max_chain);
                        canonical_configuration.set_matching_type(matching_type);
                        canonical_configuration
                    });
                }
            }
            candidates.push({
                let mut canonical_configuration = params;
                canonical_configuration.set_matching_type(MatchingType::Greedy);
                canonical_configuration
            });
            candidates.push({
                let mut canonical_configuration = params;
                canonical_configuration.set_matching_type(MatchingType::Lazy {
                    max_lazy: 258,
                    filtered_matching: false,
                    behavior: LazyBehavior::RecomputeAfterLiteral,
                });
                canonical_configuration
            });
            for max_probes in [32, 128, 512, 1500] {
                for greedy in [false, true] {
                    candidates.push({
                        let mut canonical_configuration = params;
                        canonical_configuration
                            .set_max_chain(u32::from(max_probes).div_ceil(3) * 3);
                        canonical_configuration
                            .set_matching_type(MatchingType::MiniZ { max_probes, greedy });
                        canonical_configuration
                    });
                }
            }
        } else {
            for hash_algorithm in [params.hash_algorithm(), HashAlgorithm::RandomVector] {
                for filtered_matching in [false, true] {
                    candidates.push({
                        let mut canonical_configuration = params;
                        canonical_configuration.set_hash_algorithm(hash_algorithm);
                        canonical_configuration.set_matching_type(MatchingType::Lazy {
                            max_lazy: 16,
                            filtered_matching,
                            behavior: LazyBehavior::RecomputeAfterLiteral,
                        });
                        canonical_configuration
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
                candidates.push({
                    let mut canonical_configuration = params;
                    canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4);
                    canonical_configuration.set_nice_length(nice_length);
                    canonical_configuration.set_max_chain(max_chain);
                    canonical_configuration.set_short_match_cutoff(4096);
                    canonical_configuration.set_matching_type(matching_type);
                    canonical_configuration
                });
            }
        }
        for (index, candidate) in candidates.iter().enumerate() {
            if candidates[..index].contains(candidate) {
                continue;
            }
            let (prefix_errors, prefix_tokens) = crate::estimator::test_support::score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    candidate.into(),
                ),
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
#[ignore = "offline miniz-assignment investigation; requires local fixtures and PREFLATE_FAMILY_RESULTS"]
fn diagnose_miniz_profile_selection() {
    use std::io::Write;

    let path = std::env::var_os("PREFLATE_FAMILY_RESULTS").expect("set PREFLATE_FAMILY_RESULTS");
    let mut output = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap(),
    );
    writeln!(
        output,
        "case\ttrial\tprefix_errors\tbytes\tmismatches\tparams"
    )
    .unwrap();
    let mut files: Vec<_> = std::fs::read_dir(fixture_directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|file| file.extension().is_some_and(|ext| ext == "deflate"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .deflate fixtures found");
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy();
        let compressed = std::fs::read(&file).unwrap();
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len());
        let info = extract_preflate_info(&contents.blocks);
        let params = estimate_preflate_parameters(&contents, &plain).unwrap();
        println!(
            "PROFILE_INFO {name}: max_distance={} max_short_distance={} min_length={} inferred={params:?}",
            info.max_dist, info.max_dist_3_matches, info.min_len,
        );
        let baseline = measure(&contents, &plain, &params).unwrap();
        verify(&baseline, &plain, &compressed);
        writeln!(
            output,
            "{name}\tbaseline\t0\t{}\t{}\t{params:?}",
            baseline.corrections.len(),
            baseline.trace.mismatch_count,
        )
        .unwrap();
        let shallow = {
            let mut canonical_configuration = params;
            canonical_configuration
                .set_hash_algorithm(crate::estimator::test_support::zlib::DEFAULT_HASH);
            canonical_configuration.set_window_bits(15);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(258);
            canonical_configuration.set_max_chain(3);
            canonical_configuration.set_short_match_cutoff(8191);
            canonical_configuration.set_matching_type(MatchingType::MiniZ {
                max_probes: 3,
                greedy: true,
            });
            canonical_configuration
        };
        let shallow_measurement = measure(&contents, &plain, &shallow).unwrap();
        verify(&shallow_measurement, &plain, &compressed);
        writeln!(
            output,
            "{name}\tnative-shallow\t0\t{}\t{}\t{shallow:?}",
            shallow_measurement.corrections.len(),
            shallow_measurement.trace.mismatch_count,
        )
        .unwrap();
        for (position, actual, predicted) in &shallow_measurement.trace.first_mismatches {
            let shape = |token: &DeflateToken| match token {
                DeflateToken::Literal(_) => (0, 0),
                DeflateToken::Reference(reference) => (reference.len(), reference.dist()),
            };
            println!(
                "SHALLOW_RESIDUAL {name}: position={position} actual={:?} predicted={:?}",
                shape(actual),
                shape(predicted),
            );
        }
        let mut candidates = Vec::new();
        for max_probes in [1u16, 3, 6, 9, 16] {
            for greedy in [true, false] {
                candidates.push({
                    let mut canonical_configuration = params;
                    canonical_configuration.set_nice_length(258);
                    canonical_configuration.set_max_chain(u32::from(max_probes).div_ceil(3) * 3);
                    canonical_configuration
                        .set_matching_type(MatchingType::MiniZ { max_probes, greedy });
                    canonical_configuration
                });
            }
        }
        candidates.extend(pdf_parameter_variants(params, info.min_len));
        for hash_algorithm in [params.hash_algorithm(), HashAlgorithm::RandomVector] {
            for nice_length in [3, 8, 32, 258] {
                for max_chain in [1, 2, 4] {
                    candidates.push({
                        let mut canonical_configuration = params;
                        canonical_configuration.set_hash_algorithm(hash_algorithm);
                        canonical_configuration.set_nice_length(nice_length);
                        canonical_configuration.set_max_chain(max_chain);
                        canonical_configuration.set_matching_type(MatchingType::Greedy);
                        canonical_configuration
                    });
                }
            }
        }
        let minimum_window = (32 - info.max_dist.saturating_sub(1).leading_zeros()).max(9);
        let mut variants = Vec::new();
        for candidate in std::iter::once(params).chain(candidates) {
            for window_bits in minimum_window..=15 {
                for very_far_matches_detected in [false, true] {
                    let candidate = {
                        let mut canonical_configuration = candidate;
                        canonical_configuration.set_full_window(very_far_matches_detected);
                        canonical_configuration.set_window_bits(window_bits);
                        canonical_configuration
                    };
                    if !variants.contains(&candidate) {
                        variants.push(candidate);
                    }
                }
            }
        }
        let mut scored: Vec<_> = variants
            .into_iter()
            .map(|candidate| {
                let score = crate::estimator::test_support::score_predictions(
                    &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                        (&candidate).into(),
                    ),
                    &contents.blocks,
                    &plain,
                    4096,
                    524288,
                );
                (score.0, candidate)
            })
            .collect();
        scored.sort_by_key(|(score, _)| *score);
        let mut seen = Vec::new();
        for (score, candidate) in scored {
            let family = (
                candidate.hash_algorithm(),
                candidate.matching_type(),
                candidate.window_bits(),
                candidate.add_policy(),
            );
            if seen.contains(&family) {
                continue;
            }
            seen.push(family);
            match measure(&contents, &plain, &candidate) {
                Ok(measurement) => {
                    verify(&measurement, &plain, &compressed);
                    writeln!(
                        output,
                        "{name}\t{}\t{score}\t{}\t{}\t{candidate:?}",
                        seen.len(),
                        measurement.corrections.len(),
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
                    eprintln!("PROFILE_REJECT {name}: {candidate:?}: {error:?}");
                }
                Err(error) => panic!("unexpected profile error: {error:?}"),
            }
            output.flush().unwrap();
            if seen.len() == 24 {
                break;
            }
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
        let params = if matches!(estimated.hash_algorithm(), HashAlgorithm::Zlib { .. }) {
            estimated
        } else {
            {
                let mut canonical_configuration = estimated;
                canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4);
                canonical_configuration.set_nice_length(130);
                canonical_configuration.set_max_chain(101);
                canonical_configuration.set_short_match_cutoff(4096);
                canonical_configuration.set_matching_type(MatchingType::LibdeflateLazy {
                    two_positions: false,
                });
                canonical_configuration
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
        if matches!(params.hash_algorithm(), HashAlgorithm::Zlib { .. }) {
            for cutoff in [0, 16, 64, 256, 1024] {
                probes.push({
                    let mut canonical_configuration = params;
                    canonical_configuration.set_short_match_cutoff(cutoff);
                    canonical_configuration
                });
            }
        } else {
            for max_chain in [99, 100, 101, 102] {
                for nice_length in [128, 130] {
                    probes.push({
                        let mut canonical_configuration = params;
                        canonical_configuration.set_nice_length(nice_length);
                        canonical_configuration.set_max_chain(max_chain);
                        canonical_configuration
                    });
                }
            }
        }
        for candidate in probes {
            let trial = measure(&contents, &plain, &candidate).unwrap();
            verify(&trial, &plain, &compressed);
            println!(
                "NEIGHBOR {name}: chain={} nice={} cutoff={} bytes={} mismatches={}",
                candidate.max_chain(),
                candidate.nice_length(),
                candidate.max_dist_3_matches(),
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
    assert_eq!(params.max_dist_3_matches(), 0, "{params:?}");
    let measurement = measure(&contents, &plain, &params).unwrap();
    verify(&measurement, &plain, &compressed);
    let baseline = measure(&contents, &plain, &{
        let mut canonical_configuration = params;
        canonical_configuration.set_short_match_cutoff(info.max_dist_3_matches);
        canonical_configuration
    })
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
    assert_eq!(
        production
            .parameters
            .unwrap()
            .reconstruction
            .behavior
            .short_match_cutoff(),
        0
    );
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
        let short_disabled = {
            let mut canonical_configuration = params;
            canonical_configuration.set_short_match_cutoff(0);
            canonical_configuration
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
        let mut state = crate::hash_chain_holder::tests::new_hash_chain_holder(&params);
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
                                        state.match_token_0(2, 1, &input, SearchPurpose::Prediction),
                                        crate::hash_chain_holder::MatchResult::Success(head)
                                            if head.len() == 3 && head.dist() <= params.max_dist_3_matches()
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
                                        state.match_token_0(
                                            0,
                                            params.max_chain(),
                                            &input,
                                            SearchPurpose::Prediction
                                        ),
                                        state.match_token_0(
                                            0,
                                            65535,
                                            &input,
                                            SearchPurpose::Prediction
                                        ),
                                    );
                                }
                                *lengths.entry(reference.len()).or_default() += 1;
                                if reference.len() == 3 {
                                    short_count += 1;
                                    if matches!(
                                        state.match_token_0(2, 1, &input, SearchPurpose::Prediction),
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
            {
                let mut canonical_configuration = short_disabled;
                canonical_configuration.set_nice_length(level8.nice_length);
                canonical_configuration.set_max_chain(level8.max_chain);
                canonical_configuration.set_matching_type(level8.parser.matching_type());
                canonical_configuration
            },
            {
                let mut canonical_configuration = short_disabled;
                canonical_configuration.set_max_chain(1024);
                canonical_configuration.set_matching_type(MatchingType::Lazy {
                    max_lazy: 16,
                    filtered_matching: false,
                    behavior: LazyBehavior::Zlib { good_length: 8 },
                });
                canonical_configuration
            },
        ];
        for limit in [30, 32, 64] {
            for base in [params, candidates[3]] {
                for cutoff in [0, params.max_dist_3_matches()] {
                    candidates.push({
                        let mut canonical_configuration = base;
                        canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(limit));
                        canonical_configuration.set_short_match_cutoff(cutoff);
                        canonical_configuration
                    });
                }
            }
            for nice_length in [32, 64, 128] {
                candidates.push({
                    let mut canonical_configuration = params;
                    canonical_configuration.set_nice_length(nice_length);
                    canonical_configuration
                });
            }
            for config in &SLOW_PREFLATE_PARSER_SETTINGS[2..5] {
                candidates.push({
                    let mut canonical_configuration = params;
                    canonical_configuration.set_nice_length(128);
                    canonical_configuration.set_matching_type(config.parser.matching_type());
                    canonical_configuration
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
            candidates.extend(sweep_neighborhood({
                let mut canonical_configuration = params;
                canonical_configuration.set_hash_algorithm(hash_algorithm);
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
                canonical_configuration.set_nice_length(four_byte_config.nice_length);
                canonical_configuration.set_max_chain(four_byte_config.max_chain);
                canonical_configuration.set_short_match_cutoff(0);
                canonical_configuration.set_matching_type(four_byte_config.parser.matching_type());
                canonical_configuration
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
                let parameters = {
                    let mut canonical_configuration = baseline;
                    canonical_configuration
                        .set_hash_algorithm(HashAlgorithm::Chromium { hash_mask });
                    canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
                    canonical_configuration.set_nice_length(config.nice_length);
                    canonical_configuration.set_max_chain(config.max_chain);
                    canonical_configuration.set_short_match_cutoff(4096);
                    canonical_configuration.set_matching_type(config.parser.matching_type());
                    canonical_configuration
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
#[ignore = "bounded offline insertion-origin audit; requires PREFLATE_REFERENCE"]
fn diagnose_dictionary_insertion_origins() {
    use std::{collections::VecDeque, io::Read};

    use crate::hash_chain::{HashChain, HashChainLibflate4};

    let path = std::env::var_os("PREFLATE_REFERENCE").expect("set PREFLATE_REFERENCE");
    let mut compressed = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut compressed)
        .unwrap();
    assert!(compressed.len() <= 8 * 1024 * 1024);
    let mut prefix = crate::deflate::deflate_reader::DeflateParser::new(32 * 1024 * 1024);
    let first = prefix.parse(&compressed).unwrap();
    let parameters = estimate_preflate_parameters(&first, prefix.plain_text()).unwrap();
    println!("INSERTION parameters={parameters:?}");
    println!(
        "INSERTION first_evidence={:?}",
        extract_preflate_info(&first.blocks).insertion_evidence
    );
    let first_info = extract_preflate_info(&first.blocks);
    println!(
        "INSERTION first_short_references={} first_minimum_length={} first_maximum_block_bytes={} stored_blocks={} stored_bytes={} maximum_distance={} maximum_short_distance={}",
        first_info.short_reference_count,
        first_info.min_len,
        first_info.max_huffman_block_bytes,
        first_info.count_stored_blocks,
        first_info.stored_bytes,
        first_info.max_dist,
        first_info.max_dist_3_matches,
    );
    let first_plain = prefix.detach_plain_text();
    let mut parser = crate::deflate::deflate_reader::DeflateParser::new(128 * 1024 * 1024);
    let contents = parser.parse(&compressed).unwrap();
    assert!(parser.is_done(), "audit exceeds plaintext limit");
    let plain = parser.plain_text();
    println!(
        "INSERTION whole_evidence={:?}",
        extract_preflate_info(&contents.blocks).insertion_evidence
    );
    let mut history: VecDeque<(u32, u32, usize, usize, bool)> = VecDeque::new();
    let mut position = 0u32;
    let mut skipped = 0;
    let mut source_lengths = std::collections::BTreeMap::new();
    let mut dual =
        (parameters.hash_algorithm() == HashAlgorithm::Libdeflate4).then(HashChainLibflate4::new);
    let mut missing_short = 0;
    for (block_index, block) in contents.blocks.iter().enumerate() {
        let block_start = position;
        let mut visit = |token: DeflateToken, token_index: usize, last: bool| {
            if let DeflateToken::Reference(reference) = token {
                let source = position - reference.dist();
                let index = history.partition_point(|entry| entry.0 <= source);
                let &(start, length, source_block, source_token, source_last) =
                    history.get(index - 1).unwrap();
                assert!(source < start + length);
                if reference.len() == 3
                    && let Some(chain) = &dual
                {
                    use crate::hash_algorithm::{HashImplementation, LibdeflateHash4};
                    let mut input = PreflateInput::new(plain);
                    input.advance(position);
                    let mut found = false;
                    let mut first_distances = Vec::new();
                    for distance in chain.iterate::<0>(&input).take(65535) {
                        if distance > 32768 {
                            break;
                        }
                        found |= distance == reference.dist();
                        if first_distances.len() < 8 {
                            first_distances.push(distance);
                        }
                    }
                    if !found {
                        if missing_short < 16 {
                            let head = chain.secondary_match(&input, 0).unwrap();
                            let head_source = position - head;
                            let head_index =
                                history.partition_point(|entry| entry.0 <= head_source);
                            let head_origin = history.get(head_index - 1).unwrap();
                            println!(
                                "DUAL_HASH missing position={position} reference={reference:?} block={block_index} token={token_index} source_origin={:?} secondary_distance={head} secondary_origin={head_origin:?} secondary_prefix_matches={} primary_hash_matches={} first_distances={first_distances:?}",
                                history.get(index - 1).unwrap(),
                                input.cur_chars(-(head as i32))[..3] == input.cur_chars(0)[..3],
                                LibdeflateHash4 {}.get_hash(input.cur_chars(0))
                                    == LibdeflateHash4 {}
                                        .get_hash(input.cur_chars(-(reference.dist() as i32))),
                            );
                        }
                        missing_short += 1;
                    }
                }
                let mut inserted = false;
                parameters.add_policy().update_hash(
                    &plain.text()[start as usize..],
                    start,
                    length,
                    |_, added, count| inserted |= (added..added + count).contains(&source),
                );
                if !inserted {
                    if skipped < 32 {
                        println!(
                            "INSERTION omitted position={position} reference={reference:?} block={block_index} token={token_index} block_offset={} source={source} source_match_start={start} source_match_length={length} source_offset={} source_tail={} source_block={source_block} source_token={source_token} source_last={source_last} start_mod_32k={} end_mod_32k={}",
                            position - block_start,
                            source - start,
                            start + length - source,
                            start & 0x7fff,
                            (start + length) & 0x7fff,
                        );
                    }
                    skipped += 1;
                    *source_lengths.entry(length).or_insert(0usize) += 1;
                }
            }
            let length = match token {
                DeflateToken::Literal(_) => 1,
                DeflateToken::Reference(reference) => reference.len(),
            };
            if let Some(chain) = &mut dual {
                parameters.add_policy().update_hash(
                    &plain.text()[position as usize..],
                    position,
                    length,
                    |bytes, position, count| chain.update_hash(bytes, position, count),
                );
            }
            history.push_back((position, length, block_index, token_index, last));
            position += length;
            while history
                .front()
                .is_some_and(|entry| entry.0 + entry.1 + 32768 < position)
            {
                history.pop_front();
            }
        };
        match &block.block_type {
            DeflateTokenBlockType::Huffman { tokens, .. } => {
                for (index, token) in tokens.iter().copied().enumerate() {
                    visit(token, index, index + 1 == tokens.len());
                }
            }
            DeflateTokenBlockType::Stored { uncompressed } => {
                for (index, byte) in uncompressed.iter().copied().enumerate() {
                    visit(
                        DeflateToken::Literal(byte),
                        index,
                        index + 1 == uncompressed.len(),
                    );
                }
            }
        }
    }
    println!("INSERTION skipped={skipped} source_lengths={source_lengths:?}");
    println!("DUAL_HASH missing_short_references={missing_short}");
    if dual.is_some() {
        let settings = &SLOW_PREFLATE_PARSER_SETTINGS[2];
        let alternative = {
            let mut canonical_configuration = parameters;
            canonical_configuration
                .set_hash_algorithm(crate::estimator::test_support::zlib::DEFAULT_HASH);
            canonical_configuration.set_full_window(false);
            canonical_configuration.set_window_bits(
                crate::estimator::test_support::estimate_preflate_window_bits(first_info.max_dist),
            );
            canonical_configuration.set_nice_length(settings.nice_length);
            canonical_configuration.set_max_chain(settings.max_chain);
            canonical_configuration.set_short_match_cutoff(4096);
            canonical_configuration.set_matching_type(settings.parser.matching_type());
            canonical_configuration
        };
        for (name, candidate) in [("selected", parameters), ("zlib_level6", alternative)] {
            let score = crate::estimator::test_support::score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    (&candidate).into(),
                ),
                &first.blocks,
                &first_plain,
                4096,
                524288,
            );
            let prefix =
                measure_with_tracking(&first, &first_plain, &candidate, false, false, 16).unwrap();
            println!(
                "DUAL_HASH diagnostic_only candidate={name} bounded_score={score:?} prefix_bytes={} prefix_mismatches={}",
                prefix.corrections.len(),
                prefix.trace.mismatch_count,
            );
            if name == "zlib_level6" {
                let mut start = 0;
                for (index, block) in first.blocks.iter().enumerate() {
                    let length: u32 = match &block.block_type {
                        DeflateTokenBlockType::Stored { uncompressed } => uncompressed.len() as u32,
                        DeflateTokenBlockType::Huffman { tokens, .. } => tokens
                            .iter()
                            .map(|token| match token {
                                DeflateToken::Literal(_) => 1,
                                DeflateToken::Reference(reference) => reference.len(),
                            })
                            .sum(),
                    };
                    for &(position, actual, predicted) in &prefix.trace.first_mismatches {
                        if position >= start && position < start + length && position < 524288 {
                            let shape = |token| match token {
                                DeflateToken::Literal(_) => (1, 0),
                                DeflateToken::Reference(reference) => {
                                    (reference.len(), reference.dist())
                                }
                            };
                            println!("QUALITY_MISMATCH position={position} block={index} block_start={start} block_bytes={length} bytes_to_end={} actual_length_distance={:?} predicted_length_distance={:?} followed_by_empty_stored={}",
                                start + length - position, shape(actual), shape(predicted),
                                first.blocks.get(index + 1).is_some_and(|next| matches!(&next.block_type,
                                    DeflateTokenBlockType::Stored { uncompressed } if uncompressed.is_empty())));
                        }
                    }
                    start += length;
                }
                let mut block_prediction = crate::block_predictor::BlockPrediction::default();
                block_prediction.begin_chunk(&first.blocks);
                let leading_score = crate::estimator::test_support::score_predictions(
                    &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                        (&candidate).into(),
                    ),
                    &first.blocks[..first.blocks.len().min(64)],
                    &first_plain,
                    4096,
                    524288,
                );
                println!(
                    "QUALITY_FLUSH whole_chunk_flush_enabled={} first_64_blocks_score={leading_score:?}",
                    block_prediction.flush
                );
            }
            for max_bytes in [
                524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432,
            ] {
                let (errors, tokens) = crate::estimator::test_support::score_predictions(
                    &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                        (&candidate).into(),
                    ),
                    &first.blocks,
                    &first_plain,
                    usize::MAX,
                    max_bytes,
                );
                println!(
                    "QUALITY_SAMPLE candidate={name} max_bytes={max_bytes} errors={errors} tokens={tokens} mismatch_percent={:.3}",
                    100.0 * errors as f64 / tokens.max(1) as f64,
                );
            }
        }
        let measurement = measure(&contents, plain, &alternative).unwrap();
        verify(&measurement, plain, &compressed[..contents.compressed_size]);
        println!(
            "DUAL_HASH diagnostic_only candidate=zlib_level6 whole_bytes={} whole_mismatches={} verified=true",
            measurement.corrections.len(),
            measurement.trace.mismatch_count,
        );
        for (index, settings) in SLOW_PREFLATE_PARSER_SETTINGS.iter().enumerate().skip(3) {
            for hash_algorithm in [
                crate::estimator::test_support::zlib::DEFAULT_HASH,
                HashAlgorithm::Zlib {
                    hash_mask: 4095,
                    hash_shift: 4,
                },
            ] {
                let candidate = {
                    let mut canonical_configuration = alternative;
                    canonical_configuration.set_hash_algorithm(hash_algorithm);
                    canonical_configuration.set_nice_length(settings.nice_length);
                    canonical_configuration.set_max_chain(settings.max_chain);
                    canonical_configuration.set_matching_type(settings.parser.matching_type());
                    canonical_configuration
                };
                let score = crate::estimator::test_support::score_predictions(
                    &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                        (&candidate).into(),
                    ),
                    &first.blocks,
                    &first_plain,
                    4096,
                    524288,
                );
                let measured = measure(&first, &first_plain, &candidate).unwrap();
                println!(
                    "DUAL_HASH diagnostic_only level={} hash={hash_algorithm:?} bounded_score={score:?} prefix_bytes={} prefix_mismatches={}",
                    index + 4,
                    measured.corrections.len(),
                    measured.trace.mismatch_count,
                );
                if measured.trace.mismatch_count == 0 {
                    let whole = measure(&contents, plain, &candidate).unwrap();
                    verify(&whole, plain, &compressed[..contents.compressed_size]);
                    println!(
                        "DUAL_HASH diagnostic_only level={} hash={hash_algorithm:?} whole_bytes={} whole_mismatches={} verified=true",
                        index + 4,
                        whole.corrections.len(),
                        whole.trace.mismatch_count,
                    );
                }
            }
        }
    }
    if matches!(
        parameters.add_policy(),
        DictionaryAddPolicy::AddFirst(3) | DictionaryAddPolicy::AddFirstAndLast(3)
    ) {
        let baseline = measure(&first, &first_plain, &parameters).unwrap();
        println!(
            "INSERTION original_prefix_bytes={} original_prefix_mismatches={}",
            baseline.corrections.len(),
            baseline.trace.mismatch_count,
        );
        for add_policy in [
            DictionaryAddPolicy::AddFirst(4),
            DictionaryAddPolicy::AddFirstAndLast(4),
        ] {
            let candidate = {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_insertion(add_policy);
                canonical_configuration
            };
            let prefix = measure(&first, &first_plain, &candidate).unwrap();
            let measurement = measure(&contents, plain, &candidate).unwrap();
            verify(&measurement, plain, &compressed[..contents.compressed_size]);
            println!(
                "INSERTION diagnostic_only policy={add_policy:?} prefix_bytes={} prefix_mismatches={} whole_bytes={} whole_mismatches={} verified=true",
                prefix.corrections.len(),
                prefix.trace.mismatch_count,
                measurement.corrections.len(),
                measurement.trace.mismatch_count,
            );
        }
    }
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
                    let tail: Vec<_> = tokens
                        .iter()
                        .rev()
                        .take(3)
                        .map(|token| match token {
                            DeflateToken::Literal(_) => (1, 0),
                            DeflateToken::Reference(reference) => {
                                (reference.len(), reference.dist())
                            }
                        })
                        .collect();
                    println!(
                        "BLOCK_END {name}: position={position} tokens={} reversed_tail={tail:?}",
                        tokens.len()
                    );
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

fn sweep_neighborhood(base: ReconstructionParameters) -> Vec<ReconstructionParameters> {
    let mut candidates = vec![base];
    for delta in 1..=8 {
        for max_chain in [
            base.max_chain().saturating_sub(delta).max(1),
            base.max_chain().saturating_add(delta).min(32768),
        ] {
            candidates.push({
                let mut canonical_configuration = base;
                canonical_configuration.set_max_chain(max_chain);
                canonical_configuration
            });
        }
    }
    for max_chain in [
        1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 768, 1024, 1200, 1536, 2048, 3072, 4096, 8192,
        16384, 32768,
    ] {
        candidates.push({
            let mut canonical_configuration = base;
            canonical_configuration.set_max_chain(max_chain);
            canonical_configuration
        });
    }
    for nice_length in [3, 4, 5, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 258] {
        candidates.push({
            let mut canonical_configuration = base;
            canonical_configuration.set_nice_length(nice_length);
            canonical_configuration
        });
    }
    for max_dist_3_matches in [0, 1, 16, 64, 256, 1024, 2048, 4096, 8192, 32768] {
        candidates.push({
            let mut canonical_configuration = base;
            canonical_configuration.set_short_match_cutoff(max_dist_3_matches);
            canonical_configuration
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
        candidates.push({
            let mut canonical_configuration = base;
            canonical_configuration.set_insertion(add_policy);
            canonical_configuration
        });
    }
    for very_far_matches_detected in [false, true] {
        for matches_to_start_detected in [false, true] {
            candidates.push({
                let mut canonical_configuration = base;
                canonical_configuration.set_full_window(very_far_matches_detected);
                canonical_configuration.set_matches_to_start(matches_to_start_detected);
                canonical_configuration
            });
        }
    }
    if let MatchingType::Lazy {
        filtered_matching,
        behavior,
        ..
    } = base.matching_type()
    {
        for max_lazy in [0, 4, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 258] {
            candidates.push({
                let mut canonical_configuration = base;
                canonical_configuration.set_matching_type(MatchingType::Lazy {
                    max_lazy,
                    filtered_matching,
                    behavior,
                });
                canonical_configuration
            });
        }
        if let LazyBehavior::Zlib { .. } = behavior {
            for good_length in [0, 4, 8, 12, 16, 24, 32, 64, 128, 258] {
                if let MatchingType::Lazy { max_lazy, .. } = base.matching_type() {
                    candidates.push({
                        let mut canonical_configuration = base;
                        canonical_configuration.set_matching_type(MatchingType::Lazy {
                            max_lazy,
                            filtered_matching,
                            behavior: LazyBehavior::Zlib { good_length },
                        });
                        canonical_configuration
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
        SLOW_PREFLATE_PARSER_SETTINGS[2].parser.matching_type(),
    ] {
        let base = {
            let mut canonical_configuration = synthetic_params();
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4);
            canonical_configuration.set_matching_type(matching_type);
            canonical_configuration
        };
        let candidates = sweep_neighborhood(base);
        assert!(candidates.contains(&base));
        if (2..32768).contains(&base.max_chain()) {
            for max_chain in [base.max_chain() - 1, base.max_chain() + 1] {
                assert!(candidates.contains(&{
                    let mut canonical_configuration = base;
                    canonical_configuration.set_max_chain(max_chain);
                    canonical_configuration
                }));
            }
        }
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.hash_algorithm() == base.hash_algorithm())
        );
        assert!(candidates.iter().all(|candidate| {
            match (matching_type, candidate.matching_type()) {
                (MatchingType::Lazy { .. }, MatchingType::Lazy { .. }) => true,
                (original, candidate) => original == candidate,
            }
        }));
    }
}

fn oracle_measurement_json(
    parameters: ReconstructionParameters,
    measured: &Measurement,
) -> serde_json::Value {
    serde_json::json!({
        "verified": true,
        "reconstruction_bytes": measured.corrections.len(),
        "token_mismatches": measured.trace.mismatch_count,
        "settings": {
            "hash_algorithm": format!("{:?}", parameters.hash_algorithm()),
            "matching_type": format!("{:?}", parameters.matching_type()),
            "strategy": format!("{:?}", parameters.strategy()),
            "add_policy": format!("{:?}", parameters.add_policy()),
            "block_type_strategy": format!("{:?}", parameters.block_type_strategy),
            "window_bits": parameters.window_bits(),
            "nice_length": parameters.nice_length(),
            "max_chain": parameters.max_chain(),
            "max_token_count": parameters.max_token_count,
            "max_dist_3_matches": parameters.max_dist_3_matches(),
            "matches_to_start_detected": parameters.matches_to_start_detected(),
            "very_far_matches_detected": parameters.very_far_matches_detected(),
        }
    })
}

fn oracle_search(compressed: &[u8]) -> serde_json::Value {
    use std::collections::HashSet;

    let (contents, plain) = parse_deflate_whole(compressed).unwrap();
    assert_eq!(contents.compressed_size, compressed.len());
    let baseline = estimate_preflate_parameters(&contents, &plain).unwrap();
    let measured = measure(&contents, &plain, &baseline).unwrap();
    verify(&measured, &plain, compressed);
    let expected_tokens: usize = contents
        .blocks
        .iter()
        .map(|block| match &block.block_type {
            DeflateTokenBlockType::Stored { .. } => 0,
            DeflateTokenBlockType::Huffman { tokens, .. } => tokens.len(),
        })
        .sum();
    assert_eq!(measured.trace.token_count, expected_tokens);
    let initial = oracle_measurement_json(baseline, &measured);
    let mut best = initial.clone();
    let mut perfect = if measured.trace.mismatch_count == 0 {
        Some(initial.clone())
    } else {
        None
    };
    let info = extract_preflate_info(&contents.blocks);
    let mut candidates = Vec::new();
    // Include coupled tuples with both full-window policies. A prefix cannot prove identity.
    for hash_algorithm in [
        baseline.hash_algorithm(),
        crate::estimator::test_support::zlib::DEFAULT_HASH,
    ] {
        for settings in crate::estimator::test_support::zlib::SLOW_PREFLATE_PARSER_SETTINGS {
            for very_far_matches_detected in [false, true] {
                for window_bits in [baseline.window_bits(), 15] {
                    candidates.push({
                        let mut canonical_configuration = baseline;
                        canonical_configuration.set_hash_algorithm(hash_algorithm);
                        canonical_configuration.set_full_window(very_far_matches_detected);
                        canonical_configuration.set_window_bits(window_bits);
                        canonical_configuration.set_insertion(settings.dictionary_add_policy);
                        canonical_configuration.set_nice_length(settings.nice_length);
                        canonical_configuration.set_max_chain(settings.max_chain);
                        canonical_configuration.set_matching_type(settings.parser.matching_type());
                        canonical_configuration
                    });
                }
            }
            candidates.extend(pdf_parameter_variants(baseline, info.min_len));
            candidates.extend(sweep_neighborhood(baseline));
            candidates.extend(
                distance_window_variants(baseline, plain.len())
                    .into_iter()
                    .map(|(_, parameters)| parameters),
            );
        }
    }
    let mut seen = HashSet::from([bitcode::encode(&baseline)]);
    let mut scored = 1;
    let mut evaluated = 1;
    let mut rejected = 0;
    for stage in 0..2 {
        let mut ranked = Vec::new();
        for parameters in candidates.drain(..) {
            if !seen.insert(bitcode::encode(&parameters)) {
                continue;
            }
            let (errors, _) = crate::estimator::test_support::score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    (&parameters).into(),
                ),
                &contents.blocks,
                &plain,
                4096,
                524288,
            );
            scored += 1;
            ranked.push((errors, parameters));
        }
        ranked.sort_by_key(|row| row.0);
        let seeds: Vec<_> = ranked.iter().take(4).map(|row| row.1).collect();
        for (_, parameters) in ranked.into_iter().take(32) {
            let measured = match measure(&contents, &plain, &parameters) {
                Ok(measured) => measured,
                Err(error)
                    if matches!(
                        error.exit_code(),
                        ExitCode::MatchNotFound | ExitCode::PredictionFailure
                    ) =>
                {
                    rejected += 1;
                    continue;
                }
                Err(error) => panic!("oracle candidate {parameters:?}: {error:?}"),
            };
            assert_eq!(measured.trace.token_count, expected_tokens);
            verify(&measured, &plain, compressed);
            evaluated += 1;
            let record = oracle_measurement_json(parameters, &measured);
            if measured.corrections.len() < best["reconstruction_bytes"].as_u64().unwrap() as usize
            {
                best = record.clone();
            }
            if measured.trace.mismatch_count == 0
                && perfect.as_ref().is_none_or(|previous| {
                    measured.corrections.len()
                        < previous["reconstruction_bytes"].as_u64().unwrap() as usize
                })
            {
                perfect = Some(record);
            }
        }
        if stage == 0 {
            for seed in seeds {
                candidates.extend(sweep_neighborhood(seed));
            }
        }
    }
    serde_json::json!({
        "schema_version": 1,
        "kind": "preflate_oracle",
        "deflate_bytes": compressed.len(),
        "plaintext_bytes": plain.len(),
        "token_count": expected_tokens,
        "candidates_scored": scored,
        "candidates_evaluated": evaluated,
        "baseline": initial,
        "best": best,
        "perfect": perfect,
        "search": {
            "exhaustive": false,
            "prefix_tokens": 4096,
            "prefix_plaintext_bytes": 524288,
            "stages": 2,
            "finalists_per_stage": 32,
            "rejected_candidates": rejected,
            "measurement": "whole-stream reconstruction record; includes parameters and corrections",
            "verification": "full token coverage and byte-exact compressed reconstruction",
        }
    })
}

#[test]
fn oracle_search_reports_whole_stream_verified_nullable_perfection() {
    let compressed = crate::utils::read_file("compressed_zlib_level6.deflate");
    let result = oracle_search(&compressed);
    assert_eq!(result["kind"], "preflate_oracle");
    assert!(
        result["best"]["reconstruction_bytes"].as_u64().unwrap()
            <= result["baseline"]["reconstruction_bytes"].as_u64().unwrap()
    );
    assert_eq!(result["search"]["exhaustive"], false);
    assert!(result["candidates_evaluated"].as_u64().unwrap() <= 65);
    assert!(result["token_count"].as_u64().unwrap() > 0);
    assert_eq!(result["perfect"]["token_mismatches"], 0);
    assert_eq!(result["perfect"]["verified"], true);
}

#[test]
#[ignore = "bounded offline oracle; requires PREFLATE_REFERENCE and PREFLATE_ORACLE_RESULTS"]
fn diagnose_oracle_parameters() {
    let source = std::env::var_os("PREFLATE_REFERENCE").expect("set PREFLATE_REFERENCE");
    let destination =
        std::env::var_os("PREFLATE_ORACLE_RESULTS").expect("set PREFLATE_ORACLE_RESULTS");
    let compressed = std::fs::read(source).unwrap();
    assert!(compressed.len() <= 64 * 1024 * 1024);
    let report = oracle_search(&compressed);
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .unwrap();
    serde_json::to_writer(output, &report).unwrap();
    println!(
        "ORACLE scored={} verified={} baseline={} best={} perfect={}",
        report["candidates_scored"],
        report["candidates_evaluated"],
        report["baseline"]["reconstruction_bytes"],
        report["best"]["reconstruction_bytes"],
        report["perfect"]["reconstruction_bytes"]
    );
}

#[test]
fn noncanonical_insertion_refinement_requires_a_perfect_prefix_and_roundtrips() {
    let compressed = crate::utils::read_file("compressed_zlib_level6.deflate");
    let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
    let info = extract_preflate_info(&contents.blocks);
    let estimated = estimate_preflate_parameters(&contents, &plain).unwrap();
    let baseline = {
        let mut canonical_configuration = estimated;
        canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
        canonical_configuration.set_full_window(true);
        canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(258));
        canonical_configuration.set_nice_length(255);
        canonical_configuration.set_max_chain(3525);
        canonical_configuration
    };
    let before = measure(&contents, &plain, &baseline).unwrap();
    verify(&before, &plain, &compressed);
    let selected = crate::estimator::test_support::refine_ambiguous_profile(
        baseline, &info, &contents, &plain,
    );
    assert_eq!(
        selected.hash_algorithm(),
        crate::estimator::test_support::zlib::DEFAULT_HASH
    );
    assert_eq!(selected.add_policy(), DictionaryAddPolicy::AddAll);
    assert!(!selected.very_far_matches_detected());
    let after = measure(&contents, &plain, &selected).unwrap();
    assert_eq!(after.trace.mismatch_count, 0);
    assert!(after.corrections.len() < before.corrections.len());
    verify(&after, &plain, &compressed);
    assert_eq!(
        crate::estimator::test_support::refine_ambiguous_profile(
            selected, &info, &contents, &plain
        ),
        selected
    );
    let compressed = crate::utils::read_file("compressed_zlib_level1.deflate");
    let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
    let info = extract_preflate_info(&contents.blocks);
    assert!(
        crate::estimator::test_support::score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                (&selected).into()
            ),
            &contents.blocks,
            &plain,
            4096,
            524288
        )
        .0 > 0
    );
    assert_ne!(
        crate::estimator::test_support::refine_ambiguous_profile(
            baseline, &info, &contents, &plain
        ),
        selected
    );
}

#[test]
#[ignore = "bounded release replay; requires PREFLATE_REPLAY_MANIFEST and PREFLATE_REPLAY_RESULTS"]
fn diagnose_selected_streams() {
    use std::io::Read;

    let files: Vec<std::path::PathBuf> = serde_json::from_slice(
        &std::fs::read(std::env::var_os("PREFLATE_REPLAY_MANIFEST").unwrap()).unwrap(),
    )
    .unwrap();
    assert!(!files.is_empty() && files.len() <= 512);
    let start = std::time::Instant::now();
    let mut rows = Vec::new();
    for file in files {
        let mut compressed = Vec::new();
        std::fs::File::open(&file)
            .unwrap()
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut compressed)
            .unwrap();
        assert!(compressed.len() <= 8 * 1024 * 1024);
        let mut parser = crate::deflate::deflate_reader::DeflateParser::new(8 * 1024 * 1024);
        let contents = parser.parse(&compressed).unwrap();
        assert!(parser.is_done(), "incomplete or oversized stream: {file:?}");
        let plain = parser.detach_plain_text();
        assert_eq!(contents.compressed_size, compressed.len());
        let params = estimate_preflate_parameters(&contents, &plain).unwrap();
        let measured = measure_normalized(&contents, &plain, &params)
            .unwrap_or_else(|error| panic!("{file:?}: {params:?}: {error:?}"));
        verify(&measured, &plain, &compressed);
        rows.push(serde_json::json!({
            "file": file,
            "deflate_bytes": compressed.len(),
            "reconstruction_bytes": measured.corrections.len(),
            "correction_coded_bytes": measured.cabac_size,
            "mismatches": measured.trace.mismatch_count,
            "first_mismatches": measured.trace.first_mismatches.iter()
                .map(|(offset, actual, predicted)| serde_json::json!({
                    "offset": offset,
                    "actual": format!("{actual:?}"),
                    "predicted": format!("{predicted:?}"),
                })).collect::<Vec<_>>(),
            "parameters": format!("{params:?}"),
        }));
    }
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(std::env::var_os("PREFLATE_REPLAY_RESULTS").unwrap())
        .unwrap();
    serde_json::to_writer(
        output,
        &serde_json::json!({
            "rows": rows, "wall_seconds": start.elapsed().as_secs_f64(),
        }),
    )
    .unwrap();
}

#[test]
#[ignore = "bounded token boundary trace; requires PREFLATE_REFERENCE"]
fn diagnose_prediction_boundary() {
    use std::io::Read;

    let path = std::env::var_os("PREFLATE_REFERENCE").expect("set PREFLATE_REFERENCE");
    let mut compressed = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut compressed)
        .unwrap();
    assert!(compressed.len() <= 8 * 1024 * 1024);
    let mut parser = crate::deflate::deflate_reader::DeflateParser::new(8 * 1024 * 1024);
    let contents = parser.parse(&compressed).unwrap();
    assert!(parser.is_done());
    let plain = parser.detach_plain_text();
    let parameters = estimate_preflate_parameters(&contents, &plain).unwrap();
    let measured =
        measure_with_tracking(&contents, &plain, &parameters, false, false, 8192).unwrap();
    verify(&measured, &plain, &compressed);
    println!("BOUNDARY parameters={parameters:?}");
    print_measurement("BOUNDARY", &measured, compressed.len());
    for (offset, actual, predicted) in measured.trace.first_mismatches.iter().take(32) {
        println!("BOUNDARY offset={offset} actual={actual:?} predicted={predicted:?}");
    }
    let mut position = 0;
    for (index, block) in contents.blocks.iter().enumerate() {
        let start = position;
        match &block.block_type {
            DeflateTokenBlockType::Huffman { tokens, .. } => {
                for token in tokens {
                    position += match token {
                        DeflateToken::Literal(_) => 1,
                        DeflateToken::Reference(reference) => reference.len(),
                    };
                }
                let errors = measured
                    .trace
                    .first_mismatches
                    .iter()
                    .filter(|entry| (start..position).contains(&entry.0))
                    .count();
                println!(
                    "BOUNDARY block={index} start={start} end={position} tokens={} sampled_errors={errors}",
                    tokens.len()
                );
            }
            DeflateTokenBlockType::Stored { uncompressed } => {
                position += uncompressed.len() as u32;
                println!("BOUNDARY stored={index} start={start} end={position}");
            }
        }
    }
}

#[test]
#[ignore = "bounded offline libdeflate cohort replay; requires PREFLATE_DIAGNOSTICS and PREFLATE_COHORT_RESULTS"]
fn diagnose_libdeflate_cohorts() {
    use std::io::Write;
    let destination =
        std::env::var_os("PREFLATE_COHORT_RESULTS").expect("set PREFLATE_COHORT_RESULTS");
    let mut output = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .unwrap(),
    );
    let mut files: Vec<_> = std::fs::read_dir(fixture_directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "deflate")
        })
        .collect();
    files.sort();
    assert!(!files.is_empty() && files.len() <= 64);
    for file in files {
        let compressed = std::fs::read(&file).unwrap();
        assert!(compressed.len() <= 8 * 1024 * 1024);
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert!(plain.len() <= 8 * 1024 * 1024);
        assert_eq!(contents.compressed_size, compressed.len());
        let info = extract_preflate_info(&contents.blocks);
        let baseline = estimate_preflate_parameters(&contents, &plain).unwrap();
        let prefix = |parameters: &ReconstructionParameters| {
            let score = |tokens, bytes| {
                crate::estimator::test_support::score_predictions(
                    &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                        *parameters,
                    ),
                    &contents.blocks,
                    &plain,
                    tokens,
                    bytes,
                )
            };
            serde_json::json!({"early": score(1024,262144), "late": score(4096,524288)})
        };
        let original = measure(&contents, &plain, &baseline).unwrap();
        verify(&original, &plain, &compressed);
        let mut variants = Vec::new();
        if baseline.hash_algorithm() == HashAlgorithm::Libdeflate4 {
            for cutoff in [4096, 8192, 32768] {
                variants.push(("table_hash", {
                    let mut canonical_configuration = baseline;
                    canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
                    canonical_configuration.set_nice_length(128);
                    canonical_configuration.set_max_chain(128);
                    canonical_configuration.set_short_match_cutoff(cutoff);
                    canonical_configuration.set_matching_type(MatchingType::Lazy {
                        max_lazy: 16,
                        filtered_matching: false,
                        behavior: LazyBehavior::RecomputeAfterLiteral,
                    });
                    canonical_configuration
                }));
            }
        } else {
            for hash_algorithm in [
                baseline.hash_algorithm(),
                crate::estimator::test_support::zlib::DEFAULT_HASH,
                HashAlgorithm::RandomVector,
            ] {
                for filtered_matching in [false, true] {
                    for max_chain in [
                        baseline.max_chain(),
                        baseline.max_chain().next_power_of_two(),
                    ] {
                        variants.push(("hash_filter", {
                            let mut canonical_configuration = baseline;
                            canonical_configuration.set_hash_algorithm(hash_algorithm);
                            canonical_configuration.set_nice_length(128);
                            canonical_configuration.set_max_chain(max_chain);
                            canonical_configuration.set_matching_type(MatchingType::Lazy {
                                max_lazy: 16,
                                filtered_matching,
                                behavior: LazyBehavior::Zlib { good_length: 8 },
                            });
                            canonical_configuration
                        }));
                    }
                }
            }
        }
        let mut trials = Vec::new();
        for (name, parameters) in variants {
            let prefix = prefix(&parameters);
            match measure(&contents, &plain, &parameters) {
                Ok(measured) => {
                    verify(&measured, &plain, &compressed);
                    assert_eq!(measured.trace.token_count, original.trace.token_count);
                    trials.push(serde_json::json!({
                        "name": name,"prefix": prefix,
                        "measurement": oracle_measurement_json(parameters,&measured),
                    }));
                }
                Err(error)
                    if matches!(
                        error.exit_code(),
                        ExitCode::MatchNotFound | ExitCode::PredictionFailure
                    ) =>
                {
                    trials.push(serde_json::json!({"name":name,"prefix":prefix,"error":format!("{:?}",error.exit_code())}));
                }
                Err(error) => panic!("cohort trial {parameters:?}: {error:?}"),
            }
        }
        serde_json::to_writer(&mut output,&serde_json::json!({
            "case":file.file_stem().unwrap().to_string_lossy(),
            "info":{"min_len":info.min_len,"max_len":info.max_len,"max_dist":info.max_dist,
                "max_dist_3_matches":info.max_dist_3_matches,"max_tokens_per_block":info.max_tokens_per_block,
                "max_huffman_block_bytes":info.max_huffman_block_bytes,"blocks":info.count_blocks},
            "deflate_bytes":compressed.len(),"plaintext_bytes":plain.len(),"token_count":original.trace.token_count,
            "baseline":oracle_measurement_json(baseline,&original),"baseline_prefix":prefix(&baseline),"trials":trials,
        })).unwrap();
        writeln!(output).unwrap();
        output.flush().unwrap();
        println!(
            "COHORT_COMPLETE {}",
            file.file_stem().unwrap().to_string_lossy()
        );
    }
}

#[test]
#[ignore = "offline whole-stream sweep; requires PREFLATE_REFERENCE and PREFLATE_SWEEP_RESULTS"]
fn sweep_compressor_parameters() {
    use std::{collections::HashSet, io::Write};

    fn representatives(
        ranked: &[(usize, ReconstructionParameters)],
    ) -> Vec<ReconstructionParameters> {
        let mut hashes = Vec::new();
        let mut parsers = Vec::new();
        let mut result = Vec::new();
        for &(_, parameters) in ranked {
            let parser = std::mem::discriminant(&parameters.matching_type());
            if !hashes.contains(&parameters.hash_algorithm()) || !parsers.contains(&parser) {
                hashes.push(parameters.hash_algorithm());
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
                        candidates.push({
                            let mut canonical_configuration = baseline;
                            canonical_configuration.set_hash_algorithm(hash_algorithm);
                            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
                            canonical_configuration.set_nice_length(nice_length);
                            canonical_configuration.set_max_chain(max_chain);
                            canonical_configuration.set_short_match_cutoff(max_dist_3_matches);
                            canonical_configuration.set_matching_type(matching_type);
                            canonical_configuration
                        });
                    }
                }
            }
        }
    }
    for max_probes in [1, 6, 16, 32, 128, 512, 1024, 4096] {
        for greedy in [false, true] {
            for max_dist_3_matches in [0, 4096] {
                candidates.push({
                    let mut canonical_configuration = baseline;
                    canonical_configuration
                        .set_hash_algorithm(crate::estimator::test_support::zlib::DEFAULT_HASH);
                    canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
                    canonical_configuration.set_short_match_cutoff(max_dist_3_matches);
                    canonical_configuration
                        .set_matching_type(MatchingType::MiniZ { max_probes, greedy });
                    canonical_configuration
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
            let (mismatches, tokens) = crate::estimator::test_support::score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    (&candidate).into(),
                ),
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
    let mut best: Option<(ReconstructionParameters, Measurement)> = None;
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
                        error.to_string().replace(['\n', '\t'], " ")
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
#[ignore = "offline lazy-policy investigation; requires PREFLATE_REFERENCE and PREFLATE_LAZY_RESULTS"]
fn diagnose_lazy_neighborhood() {
    use std::io::Write;

    let path = std::env::var_os("PREFLATE_REFERENCE").expect("set PREFLATE_REFERENCE");
    let prefix = PathBuf::from(
        std::env::var_os("PREFLATE_LAZY_RESULTS").expect("set PREFLATE_LAZY_RESULTS"),
    );
    let mut scores = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(prefix.with_extension("scores.tsv"))
            .unwrap(),
    );
    let mut residuals = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(prefix.with_extension("residuals.tsv"))
            .unwrap(),
    );
    writeln!(scores, "mismatches\ttokens\tparameters").unwrap();
    writeln!(
        residuals,
        "offset\tactual_length\tactual_distance\tpredicted_length\tpredicted_distance"
    )
    .unwrap();
    let compressed = std::fs::read(path).unwrap();
    let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
    assert_eq!(contents.compressed_size, compressed.len());
    let baseline = estimate_preflate_parameters(&contents, &plain).unwrap();
    let mut ranked = Vec::new();
    for max_lazy in [16, 64, 96, 128, 192, 258] {
        for nice_length in [64, 128, 258] {
            for behavior in [
                LazyBehavior::RecomputeAfterLiteral,
                LazyBehavior::Zlib { good_length: 4 },
                LazyBehavior::Zlib { good_length: 8 },
                LazyBehavior::Zlib { good_length: 32 },
                LazyBehavior::Zlib { good_length: 128 },
                LazyBehavior::Zlib { good_length: 258 },
            ] {
                let parameters = {
                    let mut canonical_configuration = baseline;
                    canonical_configuration.set_nice_length(nice_length);
                    canonical_configuration.set_matching_type(MatchingType::Lazy {
                        max_lazy,
                        filtered_matching: false,
                        behavior,
                    });
                    canonical_configuration
                };
                let (errors, tokens) = crate::estimator::test_support::score_predictions(
                    &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                        (&parameters).into(),
                    ),
                    &contents.blocks,
                    &plain,
                    usize::MAX,
                    u32::MAX,
                );
                writeln!(scores, "{errors}\t{tokens}\t{parameters:?}").unwrap();
                ranked.push((errors, parameters));
            }
        }
    }
    ranked.sort_by_key(|row| row.0);
    let seed = ranked[0].1;
    for parameters in sweep_neighborhood(seed) {
        let (errors, tokens) = crate::estimator::test_support::score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                (&parameters).into(),
            ),
            &contents.blocks,
            &plain,
            usize::MAX,
            u32::MAX,
        );
        writeln!(scores, "{errors}\t{tokens}\t{parameters:?}").unwrap();
        ranked.push((errors, parameters));
    }
    ranked.sort_by_key(|row| row.0);
    scores.flush().unwrap();
    let parameters = ranked[0].1;
    let measured =
        measure_with_tracking(&contents, &plain, &parameters, false, false, 100_000).unwrap();
    verify(&measured, &plain, &compressed);
    assert_eq!(measured.trace.mismatch_count, ranked[0].0);
    let shape = |token: DeflateToken| match token {
        DeflateToken::Literal(_) => (0, 0),
        DeflateToken::Reference(reference) => (reference.len(), reference.dist()),
    };
    let mut pairs = std::collections::BTreeMap::new();
    for &(offset, actual, predicted) in &measured.trace.first_mismatches {
        let (actual_length, actual_distance) = shape(actual);
        let (predicted_length, predicted_distance) = shape(predicted);
        *pairs
            .entry((actual_length, predicted_length))
            .or_insert(0usize) += 1;
        writeln!(
            residuals,
            "{offset}\t{actual_length}\t{actual_distance}\t{predicted_length}\t{predicted_distance}"
        )
        .unwrap();
    }
    println!(
        "LAZY_FINAL bytes={} mismatches={} params={parameters:?} pairs={pairs:?}",
        measured.corrections.len(),
        measured.trace.mismatch_count,
    );
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
    params: ReconstructionParameters,
    observed_min_len: u32,
) -> Vec<ReconstructionParameters> {
    use crate::estimator::test_support::zlib::ZLIB_PREFLATE_PARSER_SETTINGS;

    let mut variants = parameter_variants(params, observed_min_len, false);
    let compatible = zlib_compatible(&params);
    let mut add = |candidate: ReconstructionParameters| {
        let candidate = candidate.with_lazy_behavior(compatible, observed_min_len);
        if candidate != params && !variants.contains(&candidate) {
            variants.push(candidate);
        }
    };
    for hash_algorithm in [
        params.hash_algorithm(),
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
        add({
            let mut canonical_configuration = params;
            canonical_configuration.set_hash_algorithm(hash_algorithm);
            canonical_configuration
        });
        for config in ZLIB_PREFLATE_PARSER_SETTINGS
            .iter()
            .chain(SLOW_PREFLATE_PARSER_SETTINGS.iter())
        {
            add({
                let mut canonical_configuration = params;
                canonical_configuration.set_hash_algorithm(hash_algorithm);
                canonical_configuration.set_insertion(config.dictionary_add_policy);
                canonical_configuration.set_nice_length(config.nice_length);
                canonical_configuration.set_max_chain(config.max_chain);
                canonical_configuration.set_matching_type(config.parser.matching_type());
                canonical_configuration
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
        add({
            let mut canonical_configuration = params;
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4);
            canonical_configuration.set_window_bits(15);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(nice_length);
            canonical_configuration.set_max_chain(depth);
            canonical_configuration.set_short_match_cutoff(4096);
            canonical_configuration.set_matching_type(matching_type);
            canonical_configuration
        });
    }
    for max_probes in [6, 16, 32, 128, 256, 512, 768, 1500] {
        for greedy in [false, true] {
            add({
                let mut canonical_configuration = params;
                canonical_configuration.set_hash_algorithm(HashAlgorithm::Zlib {
                    hash_mask: 32767,
                    hash_shift: 5,
                });
                canonical_configuration.set_window_bits(15);
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
                canonical_configuration.set_nice_length(258);
                canonical_configuration.set_max_chain(u32::from(max_probes).div_ceil(3) * 3);
                canonical_configuration
                    .set_matching_type(MatchingType::MiniZ { max_probes, greedy });
                canonical_configuration
            });
        }
    }
    variants.retain(|candidate| match candidate.matching_type() {
        MatchingType::LibdeflateGreedy | MatchingType::LibdeflateLazy { .. } => {
            candidate.hash_algorithm() == HashAlgorithm::Libdeflate4
        }
        MatchingType::MiniZ { .. } => {
            candidate.hash_algorithm()
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
            match candidate.matching_type() {
                MatchingType::LibdeflateGreedy | MatchingType::LibdeflateLazy { .. } => {
                    assert_eq!(candidate.hash_algorithm(), HashAlgorithm::Libdeflate4);
                }
                MatchingType::MiniZ { .. } => {
                    assert_eq!(
                        candidate.hash_algorithm(),
                        HashAlgorithm::Zlib {
                            hash_mask: 32767,
                            hash_shift: 5
                        }
                    );
                }
                _ => {}
            }
            crate::estimator::test_support::score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    candidate.into(),
                ),
                &contents.blocks,
                &plain,
                128,
                65536,
            );
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
#[ignore = "offline compatibility check; requires previously captured public model snapshots"]
fn verify_model_snapshot_decoding() {
    let destination = PathBuf::from(
        std::env::var_os("PREFLATE_MODEL_SNAPSHOTS").expect("set PREFLATE_MODEL_SNAPSHOTS"),
    );
    let mut checked = 0;
    for entry in std::fs::read_dir(fixture_directory()).unwrap() {
        let file = entry.unwrap().path();
        if !file.extension().is_some_and(|ext| ext == "deflate") {
            continue;
        }
        let name = file.file_stem().unwrap().to_string_lossy();
        let snapshot = std::fs::read(destination.join(format!("{name}.model"))).unwrap();
        if snapshot.starts_with(b"UNSUPPORTED:") {
            continue;
        }
        let split = snapshot.iter().position(|&b| b == b'\n').unwrap();
        let compressed = std::fs::read(&file).unwrap();
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(
            recreate_whole_deflate_stream(plain.text(), &snapshot[split + 1..]).unwrap(),
            compressed[..contents.compressed_size],
            "{name}"
        );
        checked += 1;
    }
    assert!(checked > 0);
    println!("LEGACY_SNAPSHOTS verified={checked}");
}

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
        if !sweep || params.max_chain() == 0 {
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
                        candidate.matching_type(),
                        candidate.nice_length(),
                        candidate.max_chain()
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
                params.hash_algorithm(),
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
                let changes = usize::from(candidate.matching_type() != params.matching_type())
                    + usize::from(candidate.nice_length() != params.nice_length())
                    + usize::from(candidate.max_chain() != params.max_chain());
                assert!((1..=3).contains(&changes), "{name}");
                if !combined {
                    assert_eq!(changes, 1, "{name}");
                }
                let expected = {
                    let mut canonical_configuration = params;
                    canonical_configuration.set_nice_length(candidate.nice_length());
                    canonical_configuration.set_max_chain(candidate.max_chain());
                    canonical_configuration.set_matching_type(candidate.matching_type());
                    canonical_configuration
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

#[test]
fn windows_lazy_parameters_and_corrections_roundtrip() {
    let (compressed, contents, plain) = synthetic_stream(vec![
        DeflateToken::Literal(b'a'),
        DeflateToken::new_ref(37, 1),
        DeflateToken::Literal(b'a'),
        DeflateToken::Literal(b'a'),
    ]);
    let parameters = {
        let mut canonical_configuration = synthetic_params();
        canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
        canonical_configuration.set_matches_to_start(true);
        canonical_configuration.set_max_chain(100);
        canonical_configuration.set_matching_type(MatchingType::WindowsLazy { max_lazy: 128 });
        canonical_configuration.max_token_count = 4;
        canonical_configuration
    };
    let measured = measure(&contents, &plain, &parameters).unwrap();
    assert_eq!(measured.trace.mismatch_count, 0);
    verify(&measured, &plain, &compressed);
}

#[test]
fn obsolete_flat_record_is_rejected() {
    let record = [
        0x83, 0x00, 0x00, 0x04, 0x0f, 0x00, 0x04, 0x80, 0x00, 0xff, 0x3f, 0x02, 0xfe, 0x0f, 0x01,
        0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x80, 0x01, 0xff, 0x7f, 0x04, 0x05, 0x00, 0x00,
    ];
    let error = recreate_whole_deflate_stream(&[], &record).unwrap_err();
    assert_eq!(error.exit_code(), ExitCode::InvalidCompressedWrapper);
    assert!(
        error
            .to_string()
            .contains("unsupported corrections version 0x83")
    );
}

fn synthetic_params() -> ReconstructionParameters {
    {
        let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
        canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
        canonical_configuration.set_nice_length(258);
        canonical_configuration.set_max_chain(32);
        canonical_configuration.block_type_strategy = BlockTypeStrategy::Static;
        canonical_configuration
    }
}

#[test]
fn table_hash_refinement_preserves_partial_compressed_input() {
    let compressed = crate::utils::read_file("pptxplaintext.zip");
    let mut processor = PreflateStreamProcessor::new(&PreflateConfig::default());
    processor.trace = Some(TokenPredictionTrace::default());
    let result = processor.decompress(&compressed[79..128000]);
    assert!(
        result.is_ok(),
        "{:?}; parameters={:?}",
        result.err(),
        processor.trace.as_ref().and_then(|trace| trace.parameters)
    );
    let mut offset = 79 + result.unwrap().compressed_size;
    while !processor.is_done() {
        processor.shrink_to_dictionary();
        offset += processor
            .decompress(&compressed[offset..])
            .unwrap()
            .compressed_size;
    }
    assert_eq!(offset, 279012);
}

#[test]
fn table_hash_refinement_recovers_coupled_fast_and_small_window_zlib() {
    use crate::{deflate::deflate_token::TokenFrequency, prediction_state::PredictionState};
    let source = crate::utils::read_file("compressed_zlib_level6.deflate");
    let (_, source_plain) = parse_deflate_whole(&source).unwrap();
    let mut seed = 1234567u32;
    let mut random_byte = || {
        seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
        (seed >> 24) as u8
    };
    let pattern: Vec<_> = (0..256).map(|_| random_byte()).collect();
    let mut fast_plain = pattern.repeat(32);
    for index in 0..256 {
        let position = (index * 7) % 253;
        fast_plain.extend_from_slice(&pattern[position..position + 3]);
        fast_plain.push(pattern[position + 3] ^ 255);
    }
    for _ in 0..128 {
        let target = [random_byte(), random_byte(), random_byte(), random_byte()];
        fast_plain.extend_from_slice(&target);
        for collision in 1..8 {
            fast_plain.extend_from_slice(&[
                target[0] ^ (collision * 32),
                target[1],
                target[2],
                target[3],
            ]);
        }
        fast_plain.extend_from_slice(&target);
    }
    fast_plain.extend((0..2048).map(|_| random_byte()));
    let mut slow_plain = source_plain.text()[..10000].to_vec();
    slow_plain.extend((0..4096).map(|_| random_byte()));
    for (fast, bytes) in [(true, fast_plain), (false, slow_plain)] {
        let settings = if fast {
            &crate::estimator::test_support::zlib::ZLIB_PREFLATE_PARSER_SETTINGS[0]
        } else {
            &SLOW_PREFLATE_PARSER_SETTINGS[2]
        };
        let parameters = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(
                crate::estimator::test_support::zlib::memory_hash(if fast { 8 } else { 5 }),
            );
            canonical_configuration.set_window_bits(if fast { 15 } else { 12 });
            canonical_configuration.set_insertion(settings.dictionary_add_policy);
            canonical_configuration.set_nice_length(settings.nice_length);
            canonical_configuration.set_max_chain(settings.max_chain);
            canonical_configuration.set_short_match_cutoff(if fast { 32768 } else { 4096 });
            canonical_configuration.set_matching_type(settings.parser.matching_type());
            canonical_configuration.max_token_count = if fast { 16383 } else { 2047 };
            canonical_configuration.block_type_strategy = BlockTypeStrategy::Static;
            canonical_configuration
        };
        let plain = PlainText::new_with_data(bytes);
        let mut state = PredictionState::from_reconstruction_parameters((&parameters).into());
        let mut input = PreflateInput::new(&plain);
        let mut writer = DeflateWriter::new();
        while input.remaining() != 0 {
            state
                .begin_decoded_huffman_block(&mut input, None, false)
                .unwrap();
            let mut tokens = Vec::new();
            while input.remaining() != 0 && tokens.len() < usize::from(parameters.max_token_count) {
                let token = state.predict(&input, &TokenFrequency::default());
                state.accept_token(&token, token, &mut input);
                tokens.push(token);
            }
            state.finish_block(&mut input).unwrap();
            writer
                .encode_block(&DeflateTokenBlock {
                    block_type: DeflateTokenBlockType::Huffman {
                        tokens,
                        huffman_type: DeflateHuffmanType::Static,
                    },
                    last: input.remaining() == 0,
                })
                .unwrap();
        }
        writer.flush();
        let compressed = writer.detach_output();
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        let info = extract_preflate_info(&contents.blocks);
        let baseline = {
            let mut canonical_configuration = parameters;
            canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
            canonical_configuration.set_full_window(!fast);
            canonical_configuration.set_nice_length(if fast {
                parameters.nice_length()
            } else {
                258
            });
            canonical_configuration.set_max_chain(if fast { parameters.max_chain() } else { 1 });
            canonical_configuration.set_short_match_cutoff(info.max_dist_3_matches);
            canonical_configuration.set_matching_type(if fast {
                parameters.matching_type()
            } else {
                MatchingType::Lazy {
                    max_lazy: 128,
                    filtered_matching: false,
                    behavior: LazyBehavior::RecomputeAfterLiteral,
                }
            });
            canonical_configuration
        };
        let before = measure(&contents, &plain, &baseline).unwrap();
        assert!(before.trace.mismatch_count >= 2, "fast={fast}");
        let candidates = [crate::estimator::test_support::CandidateEvidence {
            hash_algorithm: parameters.hash_algorithm(),
            required_chain: parameters.max_chain(),
            distance_policy: crate::estimator::test_support::DistancePolicy::ZlibWindow,
            parser: crate::estimator::test_support::ParserInference::Unresolved,
            shallow_miniz_greedy: false,
            minimum_nice_length: 0,
        }];
        let selected = crate::estimator::test_support::refine_profile(
            crate::estimator::test_support::CompressorProfile::Custom.with_parameters(baseline),
            &info,
            &contents,
            &plain,
            &candidates,
        )
        .reconstruction;
        assert_eq!(
            selected.hash_algorithm(),
            parameters.hash_algorithm(),
            "fast={fast}"
        );
        let after = measure(&contents, &plain, &selected).unwrap();
        assert_eq!(after.trace.mismatch_count, 0, "fast={fast}");
        assert!(after.cabac_size < before.cabac_size);
        verify(&before, &plain, &compressed);
        verify(&after, &plain, &compressed);
        assert_eq!(
            crate::estimator::test_support::refine_ambiguous_profile(
                selected, &info, &contents, &plain,
            ),
            selected
        );
    }
}

#[test]
fn ambiguous_fast_hash_refinement_selects_the_missing_memory_size() {
    use crate::{deflate::deflate_token::TokenFrequency, prediction_state::PredictionState};
    let source = crate::utils::read_file("compressed_zlib_level1.deflate");
    let (_, source_plain) = parse_deflate_whole(&source).unwrap();
    let plain = PlainText::new_with_data(source_plain.text()[..10000].to_vec());
    let parameters = {
        let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
        canonical_configuration
            .set_hash_algorithm(crate::estimator::test_support::zlib::memory_hash(7));
        canonical_configuration.max_token_count = 8191;
        canonical_configuration
    };
    let mut state = PredictionState::from_reconstruction_parameters((&parameters).into());
    let mut input = PreflateInput::new(&plain);
    let mut tokens = Vec::new();
    while input.remaining() != 0 {
        let token = state.predict(&input, &TokenFrequency::default());
        state.accept_token(&token, token, &mut input);
        tokens.push(token);
    }
    let (compressed, contents, plain) = synthetic_stream(tokens);
    let info = extract_preflate_info(&contents.blocks);
    assert_eq!(
        crate::estimator::test_support::zlib::adjacent_memory_hash(&info, parameters.add_policy()),
        Some(parameters.hash_algorithm()),
        "tokens={}",
        info.max_tokens_per_block
    );
    let baseline = {
        let mut canonical_configuration = parameters;
        canonical_configuration
            .set_hash_algorithm(crate::estimator::test_support::zlib::DEFAULT_HASH);
        canonical_configuration.block_type_strategy = BlockTypeStrategy::Static;
        canonical_configuration
    };
    let before = measure(&contents, &plain, &baseline).unwrap();
    let selected = crate::estimator::test_support::refine_ambiguous_profile(
        baseline, &info, &contents, &plain,
    );
    assert_eq!(selected.hash_algorithm(), parameters.hash_algorithm());
    let after = measure(&contents, &plain, &selected).unwrap();
    assert!(before.trace.mismatch_count >= 2);
    assert_eq!(after.trace.mismatch_count, 0);
    assert!(after.cabac_size < before.cabac_size);
    verify(&before, &plain, &compressed);
    verify(&after, &plain, &compressed);
    let unchanged = crate::estimator::test_support::refine_ambiguous_profile(
        selected, &info, &contents, &plain,
    );
    assert_eq!(unchanged, selected);
}

#[test]
#[ignore = "offline bounded cross-family candidate verification using guarded exported streams"]
fn diagnose_table_hash_alternative() {
    use std::io::Write;
    let path = std::env::var_os("PREFLATE_TABLE_RESULTS").expect("set PREFLATE_TABLE_RESULTS");
    let mut output = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap(),
    );
    writeln!(output, "case\tminimum\tshort_distance\tblock_tokens\tbaseline_prefix\tcandidate_prefix\tbytes\tmismatches").unwrap();
    for entry in std::fs::read_dir(fixture_directory()).unwrap() {
        let file = entry.unwrap().path();
        if !file
            .extension()
            .is_some_and(|extension| extension == "deflate")
        {
            continue;
        }
        let compressed = std::fs::read(&file).unwrap();
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        let info = extract_preflate_info(&contents.blocks);
        let baseline = estimate_preflate_parameters(&contents, &plain).unwrap();
        let candidate = {
            let mut canonical_configuration = baseline;
            canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(128);
            canonical_configuration.set_max_chain(128);
            canonical_configuration.set_short_match_cutoff(4096);
            canonical_configuration.set_matching_type(MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: false,
                behavior: LazyBehavior::RecomputeAfterLiteral,
            });
            canonical_configuration
        };
        let candidate = if std::env::var_os("PREFLATE_TABLE_WINDOWS").is_some() {
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
                canonical_configuration.set_full_window(true);
                canonical_configuration.set_nice_length(258);
                canonical_configuration.set_max_chain(100);
                canonical_configuration
                    .set_matching_type(MatchingType::WindowsLazy { max_lazy: 258 });
                canonical_configuration.max_token_count =
                    if info.max_tokens_per_block.is_power_of_two() {
                        u16::try_from(info.max_tokens_per_block).unwrap()
                    } else {
                        baseline.max_token_count
                    };
                canonical_configuration
            }
        } else {
            candidate
        };
        let candidate = if std::env::var_os("PREFLATE_TABLE_GREEDY").is_some() {
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_nice_length(258);
                canonical_configuration.set_matching_type(
                    if std::env::var_os("PREFLATE_TABLE_WINDOWS_GREEDY").is_some() {
                        MatchingType::WindowsLazy { max_lazy: 0 }
                    } else {
                        MatchingType::Greedy
                    },
                );
                canonical_configuration
            }
        } else {
            candidate
        };
        let first = crate::estimator::test_support::score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                (&baseline).into(),
            ),
            &contents.blocks,
            &plain,
            4096,
            524288,
        );
        let next = crate::estimator::test_support::score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                (&candidate).into(),
            ),
            &contents.blocks,
            &plain,
            4096,
            524288,
        );
        let measured = measure(&contents, &plain, &candidate).unwrap();
        verify(&measured, &plain, &compressed);
        writeln!(
            output,
            "{}\t{}\t{}\t{}\t{first:?}\t{next:?}\t{}\t{}",
            file.file_stem().unwrap().to_string_lossy(),
            info.min_len,
            info.max_dist_3_matches,
            info.max_tokens_per_block,
            measured.corrections.len(),
            measured.trace.mismatch_count
        )
        .unwrap();
    }
}

#[test]
#[ignore = "offline table-hash residual study; requires guarded exports of at most 8 MiB plaintext"]
fn diagnose_table_hash_residuals() {
    use std::io::Write;
    let path = std::env::var_os("PREFLATE_TABLE_RESULTS").expect("set PREFLATE_TABLE_RESULTS");
    let mut output = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap(),
    );
    writeln!(
        output,
        "case\tvariant\tbytes\tmismatches\tprefix_errors\tprefix_tokens\tparams\terror"
    )
    .unwrap();
    let files: Vec<_> = std::fs::read_dir(fixture_directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "deflate"))
        .collect();
    assert!(!files.is_empty() && files.len() <= 16);
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy();
        let compressed = std::fs::read(&file).unwrap();
        assert!(compressed.len() <= 8 * 1024 * 1024);
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert!(plain.len() <= 8 * 1024 * 1024);
        assert_eq!(contents.compressed_size, compressed.len());
        let baseline = estimate_preflate_parameters(&contents, &plain).unwrap();
        assert!(matches!(
            baseline.hash_algorithm(),
            HashAlgorithm::RandomVector | HashAlgorithm::Zlib { .. }
        ));
        let observed =
            measure_with_tracking(&contents, &plain, &baseline, false, false, 65536).unwrap();
        verify(&observed, &plain, &compressed);
        let length = |token: &DeflateToken| match token {
            DeflateToken::Literal(_) => 0,
            DeflateToken::Reference(reference) => reference.len(),
        };
        let mut pairs = std::collections::BTreeMap::new();
        for (_, actual, predicted) in &observed.trace.first_mismatches {
            *pairs
                .entry((length(actual), length(predicted)))
                .or_insert(0usize) += 1;
        }
        let mut pairs: Vec<_> = pairs.into_iter().collect();
        pairs.sort_by_key(|row| std::cmp::Reverse(row.1));
        println!(
            "{name}: baseline_bytes={} mismatches={} sampled={} length_pairs={:?}",
            observed.corrections.len(),
            observed.trace.mismatch_count,
            observed.trace.first_mismatches.len(),
            &pairs[..pairs.len().min(10)],
        );
        for (offset, actual, predicted) in observed.trace.first_mismatches.iter().take(6) {
            let distance = |token: &DeflateToken| match token {
                DeflateToken::Literal(_) => 0,
                DeflateToken::Reference(reference) => reference.dist(),
            };
            println!(
                "{name}: offset={offset} actual_length={} predicted_length={} actual_distance={} predicted_distance={}",
                length(actual),
                length(predicted),
                distance(actual),
                distance(predicted),
            );
        }
        let mismatches: std::collections::BTreeSet<_> = observed
            .trace
            .first_mismatches
            .iter()
            .map(|row| row.0)
            .collect();
        let mut tail_ranks = std::collections::BTreeMap::new();
        let mut offset = 0u32;
        for (block_index, block) in contents.blocks.iter().enumerate() {
            match &block.block_type {
                DeflateTokenBlockType::Stored { uncompressed } => {
                    offset += uncompressed.len() as u32
                }
                DeflateTokenBlockType::Huffman { tokens, .. } => {
                    for (index, token) in tokens.iter().enumerate() {
                        if mismatches.contains(&offset) {
                            let tail = tokens.len() - index - 1;
                            *tail_ranks.entry(tail.min(8)).or_insert(0usize) += 1;
                            if observed
                                .trace
                                .first_mismatches
                                .iter()
                                .take(6)
                                .any(|row| row.0 == offset)
                            {
                                println!(
                                    "{name}: offset={offset} block={block_index} index={index} block_tokens={} tail={tail}",
                                    tokens.len()
                                );
                            }
                        }
                        offset += match token {
                            DeflateToken::Literal(_) => 1,
                            DeflateToken::Reference(reference) => reference.len(),
                        };
                    }
                }
            }
        }
        println!(
            "{name}: blocks={} tail_ranks={tail_ranks:?}",
            contents.blocks.len()
        );
        let mut variants = distance_window_variants(baseline, plain.len());
        let mem_level = (u32::from(baseline.max_token_count) + 1)
            .ilog2()
            .saturating_sub(6);
        let hashes = crate::estimator::test_support::zlib::candidate_hashes(mem_level);
        for hash_algorithm in [Some(hashes.memory), hashes.default, hashes.small]
            .into_iter()
            .flatten()
        {
            variants.push(("zlib_hash", {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_hash_algorithm(hash_algorithm);
                canonical_configuration
            }));
            for settings in crate::estimator::test_support::zlib::SLOW_PREFLATE_PARSER_SETTINGS {
                if settings.max_chain < baseline.max_chain() {
                    continue;
                }
                variants.push(("zlib_tuple", {
                    let mut canonical_configuration = baseline;
                    canonical_configuration.set_hash_algorithm(hash_algorithm);
                    canonical_configuration.set_full_window(false);
                    canonical_configuration.set_nice_length(settings.nice_length);
                    canonical_configuration.set_max_chain(settings.max_chain);
                    canonical_configuration.set_matching_type(settings.parser.matching_type());
                    canonical_configuration
                }));
                break;
            }
        }
        variants.push(("long_nice", {
            let mut canonical_configuration = baseline;
            canonical_configuration.set_nice_length(258);
            canonical_configuration
        }));
        variants.push(("long_chain", {
            let mut canonical_configuration = baseline;
            canonical_configuration.set_max_chain(4096);
            canonical_configuration
        }));
        if baseline.matching_type() == MatchingType::Greedy {
            for add_policy in [
                DictionaryAddPolicy::AddFirst(0),
                DictionaryAddPolicy::AddFirstAndLast(0),
            ] {
                variants.push(("insertion_boundary", {
                    let mut canonical_configuration = baseline;
                    canonical_configuration.set_insertion(add_policy);
                    canonical_configuration
                }));
            }
        }
        if let MatchingType::Lazy {
            filtered_matching,
            behavior,
            ..
        } = baseline.matching_type()
        {
            for max_lazy in [128, 258] {
                for behavior in [
                    behavior,
                    LazyBehavior::Zlib { good_length: 258 },
                    LazyBehavior::RecomputeAfterLiteral,
                ] {
                    variants.push(("long_lazy", {
                        let mut canonical_configuration = baseline;
                        canonical_configuration.set_matching_type(MatchingType::Lazy {
                            max_lazy,
                            filtered_matching,
                            behavior,
                        });
                        canonical_configuration
                    }));
                }
            }
        }
        for (variant, candidate) in variants {
            let (errors, tokens) = crate::estimator::test_support::score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    (&candidate).into(),
                ),
                &contents.blocks,
                &plain,
                4096,
                524288,
            );
            match measure(&contents, &plain, &candidate) {
                Ok(measured) => {
                    verify(&measured, &plain, &compressed);
                    writeln!(
                        output,
                        "{name}\t{variant}\t{}\t{}\t{errors}\t{tokens}\t{candidate:?}\t",
                        measured.corrections.len(),
                        measured.trace.mismatch_count
                    )
                    .unwrap();
                }
                Err(error) => {
                    writeln!(
                        output,
                        "{name}\t{variant}\t\t\t{errors}\t{tokens}\t{candidate:?}\t{:?}",
                        error.exit_code()
                    )
                    .unwrap();
                }
            }
        }
        output.flush().unwrap();
    }
}

#[test]
fn sparse_windows_profile_selects_hash_and_long_lazy_policy_together() {
    let mut patterns = Vec::new();
    let mut position = 0u32;
    let mut first_deferral = None;
    for reverse in [false, true] {
        let mut alphabet: Vec<u8> = (32..182).collect();
        if reverse {
            alphabet.reverse();
        }
        let source = position;
        patterns.push(DeflateToken::Literal(b'$'));
        patterns.extend(alphabet.iter().copied().map(DeflateToken::Literal));
        patterns.push(DeflateToken::Literal(b'!'));
        position += 152;
        let near = position;
        patterns.push(DeflateToken::new_ref(149, position - (source + 2)));
        let suffix = if reverse { 202..212 } else { 192..202 };
        patterns.extend(suffix.map(DeflateToken::Literal));
        patterns.push(DeflateToken::Literal(b'#'));
        position += 160;
        if !reverse {
            first_deferral = Some((patterns.len(), position - (source + 1)));
        }
        patterns.push(DeflateToken::Literal(alphabet[0]));
        position += 1;
        patterns.push(DeflateToken::new_ref(159, position - near));
        position += 159;
        if reverse {
            patterns.extend([DeflateToken::Literal(240), DeflateToken::Literal(241)]);
        } else {
            patterns.push(DeflateToken::Literal(b'~'));
            position += 1;
        }
    }
    let mut tokens: Vec<_> = [b'@', 224, 225, 226, 227, 228, 229, b'X']
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.push(DeflateToken::new_ref(5, 7));
    tokens.push(DeflateToken::Literal(b'Y'));
    let padding = 4096 - tokens.len() - patterns.len();
    tokens.extend(
        (0..8u8)
            .flat_map(|middle| (0..=255u8).flat_map(move |value| [middle, value]))
            .take(padding)
            .map(DeflateToken::Literal),
    );
    let (deferral, distance) = first_deferral.unwrap();
    let deferral = tokens.len() + deferral;
    tokens.extend(patterns);
    let mut greedy_tokens = tokens.clone();
    let DeflateToken::Reference(next) = tokens[deferral + 1] else {
        unreachable!()
    };
    greedy_tokens[deferral] = DeflateToken::new_ref(150, distance);
    greedy_tokens[deferral + 1] = DeflateToken::new_ref(10, next.dist());
    let (compressed, contents, plain) = synthetic_stream(tokens);
    assert!(compressed.len() > 1024);
    let info = extract_preflate_info(&contents.blocks);
    assert_eq!(info.min_len, 5);
    assert_eq!(info.max_tokens_per_block, 4096);
    let baseline = {
        let mut canonical_configuration = synthetic_params();
        canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4Fast);
        canonical_configuration.set_nice_length(128);
        canonical_configuration.set_max_chain(99);
        canonical_configuration.set_short_match_cutoff(0);
        canonical_configuration.set_matching_type(MatchingType::Lazy {
            max_lazy: 16,
            filtered_matching: false,
            behavior: LazyBehavior::RecomputeAfterLiteral,
        });
        canonical_configuration.max_token_count = 8191;
        canonical_configuration
    };
    let expected = {
        let mut canonical_configuration = baseline;
        canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
        canonical_configuration.set_nice_length(258);
        canonical_configuration.set_max_chain(100);
        canonical_configuration.set_matching_type(MatchingType::WindowsLazy { max_lazy: 258 });
        canonical_configuration.max_token_count = 4096;
        canonical_configuration
    };
    let score = |parameters: &ReconstructionParameters| {
        crate::estimator::test_support::score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                *parameters,
            ),
            &contents.blocks,
            &plain,
            4096,
            524288,
        )
    };
    assert!(score(&baseline).0 >= 2);
    assert_eq!(
        score(&expected),
        (0, 4096),
        "{:?}",
        measure(&contents, &plain, &expected)
            .unwrap()
            .trace
            .first_mismatches
    );
    assert!(
        score(&{
            let mut canonical_configuration = expected;
            canonical_configuration.set_matching_type(MatchingType::WindowsLazy { max_lazy: 128 });
            canonical_configuration
        })
        .0 >= 2
    );
    let selected = crate::estimator::test_support::refine_profile(
        crate::estimator::test_support::CompressorProfile::Custom.with_parameters(baseline),
        &info,
        &contents,
        &plain,
        &[],
    );
    assert_eq!(selected.reconstruction, expected);
    assert_eq!(
        selected.model,
        crate::estimator::test_support::CompressorProfile::Windows
    );
    let measured = measure(&contents, &plain, &selected.reconstruction).unwrap();
    assert_eq!(measured.trace.mismatch_count, 0);
    verify(&measured, &plain, &compressed);
    assert_eq!(
        crate::estimator::test_support::refine_ambiguous_profile(
            expected, &info, &contents, &plain
        ),
        expected
    );
    let (greedy_compressed, greedy_contents, greedy_plain) = synthetic_stream(greedy_tokens);
    assert_eq!(plain.text(), greedy_plain.text());
    assert!(
        crate::estimator::test_support::score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                (&expected).into()
            ),
            &greedy_contents.blocks,
            &greedy_plain,
            4096,
            524288
        )
        .0 > 0
    );
    let rejected = crate::estimator::test_support::refine_ambiguous_profile(
        baseline,
        &extract_preflate_info(&greedy_contents.blocks),
        &greedy_contents,
        &greedy_plain,
    );
    assert_eq!(rejected, baseline);
    verify(
        &measure(&greedy_contents, &greedy_plain, &rejected).unwrap(),
        &greedy_plain,
        &greedy_compressed,
    );
}

#[test]
fn bounded_table_hash_repair_rejects_libdeflate_equal_length_deferral() {
    let mut tokens = Vec::new();
    for group in 0..4u8 {
        let base = 40 + 16 * group;
        tokens.extend((base..base + 6).map(DeflateToken::Literal));
    }
    tokens.push(DeflateToken::new_ref(3, 4));
    tokens.push(DeflateToken::Literal(110));
    tokens.push(DeflateToken::Literal(255));
    let mut position = 29u32;
    for middle in 0..4u8 {
        for value in 0..=255u8 {
            tokens.push(DeflateToken::Literal(middle));
            tokens.push(DeflateToken::Literal(value));
            position += 2;
        }
    }
    for group in 0..3u8 {
        let base = 40 + 16 * group;
        tokens.push(DeflateToken::new_ref(
            3,
            position - (6 * u32::from(group) + 2),
        ));
        tokens.push(DeflateToken::Literal(base + 6));
        tokens.push(DeflateToken::Literal(base + 9));
        position += 5;
        tokens.push(DeflateToken::new_ref(
            4,
            position - (6 * u32::from(group) + 1),
        ));
        tokens.push(DeflateToken::Literal(base + 6));
        tokens.push(DeflateToken::Literal(base + 10));
        position += 6;
    }
    let (compressed, contents, plain) = synthetic_stream(tokens);
    assert!(compressed.len() > 1024);
    let info = extract_preflate_info(&contents.blocks);
    assert_eq!(info.min_len, 3);
    let expected = {
        let mut canonical_configuration = synthetic_params();
        canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
        canonical_configuration.set_full_window(true);
        canonical_configuration.set_nice_length(128);
        canonical_configuration.set_max_chain(128);
        canonical_configuration.set_short_match_cutoff(4096);
        canonical_configuration.set_matching_type(MatchingType::Lazy {
            max_lazy: 16,
            filtered_matching: false,
            behavior: LazyBehavior::RecomputeAfterLiteral,
        });
        canonical_configuration
    };
    let baseline = {
        let mut canonical_configuration = expected;
        canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4);
        canonical_configuration.set_nice_length(258);
        canonical_configuration.set_max_chain(301);
        canonical_configuration.set_short_match_cutoff(8192);
        canonical_configuration.set_matching_type(MatchingType::LibdeflateLazy {
            two_positions: true,
        });
        canonical_configuration
    };
    assert!(
        crate::estimator::test_support::score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                (&baseline).into()
            ),
            &contents.blocks,
            &plain,
            4096,
            524288
        )
        .0 >= 2
    );
    assert_eq!(
        crate::estimator::test_support::score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                (&expected).into()
            ),
            &contents.blocks,
            &plain,
            4096,
            524288
        )
        .0,
        0
    );
    let selected = crate::estimator::test_support::refine_ambiguous_profile(
        baseline, &info, &contents, &plain,
    );
    assert_eq!(selected, expected);
    let measured = measure(&contents, &plain, &selected).unwrap();
    assert_eq!(measured.trace.mismatch_count, 0);
    verify(&measured, &plain, &compressed);
    assert_eq!(
        crate::estimator::test_support::refine_ambiguous_profile(
            expected, &info, &contents, &plain
        ),
        expected
    );
}

#[test]
fn partial_windows_profile_recreates_long_deferrals_and_trailing_literals() {
    let mut tokens: Vec<_> = b"@abcdX"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.push(DeflateToken::new_ref(3, 4));
    tokens.extend(b"eY".iter().copied().map(DeflateToken::Literal));
    let mut position = 11u32;
    for middle in 0..4u8 {
        for value in 0..=255u8 {
            tokens.push(DeflateToken::Literal(middle));
            tokens.push(DeflateToken::Literal(value));
            position += 2;
        }
    }
    for (index, start) in [b'A', 128].into_iter().enumerate() {
        let source = position;
        tokens.push(DeflateToken::Literal(b'$'));
        tokens.extend((start..start + 16).map(DeflateToken::Literal));
        tokens.push(DeflateToken::Literal(b'!'));
        position += 18;
        let near = position;
        tokens.push(DeflateToken::new_ref(15, position - (source + 2)));
        tokens.extend((start + 16..start + 26).map(DeflateToken::Literal));
        tokens.push(DeflateToken::Literal(b'#'));
        position += 26;
        tokens.push(DeflateToken::Literal(start));
        position += 1;
        let length = if index == 0 { 25 } else { 23 };
        tokens.push(DeflateToken::new_ref(length, position - near));
        position += length;
        if index == 0 {
            tokens.push(DeflateToken::Literal(b'~'));
            position += 1;
        } else {
            tokens.extend([
                DeflateToken::Literal(start + 24),
                DeflateToken::Literal(start + 25),
            ]);
            position += 2;
        }
    }
    let (compressed, contents, plain) = synthetic_stream(tokens);
    assert_eq!(plain.len(), position as usize);
    assert!(compressed.len() > 1024);
    let info = extract_preflate_info(&contents.blocks);
    let baseline = {
        let mut canonical_configuration = synthetic_params();
        canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
        canonical_configuration.set_nice_length(128);
        canonical_configuration.set_max_chain(100);
        canonical_configuration.set_short_match_cutoff(4096);
        canonical_configuration.set_matching_type(MatchingType::Lazy {
            max_lazy: 16,
            filtered_matching: false,
            behavior: LazyBehavior::RecomputeAfterLiteral,
        });
        canonical_configuration.max_token_count = 8191;
        canonical_configuration
    };
    assert!(
        crate::estimator::test_support::score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                (&baseline).into()
            ),
            &contents.blocks,
            &plain,
            4096,
            524288
        )
        .0 >= 2
    );
    let expected = {
        let mut canonical_configuration = baseline;
        canonical_configuration.set_full_window(true);
        canonical_configuration.set_nice_length(258);
        canonical_configuration.set_matching_type(MatchingType::WindowsLazy { max_lazy: 258 });
        canonical_configuration
    };
    assert_eq!(
        crate::estimator::test_support::score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                (&expected).into()
            ),
            &contents.blocks,
            &plain,
            4096,
            524288
        )
        .0,
        0
    );
    let selected = crate::estimator::test_support::refine_ambiguous_profile(
        baseline, &info, &contents, &plain,
    );
    assert_eq!(selected, expected);
    let measured = measure(&contents, &plain, &selected).unwrap();
    assert_eq!(measured.trace.mismatch_count, 0);
    verify(&measured, &plain, &compressed);
}

#[test]
fn shallow_windows_profile_recreates_greedy_decisions_and_trailing_literals() {
    let mut tokens: Vec<_> = b"@abcXbcdeY"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.push(DeflateToken::new_ref(3, 9));
    tokens.extend(b"de".iter().copied().map(DeflateToken::Literal));
    for middle in 0..4u8 {
        for value in 0..=255u8 {
            tokens.push(DeflateToken::Literal(middle));
            tokens.push(DeflateToken::Literal(value));
        }
    }
    tokens.extend((128..155).map(DeflateToken::Literal));
    tokens.push(DeflateToken::Literal(200));
    tokens.push(DeflateToken::new_ref(25, 28));
    tokens.extend([DeflateToken::Literal(153), DeflateToken::Literal(154)]);
    let (compressed, contents, plain) = synthetic_stream(tokens);
    assert!(compressed.len() > 1024);
    let info = extract_preflate_info(&contents.blocks);
    let baseline = {
        let mut canonical_configuration = synthetic_params();
        canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
        canonical_configuration.set_nice_length(16);
        canonical_configuration.set_max_chain(5);
        canonical_configuration.set_short_match_cutoff(4096);
        canonical_configuration.set_matching_type(MatchingType::Lazy {
            max_lazy: 4,
            filtered_matching: false,
            behavior: LazyBehavior::Zlib { good_length: 4 },
        });
        canonical_configuration.max_token_count = 16383;
        canonical_configuration
    };
    assert!(
        crate::estimator::test_support::score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                (&baseline).into()
            ),
            &contents.blocks,
            &plain,
            4096,
            524288
        )
        .0 >= 2
    );
    let expected = {
        let mut canonical_configuration = baseline;
        canonical_configuration.set_nice_length(258);
        canonical_configuration.set_matching_type(MatchingType::WindowsLazy { max_lazy: 0 });
        canonical_configuration
    };
    assert_eq!(
        crate::estimator::test_support::score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                (&expected).into()
            ),
            &contents.blocks,
            &plain,
            4096,
            524288
        )
        .0,
        0
    );
    let selected = crate::estimator::test_support::refine_ambiguous_profile(
        baseline, &info, &contents, &plain,
    );
    assert_eq!(selected, expected);
    let measured = measure(&contents, &plain, &selected).unwrap();
    assert_eq!(measured.trace.mismatch_count, 0);
    verify(&measured, &plain, &compressed);
    assert_eq!(
        crate::estimator::test_support::refine_ambiguous_profile(
            expected, &info, &contents, &plain
        ),
        expected
    );
}

#[test]
fn rle_matching_roundtrips_out_of_policy_reference_corrections() {
    use crate::parameters::PreflateStrategy;

    let (compressed, contents, plain) = synthetic_stream(vec![
        DeflateToken::Literal(b'A'),
        DeflateToken::new_ref(6, 1),
        DeflateToken::Literal(b'B'),
        DeflateToken::new_ref(5, 1),
        DeflateToken::Literal(b'A'),
        DeflateToken::new_ref(4, 14),
        DeflateToken::Literal(b'X'),
        DeflateToken::Literal(b'Y'),
        DeflateToken::Literal(b'Z'),
    ]);
    for hash_algorithm in [
        HashAlgorithm::Zlib {
            hash_mask: 4095,
            hash_shift: 4,
        },
        HashAlgorithm::MiniZFast,
        HashAlgorithm::Libdeflate4Fast,
        HashAlgorithm::Libdeflate4,
        HashAlgorithm::ZlibNG,
        HashAlgorithm::RandomVector,
        HashAlgorithm::Crc32cHash,
        HashAlgorithm::Libdeflate4Fast15,
        HashAlgorithm::Chromium { hash_mask: 32767 },
    ] {
        for matching_type in [
            MatchingType::Greedy,
            MatchingType::Lazy {
                max_lazy: 32,
                filtered_matching: false,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            },
            MatchingType::Lazy {
                max_lazy: 128,
                filtered_matching: true,
                behavior: LazyBehavior::RecomputeAfterLiteral,
            },
            MatchingType::LibdeflateGreedy,
            MatchingType::LibdeflateLazy {
                two_positions: false,
            },
            MatchingType::LibdeflateLazy {
                two_positions: true,
            },
            MatchingType::WindowsLazy { max_lazy: 128 },
        ] {
            // Only the combined hash supports the second lookahead position.
            if matching_type
                == (MatchingType::LibdeflateLazy {
                    two_positions: true,
                })
                && hash_algorithm != HashAlgorithm::Libdeflate4
            {
                continue;
            }
            let parameters = {
                let mut canonical_configuration = synthetic_params();
                canonical_configuration.set_hash_algorithm(hash_algorithm);
                canonical_configuration.set_strategy(PreflateStrategy::RleOnly);
                canonical_configuration.set_full_window(false);
                canonical_configuration.set_matches_to_start(false);
                canonical_configuration.set_window_bits(9);
                canonical_configuration.set_matching_type(matching_type);
                canonical_configuration.max_token_count = 8191;
                canonical_configuration
            };
            let baseline = measure(&contents, &plain, &parameters).unwrap();
            verify(&baseline, &plain, &compressed);
            assert!(baseline.trace.mismatch_count > 0);
            assert!(
                baseline.trace.first_mismatches.iter().any(|(_, actual, _)| {
                    matches!(actual, DeflateToken::Reference(reference) if reference.dist() == 14)
                }),
                "{hash_algorithm:?}, {matching_type:?}"
            );
        }
    }
}

#[test]
fn disabled_matching_roundtrips_literals_and_rejects_references() {
    use crate::parameters::PreflateStrategy;

    let mut tokens: Vec<_> = b"@abcdefX"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.push(DeflateToken::new_ref(3, 7));
    tokens.push(DeflateToken::Literal(b'Y'));
    tokens.push(DeflateToken::new_ref(6, 11));
    let (_, reference_contents, reference_plain) = synthetic_stream(tokens);
    let (compressed, contents, plain) = synthetic_stream(
        b"@abcdefXabcYabcdef"
            .iter()
            .copied()
            .map(DeflateToken::Literal)
            .collect(),
    );
    for matching_type in [
        MatchingType::Greedy,
        MatchingType::Lazy {
            max_lazy: 128,
            filtered_matching: false,
            behavior: LazyBehavior::Zlib { good_length: 32 },
        },
        MatchingType::MiniZ {
            max_probes: 32,
            greedy: false,
        },
        MatchingType::LibdeflateLazy {
            two_positions: true,
        },
        MatchingType::WindowsLazy { max_lazy: 258 },
    ] {
        let parameters = {
            let mut canonical_configuration = synthetic_params();
            canonical_configuration.set_strategy(PreflateStrategy::HuffOnly);
            canonical_configuration.set_full_window(false);
            canonical_configuration.set_matches_to_start(false);
            canonical_configuration.set_matching_type(matching_type);
            canonical_configuration
        };
        let baseline = measure(&contents, &plain, &parameters).unwrap();
        verify(&baseline, &plain, &compressed);
        assert_eq!(baseline.trace.mismatch_count, 0);
        let error = measure(&reference_contents, &reference_plain, &parameters)
            .err()
            .expect("disabled matching must still reject reference reprediction");
        assert_eq!(error.exit_code(), ExitCode::PredictionFailure);
    }
}

#[test]
fn dynamic_and_mixed_strategies_produce_identical_corrections() {
    for name in ["compressed_zlib_level6.deflate", "treegdi.extract.deflate"] {
        let compressed = crate::utils::read_file(name);
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        let parameters = estimate_preflate_parameters(&contents, &plain).unwrap();
        let dynamic = measure(&contents, &plain, &{
            let mut canonical_configuration = parameters;
            canonical_configuration.block_type_strategy = BlockTypeStrategy::Dynamic;
            canonical_configuration
        })
        .unwrap();
        let mixed = measure(&contents, &plain, &{
            let mut canonical_configuration = parameters;
            canonical_configuration.block_type_strategy = BlockTypeStrategy::Mixed;
            canonical_configuration
        })
        .unwrap();
        verify(&dynamic, &plain, &compressed[..contents.compressed_size]);
        verify(&mixed, &plain, &compressed[..contents.compressed_size]);
        assert_eq!(
            InspectedReconstructionData::read(&dynamic.corrections)
                .unwrap()
                .corrections,
            InspectedReconstructionData::read(&mixed.corrections)
                .unwrap()
                .corrections
        );
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
    let lazy = measure(&contents, &plain_text, &{
        let mut canonical_configuration = params;
        canonical_configuration.set_matching_type(MatchingType::Lazy {
            max_lazy: 258,
            filtered_matching: false,
            behavior: LazyBehavior::Zlib { good_length: 32 },
        });
        canonical_configuration
    })
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
    let early_exit = measure(&contents, &plain_text, &{
        let mut canonical_configuration = params;
        canonical_configuration.set_nice_length(3);
        canonical_configuration
    })
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

use crate::estimator::estimate_preflate_parameters;

type InspectedReconstructionData = ReconstructionData;

#[test]
fn parameter_reports_match_the_finalized_wire_settings_and_trace() {
    let compressed = crate::utils::read_file("compressed_zlib_level6.deflate");
    let mut processor = PreflateStreamProcessor::new(&PreflateConfig::default());
    processor.enable_trace(0);
    let chunk = processor.decompress(&compressed).unwrap();
    let encoded = ReconstructionData::read(&chunk.corrections)
        .unwrap()
        .parameters;
    let reconstruction_json = chunk.reconstruction_parameters_json().unwrap().unwrap();
    let reconstruction: ReconstructionParameters =
        serde_json::from_str(&reconstruction_json).unwrap();
    assert_eq!(encoded, reconstruction);
    assert_eq!(chunk.hash_algorithm(), Some(encoded.hash_algorithm()));
    let wrapper: serde_json::Value =
        serde_json::from_str(&chunk.estimator_parameters_json().unwrap().unwrap()).unwrap();
    assert_eq!(wrapper.as_object().unwrap().len(), 2);
    assert_eq!(
        wrapper["reconstruction"],
        serde_json::to_value(encoded).unwrap()
    );
    assert!(wrapper["model"].is_string());
    let trace = processor.prediction_trace().unwrap();
    assert_eq!(
        trace.reconstruction_parameters_json().unwrap(),
        Some(reconstruction_json)
    );
    assert_eq!(
        trace.estimator_parameters_json().unwrap(),
        chunk.estimator_parameters_json().unwrap()
    );
}

#[test]
fn continuation_chunks_do_not_repeat_parameter_reports() {
    let mut writer = DeflateWriter::new();
    for last in [false, true] {
        writer
            .encode_block(&DeflateTokenBlock {
                block_type: crate::deflate::deflate_token::DeflateTokenBlockType::Stored {
                    uncompressed: vec![b'a'; 768],
                },
                last,
            })
            .unwrap();
    }
    writer.flush();
    let compressed = writer.detach_output();
    let mut processor = PreflateStreamProcessor::new(&PreflateConfig {
        plain_text_limit: 1024,
        ..PreflateConfig::default()
    });
    let first = processor.decompress(&compressed).unwrap();
    assert!(first.estimator_parameters_json().unwrap().is_some());
    assert!(!processor.is_done());
    processor.shrink_to_dictionary();
    let second = processor
        .decompress(&compressed[first.compressed_size..])
        .unwrap();
    assert!(second.estimator_parameters_json().unwrap().is_none());
    assert!(second.reconstruction_parameters_json().unwrap().is_none());
    assert!(second.hash_algorithm().is_none());
}

/// takes a deflate compressed stream, analyzes it, decoompresses it, and records
/// any differences in the encoder codec
fn encode_mispredictions(
    deflate: &crate::deflate::deflate_reader::DeflateContents,
    plain_text: &PlainText,
    params: &ReconstructionParameters,
    encoder: &mut impl PredictionEncoder,
) -> Result<()> {
    let mut input = PreflateInput::new(plain_text);

    let mut token_predictor = TokenPredictor::from_parameters(params);

    predict_blocks(&deflate.blocks, &mut token_predictor, encoder, &mut input)?;

    Ok(())
}

fn decode_mispredictions(
    params: &ReconstructionParameters,
    input: &mut PreflateInput,
    decoder: &mut impl crate::statistical_codec::PredictionDecoder,
) -> Result<(Vec<u8>, Vec<DeflateTokenBlock>)> {
    let mut deflate_writer: DeflateWriter = DeflateWriter::new();
    let mut predictor = TokenPredictor::from_parameters(params);

    let output_blocks = recreate_blocks(&mut predictor, decoder, &mut deflate_writer, input)?;

    deflate_writer.flush();

    Ok((deflate_writer.detach_output(), output_blocks))
}

/// decompresses a deflate stream and returns the plaintext and cabac_encoded data that can be used to reconstruct it
/// This version uses DebugWriter and DebugReader, which are slower but can be used to debug the cabac encoding errors.
fn decompress_deflate_stream_assert(
    compressed_data: &[u8],
    verify: bool,
) -> Result<(PreflateStreamChunkResult, PlainText)> {
    use crate::{
        cabac::debug::{DebugReader, DebugWriter},
        deflate::deflate_reader::tests::parse_deflate_whole,
        preflate_error::AddContext,
    };

    let mut cabac_encoded = Vec::new();

    let mut cabac_encoder =
        PredictionEncoderCabac::new(DebugWriter::new(&mut cabac_encoded).unwrap());

    let (contents, plain_text) = parse_deflate_whole(compressed_data)?;

    let params = estimate_preflate_parameters(&contents, &plain_text).context()?;

    encode_mispredictions(&contents, &plain_text, &params, &mut cabac_encoder)?;
    assert_eq!(contents.compressed_size, compressed_data.len());
    cabac_encoder.finish();

    let reconstruction_data = ReconstructionData {
        parameters: params,
        corrections: cabac_encoded,
    }
    .write();

    if verify {
        let r = InspectedReconstructionData::read(&reconstruction_data)?;

        let mut cabac_decoder =
            PredictionDecoderCabac::new(DebugReader::new(Cursor::new(&r.corrections)).unwrap());

        let params = r.parameters;
        let mut input = PreflateInput::new(&plain_text);
        let (recompressed, _recreated_blocks) =
            decode_mispredictions(&params, &mut input, &mut cabac_decoder)?;

        if recompressed[..] != compressed_data[..] {
            return Err(PreflateError::new(
                ExitCode::RoundtripMismatch,
                "recompressed data does not match original",
            ));
        }
    }

    Ok((
        PreflateStreamChunkResult {
            corrections: reconstruction_data,
            compressed_size: contents.compressed_size,
            parameters: Some(crate::estimator::EstimationResult::test_fixture(params)),
            blocks: contents.blocks,
        },
        plain_text,
    ))
}

#[test]
fn verify_roundtrip_assert() {
    crate::utils::init_logging();

    use crate::utils::read_file;

    let v = read_file("compressed_zlib_level1.deflate");

    let (r, plain_text) = decompress_deflate_stream_assert(&v, true).unwrap();
    let recompressed = recompress_deflate_stream_assert(&plain_text, &r.corrections).unwrap();
    assert!(v == recompressed);
}

#[test]
fn verify_roundtrip_zlib() {
    crate::utils::init_logging();

    for i in 0..9 {
        verify_file(&format!("compressed_zlib_level{}.deflate", i));
    }
}

#[test]
fn verify_roundtrip_flate2() {
    crate::utils::init_logging();

    for i in 0..9 {
        verify_file(&format!("compressed_flate2_level{}.deflate", i));
    }
}

#[test]
fn verify_roundtrip_libdeflate() {
    crate::utils::init_logging();

    for i in 0..9 {
        verify_file(&format!("compressed_libdeflate_level{}.deflate", i));
    }
}

#[test]
fn typed_parameters_normalize_and_roundtrip() {
    use crate::deflate::deflate_token::{DeflateHuffmanType, DeflateToken, DeflateTokenBlockType};

    let text = b"@abcdXabcdYabcdZabcdW";
    let block = DeflateTokenBlock {
        last: true,
        block_type: DeflateTokenBlockType::Huffman {
            tokens: text.iter().copied().map(DeflateToken::Literal).collect(),
            huffman_type: DeflateHuffmanType::Static,
        },
    };
    let mut writer = DeflateWriter::new();
    writer.encode_block(&block).unwrap();
    writer.flush();
    let compressed = writer.detach_output();
    let (contents, plain) =
        crate::deflate::deflate_reader::tests::parse_deflate_whole(&compressed).unwrap();
    assert!(contents.compressed_size < 1024);
    let mut predictor =
        TokenPredictor::from_parameters(&crate::token_predictor::tests::zlib_level_1_params());
    let original = bitcode::encode(&predictor.reconstruction_parameters());
    let encoded = encode_first_chunk(&mut predictor, &contents, &plain, true, None).unwrap();
    let record = ReconstructionData::read(&encoded).unwrap();
    assert_ne!(original, bitcode::encode(&record.parameters));
    let decoder = TokenPredictor::from_reconstruction_parameters(record.parameters);
    assert_eq!(
        bitcode::encode(&decoder.reconstruction_parameters()),
        bitcode::encode(&record.parameters)
    );
    assert_eq!(
        recreate_whole_deflate_stream(plain.text(), &encoded).unwrap(),
        compressed
    );
}

#[test]
fn reconstruction_data_version() {
    use crate::utils::read_file;

    let v = read_file("compressed_zlib_level1.deflate");
    let (r, plain_text) = preflate_whole_deflate_stream(&v, &PreflateConfig::default()).unwrap();
    assert_eq!(r.corrections[0], RECONSTRUCTION_DATA_VERSION);

    let parsed = InspectedReconstructionData::read(&r.corrections).unwrap();

    // blobs written before the version byte existed are plain bitcode
    let unversioned = bitcode::encode(&parsed);
    let mut wrong_version = r.corrections.clone();
    wrong_version[0] = RECONSTRUCTION_DATA_VERSION + 1;
    let mut previous_version = r.corrections.clone();
    previous_version[0] = 0x81;
    let mut previous_models = r.corrections.clone();
    previous_models[0] = 0x82;
    let mut previous_flat = r.corrections.clone();
    previous_flat[0] = 0x83;

    for bad in [
        &unversioned[..],
        &wrong_version[..],
        &previous_version[..],
        &previous_models[..],
        &previous_flat[..],
        &[],
    ] {
        let e = recreate_whole_deflate_stream(plain_text.text(), bad).unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::InvalidCompressedWrapper);
    }
}

#[test]
fn truncated_nested_reconstruction_parameters_are_rejected() {
    let compressed = crate::utils::read_file("compressed_zlib_level1.deflate");
    let (record, _) =
        preflate_whole_deflate_stream(&compressed, &PreflateConfig::default()).unwrap();
    for length in 0..record.corrections.len() {
        let error = InspectedReconstructionData::read(&record.corrections[..length])
            .err()
            .unwrap();
        assert_eq!(error.exit_code(), ExitCode::InvalidCompressedWrapper);
    }
}

/// Adobe PDF Library 25/26 emits libdeflate-style streams whose final token is a
/// length 3 match covering the last 3 bytes of the plaintext. Stock libdeflate never
/// matches in the last 4 bytes, but the libdeflate model's length 3 hash table can
/// still find this match (see `HashChain::min_lookup_bytes`).
#[test]
fn verify_roundtrip_adobe_tail3() {
    crate::utils::init_logging();

    use crate::utils::read_file;
    let v = read_file("compressed_adobe_tail3.deflate");

    let (r, plain_text) = preflate_whole_deflate_stream(&v, &PreflateConfig::default()).unwrap();
    let recompressed = recreate_whole_deflate_stream(plain_text.text(), &r.corrections).unwrap();

    assert_eq!(r.compressed_size, v.len());
    assert!(v == recompressed);
}

fn verify_file(filename: &str) {
    use crate::utils::read_file;
    let v = read_file(filename);

    let (r, plain_text) = preflate_whole_deflate_stream(&v, &PreflateConfig::default()).unwrap();
    let recompressed = recreate_whole_deflate_stream(plain_text.text(), &r.corrections).unwrap();
    assert!(v == recompressed);
}

/// recompresses a deflate stream using the cabac_encoded data that was returned from decompress_deflate_stream
/// This version uses DebugWriter and DebugReader, which are slower and don't compress but can be used to debug the cabac encoding errors.
fn recompress_deflate_stream_assert(
    plain_text: &PlainText,
    prediction_corrections: &[u8],
) -> Result<Vec<u8>> {
    use crate::cabac::debug::DebugReader;

    let r = InspectedReconstructionData::read(prediction_corrections)?;

    let mut cabac_decoder =
        PredictionDecoderCabac::new(DebugReader::new(Cursor::new(&r.corrections)).unwrap());

    let mut input = PreflateInput::new(plain_text);
    let (recompressed, _recreated_blocks) =
        decode_mispredictions(&r.parameters, &mut input, &mut cabac_decoder)?;
    Ok(recompressed)
}

fn analyze_compressed_data_fast(
    compressed_data: &[u8],
    header_crc32: Option<u32>,
    uncompressed_size: &mut u64,
) {
    use std::io::Cursor;

    use crate::{
        cabac::vp8::{VP8Reader, VP8Writer},
        cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
        deflate::deflate_reader::tests::parse_deflate_whole,
    };

    let mut buffer = Vec::new();

    let mut cabac_encoder = PredictionEncoderCabac::new(VP8Writer::new(&mut buffer).unwrap());

    let (contents, plain_text) = parse_deflate_whole(compressed_data).unwrap();

    let params = estimate_preflate_parameters(&contents, &plain_text).unwrap();

    println!("params: {:?}", params);

    encode_mispredictions(&contents, &plain_text, &params, &mut cabac_encoder).unwrap();

    if let Some(crc) = header_crc32 {
        let result_crc = crc32fast::hash(plain_text.text());
        assert_eq!(result_crc, crc);
    }

    assert_eq!(contents.compressed_size, compressed_data.len());

    cabac_encoder.finish();

    cabac_encoder.print();

    println!("buffer size: {}", buffer.len());

    let mut cabac_decoder =
        PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&buffer)).unwrap());

    let mut input = PreflateInput::new(&plain_text);

    let (recompressed, _recreated_blocks) =
        decode_mispredictions(&params, &mut input, &mut cabac_decoder).unwrap();

    assert!(recompressed[..] == compressed_data[..]);

    *uncompressed_size = plain_text.text().len() as u64;
}

fn analyze_compressed_data_verify(
    compressed_data: &[u8],
    header_crc32: Option<u32>,
    _deflate_info_dump_level: i32,
    uncompressed_size: &mut u64,
) {
    use std::io::Cursor;

    use crate::{
        cabac::debug::{DebugReader, DebugWriter},
        cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
        deflate::{
            deflate_reader::tests::parse_deflate_whole, deflate_token::DeflateTokenBlockType,
        },
        statistical_codec::{VerifyPredictionDecoder, VerifyPredictionEncoder},
        utils::assert_eq_array,
    };

    let mut buffer = Vec::new();

    let cabac_encoder = PredictionEncoderCabac::new(DebugWriter::new(&mut buffer).unwrap());
    let debug_encoder = VerifyPredictionEncoder::new();

    let mut combined_encoder = (debug_encoder, cabac_encoder);

    let (contents, plain_text) = parse_deflate_whole(compressed_data).unwrap();

    let params = estimate_preflate_parameters(&contents, &plain_text).unwrap();

    println!("params: {:?}", params);

    encode_mispredictions(&contents, &plain_text, &params, &mut combined_encoder).unwrap();

    assert_eq!(contents.compressed_size, compressed_data.len());

    combined_encoder.finish();

    combined_encoder.0.print();

    let actions = combined_encoder.0.actions();

    println!("buffer size: {}", buffer.len());

    let debug_decoder = VerifyPredictionDecoder::new(actions);
    let cabac_decoder =
        PredictionDecoderCabac::new(DebugReader::new(Cursor::new(&buffer)).unwrap());

    let mut combined_decoder = (debug_decoder, cabac_decoder);
    let mut input = PreflateInput::new(&plain_text);

    let (recompressed, recreated_blocks) =
        decode_mispredictions(&params, &mut input, &mut combined_decoder).unwrap();

    assert_eq!(contents.blocks.len(), recreated_blocks.len());
    contents
        .blocks
        .iter()
        .zip(recreated_blocks)
        .enumerate()
        .for_each(|(index, (a, b))| match (&a.block_type, &b.block_type) {
            (
                DeflateTokenBlockType::Stored { uncompressed: a },
                DeflateTokenBlockType::Stored { uncompressed: c },
            ) => {
                assert_eq!(a, c, "uncompressed data differs {index}");
            }
            (
                DeflateTokenBlockType::Huffman {
                    tokens: t1,
                    huffman_type: h1,
                },
                DeflateTokenBlockType::Huffman {
                    tokens: t2,
                    huffman_type: h2,
                },
            ) => {
                assert_eq_array(t1, t2);
                assert_eq!(h1, h2, "huffman type differs {index}");
            }
            _ => panic!("block type differs {index}"),
        });

    assert_eq!(
        recompressed.len(),
        compressed_data.len(),
        "re-compressed version should be same (length)"
    );
    assert!(
        &recompressed[..] == compressed_data,
        "re-compressed version should be same (content)"
    );

    let result_crc = crc32fast::hash(plain_text.text());

    if let Some(crc) = header_crc32 {
        assert_eq!(crc, result_crc, "crc mismatch");
    }

    *uncompressed_size = plain_text.text().len() as u64;
}

fn do_analyze(crc: Option<u32>, compressed_data: &[u8]) {
    let mut uncompressed_size = 0;

    analyze_compressed_data_verify(compressed_data, crc, 1, &mut uncompressed_size);
    analyze_compressed_data_fast(compressed_data, crc, &mut uncompressed_size);
}

/// verify that levels 1-6 of zlib are compressed without any correction data
///
/// Future work: figure out why level 7 and above are not perfect
#[test]
fn verify_zlib_perfect_compression() {
    crate::utils::init_logging();

    use crate::{deflate::deflate_reader::tests::parse_deflate_whole, utils::read_file};

    for i in 1..6 {
        println!("iteration {}", i);
        let compressed_data: &[u8] =
            &read_file(format!("compressed_zlib_level{i}.deflate").as_str());

        let (contents, plain_text) = parse_deflate_whole(compressed_data).unwrap();

        let params = estimate_preflate_parameters(&contents, &plain_text).unwrap();

        println!("params: {:?}", params);

        // this "encoder" just asserts if anything gets passed to it
        let mut verify_encoder = crate::statistical_codec::tests::AssertDefaultOnlyEncoder {};
        encode_mispredictions(&contents, &plain_text, &params, &mut verify_encoder).unwrap();

        println!("params buffer length {}", params.serialized_size());
    }
}

#[test]
fn verify_longmatch() {
    crate::utils::init_logging();

    use crate::utils::read_file;
    do_analyze(
        None,
        &read_file("compressed_flate2_level1_longmatch.deflate"),
    );
}

#[test]
fn verify_zlibng() {
    crate::utils::init_logging();

    use crate::utils::read_file;

    do_analyze(None, &read_file("compressed_zlibng_level1.deflate"));
}

#[test]
fn verify_miniz() {
    crate::utils::init_logging();

    use crate::utils::read_file;

    do_analyze(None, &read_file("compressed_minizoxide_level1.deflate"));
}

/// this is the deflate stream extracted out of the png file (minus the idat wrapper)
#[test]
fn verify_png_deflate() {
    crate::utils::init_logging();

    use crate::utils::read_file;
    do_analyze(None, &read_file("treegdi.extract.deflate"));
}

pub fn analyze_compressed_data_verify_incremental(compressed_data: &[u8], config: &PreflateConfig) {
    use crate::{deflate::deflate_reader::tests::parse_deflate_whole, utils::assert_eq_array};

    let (original_con, _) = parse_deflate_whole(compressed_data).unwrap();

    let mut start_offset = 0;
    let mut end_offset = compressed_data.len().min(100001);

    let mut stream = PreflateStreamProcessor::new(config);

    let mut plain_text_offset = 0;

    let mut expanded_contents = Vec::new();
    while !stream.is_done() {
        let result = stream.decompress(&compressed_data[start_offset..end_offset]);
        match result {
            Ok(r) => {
                println!(
                    "chunk cmp_start={} cmp_size={} blocks={} pt_off={}({})",
                    start_offset,
                    r.compressed_size,
                    r.blocks.len(),
                    plain_text_offset,
                    stream.plain_text().len()
                );
                start_offset += r.compressed_size;
                end_offset = (start_offset + 10001).min(compressed_data.len());

                plain_text_offset += stream.plain_text().len();
                expanded_contents.push((r.corrections, stream.plain_text().text().to_vec()));

                stream.shrink_to_dictionary();
            }
            Err(e) => {
                if e.exit_code() == ExitCode::PredictionFailure {
                    println!(
                        "Prediction failure for {:?} not great, but some corner cases where the initial estimator isn't totaly right",
                        e
                    );
                    return;
                }
                assert_eq!(
                    e.exit_code(),
                    ExitCode::ShortRead,
                    "unexpected error {:?}",
                    e
                );
                end_offset = (end_offset + 10001).min(compressed_data.len());
            }
        }
    }

    // now reconstruct the data and make sure it is identical
    let mut recompressed = Vec::new();
    let mut reconstructed_blocks = Vec::new();

    let mut reconstruct = RecreateStreamProcessor::new();
    for (i, (corrections, plaintext)) in expanded_contents.iter().enumerate() {
        let (mut r, mut b) = reconstruct
            .recompress(&mut Cursor::new(plaintext), corrections)
            .unwrap();

        println!(
            "reconstruct block offset={} blocks={} pt={}",
            i,
            b.len(),
            plaintext.len()
        );

        recompressed.append(&mut r);
        reconstructed_blocks.append(&mut b);
    }

    //assert_eq!(original_con.blocks.len(), reconstructed_blocks.len());
    for (i, block) in original_con.blocks.iter().enumerate() {
        println!("block {}", i);
        crate::utils::assert_block_eq(block, &reconstructed_blocks[i]);
    }

    assert_eq_array(compressed_data, &recompressed);
}

#[test]
fn verify_plain_text_limit() {
    crate::utils::init_logging();

    analyze_compressed_data_verify_incremental(
        &crate::utils::read_file("compressed_zlib_level3.deflate"),
        &PreflateConfig {
            plain_text_limit: 1024 * 1024,
            ..Default::default()
        },
    );
}

/// test partial reading reading
#[test]
fn verify_partial_blocks() {
    crate::utils::init_logging();

    for i in 0..=9 {
        analyze_compressed_data_verify_incremental(
            &crate::utils::read_file(&format!("compressed_zlib_level{}.deflate", i)),
            &PreflateConfig::default(),
        );
    }
}

/// Replicates exactly what `scan_deflate::find_compressable_stream` does when it
/// encounters a gzip stream in a truncated 200 KiB content buffer:
///
/// 1. strip the 10-byte gzip header (and 8-byte footer) to obtain the raw DEFLATE body
/// 2. call `decompress` with only the first ~190 KB of that body (what fits in the
///    200 KiB content window after the header)
/// 3. assert the call returns `Ok` and `is_done() == false`  ← DeflateContinue requires this
/// 4. call `decompress` again with the remainder of the body, assert `is_done() == true`
/// 5. reconstruct the original DEFLATE bytes and assert roundtrip identity
#[test]
fn verify_decompress_partial_gzip_deflate_body_roundtrip() {
    crate::utils::init_logging();

    // sample1.bin.gz: 263 972 bytes total; gzip header = 10 bytes, footer = 8 bytes
    // → raw DEFLATE body = 263 954 bytes
    let gzip = crate::utils::read_file("sample1.bin.gz");
    assert!(gzip.len() > 18, "gzip file too short");

    // Gzip header for this file has no extra flags, so it is exactly 10 bytes.
    let deflate_start: usize = 10;
    let deflate_end: usize = gzip.len() - 8;
    let deflate_body = &gzip[deflate_start..deflate_end];

    // Mimic what find_compressable_stream does: content buffer contains the first
    // 200 000 bytes of the gzip file, and the DEFLATE body starts at offset 10,
    // so the slice passed to decompress() is bytes [10..200000] = 199 990 bytes.
    let content_window: usize = 200_000 - deflate_start; // 199 990
    assert!(
        content_window < deflate_body.len(),
        "content window must truncate the DEFLATE body (window={content_window}, body={})",
        deflate_body.len()
    );

    let mut state = PreflateStreamProcessor::new(&PreflateConfig::default());

    // ── First call: truncated slice ──────────────────────────────────────────
    let r1 = state.decompress(&deflate_body[..content_window]);
    let r1 = match r1 {
        Ok(r) => r,
        Err(e) => panic!(
            "decompress on truncated DEFLATE body ({content_window} B of {} B) returned \
             Err({e:?}); expected Ok(partial) with is_done()=false",
            deflate_body.len()
        ),
    };
    assert!(
        !state.is_done(),
        "is_done() must be false after truncated first call; compressed_size={}",
        r1.compressed_size
    );
    assert!(
        r1.compressed_size > 0,
        "at least one block must have been consumed"
    );
    assert!(
        r1.compressed_size <= content_window,
        "compressed_size ({}) must not exceed the slice length ({content_window})",
        r1.compressed_size
    );
    println!(
        "first call: compressed_size={} / {content_window}  blocks={}",
        r1.compressed_size,
        r1.blocks.len()
    );

    let first_corrections = r1.corrections.clone();
    let first_plain_text = state.plain_text().text().to_vec();
    state.shrink_to_dictionary();

    // ── Second call: remainder ────────────────────────────────────────────────
    let offset = r1.compressed_size;
    let r2 = state.decompress(&deflate_body[offset..]);
    let r2 = match r2 {
        Ok(r) => r,
        Err(e) => panic!(
            "decompress on remainder ({} B) returned Err({e:?})",
            deflate_body.len() - offset
        ),
    };
    assert!(
        state.is_done(),
        "is_done() must be true after consuming the full body"
    );
    println!(
        "second call: compressed_size={}  blocks={}",
        r2.compressed_size,
        r2.blocks.len()
    );

    let second_corrections = r2.corrections.clone();
    let second_plain_text = state.plain_text().text().to_vec();

    // ── Roundtrip: reconstruct the original bytes ─────────────────────────────
    let mut reconstruct = RecreateStreamProcessor::new();
    let (mut recompressed, _) = reconstruct
        .recompress(
            &mut std::io::Cursor::new(&first_plain_text),
            &first_corrections,
        )
        .expect("recompress chunk 1 failed");

    let (mut rest, _) = reconstruct
        .recompress(
            &mut std::io::Cursor::new(&second_plain_text),
            &second_corrections,
        )
        .expect("recompress chunk 2 failed");

    recompressed.append(&mut rest);
    crate::utils::assert_eq_array(deflate_body, &recompressed);
}
