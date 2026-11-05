//! Assembly of executable compressor settings from stream and match-chain evidence.
//! Coordinates insertion, hash, window, and parser estimation with bounded profile refinements.

/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use super::{
    complevel_estimator::estimate_preflate_depth, compressor_profile::select_compressor_profile,
    initial_estimate::InitialEstimate, models::zlib, preflate_stream_info::PreflateStreamInfo,
};
use crate::{
    bit_helper::bit_length,
    deflate::{deflate_constants, deflate_reader::DeflateContents},
    estimator::models::zlib::refine_parameters as refine_zlib_parameters,
    parameters::{BlockTypeStrategy, DictionaryAddPolicy, PreflateStrategy},
    preflate_error::Result,
    preflate_input::PlainText,
    reconstruction_parameters::ReconstructionParameters,
};

#[cfg(feature = "diagnostics")]
pub fn estimate_preflate_result(
    deflate_contents: &DeflateContents,
    plain_text: &PlainText,
) -> Result<super::estimation_result::EstimationResult> {
    estimate_preflate_profile(deflate_contents, plain_text)
}

pub fn estimate_preflate_profile(
    deflate_contents: &DeflateContents,
    plain_text: &PlainText,
) -> Result<super::estimation_result::EstimationResult> {
    let info = super::preflate_stream_info::extract_preflate_info_with_plaintext(
        &deflate_contents.blocks,
        plain_text,
    );

    let preflate_strategy = estimate_preflate_strategy(&info);
    let huff_strategy = estimate_preflate_huff_strategy(&info);

    if preflate_strategy == PreflateStrategy::Store
        || preflate_strategy == PreflateStrategy::HuffOnly
    {
        // No dictionary used
        return Ok(
            crate::estimator::compressor_profile::CompressorProfile::Custom.with_parameters(
                ReconstructionParameters {
                    max_token_count: (1
                        << (6 + estimate_preflate_mem_level(info.max_tokens_per_block)))
                        - 1,
                    block_type_strategy: huff_strategy,
                    behavior: crate::reconstruction_parameters::BehaviorSettings::NoDictionary {
                        strategy: preflate_strategy,
                    },
                },
            ),
        );
    }

    let window_bits = estimate_preflate_window_bits(info.max_dist);
    let mem_level = estimate_preflate_mem_level(info.max_tokens_per_block);
    let add_policy = info
        .insertion_evidence
        .inferred_policy(info.ends_with_final_block);

    let max_token_count = (1 << (6 + mem_level)) - 1;

    let depth = estimate_preflate_depth(
        window_bits,
        mem_level,
        &info,
        deflate_contents,
        plain_text,
        add_policy,
    )?;

    let initial = InitialEstimate {
        evidence: depth.selected,
        window_bits,
        insertion: crate::estimator::compressor_profile::chain_add_policy(
            depth.selected.hash_algorithm,
            add_policy,
            info.max_len,
        ),
        max_token_count,
        block_type_strategy: huff_strategy,
        strategy: preflate_strategy,
        info: &info,
    };
    let profile = select_compressor_profile(&initial);
    let estimate = refine_zlib_parameters(profile, &depth, &info, deflate_contents, plain_text);
    // Keep prediction refinement first; changing its starting parser changes its ranking.
    let mut profile = estimate.resolve_profile(depth.selected.parser, info.max_len);
    let parameters = profile.reconstruction;
    let short_match_rejections = depth
        .short_match_rejections
        .iter()
        .find_map(|&(hash, count)| (hash == parameters.hash_algorithm()).then_some(count))
        .unwrap_or(0);
    zlib::refine_short_match_policy(&mut profile.reconstruction, &info, short_match_rejections);
    let mut profile = super::prediction_scoring::refine_profile(
        profile,
        &info,
        deflate_contents,
        plain_text,
        &depth.zlib_candidates,
    );
    if info.ends_with_final_block {
        canonicalize_first_only_insertion(&mut profile.reconstruction, plain_text.total_length());
    }
    if deflate_contents.compressed_size < 1024 && info.ends_with_final_block {
        canonicalize_unobserved_insertion(&mut profile.reconstruction, info.max_len);
    }
    Ok(profile)
}

fn estimate_preflate_mem_level(max_block_size_: u32) -> u32 {
    let mut max_block_size = max_block_size_;
    let mut mbits = 0;
    while max_block_size > 0 {
        mbits += 1;
        max_block_size >>= 1;
    }
    mbits = mbits.clamp(7, 15);
    mbits - 6
}

pub fn estimate_preflate_window_bits(max_dist_: u32) -> u32 {
    let mut max_dist = max_dist_;
    max_dist += deflate_constants::MIN_LOOKAHEAD;
    let wbits = bit_length(max_dist - 1);
    wbits.clamp(9, 15)
}

fn estimate_preflate_strategy(info: &PreflateStreamInfo) -> PreflateStrategy {
    if info.count_stored_blocks == info.count_blocks
        || (info.stored_bytes != 0 && info.token_count == 0)
    {
        return PreflateStrategy::Store;
    }
    // Empty flush/end blocks carry no parser evidence. Nonempty stored payloads
    // still require the general model when mixed with Huffman blocks.
    if info.stored_bytes != 0 {
        return PreflateStrategy::Default;
    }
    if info.reference_count == 0 {
        return PreflateStrategy::HuffOnly;
    }
    if info.max_dist == 1 {
        return PreflateStrategy::RleOnly;
    }
    PreflateStrategy::Default
}

fn estimate_preflate_huff_strategy(info: &PreflateStreamInfo) -> BlockTypeStrategy {
    if info.count_static_huff_tree_blocks == info.count_blocks {
        return BlockTypeStrategy::Static;
    }
    if info.count_stored_blocks == info.count_blocks {
        return BlockTypeStrategy::Uncompressed;
    }
    if info.count_static_huff_tree_blocks == 0 {
        return BlockTypeStrategy::Dynamic;
    }
    BlockTypeStrategy::Dynamic
}

pub fn canonicalize_unobserved_insertion(
    parameters: &mut ReconstructionParameters,
    longest_match: u32,
) {
    if matches!(parameters.dictionary().expect("dictionary candidate").insertion,
            DictionaryAddPolicy::AddFirst(limit) | DictionaryAddPolicy::AddFirstAndLast(limit)
                if u32::from(limit) >= longest_match)
    {
        parameters
            .dictionary_mut()
            .expect("dictionary candidate")
            .insertion = DictionaryAddPolicy::AddAll;
    }
}

fn canonicalize_first_only_insertion(
    parameters: &mut ReconstructionParameters,
    plaintext_bytes: u32,
) {
    if parameters
        .dictionary()
        .expect("dictionary candidate")
        .insertion
        == DictionaryAddPolicy::AddFirst(0)
        && plaintext_bytes <= crate::compressors::zlib_ng::SLIDE_POINT
    {
        // No later token can observe an insertion at the slide point.
        parameters
            .dictionary_mut()
            .expect("dictionary candidate")
            .insertion = DictionaryAddPolicy::AddFirstWith32KBoundary;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        super::{
            complevel_estimator::DepthEstimate,
            compressor_profile::{
                CompressorProfile, EstimateProvenance, ParameterEstimate, ParserContext,
            },
            estimation_result::EstimationResult,
            preflate_stream_info::tests::extract_preflate_info,
        },
        *,
    };
    use crate::{
        estimator::{depth_estimator::DistancePolicy, models::zlib::SLOW_PREFLATE_PARSER_SETTINGS},
        parameters::{LazyBehavior, tests::MatchingType},
    };

    /// From the plain text and the preflate blocks, estimate the preflate parameters
    pub fn estimate_preflate_parameters(
        deflate_contents: &DeflateContents,
        plain_text: &PlainText,
    ) -> Result<ReconstructionParameters> {
        estimate_preflate_profile(deflate_contents, plain_text).map(|result| result.reconstruction)
    }

    #[test]
    fn canonical_short_match_cutoffs_preserve_intervals_and_encoded_parameter_size() {
        let mut params = crate::token_predictor::tests::zlib_level_1_params();
        for original in 0..=32768 {
            params.set_short_match_cutoff(original);
            let original_size = params.serialized_size();
            for bounds in [
                (0, 32768),
                (original, 32768),
                (original / 2, original),
                (original, original),
            ] {
                let cutoff = params.canonical_short_match_cutoff(bounds);
                assert!(
                    (bounds.0..=bounds.1).contains(&cutoff),
                    "{original}: {bounds:?}"
                );
                let candidate = {
                    let mut canonical_configuration = params;
                    canonical_configuration.set_short_match_cutoff(cutoff);
                    canonical_configuration
                };
                assert!(
                    candidate.serialized_size() <= original_size,
                    "{original} -> {cutoff}"
                );
                assert_eq!(candidate.canonical_short_match_cutoff(bounds), cutoff);
            }
        }
        for (original, bounds, expected) in [
            (4, (4, 8), 8),
            (255, (255, 32768), 255),
            (256, (256, 32768), 32768),
            (8193, (8193, 9000), 8704),
            (4097, (4097, 32768), 32768),
            (3000, (2500, 3500), 3072),
            (5, (4, 7), 4),
            (32769, (32769, u32::MAX), 32769),
        ] {
            params.set_short_match_cutoff(original);
            assert_eq!(params.canonical_short_match_cutoff(bounds), expected);
        }
    }

    #[test]
    fn canonical_short_match_cutoffs_choose_the_coarsest_binary_grid() {
        let mut params = crate::token_predictor::tests::zlib_level_1_params();
        for lower in 0u32..=512 {
            let mut expected = lower;
            for upper in lower..=512 {
                if upper == 0 || upper.trailing_zeros() > expected.trailing_zeros() {
                    expected = upper;
                }
                params.set_short_match_cutoff(upper);
                assert_eq!(
                    params.canonical_short_match_cutoff((lower, upper)),
                    expected,
                    "{lower}..={upper}"
                );
            }
        }
    }

    #[test]
    fn strategy_ignores_empty_structural_blocks() {
        use crate::deflate::deflate_token::{
            DeflateHuffmanType, DeflateToken, DeflateTokenBlock, DeflateTokenBlockType,
        };

        fn huffman(tokens: Vec<DeflateToken>) -> DeflateTokenBlock {
            DeflateTokenBlock {
                block_type: DeflateTokenBlockType::Huffman {
                    tokens,
                    huffman_type: DeflateHuffmanType::Static,
                },
                last: false,
            }
        }

        fn stored(bytes: Vec<u8>) -> DeflateTokenBlock {
            DeflateTokenBlock {
                block_type: DeflateTokenBlockType::Stored {
                    uncompressed: bytes,
                },
                last: false,
            }
        }

        for (body, expected) in [
            (
                huffman(vec![DeflateToken::Literal(b'A')]),
                PreflateStrategy::HuffOnly,
            ),
            (
                huffman(vec![
                    DeflateToken::Literal(b'A'),
                    DeflateToken::new_ref(199, 1),
                ]),
                PreflateStrategy::RleOnly,
            ),
            (
                huffman(vec![
                    DeflateToken::Literal(b'A'),
                    DeflateToken::Literal(b'B'),
                    DeflateToken::new_ref(198, 2),
                ]),
                PreflateStrategy::Default,
            ),
            (stored(vec![b'A']), PreflateStrategy::Store),
        ] {
            let mut blocks = vec![body];
            assert_eq!(
                estimate_preflate_strategy(&extract_preflate_info(&blocks)),
                expected
            );
            blocks.insert(0, stored(Vec::new()));
            blocks.insert(0, huffman(Vec::new()));
            blocks.push(stored(Vec::new()));
            blocks.push(huffman(Vec::new()));
            assert_eq!(
                estimate_preflate_strategy(&extract_preflate_info(&blocks)),
                expected
            );
        }

        let mixed = [
            huffman(vec![DeflateToken::Literal(b'A')]),
            stored(vec![b'B']),
        ];
        assert_eq!(
            estimate_preflate_strategy(&extract_preflate_info(&mixed)),
            PreflateStrategy::Default
        );
    }

    #[test]
    fn skipped_prefix_refinement_preserves_fingerprint_provenance() {
        use super::super::{
            complevel_estimator::CandidateEvidence, parser_estimator::ParserInference,
        };

        let parameters = crate::token_predictor::tests::zlib_level_1_params();
        let contents = DeflateContents {
            compressed_size: 0,
            blocks: Vec::new(),
        };
        let info = extract_preflate_info(&contents.blocks);
        let depth = DepthEstimate {
            selected: CandidateEvidence {
                hash_algorithm: parameters.hash_algorithm(),
                required_chain: parameters.max_chain(),
                distance_policy: DistancePolicy::ZlibWindow,
                parser: ParserInference::Unresolved,
                shallow_miniz_greedy: false,
                minimum_nice_length: 0,
            },
            zlib_candidates: Vec::new(),
            short_match_rejections: Vec::new(),
        };
        assert!(matches!(
            refine_zlib_parameters(
                ParameterEstimate {
                    profile: crate::estimator::compressor_profile::CompressorProfile::Zlib
                        .with_parameters(parameters),
                    provenance: EstimateProvenance::Fingerprinted,
                },
                &depth,
                &info,
                &contents,
                &PlainText::new(),
            )
            .provenance,
            EstimateProvenance::Fingerprinted
        ));
    }

    #[test]
    fn parser_resolution_preserves_search_parameters_and_validated_choices() {
        use super::super::parser_estimator::ParserEvidence;
        let parameters = crate::token_predictor::tests::zlib_level_1_params();
        let inference = ParserEvidence {
            lazy_matches: 4,
            longest_lazy_match: 7,
        }
        .infer(false);
        let expected = {
            let mut canonical_configuration = parameters;
            canonical_configuration.set_matching_type(MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: false,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            });
            canonical_configuration
        };
        assert_eq!(
            ParameterEstimate {
                profile: crate::estimator::compressor_profile::CompressorProfile::Custom
                    .with_parameters(parameters),
                provenance: EstimateProvenance::Inferred(ParserContext {
                    zlib_compatible: true,
                    observed_min_len: 3,
                }),
            }
            .resolve_parser(inference, 4),
            expected
        );
        assert_eq!(
            ParameterEstimate {
                profile: crate::estimator::compressor_profile::CompressorProfile::Custom
                    .with_parameters(parameters),
                provenance: EstimateProvenance::PrefixValidated,
            }
            .resolve_parser(inference, 4),
            parameters
        );
        assert_eq!(
            ParameterEstimate {
                profile: crate::estimator::compressor_profile::CompressorProfile::Custom
                    .with_parameters(parameters),
                provenance: EstimateProvenance::Fingerprinted,
            }
            .resolve_parser(inference, 4),
            parameters
        );
        assert_eq!(
            ParameterEstimate {
                profile: crate::estimator::compressor_profile::CompressorProfile::Custom
                    .with_parameters(parameters),
                provenance: EstimateProvenance::Inferred(ParserContext {
                    zlib_compatible: true,
                    observed_min_len: 3,
                }),
            }
            .resolve_parser(inference, 5),
            parameters
        );
    }

    #[test]
    fn parser_resolution_matches_previous_refinement_rules() {
        use super::super::parser_estimator::ParserEvidence;

        // Frozen pre-refactor rules are the oracle for this metadata-only equivalence test.
        fn previous_policy(
            parameters: &ReconstructionParameters,
            hash_unchanged: bool,
            longest_match: u32,
            greedy: bool,
            evidence: ParserEvidence,
        ) -> MatchingType {
            if hash_unchanged
                && parameters.matching_type() == MatchingType::Greedy
                && matches!(parameters.add_policy(),
                DictionaryAddPolicy::AddFirst(limit) if u32::from(limit) >= longest_match)
                && !greedy
                && evidence.lazy_matches >= 4
                && evidence.longest_lazy_match >= 6
                && let Some(config) = SLOW_PREFLATE_PARSER_SETTINGS[2..].iter().find(|config| {
                    matches!(config.parser.matching_type(), MatchingType::Lazy { max_lazy, .. }
                    if max_lazy > evidence.longest_lazy_match)
                })
            {
                config.parser.matching_type()
            } else {
                parameters.matching_type()
            }
        }

        let base = crate::token_predictor::tests::zlib_level_1_params();
        for matching_type in [
            MatchingType::Greedy,
            MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: false,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            },
            MatchingType::MiniZ {
                max_probes: 32,
                greedy: true,
            },
            MatchingType::LibdeflateGreedy,
            MatchingType::LibdeflateLazy {
                two_positions: true,
            },
        ] {
            for add_policy in [
                DictionaryAddPolicy::AddAll,
                DictionaryAddPolicy::AddFirst(0),
                DictionaryAddPolicy::AddFirst(4),
                DictionaryAddPolicy::AddFirst(6),
                DictionaryAddPolicy::AddFirst(128),
                DictionaryAddPolicy::AddFirst(258),
                DictionaryAddPolicy::AddFirstAndLast(6),
                DictionaryAddPolicy::AddFirstWith32KBoundary,
                DictionaryAddPolicy::AddFirstExcept4kBoundary,
            ] {
                let parameters = {
                    let mut canonical_configuration = base;
                    canonical_configuration.set_insertion(add_policy);
                    canonical_configuration.set_matching_type(matching_type);
                    canonical_configuration
                };
                for longest_match in [0, 4, 6, 128, 258] {
                    for lazy_matches in [0, 3, 4, 256] {
                        for longest_lazy_match in [
                            0,
                            3,
                            5,
                            6,
                            7,
                            15,
                            16,
                            31,
                            32,
                            127,
                            128,
                            129,
                            257,
                            258,
                            u16::MAX,
                        ] {
                            let evidence = ParserEvidence {
                                lazy_matches,
                                longest_lazy_match,
                            };
                            for greedy in [false, true] {
                                for hash_unchanged in [false, true] {
                                    let expected = {
                                        let mut canonical_configuration = parameters;
                                        canonical_configuration.set_matching_type(previous_policy(
                                            &parameters,
                                            hash_unchanged,
                                            longest_match,
                                            greedy,
                                            evidence,
                                        ));
                                        canonical_configuration
                                    };
                                    // Map the old hash-based protection to explicit provenance.
                                    // Same-hash validated choices are covered separately above.
                                    let estimate = if hash_unchanged {
                                        ParameterEstimate {
                                        profile:
                                            crate::estimator::compressor_profile::CompressorProfile::Custom
                                                .with_parameters(parameters),
                                        provenance: EstimateProvenance::Inferred(ParserContext {
                                            zlib_compatible: true,
                                            observed_min_len: 3,
                                        }),
                                    }
                                    } else {
                                        ParameterEstimate {
                                        profile:
                                            crate::estimator::compressor_profile::CompressorProfile::Custom
                                                .with_parameters(parameters),
                                        provenance: EstimateProvenance::PrefixValidated,
                                    }
                                    };
                                    assert_eq!(
                                        estimate
                                            .resolve_parser(evidence.infer(greedy), longest_match),
                                        expected
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn zlib_stream_with_distance_4096_keeps_compatible_search_semantics() {
        use crate::{deflate::deflate_reader::tests::parse_deflate_whole, utils::read_file};

        let compressed = read_file("pptxplaintext.deflate");
        let (contents, plain_text) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(
            extract_preflate_info(&contents.blocks).max_dist_3_matches,
            4096
        );
        let parameters = estimate_preflate_parameters(&contents, &plain_text).unwrap();
        assert_eq!(parameters.add_policy(), DictionaryAddPolicy::AddAll);
        assert!(matches!(
            parameters.matching_type(),
            MatchingType::Lazy {
                behavior: LazyBehavior::Zlib { .. },
                ..
            }
        ));
    }

    #[test]
    fn first_only_canonicalization_requires_an_unobservable_slide_insertion() {
        let parameters = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(0));
            canonical_configuration
        };
        for (bytes, expected) in [
            (0, DictionaryAddPolicy::AddFirstWith32KBoundary),
            (
                crate::compressors::zlib_ng::SLIDE_POINT,
                DictionaryAddPolicy::AddFirstWith32KBoundary,
            ),
            (
                crate::compressors::zlib_ng::SLIDE_POINT + 1,
                DictionaryAddPolicy::AddFirst(0),
            ),
        ] {
            let mut profile = CompressorProfile::Custom.with_parameters(parameters);
            canonicalize_first_only_insertion(&mut profile.reconstruction, bytes);
            assert!(matches!(
                profile,
                EstimationResult {
                    model: CompressorProfile::Custom,
                    ..
                }
            ));
            assert_eq!(profile.reconstruction.add_policy(), expected);
            assert!(profile.reconstruction.serialized_size() <= parameters.serialized_size());
        }
    }

    #[test]
    fn unobserved_insertion_limits_preserve_family_and_active_overrides() {
        let parameters = crate::token_predictor::tests::zlib_level_1_params();
        for (policy, maximum, expected) in [
            (
                DictionaryAddPolicy::AddFirst(4),
                4,
                DictionaryAddPolicy::AddAll,
            ),
            (
                DictionaryAddPolicy::AddFirstAndLast(4),
                4,
                DictionaryAddPolicy::AddAll,
            ),
            (
                DictionaryAddPolicy::AddFirst(4),
                5,
                DictionaryAddPolicy::AddFirst(4),
            ),
            (
                DictionaryAddPolicy::AddFirstAndLast(4),
                5,
                DictionaryAddPolicy::AddFirstAndLast(4),
            ),
            (
                DictionaryAddPolicy::AddFirstExcept4kBoundary,
                4,
                DictionaryAddPolicy::AddFirstExcept4kBoundary,
            ),
            (
                DictionaryAddPolicy::AddFirstWith32KBoundary,
                4,
                DictionaryAddPolicy::AddFirstWith32KBoundary,
            ),
        ] {
            let parameters = {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_insertion(policy);
                canonical_configuration
            };
            let mut profile = CompressorProfile::Zlib.with_parameters(parameters);
            canonicalize_unobserved_insertion(&mut profile.reconstruction, maximum);
            assert!(matches!(
                profile,
                EstimationResult {
                    model: CompressorProfile::Zlib,
                    ..
                }
            ));
            assert_eq!(profile.reconstruction.add_policy(), expected);
            assert!(profile.reconstruction.serialized_size() <= parameters.serialized_size());
        }
    }

    #[test]
    fn canonical_token_limits_preserve_bounds_width_and_idempotence() {
        let mut parameters = crate::token_predictor::tests::zlib_level_1_params();
        for original in 0..=u16::MAX {
            parameters.max_token_count = original;
            let size = parameters.serialized_size();
            for bounds in [
                (0, u32::from(u16::MAX)),
                (u32::from(original), u32::from(original)),
                (u32::from(original / 2), u32::from(original)),
            ] {
                let limit = crate::reconstruction_parameters::canonical_token_limit(
                    parameters.max_token_count,
                    bounds,
                );
                assert!((bounds.0..=bounds.1).contains(&u32::from(limit)));
                let canonical = {
                    let mut canonical_configuration = parameters;
                    canonical_configuration.max_token_count = limit;
                    canonical_configuration
                };
                assert!(canonical.serialized_size() <= size);
                assert_eq!(
                    crate::reconstruction_parameters::canonical_token_limit(
                        canonical.max_token_count,
                        bounds
                    ),
                    limit
                );
            }
        }
    }
}
