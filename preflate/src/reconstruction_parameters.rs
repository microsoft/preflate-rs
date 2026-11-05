/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Executable compressor settings and their compact reconstruction format.
//!
//! The configuration first selects dictionary-free, chain-based, or MiniZ
//! behavior. Chain-based behavior shares dictionary and search settings while
//! keeping parser-specific options in separate variants. MiniZ has its own probe
//! settings, and dictionary-free streams carry no dictionary payload.
//! Dictionary layout, hash calculation, input-tail restrictions, and distance
//! bounds are explicit choices. The supported dual-hash index couples its primary
//! chain and singleton secondary head, without making the hash select a parser
//! or window policy.
//!
//! These are the settings executed by prediction and stored for reconstruction,
//! not a description of which library produced the stream. Model identity is
//! separate estimation metadata. Normalization uses bounds established during
//! replay to choose smaller serialized values with equivalent behavior, and
//! removes aliases such as the identical Dynamic and Mixed block predictions.

use bitcode::{Decode, Encode};

use crate::{
    hash_algorithm::HashAlgorithm,
    parameters::{BlockTypeStrategy, DictionaryAddPolicy, LazyBehavior, PreflateStrategy},
};

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReconstructionParameters {
    pub max_token_count: u16,
    pub block_type_strategy: BlockTypeStrategy,
    pub behavior: BehaviorSettings,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NormalizationBounds {
    pub window_bits: Option<u32>,
    pub short_match_cutoff: Option<(u32, u32)>,
    pub token_count: Option<(u32, u32)>,
}

pub(crate) fn canonical_short_match_cutoff(original: u32, bounds: (u32, u32)) -> u32 {
    debug_assert!(bounds.0 <= original && original <= bounds.1);
    // Keep the singleton bitcode integer within its original width.
    let maximum = if original <= u32::from(u8::MAX) {
        u32::from(u8::MAX)
    } else {
        32768
    };
    let lower = bounds.0;
    let upper = bounds.1.min(maximum);
    if lower == 0 {
        return 0;
    }
    if lower > upper {
        return original;
    }
    let alignment = ((lower - 1) ^ upper).ilog2();
    upper & (u32::MAX << alignment)
}

pub(crate) fn canonical_token_limit(original: u16, bounds: (u32, u32)) -> u16 {
    debug_assert!(bounds.0 <= u32::from(original) && u32::from(original) <= bounds.1);
    let maximum = if original <= u16::from(u8::MAX) {
        u16::from(u8::MAX)
    } else {
        u16::MAX
    };
    [1023, 2047, 4095, 8191, 16383, 32767, 65535, 511, 255, 127]
        .into_iter()
        .find(|&limit| {
            limit <= maximum && bounds.0 <= u32::from(limit) && u32::from(limit) <= bounds.1
        })
        .unwrap_or(original)
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) enum BehaviorSettings {
    NoDictionary {
        strategy: PreflateStrategy,
    },
    Chain {
        common: ChainMatchSettings,
        parser: ChainParser,
    },
    MiniZ {
        common: MiniZMatchSettings,
        greedy: bool,
        short_match_cutoff: u32,
    },
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) enum ChainParser {
    Greedy {
        short_match_cutoff: u32,
    },
    Lazy {
        lookahead: LazyLookaheadSettings,
        minimum: LazyMinimum,
    },
    LibdeflateGreedy {
        short_match_cutoff: u32,
    },
    LibdeflateLazy {
        two_positions: bool,
        short_match_cutoff: u32,
    },
    WindowsLazy {
        max_lazy: u16,
        short_match_cutoff: u32,
    },
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChainMatchSettings {
    pub dictionary: DictionarySettings,
    pub distance: ChainDistancePolicy,
    pub search: ChainSettings,
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) struct LazyLookaheadSettings {
    pub max_lazy: u16,
    pub behavior: LazyBehavior,
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) struct MiniZMatchSettings {
    pub dictionary: DictionarySettings,
    pub distance: MiniZDistancePolicy,
    pub search: MiniZSearchSettings,
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) struct MiniZSearchSettings {
    pub max_probes: u16,
    pub budget: SearchBudget,
    pub input_tail: InputTailPolicy,
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) struct DictionarySettings {
    pub index: DictionaryIndex,
    // Hop-based correction recovery uses the window even when prediction is disabled.
    pub window_bits: u32,
    pub insertion: DictionaryAddPolicy,
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceHistorySettings {
    pub matches_to_start: bool,
}

impl SourceHistorySettings {
    #[inline]
    pub(crate) fn maximum_distance(self, history: u32) -> u32 {
        history.saturating_sub(u32::from(!self.matches_to_start))
    }
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) enum MiniZDistancePolicy {
    Disabled,
    Enabled(SourceHistorySettings),
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) enum ChainDistancePolicy {
    Disabled,
    RleOnly,
    Window {
        history: SourceHistorySettings,
        bounds: WindowBounds,
    },
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) enum WindowBounds {
    Full,
    /// Prediction excludes the oldest window position; correction recovery admits it.
    ExcludeOldest,
    /// The head admits window - MIN_LOOKAHEAD + 1; later links admit one less.
    Lookahead,
    /// Prediction tightens both lookahead bounds by one; recovery uses Lookahead.
    LookaheadMinusOne,
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) enum DictionaryIndex {
    Chain {
        hash: HashFunction,
    },
    /// A four-byte primary chain with one three-byte secondary head per bucket.
    LibdeflateDualHash,
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) enum HashFunction {
    Zlib { hash_mask: u16, hash_shift: u32 },
    MiniZFast,
    Libdeflate4,
    ZlibNG,
    RandomVector,
    Crc32cHash,
    Libdeflate4_15,
    Chromium { hash_mask: u16 },
}

impl DictionaryIndex {
    pub(crate) fn from_algorithm(hash: HashAlgorithm) -> Option<Self> {
        Some(match hash {
            HashAlgorithm::None => return None,
            HashAlgorithm::Libdeflate4 => return Some(Self::LibdeflateDualHash),
            other => Self::Chain {
                hash: HashFunction::from_algorithm(other),
            },
        })
    }

    pub(crate) fn into_algorithm(self) -> HashAlgorithm {
        match self {
            Self::Chain { hash } => hash.into_algorithm(),
            Self::LibdeflateDualHash => HashAlgorithm::Libdeflate4,
        }
    }
}

impl HashFunction {
    fn from_algorithm(hash: HashAlgorithm) -> Self {
        match hash {
            HashAlgorithm::None | HashAlgorithm::Libdeflate4 => {
                unreachable!("dictionary index handles dictionary-free and dual-hash signatures")
            }
            HashAlgorithm::Zlib {
                hash_mask,
                hash_shift,
            } => Self::Zlib {
                hash_mask,
                hash_shift,
            },
            HashAlgorithm::MiniZFast => Self::MiniZFast,
            HashAlgorithm::Libdeflate4Fast => Self::Libdeflate4,
            HashAlgorithm::ZlibNG => Self::ZlibNG,
            HashAlgorithm::RandomVector => Self::RandomVector,
            HashAlgorithm::Crc32cHash => Self::Crc32cHash,
            HashAlgorithm::Libdeflate4Fast15 => Self::Libdeflate4_15,
            HashAlgorithm::Chromium { hash_mask } => Self::Chromium { hash_mask },
        }
    }

    pub(crate) fn into_algorithm(self) -> HashAlgorithm {
        match self {
            Self::Zlib {
                hash_mask,
                hash_shift,
            } => HashAlgorithm::Zlib {
                hash_mask,
                hash_shift,
            },
            Self::MiniZFast => HashAlgorithm::MiniZFast,
            Self::Libdeflate4 => HashAlgorithm::Libdeflate4Fast,
            Self::ZlibNG => HashAlgorithm::ZlibNG,
            Self::RandomVector => HashAlgorithm::RandomVector,
            Self::Crc32cHash => HashAlgorithm::Crc32cHash,
            Self::Libdeflate4_15 => HashAlgorithm::Libdeflate4Fast15,
            Self::Chromium { hash_mask } => HashAlgorithm::Chromium { hash_mask },
        }
    }
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) struct SearchBudget {
    pub max_chain: u32,
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChainSettings {
    pub budget: SearchBudget,
    pub nice_length: u32,
    pub input_tail: InputTailPolicy,
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) enum InputTailPolicy {
    HashMinimum,
    /// Normal prediction needs five bytes; recovery still uses the index's lookup minimum.
    AtLeastFiveBytes,
}

impl InputTailPolicy {
    pub(crate) fn rejects_input(self, remaining: u32) -> bool {
        matches!(self, Self::AtLeastFiveBytes) && remaining < 5
    }
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub(crate) enum LazyMinimum {
    Three { short_match_cutoff: u32 },
    FilteredSix,
}

impl ReconstructionParameters {
    pub(crate) fn normalized(mut self, bounds: NormalizationBounds) -> Self {
        if self.block_type_strategy == BlockTypeStrategy::Mixed {
            self.block_type_strategy = BlockTypeStrategy::Dynamic;
        }
        if let Some(bounds) = bounds.token_count {
            self.max_token_count = canonical_token_limit(self.max_token_count, bounds);
        }
        let (dictionary, cutoff) = match &mut self.behavior {
            BehaviorSettings::NoDictionary { .. } => return self,
            BehaviorSettings::Chain { common, parser } => {
                let cutoff = match parser {
                    ChainParser::Greedy {
                        short_match_cutoff: cutoff,
                    }
                    | ChainParser::LibdeflateGreedy {
                        short_match_cutoff: cutoff,
                    }
                    | ChainParser::LibdeflateLazy {
                        short_match_cutoff: cutoff,
                        ..
                    }
                    | ChainParser::WindowsLazy {
                        short_match_cutoff: cutoff,
                        ..
                    }
                    | ChainParser::Lazy {
                        minimum:
                            LazyMinimum::Three {
                                short_match_cutoff: cutoff,
                            },
                        ..
                    } => Some(cutoff),
                    ChainParser::Lazy {
                        minimum: LazyMinimum::FilteredSix,
                        ..
                    } => None,
                };
                (&mut common.dictionary, cutoff)
            }
            BehaviorSettings::MiniZ {
                common,
                short_match_cutoff: cutoff,
                ..
            } => (&mut common.dictionary, Some(cutoff)),
        };
        if let Some(window_bits) = bounds.window_bits {
            dictionary.window_bits = window_bits;
        }
        if let (Some(cutoff), Some(bounds)) = (cutoff, bounds.short_match_cutoff) {
            *cutoff = canonical_short_match_cutoff(*cutoff, bounds);
        }
        self
    }
}

impl BehaviorSettings {
    pub(crate) fn supports_deferred_cutoff(self) -> bool {
        let Self::Chain { common, parser } = self else {
            return false;
        };
        matches!(
            common.dictionary.index,
            DictionaryIndex::Chain {
                hash: HashFunction::Zlib { .. }
            } | DictionaryIndex::Chain {
                hash: HashFunction::RandomVector
            }
        ) && common.dictionary.insertion != DictionaryAddPolicy::AddFirstExcept4kBoundary
            && common.search.nice_length >= 4
            && matches!(
                parser,
                ChainParser::Lazy {
                    lookahead: LazyLookaheadSettings {
                        max_lazy: 4..,
                        behavior: LazyBehavior::Zlib { good_length: 4.. }
                            | LazyBehavior::RecomputeAfterLiteral,
                    },
                    minimum: LazyMinimum::Three { .. },
                }
            )
    }

    pub(crate) fn dictionary_and_budget(self) -> Option<(DictionarySettings, SearchBudget)> {
        match self {
            Self::NoDictionary { strategy: _ } => None,
            Self::Chain { common, .. } => Some((common.dictionary, common.search.budget)),
            Self::MiniZ { common, .. } => Some((common.dictionary, common.search.budget)),
        }
    }

    pub(crate) fn short_match_cutoff(self) -> u32 {
        match self {
            Self::NoDictionary { strategy: _ } => 0,
            Self::Chain { parser, .. } => match parser {
                ChainParser::Greedy { short_match_cutoff }
                | ChainParser::LibdeflateGreedy { short_match_cutoff }
                | ChainParser::LibdeflateLazy {
                    short_match_cutoff, ..
                }
                | ChainParser::WindowsLazy {
                    short_match_cutoff, ..
                }
                | ChainParser::Lazy {
                    minimum: LazyMinimum::Three { short_match_cutoff },
                    ..
                } => short_match_cutoff,
                ChainParser::Lazy {
                    minimum: LazyMinimum::FilteredSix,
                    ..
                } => 0,
            },
            Self::MiniZ {
                short_match_cutoff, ..
            } => short_match_cutoff,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        parameters::tests::MatchingType, reconstruction_parameters::ReconstructionParameters,
    };

    #[test]
    fn normalization_does_not_consult_inactive_cutoffs() {
        let base = crate::token_predictor::tests::zlib_level_1_params();
        for parameters in [
            {
                let mut canonical_configuration = base;
                canonical_configuration.set_hash_algorithm(HashAlgorithm::None);
                canonical_configuration.set_strategy(PreflateStrategy::HuffOnly);
                canonical_configuration
            },
            {
                let mut canonical_configuration = base;
                canonical_configuration.set_matching_type(MatchingType::Lazy {
                    max_lazy: 32,
                    filtered_matching: true,
                    behavior: LazyBehavior::Zlib { good_length: 8 },
                });
                canonical_configuration
            },
        ] {
            let settings = parameters;
            assert_eq!(
                bitcode::encode(&settings),
                bitcode::encode(&settings.normalized(NormalizationBounds {
                    short_match_cutoff: Some((4, 8192)),
                    ..NormalizationBounds::default()
                }))
            );
        }
    }

    fn round_trip(parameters: &ReconstructionParameters) -> ReconstructionParameters {
        bitcode::decode::<ReconstructionParameters>(&bitcode::encode(parameters)).unwrap()
    }

    #[test]
    fn active_dictionary_settings_round_trip_for_every_hash_and_parser() {
        let hashes = [
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
        ];
        let parsers = [
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
            MatchingType::MiniZ {
                max_probes: 32,
                greedy: false,
            },
            MatchingType::MiniZ {
                max_probes: 16,
                greedy: true,
            },
            MatchingType::LibdeflateGreedy,
            MatchingType::LibdeflateLazy {
                two_positions: false,
            },
            MatchingType::LibdeflateLazy {
                two_positions: true,
            },
            MatchingType::WindowsLazy { max_lazy: 128 },
            MatchingType::WindowsLazy { max_lazy: 258 },
        ];
        for hash_algorithm in hashes {
            for matching_type in parsers {
                let mut parameters = {
                    let mut canonical_configuration =
                        crate::token_predictor::tests::zlib_level_1_params();
                    canonical_configuration.set_hash_algorithm(hash_algorithm);
                    canonical_configuration.set_full_window(true);
                    canonical_configuration.set_matches_to_start(true);
                    canonical_configuration.set_window_bits(14);
                    canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirstAndLast(7));
                    canonical_configuration.set_nice_length(
                        if matches!(matching_type, MatchingType::MiniZ { .. }) {
                            258
                        } else {
                            64
                        },
                    );
                    canonical_configuration.set_max_chain(29);
                    canonical_configuration.set_short_match_cutoff(3884);
                    canonical_configuration.set_matching_type(matching_type);
                    canonical_configuration.max_token_count = 8191;
                    canonical_configuration.block_type_strategy = BlockTypeStrategy::Dynamic;
                    canonical_configuration
                };
                if matches!(
                    matching_type,
                    MatchingType::Lazy {
                        filtered_matching: true,
                        ..
                    }
                ) {
                    parameters.set_short_match_cutoff(0);
                }
                assert_eq!(round_trip(&parameters), parameters);
                let bounds = NormalizationBounds {
                    window_bits: Some(9),
                    short_match_cutoff: Some((0, 32768)),
                    token_count: Some((0, u32::from(u16::MAX))),
                };
                let normalized = parameters.normalized(bounds);
                assert_eq!(
                    normalized.normalized(bounds),
                    normalized,
                    "{hash_algorithm:?} {matching_type:?}"
                );
                assert_eq!(round_trip(&normalized), normalized);
                assert!(bitcode::encode(&normalized).len() <= bitcode::encode(&parameters).len());
            }
        }
    }

    #[test]
    fn equivalent_block_strategies_share_one_serialized_profile() {
        let parameters = crate::token_predictor::tests::zlib_level_1_params();
        let encode = |strategy| {
            let parameters = {
                let mut canonical_configuration = parameters;
                canonical_configuration.block_type_strategy = strategy;
                canonical_configuration
            };
            bitcode::encode(&parameters.normalized(NormalizationBounds::default()))
        };
        assert_eq!(
            encode(BlockTypeStrategy::Dynamic),
            encode(BlockTypeStrategy::Mixed)
        );
        assert_ne!(
            encode(BlockTypeStrategy::Dynamic),
            encode(BlockTypeStrategy::Static)
        );
        assert_ne!(
            encode(BlockTypeStrategy::Dynamic),
            encode(BlockTypeStrategy::Uncompressed)
        );
    }

    #[test]
    fn distance_policy_serialization_follows_the_matcher_branches() {
        let base = crate::token_predictor::tests::zlib_level_1_params();
        let BehaviorSettings::Chain { common, parser } = base.behavior else {
            unreachable!()
        };
        for distance in [
            ChainDistancePolicy::Disabled,
            ChainDistancePolicy::RleOnly,
            ChainDistancePolicy::Window {
                history: SourceHistorySettings {
                    matches_to_start: true,
                },
                bounds: WindowBounds::Full,
            },
            ChainDistancePolicy::Window {
                history: SourceHistorySettings {
                    matches_to_start: false,
                },
                bounds: WindowBounds::Full,
            },
            ChainDistancePolicy::Window {
                history: SourceHistorySettings {
                    matches_to_start: true,
                },
                bounds: WindowBounds::Lookahead,
            },
            ChainDistancePolicy::Window {
                history: SourceHistorySettings {
                    matches_to_start: false,
                },
                bounds: WindowBounds::Lookahead,
            },
        ] {
            let parameters = ReconstructionParameters {
                behavior: BehaviorSettings::Chain {
                    common: ChainMatchSettings { distance, ..common },
                    parser,
                },
                ..base
            };
            assert_eq!(round_trip(&parameters), parameters);
            let mut altered = parameters;
            altered.dictionary_mut().unwrap().window_bits = 10;
            assert_ne!(bitcode::encode(&parameters), bitcode::encode(&altered));
            let json = serde_json::to_value(parameters).unwrap();
            let distance_json = &json["behavior"]["Chain"]["common"]["distance"];
            assert_eq!(
                distance_json.to_string().contains("matches_to_start"),
                matches!(
                    distance,
                    ChainDistancePolicy::Window {
                        history: _,
                        bounds: WindowBounds::Full
                    } | ChainDistancePolicy::Window {
                        history: _,
                        bounds: WindowBounds::Lookahead
                    }
                )
            );
            assert!(json.get("strategy").is_none());
        }
        for distance in [
            MiniZDistancePolicy::Disabled,
            MiniZDistancePolicy::Enabled(SourceHistorySettings {
                matches_to_start: false,
            }),
            MiniZDistancePolicy::Enabled(SourceHistorySettings {
                matches_to_start: true,
            }),
        ] {
            let parameters = ReconstructionParameters {
                behavior: BehaviorSettings::MiniZ {
                    common: MiniZMatchSettings {
                        dictionary: common.dictionary,
                        distance,
                        search: MiniZSearchSettings {
                            input_tail: InputTailPolicy::HashMinimum,
                            max_probes: 32,
                            budget: common.search.budget,
                        },
                    },
                    greedy: false,
                    short_match_cutoff: 3884,
                },
                ..base
            };
            assert_eq!(round_trip(&parameters), parameters);
            let json = serde_json::to_value(parameters).unwrap().to_string();
            assert_eq!(
                json.contains("matches_to_start"),
                matches!(distance, MiniZDistancePolicy::Enabled(_))
            );
            assert!(!json.contains("nice_length"));
            assert!(!json.contains("FullWindow"));
        }
    }

    #[test]
    fn engine_distance_selector_costs_only_include_active_window_and_history() {
        let base = crate::token_predictor::tests::zlib_level_1_params();
        let size = |parameters: &ReconstructionParameters| bitcode::encode(parameters).len();
        for (matching_type, active_bytes) in [
            (MatchingType::Greedy, 2),
            (
                MatchingType::MiniZ {
                    max_probes: 32,
                    greedy: false,
                },
                1,
            ),
        ] {
            let disabled = {
                let mut canonical_configuration = base;
                canonical_configuration.set_strategy(PreflateStrategy::HuffOnly);
                canonical_configuration.set_full_window(false);
                canonical_configuration.set_matching_type(matching_type);
                canonical_configuration
            };
            let enabled = {
                let mut canonical_configuration = disabled;
                canonical_configuration.set_strategy(PreflateStrategy::Default);
                canonical_configuration
            };
            assert_eq!(size(&enabled), size(&disabled) + active_bytes);
            let full_window = {
                let mut canonical_configuration = enabled;
                canonical_configuration.set_full_window(true);
                canonical_configuration
            };
            assert_eq!(size(&full_window), size(&enabled));
            if matching_type == MatchingType::Greedy {
                let rle = {
                    let mut canonical_configuration = enabled;
                    canonical_configuration.set_strategy(PreflateStrategy::RleOnly);
                    canonical_configuration
                };
                assert_eq!(size(&rle), size(&disabled));
            }
        }
    }

    #[test]
    fn canonical_parameter_wire_sizes() {
        let cases = [
            ("compressed_zlib_level0.deflate", 5),
            ("compressed_zlib_level1.deflate", 27),
            ("compressed_zlib_level6.deflate", 31),
            ("compressed_libdeflate_level5.deflate", 21),
            ("compressed_flate2_level3.deflate", 24),
            ("treegdi.extract.deflate", 24),
        ];
        let mut actual_sizes = Vec::new();
        for (name, _) in cases {
            let compressed = crate::utils::read_file(name);
            let (contents, plain) =
                crate::deflate::deflate_reader::tests::parse_deflate_whole(&compressed).unwrap();
            let parameters =
                crate::estimator::estimate_preflate_parameters(&contents, &plain).unwrap();
            let nested_size = bitcode::encode(&parameters).len();
            actual_sizes.push(nested_size);
        }
        assert_eq!(actual_sizes, cases.map(|(_, size)| size));
    }
}
