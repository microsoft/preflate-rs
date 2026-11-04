/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use bitcode::{Decode, Encode};

#[cfg(test)]
impl crate::parameters::TokenPredictorParameters {
    pub(crate) fn serialized_size(&self) -> usize {
        bitcode::encode(&ReconstructionParameters::from(self)).len()
    }
}

use crate::{
    hash_algorithm::HashAlgorithm,
    parameters::{
        BlockTypeStrategy, DictionaryAddPolicy, LazyBehavior, MatchingType, PreflateStrategy,
        TokenPredictorParameters,
    },
};

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) struct ReconstructionParameters {
    pub(crate) max_token_count: u16,
    pub(crate) block_type_strategy: BlockTypeStrategy,
    pub(crate) behavior: BehaviorSettings,
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) enum BehaviorSettings {
    NoDictionary { strategy: PreflateStrategy },
    Greedy(GreedySettings),
    Lazy(LazySettings),
    MiniZ(MiniZSettings),
    LibdeflateGreedy(GreedySettings),
    LibdeflateLazy(LibdeflateLazySettings),
    WindowsLazy(WindowsLazySettings),
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) struct ChainMatchSettings {
    pub(crate) dictionary: DictionarySettings,
    pub(crate) distance: ChainDistancePolicy,
    pub(crate) search: ChainSettings,
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) struct GreedySettings {
    pub(crate) common: ChainMatchSettings,
    pub(crate) short_match_cutoff: u32,
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) struct LazySettings {
    pub(crate) common: ChainMatchSettings,
    pub(crate) lookahead: LazyLookaheadSettings,
    pub(crate) minimum: LazyMinimum,
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) struct LazyLookaheadSettings {
    pub(crate) max_lazy: u16,
    pub(crate) behavior: LazyBehavior,
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) struct MiniZSettings {
    pub(crate) common: MiniZMatchSettings,
    pub(crate) greedy: bool,
    pub(crate) short_match_cutoff: u32,
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) struct MiniZMatchSettings {
    pub(crate) dictionary: DictionarySettings,
    pub(crate) distance: MiniZDistancePolicy,
    pub(crate) search: MiniZSearchSettings,
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) struct MiniZSearchSettings {
    pub(crate) max_probes: u16,
    pub(crate) budget: SearchBudget,
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) struct LibdeflateLazySettings {
    pub(crate) common: ChainMatchSettings,
    pub(crate) two_positions: bool,
    pub(crate) short_match_cutoff: u32,
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) struct WindowsLazySettings {
    pub(crate) common: ChainMatchSettings,
    pub(crate) max_lazy: u16,
    pub(crate) short_match_cutoff: u32,
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) struct DictionarySettings {
    pub(crate) hash: DictionaryHash,
    // Hop-based correction recovery uses the window even when prediction is disabled.
    pub(crate) window_bits: u32,
    pub(crate) insertion: DictionaryAddPolicy,
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) struct SourceHistorySettings {
    pub(crate) matches_to_start: bool,
}

impl SourceHistorySettings {
    #[inline]
    pub(crate) fn maximum_distance(self, history: u32) -> u32 {
        history.saturating_sub(u32::from(!self.matches_to_start))
    }
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) enum MiniZDistancePolicy {
    Disabled,
    Enabled(SourceHistorySettings),
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) enum ChainDistancePolicy {
    Disabled,
    RleOnly,
    FullWindow(SourceHistorySettings),
    HashWindow(SourceHistorySettings),
}

fn prediction_disabled(parameters: &TokenPredictorParameters) -> bool {
    !parameters.very_far_matches_detected
        && matches!(
            parameters.strategy,
            PreflateStrategy::HuffOnly | PreflateStrategy::Store
        )
}

impl ChainDistancePolicy {
    fn from_parameters(parameters: &TokenPredictorParameters) -> Self {
        if prediction_disabled(parameters) {
            Self::Disabled
        } else if parameters.very_far_matches_detected {
            Self::FullWindow(SourceHistorySettings {
                matches_to_start: parameters.matches_to_start_detected,
            })
        } else if parameters.strategy == PreflateStrategy::RleOnly {
            Self::RleOnly
        } else {
            Self::HashWindow(SourceHistorySettings {
                matches_to_start: parameters.matches_to_start_detected,
            })
        }
    }

    fn apply_to(self, parameters: &mut TokenPredictorParameters) {
        let (matches_to_start, full_window, strategy) = match self {
            Self::Disabled => (false, false, PreflateStrategy::HuffOnly),
            Self::RleOnly => (false, false, PreflateStrategy::RleOnly),
            Self::FullWindow(history) => {
                (history.matches_to_start, true, PreflateStrategy::Default)
            }
            Self::HashWindow(history) => {
                (history.matches_to_start, false, PreflateStrategy::Default)
            }
        };
        parameters.matches_to_start_detected = matches_to_start;
        parameters.very_far_matches_detected = full_window;
        parameters.strategy = strategy;
    }
}

impl MiniZDistancePolicy {
    fn from_parameters(parameters: &TokenPredictorParameters) -> Self {
        if prediction_disabled(parameters) {
            Self::Disabled
        } else {
            Self::Enabled(SourceHistorySettings {
                matches_to_start: parameters.matches_to_start_detected,
            })
        }
    }

    fn apply_to(self, parameters: &mut TokenPredictorParameters) {
        let (matches_to_start, strategy) = match self {
            Self::Disabled => (false, PreflateStrategy::HuffOnly),
            Self::Enabled(history) => (history.matches_to_start, PreflateStrategy::Default),
        };
        parameters.matches_to_start_detected = matches_to_start;
        parameters.very_far_matches_detected = false;
        parameters.strategy = strategy;
    }
}

impl DictionarySettings {
    fn apply_to(self, parameters: &mut TokenPredictorParameters) {
        parameters.hash_algorithm = self.hash.into_algorithm();
        parameters.window_bits = self.window_bits;
        parameters.add_policy = self.insertion;
    }
}

impl ChainMatchSettings {
    fn apply_to(self, parameters: &mut TokenPredictorParameters) {
        self.dictionary.apply_to(parameters);
        self.distance.apply_to(parameters);
        parameters.max_chain = self.search.budget.max_chain;
        parameters.nice_length = self.search.nice_length;
    }
}

impl MiniZMatchSettings {
    fn apply_to(self, parameters: &mut TokenPredictorParameters) {
        self.dictionary.apply_to(parameters);
        self.distance.apply_to(parameters);
        parameters.max_chain = self.search.budget.max_chain;
        parameters.nice_length = 258;
    }
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) enum DictionaryHash {
    Zlib { hash_mask: u16, hash_shift: u32 },
    MiniZFast,
    Libdeflate4Fast,
    Libdeflate4,
    ZlibNG,
    RandomVector,
    Crc32cHash,
    Libdeflate4Fast15,
    Chromium { hash_mask: u16 },
}

impl DictionaryHash {
    fn from_algorithm(hash: HashAlgorithm) -> Option<Self> {
        Some(match hash {
            HashAlgorithm::None => return None,
            HashAlgorithm::Zlib {
                hash_mask,
                hash_shift,
            } => Self::Zlib {
                hash_mask,
                hash_shift,
            },
            HashAlgorithm::MiniZFast => Self::MiniZFast,
            HashAlgorithm::Libdeflate4Fast => Self::Libdeflate4Fast,
            HashAlgorithm::Libdeflate4 => Self::Libdeflate4,
            HashAlgorithm::ZlibNG => Self::ZlibNG,
            HashAlgorithm::RandomVector => Self::RandomVector,
            HashAlgorithm::Crc32cHash => Self::Crc32cHash,
            HashAlgorithm::Libdeflate4Fast15 => Self::Libdeflate4Fast15,
            HashAlgorithm::Chromium { hash_mask } => Self::Chromium { hash_mask },
        })
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
            Self::Libdeflate4Fast => HashAlgorithm::Libdeflate4Fast,
            Self::Libdeflate4 => HashAlgorithm::Libdeflate4,
            Self::ZlibNG => HashAlgorithm::ZlibNG,
            Self::RandomVector => HashAlgorithm::RandomVector,
            Self::Crc32cHash => HashAlgorithm::Crc32cHash,
            Self::Libdeflate4Fast15 => HashAlgorithm::Libdeflate4Fast15,
            Self::Chromium { hash_mask } => HashAlgorithm::Chromium { hash_mask },
        }
    }
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) struct SearchBudget {
    pub(crate) max_chain: u32,
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) struct ChainSettings {
    pub(crate) budget: SearchBudget,
    pub(crate) nice_length: u32,
}

#[derive(Encode, Decode, Debug, Copy, Clone)]
pub(crate) enum LazyMinimum {
    Three { short_match_cutoff: u32 },
    FilteredSix,
}

impl From<&TokenPredictorParameters> for ReconstructionParameters {
    fn from(parameters: &TokenPredictorParameters) -> Self {
        let behavior = if let Some(hash) = DictionaryHash::from_algorithm(parameters.hash_algorithm)
        {
            let dictionary = DictionarySettings {
                hash,
                window_bits: parameters.window_bits,
                insertion: parameters.add_policy,
            };
            let search = ChainSettings {
                budget: SearchBudget {
                    max_chain: parameters.max_chain,
                },
                nice_length: parameters.nice_length,
            };
            let common = ChainMatchSettings {
                dictionary,
                distance: ChainDistancePolicy::from_parameters(parameters),
                search,
            };
            let short_match_cutoff = parameters.max_dist_3_matches;
            match parameters.matching_type {
                MatchingType::Greedy => BehaviorSettings::Greedy(GreedySettings {
                    common,
                    short_match_cutoff,
                }),
                MatchingType::Lazy {
                    max_lazy,
                    filtered_matching,
                    behavior,
                } => BehaviorSettings::Lazy(LazySettings {
                    common,
                    lookahead: LazyLookaheadSettings { max_lazy, behavior },
                    minimum: if filtered_matching {
                        LazyMinimum::FilteredSix
                    } else {
                        LazyMinimum::Three { short_match_cutoff }
                    },
                }),
                MatchingType::MiniZ { max_probes, greedy } => {
                    BehaviorSettings::MiniZ(MiniZSettings {
                        common: MiniZMatchSettings {
                            dictionary,
                            distance: MiniZDistancePolicy::from_parameters(parameters),
                            search: MiniZSearchSettings {
                                max_probes,
                                budget: search.budget,
                            },
                        },
                        greedy,
                        short_match_cutoff,
                    })
                }
                MatchingType::LibdeflateGreedy => {
                    BehaviorSettings::LibdeflateGreedy(GreedySettings {
                        common,
                        short_match_cutoff,
                    })
                }
                MatchingType::LibdeflateLazy { two_positions } => {
                    BehaviorSettings::LibdeflateLazy(LibdeflateLazySettings {
                        common,
                        two_positions,
                        short_match_cutoff,
                    })
                }
                MatchingType::WindowsLazy { max_lazy } => {
                    BehaviorSettings::WindowsLazy(WindowsLazySettings {
                        common,
                        max_lazy,
                        short_match_cutoff,
                    })
                }
            }
        } else {
            BehaviorSettings::NoDictionary {
                strategy: parameters.strategy,
            }
        };
        Self {
            max_token_count: parameters.max_token_count,
            block_type_strategy: match parameters.block_type_strategy {
                BlockTypeStrategy::Mixed => BlockTypeStrategy::Dynamic,
                strategy => strategy,
            },
            behavior,
        }
    }
}

impl ReconstructionParameters {
    pub(crate) fn into_runtime(self) -> TokenPredictorParameters {
        let mut parameters = TokenPredictorParameters {
            matches_to_start_detected: false,
            very_far_matches_detected: false,
            window_bits: 0,
            strategy: PreflateStrategy::HuffOnly,
            nice_length: 0,
            add_policy: DictionaryAddPolicy::AddAll,
            max_token_count: self.max_token_count,
            max_dist_3_matches: 0,
            matching_type: MatchingType::Greedy,
            max_chain: 0,
            hash_algorithm: HashAlgorithm::None,
            block_type_strategy: self.block_type_strategy,
        };
        match self.behavior {
            BehaviorSettings::NoDictionary { strategy } => {
                parameters.strategy = strategy;
                return parameters;
            }
            BehaviorSettings::Greedy(settings) | BehaviorSettings::LibdeflateGreedy(settings) => {
                settings.common.apply_to(&mut parameters);
            }
            BehaviorSettings::Lazy(settings) => {
                settings.common.apply_to(&mut parameters);
            }
            BehaviorSettings::MiniZ(settings) => settings.common.apply_to(&mut parameters),
            BehaviorSettings::LibdeflateLazy(settings) => {
                settings.common.apply_to(&mut parameters);
            }
            BehaviorSettings::WindowsLazy(settings) => {
                settings.common.apply_to(&mut parameters);
            }
        }
        parameters.matching_type = self.behavior.matching_type();
        parameters.max_dist_3_matches = self.behavior.short_match_cutoff();
        parameters
    }
}

impl BehaviorSettings {
    pub(crate) fn dictionary_and_budget(self) -> Option<(DictionarySettings, SearchBudget)> {
        let common = match self {
            Self::NoDictionary { strategy: _ } => return None,
            Self::Greedy(settings) | Self::LibdeflateGreedy(settings) => settings.common,
            Self::Lazy(settings) => settings.common,
            Self::MiniZ(settings) => {
                return Some((settings.common.dictionary, settings.common.search.budget));
            }
            Self::LibdeflateLazy(settings) => settings.common,
            Self::WindowsLazy(settings) => settings.common,
        };
        Some((common.dictionary, common.search.budget))
    }

    pub(crate) fn matching_type(self) -> MatchingType {
        match self {
            Self::NoDictionary { strategy: _ } | Self::Greedy(_) => MatchingType::Greedy,
            Self::LibdeflateGreedy(_) => MatchingType::LibdeflateGreedy,
            Self::Lazy(settings) => MatchingType::Lazy {
                max_lazy: settings.lookahead.max_lazy,
                behavior: settings.lookahead.behavior,
                filtered_matching: matches!(settings.minimum, LazyMinimum::FilteredSix),
            },
            Self::MiniZ(settings) => MatchingType::MiniZ {
                max_probes: settings.common.search.max_probes,
                greedy: settings.greedy,
            },
            Self::LibdeflateLazy(settings) => MatchingType::LibdeflateLazy {
                two_positions: settings.two_positions,
            },
            Self::WindowsLazy(settings) => MatchingType::WindowsLazy {
                max_lazy: settings.max_lazy,
            },
        }
    }

    pub(crate) fn short_match_cutoff(self) -> u32 {
        match self {
            Self::NoDictionary { strategy: _ } => 0,
            Self::Greedy(settings) | Self::LibdeflateGreedy(settings) => {
                settings.short_match_cutoff
            }
            Self::Lazy(settings) => match settings.minimum {
                LazyMinimum::Three { short_match_cutoff } => short_match_cutoff,
                LazyMinimum::FilteredSix => 0,
            },
            Self::MiniZ(settings) => settings.short_match_cutoff,
            Self::LibdeflateLazy(settings) => settings.short_match_cutoff,
            Self::WindowsLazy(settings) => settings.short_match_cutoff,
        }
    }

    pub(crate) fn for_legacy(mut self, cutoff: u32) -> Self {
        if let Self::Lazy(settings) = &mut self {
            settings.minimum = LazyMinimum::Three {
                short_match_cutoff: cutoff,
            };
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(parameters: &TokenPredictorParameters) -> TokenPredictorParameters {
        bitcode::decode::<ReconstructionParameters>(&bitcode::encode(
            &ReconstructionParameters::from(parameters),
        ))
        .unwrap()
        .into_runtime()
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
            MatchingType::LibdeflateGreedy,
            MatchingType::LibdeflateLazy {
                two_positions: true,
            },
            MatchingType::WindowsLazy { max_lazy: 258 },
        ];
        for hash_algorithm in hashes {
            for matching_type in parsers {
                let mut parameters = TokenPredictorParameters {
                    hash_algorithm,
                    matching_type,
                    nice_length: if matches!(matching_type, MatchingType::MiniZ { .. }) {
                        258
                    } else {
                        64
                    },
                    max_chain: 29,
                    window_bits: 14,
                    max_dist_3_matches: 3884,
                    max_token_count: 8191,
                    add_policy: DictionaryAddPolicy::AddFirstAndLast(7),
                    matches_to_start_detected: true,
                    very_far_matches_detected: true,
                    block_type_strategy: BlockTypeStrategy::Mixed,
                    ..crate::token_predictor::zlib_level_1_params()
                };
                if matches!(
                    matching_type,
                    MatchingType::Lazy {
                        filtered_matching: true,
                        ..
                    }
                ) {
                    parameters.max_dist_3_matches = 0;
                }
                let mut expected = parameters;
                expected.block_type_strategy = BlockTypeStrategy::Dynamic;
                if matches!(matching_type, MatchingType::MiniZ { .. }) {
                    expected.very_far_matches_detected = false;
                }
                assert_eq!(round_trip(&parameters), expected);
            }
        }
    }

    #[test]
    fn equivalent_block_strategies_share_one_serialized_profile() {
        let parameters = crate::token_predictor::zlib_level_1_params();
        let encode = |strategy| {
            let parameters = TokenPredictorParameters {
                block_type_strategy: strategy,
                ..parameters
            };
            bitcode::encode(&ReconstructionParameters::from(&parameters))
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
        let encode = |parameters: &TokenPredictorParameters| {
            bitcode::encode(&ReconstructionParameters::from(parameters))
        };
        for matching_type in [
            MatchingType::Greedy,
            MatchingType::MiniZ {
                max_probes: 32,
                greedy: false,
            },
        ] {
            for full_window in [false, true] {
                for strategy in [
                    PreflateStrategy::Default,
                    PreflateStrategy::RleOnly,
                    PreflateStrategy::HuffOnly,
                    PreflateStrategy::Store,
                ] {
                    let parameters = TokenPredictorParameters {
                        matching_type,
                        very_far_matches_detected: full_window,
                        strategy,
                        matches_to_start_detected: true,
                        window_bits: 9,
                        ..crate::token_predictor::zlib_level_1_params()
                    };
                    let decoded = round_trip(&parameters);
                    assert_eq!(decoded.window_bits, parameters.window_bits);
                    let disabled = !full_window
                        && matches!(
                            strategy,
                            PreflateStrategy::HuffOnly | PreflateStrategy::Store
                        );
                    let rle = !full_window
                        && matching_type == MatchingType::Greedy
                        && strategy == PreflateStrategy::RleOnly;
                    if disabled {
                        assert_eq!(decoded.strategy, PreflateStrategy::HuffOnly);
                        assert!(!decoded.matches_to_start_detected);
                        assert!(!decoded.very_far_matches_detected);
                    } else {
                        assert_eq!(decoded.matches_to_start_detected, !rle);
                        assert_eq!(
                            decoded.very_far_matches_detected,
                            full_window && !matches!(matching_type, MatchingType::MiniZ { .. })
                        );
                        assert_eq!(
                            decoded.strategy,
                            if !full_window && matching_type == MatchingType::Greedy {
                                strategy
                            } else {
                                PreflateStrategy::Default
                            }
                        );
                    }
                    assert_eq!(encode(&parameters), encode(&decoded));
                    assert_ne!(
                        encode(&parameters),
                        encode(&TokenPredictorParameters {
                            window_bits: 10,
                            ..parameters
                        })
                    );
                    if !disabled && !rle {
                        assert_ne!(
                            encode(&parameters),
                            encode(&TokenPredictorParameters {
                                matches_to_start_detected: false,
                                ..parameters
                            })
                        );
                    } else {
                        assert_eq!(
                            encode(&parameters),
                            encode(&TokenPredictorParameters {
                                matches_to_start_detected: false,
                                ..parameters
                            })
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn typed_legacy_lazy_settings_keep_the_active_three_byte_cutoff() {
        let parameters = TokenPredictorParameters {
            matching_type: MatchingType::Lazy {
                max_lazy: 32,
                filtered_matching: true,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            },
            max_dist_3_matches: 3884,
            max_chain: 29,
            nice_length: 64,
            ..crate::token_predictor::zlib_level_1_params()
        };
        let current = ReconstructionParameters::from(&parameters).behavior;
        assert_eq!(current.short_match_cutoff(), 0);
        let legacy = current.for_legacy(parameters.max_dist_3_matches);
        assert_eq!(legacy.short_match_cutoff(), parameters.max_dist_3_matches);
        let BehaviorSettings::Lazy(settings) = legacy else {
            panic!("legacy conversion changed the parser");
        };
        assert_eq!(settings.lookahead.max_lazy, 32);
        assert_eq!(settings.common.search.budget.max_chain, 29);
        assert_eq!(settings.common.search.nice_length, 64);
        assert!(matches!(
            settings.minimum,
            LazyMinimum::Three {
                short_match_cutoff: 3884
            }
        ));
    }

    #[test]
    fn inactive_settings_do_not_appear_in_serialization() {
        let encode = |parameters: &TokenPredictorParameters| {
            bitcode::encode(&ReconstructionParameters::from(parameters))
        };
        let base = crate::token_predictor::zlib_level_1_params();
        let miniz = TokenPredictorParameters {
            matching_type: MatchingType::MiniZ {
                max_probes: 32,
                greedy: false,
            },
            nice_length: 258,
            ..base
        };
        assert_eq!(
            encode(&miniz),
            encode(&TokenPredictorParameters {
                nice_length: 3,
                ..miniz
            })
        );
        let filtered = TokenPredictorParameters {
            matching_type: MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: true,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            },
            ..base
        };
        assert_eq!(
            encode(&filtered),
            encode(&TokenPredictorParameters {
                max_dist_3_matches: 0,
                ..filtered
            })
        );
        let none = TokenPredictorParameters {
            hash_algorithm: HashAlgorithm::None,
            strategy: PreflateStrategy::HuffOnly,
            ..base
        };
        assert_eq!(
            encode(&none),
            encode(&TokenPredictorParameters {
                matches_to_start_detected: !none.matches_to_start_detected,
                very_far_matches_detected: !none.very_far_matches_detected,
                window_bits: 0,
                nice_length: 258,
                max_chain: 4096,
                add_policy: DictionaryAddPolicy::AddAll,
                max_dist_3_matches: 0,
                ..none
            })
        );
        assert!(encode(&none).len() < bitcode::encode(&none).len());
    }

    #[test]
    fn engine_distance_selector_costs_only_include_active_history() {
        let base = crate::token_predictor::zlib_level_1_params();
        let size = |parameters: &TokenPredictorParameters| {
            bitcode::encode(&ReconstructionParameters::from(parameters)).len()
        };
        for matching_type in [
            MatchingType::Greedy,
            MatchingType::MiniZ {
                max_probes: 32,
                greedy: false,
            },
        ] {
            let disabled = TokenPredictorParameters {
                matching_type,
                very_far_matches_detected: false,
                strategy: PreflateStrategy::HuffOnly,
                ..base
            };
            let enabled = TokenPredictorParameters {
                strategy: PreflateStrategy::Default,
                ..disabled
            };
            assert_eq!(size(&enabled), size(&disabled) + 1);
            let full_window = TokenPredictorParameters {
                very_far_matches_detected: true,
                ..enabled
            };
            assert_eq!(size(&full_window), size(&enabled));
            if matching_type == MatchingType::Greedy {
                let rle = TokenPredictorParameters {
                    strategy: PreflateStrategy::RleOnly,
                    ..enabled
                };
                assert_eq!(size(&rle), size(&disabled));
            }
        }
    }

    #[test]
    fn public_parameter_serialization_sizes() {
        let cases = [
            ("compressed_zlib_level0.deflate", 5),
            ("compressed_zlib_level1.deflate", 23),
            ("compressed_zlib_level6.deflate", 27),
            ("compressed_libdeflate_level5.deflate", 18),
            ("compressed_flate2_level3.deflate", 22),
            ("treegdi.extract.deflate", 20),
        ];
        let mut actual_sizes = Vec::new();
        for (name, _) in cases {
            let compressed = crate::utils::read_file(name);
            let (contents, plain) =
                crate::deflate::deflate_reader::parse_deflate_whole(&compressed).unwrap();
            let parameters =
                crate::estimator::preflate_parameter_estimator::estimate_preflate_parameters(
                    &contents, &plain,
                )
                .unwrap();
            let nested_size = bitcode::encode(&ReconstructionParameters::from(&parameters)).len();
            let flat_size = bitcode::encode(&parameters).len();
            println!("{name}: flat={flat_size} nested={nested_size}");
            assert!(nested_size <= flat_size, "{name}");
            actual_sizes.push(nested_size);
        }
        assert_eq!(actual_sizes, cases.map(|(_, size)| size));
    }
}
