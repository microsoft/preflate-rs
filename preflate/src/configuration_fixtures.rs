//! Builds reconstruction settings for unit tests and exposes their active options.
//! Converts concise parser selections into the typed matcher configurations used by production.

impl crate::token_predictor::TokenPredictor {
    pub(crate) fn from_parameters(
        parameters: &crate::reconstruction_parameters::ReconstructionParameters,
    ) -> Self {
        Self::from_reconstruction_parameters(*parameters)
    }
}

use crate::{
    hash_algorithm::HashAlgorithm,
    parameters::{DictionaryAddPolicy, PreflateStrategy, tests::MatchingType},
    reconstruction_parameters::*,
};

impl ChainParser {
    pub(crate) fn matching_type(self) -> crate::parameters::tests::MatchingType {
        use crate::parameters::tests::MatchingType;
        match self {
            Self::Greedy { .. } => MatchingType::Greedy,
            Self::LibdeflateGreedy { .. } => MatchingType::LibdeflateGreedy,
            Self::LibdeflateLazy { two_positions, .. } => {
                MatchingType::LibdeflateLazy { two_positions }
            }
            Self::WindowsLazy { max_lazy, .. } => MatchingType::WindowsLazy { max_lazy },
            Self::Lazy { lookahead, minimum } => MatchingType::Lazy {
                max_lazy: lookahead.max_lazy,
                behavior: lookahead.behavior,
                filtered_matching: matches!(minimum, LazyMinimum::FilteredSix),
            },
        }
    }
}

impl ReconstructionParameters {
    pub(crate) fn window_bits(self) -> u32 {
        self.dictionary()
            .map_or(0, |dictionary| dictionary.window_bits)
    }

    pub(crate) fn add_policy(self) -> DictionaryAddPolicy {
        self.dictionary()
            .map_or(DictionaryAddPolicy::AddAll, |dictionary| {
                dictionary.insertion
            })
    }

    pub(crate) fn nice_length(self) -> u32 {
        match self.behavior {
            BehaviorSettings::Chain { common, .. } => common.search.nice_length,
            BehaviorSettings::MiniZ { .. } => 258,
            BehaviorSettings::NoDictionary { .. } => 0,
        }
    }

    pub(crate) fn max_chain(self) -> u32 {
        self.budget().map_or(0, |budget| budget.max_chain)
    }

    pub(crate) fn max_dist_3_matches(self) -> u32 {
        self.behavior.short_match_cutoff()
    }

    pub(crate) fn very_far_matches_detected(self) -> bool {
        matches!(
            self.behavior,
            BehaviorSettings::Chain {
                common: ChainMatchSettings {
                    distance: ChainDistancePolicy::Window {
                        bounds: WindowBounds::Full | WindowBounds::ExcludeOldest,
                        ..
                    },
                    ..
                },
                ..
            }
        )
    }

    pub(crate) fn matches_to_start_detected(self) -> bool {
        match self.behavior {
            BehaviorSettings::Chain { common, .. } => match common.distance {
                ChainDistancePolicy::Window { history, .. } => history.matches_to_start,
                _ => false,
            },
            BehaviorSettings::MiniZ { common, .. } => match common.distance {
                MiniZDistancePolicy::Enabled(history) => history.matches_to_start,
                _ => false,
            },
            _ => false,
        }
    }

    pub(crate) fn strategy(self) -> PreflateStrategy {
        match self.behavior {
            BehaviorSettings::NoDictionary { strategy } => strategy,
            BehaviorSettings::Chain { common, .. } => match common.distance {
                ChainDistancePolicy::Disabled => PreflateStrategy::HuffOnly,
                ChainDistancePolicy::RleOnly => PreflateStrategy::RleOnly,
                _ => PreflateStrategy::Default,
            },
            BehaviorSettings::MiniZ { common, .. } => match common.distance {
                MiniZDistancePolicy::Disabled => PreflateStrategy::HuffOnly,
                _ => PreflateStrategy::Default,
            },
        }
    }

    pub(crate) fn matching_type(self) -> MatchingType {
        match self.behavior {
            BehaviorSettings::NoDictionary { .. } => MatchingType::Greedy,
            BehaviorSettings::MiniZ { common, greedy, .. } => MatchingType::MiniZ {
                max_probes: common.search.max_probes,
                greedy,
            },
            BehaviorSettings::Chain { parser, .. } => match parser {
                ChainParser::Greedy { .. } => MatchingType::Greedy,
                ChainParser::LibdeflateGreedy { .. } => MatchingType::LibdeflateGreedy,
                ChainParser::LibdeflateLazy { two_positions, .. } => {
                    MatchingType::LibdeflateLazy { two_positions }
                }
                ChainParser::WindowsLazy { max_lazy, .. } => MatchingType::WindowsLazy { max_lazy },
                ChainParser::Lazy { lookahead, minimum } => MatchingType::Lazy {
                    max_lazy: lookahead.max_lazy,
                    filtered_matching: matches!(minimum, LazyMinimum::FilteredSix),
                    behavior: lookahead.behavior,
                },
            },
        }
    }

    pub(crate) fn set_hash_algorithm(&mut self, hash: HashAlgorithm) {
        let Some(hash) = DictionaryIndex::from_algorithm(hash) else {
            self.behavior = BehaviorSettings::NoDictionary {
                strategy: self.strategy(),
            };
            return;
        };
        if let Some(dictionary) = self.dictionary_mut() {
            dictionary.index = hash;
        } else {
            self.behavior = BehaviorSettings::Chain {
                common: ChainMatchSettings {
                    dictionary: DictionarySettings {
                        index: hash,
                        window_bits: 15,
                        insertion: DictionaryAddPolicy::AddAll,
                    },
                    distance: ChainDistancePolicy::Window {
                        history: SourceHistorySettings {
                            matches_to_start: false,
                        },
                        bounds: WindowBounds::Lookahead,
                    },
                    search: ChainSettings {
                        input_tail: InputTailPolicy::HashMinimum,
                        budget: SearchBudget { max_chain: 1 },
                        nice_length: 258,
                    },
                },
                parser: ChainParser::Greedy {
                    short_match_cutoff: 0,
                },
            };
        }
        self.configure_estimated_match_policies();
    }

    pub(crate) fn set_strategy(&mut self, strategy: PreflateStrategy) {
        let matches_to_start = self.matches_to_start_detected();
        match &mut self.behavior {
            BehaviorSettings::NoDictionary { strategy: current } => *current = strategy,
            BehaviorSettings::Chain { common, .. } => {
                common.distance = match strategy {
                    PreflateStrategy::HuffOnly | PreflateStrategy::Store => {
                        ChainDistancePolicy::Disabled
                    }
                    PreflateStrategy::RleOnly => ChainDistancePolicy::RleOnly,
                    PreflateStrategy::Default => match common.distance {
                        ChainDistancePolicy::Window { .. } => common.distance,
                        _ => ChainDistancePolicy::Window {
                            history: SourceHistorySettings {
                                matches_to_start: false,
                            },
                            bounds: WindowBounds::Lookahead,
                        },
                    },
                }
            }
            BehaviorSettings::MiniZ { common, .. } => {
                common.distance = match strategy {
                    PreflateStrategy::HuffOnly | PreflateStrategy::Store => {
                        MiniZDistancePolicy::Disabled
                    }
                    _ => MiniZDistancePolicy::Enabled(SourceHistorySettings { matches_to_start }),
                }
            }
        }
        self.configure_estimated_match_policies();
    }

    pub(crate) fn set_full_window(&mut self, full: bool) {
        self.behavior.set_full_window(full);
    }

    pub(crate) fn set_matches_to_start(&mut self, value: bool) {
        match &mut self.behavior {
            BehaviorSettings::Chain { common, .. } => {
                if let ChainDistancePolicy::Window { history, .. } = &mut common.distance {
                    history.matches_to_start = value;
                }
            }
            BehaviorSettings::MiniZ { common, .. } => {
                if let MiniZDistancePolicy::Enabled(history) = &mut common.distance {
                    history.matches_to_start = value;
                }
            }
            _ => {}
        }
    }

    pub(crate) fn set_window_bits(&mut self, value: u32) {
        if let Some(dictionary) = self.dictionary_mut() {
            dictionary.window_bits = value;
        }
    }

    pub(crate) fn set_insertion(&mut self, value: DictionaryAddPolicy) {
        if let Some(dictionary) = self.dictionary_mut() {
            dictionary.insertion = value;
        }
    }

    pub(crate) fn set_nice_length(&mut self, value: u32) {
        if let BehaviorSettings::Chain { common, .. } = &mut self.behavior {
            common.search.nice_length = value;
        }
    }

    pub(crate) fn set_max_chain(&mut self, value: u32) {
        if let Some(budget) = self.budget_mut() {
            budget.max_chain = value;
        }
    }

    pub(crate) fn set_short_match_cutoff(&mut self, value: u32) {
        self.behavior.set_short_match_cutoff(value);
    }

    pub(crate) fn set_matching_type(&mut self, value: MatchingType) {
        let cutoff = self.behavior.short_match_cutoff();
        let common = match self.behavior {
            BehaviorSettings::NoDictionary { .. } => return,
            BehaviorSettings::Chain { common, .. } => common,
            BehaviorSettings::MiniZ { common, .. } => ChainMatchSettings {
                dictionary: common.dictionary,
                distance: match common.distance {
                    MiniZDistancePolicy::Disabled => ChainDistancePolicy::Disabled,
                    MiniZDistancePolicy::Enabled(history) => ChainDistancePolicy::Window {
                        history,
                        bounds: WindowBounds::Lookahead,
                    },
                },
                search: ChainSettings {
                    input_tail: InputTailPolicy::HashMinimum,
                    budget: common.search.budget,
                    nice_length: 258,
                },
            },
        };
        let parser = match value {
            MatchingType::Greedy => ChainParser::Greedy {
                short_match_cutoff: cutoff,
            },
            MatchingType::LibdeflateGreedy => ChainParser::LibdeflateGreedy {
                short_match_cutoff: cutoff,
            },
            MatchingType::LibdeflateLazy { two_positions } => ChainParser::LibdeflateLazy {
                two_positions,
                short_match_cutoff: cutoff,
            },
            MatchingType::WindowsLazy { max_lazy } => ChainParser::WindowsLazy {
                max_lazy,
                short_match_cutoff: cutoff,
            },
            MatchingType::Lazy {
                max_lazy,
                filtered_matching,
                behavior,
            } => ChainParser::Lazy {
                lookahead: LazyLookaheadSettings { max_lazy, behavior },
                minimum: if filtered_matching {
                    LazyMinimum::FilteredSix
                } else {
                    LazyMinimum::Three {
                        short_match_cutoff: cutoff,
                    }
                },
            },
            MatchingType::MiniZ { max_probes, greedy } => {
                let distance = if common.distance == ChainDistancePolicy::Disabled {
                    MiniZDistancePolicy::Disabled
                } else {
                    MiniZDistancePolicy::Enabled(SourceHistorySettings {
                        matches_to_start: self.matches_to_start_detected(),
                    })
                };
                self.behavior = BehaviorSettings::MiniZ {
                    common: MiniZMatchSettings {
                        dictionary: common.dictionary,
                        distance,
                        search: MiniZSearchSettings {
                            input_tail: InputTailPolicy::HashMinimum,
                            budget: common.search.budget,
                            max_probes,
                        },
                    },
                    greedy,
                    short_match_cutoff: cutoff,
                };
                self.configure_estimated_match_policies();
                return;
            }
        };
        self.behavior = BehaviorSettings::Chain { common, parser };
        self.configure_estimated_match_policies();
    }

    pub(crate) fn serialized_size(&self) -> usize {
        bitcode::encode(self).len()
    }

    pub(crate) fn canonical_short_match_cutoff(&self, bounds: (u32, u32)) -> u32 {
        canonical_short_match_cutoff(self.behavior.short_match_cutoff(), bounds)
    }
}

impl From<&ReconstructionParameters> for ReconstructionParameters {
    fn from(parameters: &ReconstructionParameters) -> Self {
        *parameters
    }
}
