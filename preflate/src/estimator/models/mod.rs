//! Family-specific interpretation of compressor evidence.
//!
//! Each family proposes complete reconstruction settings from observations.
//! Candidate ordering, selection provenance, and refinement slots are managed
//! by the estimator's profile coordinator; executable matching rules live in
//! the peer compressors module.
//! Candidate-construction helpers here attach coupled default tail and window
//! policies when the estimated index or parser changes. This happens before
//! scoring; reconstruction and JSON replay do not run these helpers or infer
//! missing policies from a hash signature.

pub mod chromium;
pub mod generic;
pub mod libdeflate;
pub mod miniz;
pub mod windows;
pub mod zlib;
pub mod zlib_ng;

use crate::{hash_algorithm::HashAlgorithm, reconstruction_parameters::*};

impl ReconstructionParameters {
    pub(crate) fn with_estimated_chain(
        self,
        mut common: ChainMatchSettings,
        parser: ChainParser,
    ) -> Self {
        common.configure_estimated_match_policies(parser);
        Self {
            behavior: BehaviorSettings::Chain { common, parser },
            ..self
        }
    }

    pub(crate) fn configure_estimated_match_policies(&mut self) {
        self.behavior.configure_estimated_match_policies();
    }
}

impl BehaviorSettings {
    fn configure_estimated_match_policies(&mut self) {
        match self {
            Self::Chain { common, parser } => common.configure_estimated_match_policies(*parser),
            Self::MiniZ { common, .. } => {
                common.search.input_tail = if common.dictionary.index.into_algorithm()
                    == HashAlgorithm::Libdeflate4Fast15
                {
                    InputTailPolicy::AtLeastFiveBytes
                } else {
                    InputTailPolicy::HashMinimum
                };
            }
            Self::NoDictionary { .. } => {}
        }
    }
}

impl ChainMatchSettings {
    fn configure_estimated_match_policies(&mut self, parser: ChainParser) {
        let signature = self.dictionary.index.into_algorithm();
        let fast = signature == HashAlgorithm::Libdeflate4Fast15;
        let dual_greedy = signature == HashAlgorithm::Libdeflate4
            && matches!(parser, ChainParser::LibdeflateGreedy { .. });
        let dual_lazy = signature == HashAlgorithm::Libdeflate4
            && matches!(parser, ChainParser::LibdeflateLazy { .. });
        self.search.input_tail = if fast || dual_greedy {
            InputTailPolicy::AtLeastFiveBytes
        } else {
            InputTailPolicy::HashMinimum
        };
        if let ChainDistancePolicy::Window { bounds, .. } = &mut self.distance {
            *bounds = match *bounds {
                WindowBounds::Full | WindowBounds::ExcludeOldest => {
                    if fast || dual_greedy || dual_lazy {
                        WindowBounds::ExcludeOldest
                    } else {
                        WindowBounds::Full
                    }
                }

                WindowBounds::Lookahead | WindowBounds::LookaheadMinusOne => {
                    if matches!(signature, HashAlgorithm::Chromium { .. }) {
                        WindowBounds::LookaheadMinusOne
                    } else {
                        WindowBounds::Lookahead
                    }
                }
            };
        }
    }

    pub(crate) fn set_full_window(&mut self, full: bool) {
        let history = match self.distance {
            ChainDistancePolicy::Window { history, .. } => history,
            ChainDistancePolicy::Disabled | ChainDistancePolicy::RleOnly => SourceHistorySettings {
                matches_to_start: false,
            },
        };
        if full {
            self.distance = ChainDistancePolicy::Window {
                history,
                bounds: WindowBounds::Full,
            };
        } else if matches!(
            self.distance,
            ChainDistancePolicy::Window {
                bounds: WindowBounds::Full | WindowBounds::ExcludeOldest,
                ..
            }
        ) {
            self.distance = ChainDistancePolicy::Window {
                history,
                bounds: WindowBounds::Lookahead,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compressors::zlib::DEFAULT_HASH,
        estimator::{compressor_profile::profile_alternatives, test_support::initial_stream_info},
        parameters::{DictionaryAddPolicy, LazyBehavior, PreflateStrategy},
        token_predictor::tests::zlib_level_1_params,
    };

    impl BehaviorSettings {
        pub(crate) fn set_full_window(&mut self, full: bool) {
            if let Self::Chain { common, .. } = self {
                common.set_full_window(full);
            }
            self.configure_estimated_match_policies();
        }
    }

    #[test]
    fn final_chain_construction_matches_incremental_policy_updates() {
        let base = zlib_level_1_params();
        let parsers = [
            ChainParser::Greedy {
                short_match_cutoff: 32768,
            },
            ChainParser::Lazy {
                lookahead: LazyLookaheadSettings {
                    max_lazy: 16,
                    behavior: LazyBehavior::Zlib { good_length: 8 },
                },
                minimum: LazyMinimum::Three {
                    short_match_cutoff: 4096,
                },
            },
            ChainParser::Lazy {
                lookahead: LazyLookaheadSettings {
                    max_lazy: 16,
                    behavior: LazyBehavior::RecomputeAfterLiteral,
                },
                minimum: LazyMinimum::FilteredSix,
            },
            ChainParser::LibdeflateGreedy {
                short_match_cutoff: 4096,
            },
            ChainParser::LibdeflateLazy {
                two_positions: true,
                short_match_cutoff: 8192,
            },
            ChainParser::WindowsLazy {
                max_lazy: 258,
                short_match_cutoff: 4096,
            },
        ];
        let history = SourceHistorySettings {
            matches_to_start: true,
        };
        for hash in [
            DEFAULT_HASH,
            HashAlgorithm::Chromium { hash_mask: 0x7fff },
            HashAlgorithm::Libdeflate4,
            HashAlgorithm::Libdeflate4Fast15,
            HashAlgorithm::RandomVector,
        ] {
            for parser in parsers {
                for distance in [
                    ChainDistancePolicy::Disabled,
                    ChainDistancePolicy::RleOnly,
                    ChainDistancePolicy::Window {
                        history,
                        bounds: WindowBounds::Full,
                    },
                    ChainDistancePolicy::Window {
                        history,
                        bounds: WindowBounds::ExcludeOldest,
                    },
                    ChainDistancePolicy::Window {
                        history,
                        bounds: WindowBounds::Lookahead,
                    },
                    ChainDistancePolicy::Window {
                        history,
                        bounds: WindowBounds::LookaheadMinusOne,
                    },
                ] {
                    for full in [false, true] {
                        let mut original = base;
                        original.chain_common_mut().unwrap().distance = distance;
                        let mut common = *original.chain_common().unwrap();
                        common.dictionary.index = DictionaryIndex::from_algorithm(hash).unwrap();
                        common.set_full_window(full);
                        let complete = original.with_estimated_chain(common, parser);

                        let mut incremental = original;
                        if let BehaviorSettings::Chain {
                            parser: current, ..
                        } = &mut incremental.behavior
                        {
                            *current = parser;
                        }
                        incremental.configure_estimated_match_policies();
                        incremental.set_estimated_hash(hash);
                        incremental.behavior.set_full_window(full);
                        assert_eq!(
                            complete, incremental,
                            "{hash:?} {parser:?} {distance:?} full={full}"
                        );
                        assert_eq!(
                            crate::parameter_codec::encode_parameters(&complete),
                            crate::parameter_codec::encode_parameters(&incremental)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn dictionary_free_settings_have_no_dictionary_refinement_proposals() {
        let mut info = initial_stream_info();
        for strategy in [PreflateStrategy::Store, PreflateStrategy::HuffOnly] {
            let parameters = ReconstructionParameters {
                max_token_count: 63,
                behavior: BehaviorSettings::NoDictionary { strategy },
                ..zlib_level_1_params()
            };
            for max_distance in [4096, 5000] {
                info.max_dist_3_matches = max_distance;
                assert!(profile_alternatives(parameters, &info, &[]).is_empty());
                assert_eq!(zlib_ng::inferred(parameters), None);
            }
        }
    }

    #[test]
    fn cross_engine_proposals_preserve_enabled_and_disabled_history() {
        let mut info = initial_stream_info();
        info.max_dist_3_matches = 5000;
        for distance in [
            MiniZDistancePolicy::Disabled,
            MiniZDistancePolicy::Enabled(SourceHistorySettings {
                matches_to_start: false,
            }),
            MiniZDistancePolicy::Enabled(SourceHistorySettings {
                matches_to_start: true,
            }),
        ] {
            let base = zlib_level_1_params();
            let parameters = ReconstructionParameters {
                behavior: BehaviorSettings::MiniZ {
                    common: MiniZMatchSettings {
                        dictionary: DictionarySettings {
                            insertion: DictionaryAddPolicy::AddAll,
                            ..*base.dictionary().unwrap()
                        },
                        distance,
                        search: MiniZSearchSettings {
                            max_probes: 32,
                            budget: SearchBudget { max_chain: 33 },
                            input_tail: InputTailPolicy::HashMinimum,
                        },
                    },
                    greedy: false,
                    short_match_cutoff: 8191,
                },
                ..base
            };
            let proposed = miniz::shallow_alternative(parameters, &info).unwrap();
            let BehaviorSettings::MiniZ { common, .. } = proposed.behavior else {
                panic!("expected MiniZ refinement");
            };
            assert_eq!(common.distance, distance);
            let [fast, slow] = chromium::alternatives(parameters, &info);
            assert!(slow.is_none());
            let proposed = fast.unwrap();
            let BehaviorSettings::Chain { common, .. } = proposed.behavior else {
                panic!("expected chain refinement");
            };
            let expected = match distance {
                MiniZDistancePolicy::Disabled => ChainDistancePolicy::Disabled,
                MiniZDistancePolicy::Enabled(history) => ChainDistancePolicy::Window {
                    history,
                    bounds: WindowBounds::LookaheadMinusOne,
                },
            };
            assert_eq!(common.distance, expected);
        }
    }
}
