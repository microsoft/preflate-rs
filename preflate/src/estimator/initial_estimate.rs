//! Inputs to initial compressor-model interpretation, before executable settings exist.
//!
//! The selected depth-walk evidence stays separate from stream-wide observations
//! and inferred block, window, and insertion settings. Family models choose their
//! parser and search defaults before constructing complete reconstruction candidates.
//! This estimator-only record is neither serialized nor retained by prediction.
//! Stream observations are borrowed so later refinements reuse the same facts.

use super::{
    complevel_estimator::CandidateEvidence, depth_estimator::DistancePolicy,
    preflate_stream_info::PreflateStreamInfo,
};
use crate::{
    parameters::{BlockTypeStrategy, DictionaryAddPolicy, PreflateStrategy},
    reconstruction_parameters::{
        BehaviorSettings, ChainDistancePolicy, ChainMatchSettings, ChainParser, ChainSettings,
        DictionaryIndex, DictionarySettings, InputTailPolicy, ReconstructionParameters,
        SearchBudget, SourceHistorySettings, WindowBounds,
    },
};

pub struct InitialEstimate<'a> {
    pub evidence: CandidateEvidence,
    pub info: &'a PreflateStreamInfo,
    pub block_type_strategy: BlockTypeStrategy,
    pub max_token_count: u16,
    pub window_bits: u32,
    pub insertion: DictionaryAddPolicy,
    pub strategy: PreflateStrategy,
}

impl InitialEstimate<'_> {
    pub fn dictionary(&self) -> DictionarySettings {
        DictionarySettings {
            index: DictionaryIndex::from_algorithm(self.evidence.hash_algorithm)
                .expect("depth candidates have dictionaries"),
            window_bits: self.window_bits,
            insertion: self.insertion,
        }
    }

    pub fn distance(&self) -> ChainDistancePolicy {
        let history = self.source_history();
        if self.evidence.distance_policy == DistancePolicy::FullWindow {
            ChainDistancePolicy::Window {
                history,
                bounds: WindowBounds::Full,
            }
        } else if self.strategy == PreflateStrategy::RleOnly {
            ChainDistancePolicy::RleOnly
        } else {
            ChainDistancePolicy::Window {
                history,
                bounds: WindowBounds::Lookahead,
            }
        }
    }

    pub fn parameters(&self, behavior: BehaviorSettings) -> ReconstructionParameters {
        let mut parameters = ReconstructionParameters {
            max_token_count: self.max_token_count,
            block_type_strategy: self.block_type_strategy,
            behavior,
        };
        parameters.configure_estimated_match_policies();
        parameters
    }

    pub fn permits_position_zero(&self) -> bool {
        self.source_history().matches_to_start
    }

    pub fn source_history(&self) -> SourceHistorySettings {
        SourceHistorySettings {
            matches_to_start: self.info.matches_to_start_detected
                && (self.evidence.distance_policy == DistancePolicy::FullWindow
                    || self.strategy != PreflateStrategy::RleOnly),
        }
    }

    pub fn chain_parameters(
        &self,
        parser: ChainParser,
        nice_length: u32,
        max_chain: u32,
    ) -> ReconstructionParameters {
        self.parameters(BehaviorSettings::Chain {
            common: ChainMatchSettings {
                dictionary: self.dictionary(),
                distance: self.distance(),
                search: ChainSettings {
                    input_tail: InputTailPolicy::HashMinimum,
                    budget: SearchBudget { max_chain },
                    nice_length,
                },
            },
            parser,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        compressors::zlib::DEFAULT_HASH,
        estimator::{
            models::zlib::{compatible, compatible_initial},
            parser_estimator::ParserInference,
            preflate_stream_info::tests::extract_preflate_info,
        },
        hash_algorithm::HashAlgorithm,
    };

    pub fn stream_info() -> PreflateStreamInfo {
        let mut info = extract_preflate_info(&[]);
        info.min_len = 3;
        info.max_len = 258;
        info.max_dist_3_matches = 4096;
        info
    }

    fn initial(info: &PreflateStreamInfo) -> InitialEstimate<'_> {
        InitialEstimate::test_fixture(
            info,
            CandidateEvidence {
                hash_algorithm: DEFAULT_HASH,
                required_chain: 4,
                distance_policy: DistancePolicy::ZlibWindow,
                parser: ParserInference::Unresolved,
                shallow_miniz_greedy: false,
                minimum_nice_length: 0,
            },
        )
    }

    #[test]
    fn complete_candidates_attach_coupled_tail_and_window_policies() {
        for (hash, parser, five_byte_tail, exclude_oldest) in [
            (
                DEFAULT_HASH,
                ChainParser::Greedy {
                    short_match_cutoff: 4096,
                },
                false,
                false,
            ),
            (
                HashAlgorithm::Chromium { hash_mask: 0x7fff },
                ChainParser::Greedy {
                    short_match_cutoff: 4096,
                },
                false,
                false,
            ),
            (
                HashAlgorithm::Libdeflate4Fast15,
                ChainParser::Greedy {
                    short_match_cutoff: 4096,
                },
                true,
                true,
            ),
            (
                HashAlgorithm::Libdeflate4,
                ChainParser::LibdeflateGreedy {
                    short_match_cutoff: 4096,
                },
                true,
                true,
            ),
            (
                HashAlgorithm::Libdeflate4,
                ChainParser::LibdeflateLazy {
                    two_positions: true,
                    short_match_cutoff: 8192,
                },
                false,
                true,
            ),
        ] {
            for full in [false, true] {
                let info = stream_info();
                let mut initial = initial(&info);
                initial.evidence.hash_algorithm = hash;
                initial.evidence.distance_policy = if full {
                    DistancePolicy::FullWindow
                } else {
                    DistancePolicy::ZlibWindow
                };
                let parameters = initial.chain_parameters(parser, 32, 4);
                let common = parameters.chain_common().unwrap();
                let expected_bounds = if full {
                    if exclude_oldest {
                        WindowBounds::ExcludeOldest
                    } else {
                        WindowBounds::Full
                    }
                } else if matches!(hash, HashAlgorithm::Chromium { .. }) {
                    WindowBounds::LookaheadMinusOne
                } else {
                    WindowBounds::Lookahead
                };
                assert!(
                    matches!(common.distance, ChainDistancePolicy::Window { bounds, .. } if bounds == expected_bounds)
                );
                assert_eq!(
                    common.search.input_tail,
                    if five_byte_tail {
                        InputTailPolicy::AtLeastFiveBytes
                    } else {
                        InputTailPolicy::HashMinimum
                    }
                );
                assert_eq!(common.search.nice_length, 32);
                assert_eq!(
                    common.search.budget.max_chain,
                    initial.evidence.required_chain
                );
                assert_eq!(parameters.hash_algorithm(), hash);
                assert_eq!(parameters.max_token_count, initial.max_token_count);
                assert_eq!(parameters.block_type_strategy, initial.block_type_strategy);
                assert_eq!(parameters.chain_parser(), Some(parser));
            }
        }
    }

    #[test]
    fn initial_compatibility_matches_complete_candidates_including_rle_history() {
        for strategy in [PreflateStrategy::Default, PreflateStrategy::RleOnly] {
            for full in [false, true] {
                for matches_to_start in [false, true] {
                    for cutoff in [4096, 4097] {
                        let mut info = stream_info();
                        info.matches_to_start_detected = matches_to_start;
                        info.max_dist_3_matches = cutoff;
                        let mut initial = initial(&info);
                        initial.strategy = strategy;
                        initial.evidence.distance_policy = if full {
                            DistancePolicy::FullWindow
                        } else {
                            DistancePolicy::ZlibWindow
                        };
                        assert_eq!(
                            initial.source_history().matches_to_start,
                            matches_to_start && (full || strategy != PreflateStrategy::RleOnly)
                        );
                        let parameters = initial.chain_parameters(
                            ChainParser::Greedy {
                                short_match_cutoff: cutoff,
                            },
                            258,
                            4,
                        );
                        assert_eq!(
                            compatible_initial(&initial),
                            compatible(&parameters),
                            "{strategy:?}, full={full}, start={matches_to_start}, cutoff={cutoff}"
                        );
                        assert_eq!(
                            initial.permits_position_zero(),
                            parameters.behavior.permits_position_zero()
                        );
                    }
                }
            }
        }
    }

    impl<'a> InitialEstimate<'a> {
        pub fn test_fixture(info: &'a PreflateStreamInfo, evidence: CandidateEvidence) -> Self {
            Self {
                evidence,
                info,
                block_type_strategy: BlockTypeStrategy::Dynamic,
                max_token_count: 16383,
                window_bits: 15,
                insertion: DictionaryAddPolicy::AddAll,
                strategy: PreflateStrategy::Default,
            }
        }
    }
}
