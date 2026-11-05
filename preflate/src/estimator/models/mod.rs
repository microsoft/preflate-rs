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
    pub(crate) fn set_estimated_hash(&mut self, hash: HashAlgorithm) {
        self.dictionary_mut().expect("dictionary candidate").index =
            DictionaryIndex::from_algorithm(hash).expect("dictionary hash");
        self.configure_estimated_match_policies();
    }

    pub(crate) fn replace_chain_parser(&mut self, parser: ChainParser) {
        let BehaviorSettings::Chain {
            parser: current, ..
        } = &mut self.behavior
        else {
            panic!("replacing a chain parser requires chain match settings");
        };
        *current = parser;
        self.configure_estimated_match_policies();
    }

    pub(crate) fn configure_estimated_match_policies(&mut self) {
        self.behavior.configure_estimated_match_policies();
    }
}

impl BehaviorSettings {
    fn configure_estimated_match_policies(&mut self) {
        match self {
            Self::Chain { common, parser } => {
                let signature = common.dictionary.index.into_algorithm();
                let fast = signature == HashAlgorithm::Libdeflate4Fast15;
                let dual_greedy = signature == HashAlgorithm::Libdeflate4
                    && matches!(parser, ChainParser::LibdeflateGreedy { .. });
                let dual_lazy = signature == HashAlgorithm::Libdeflate4
                    && matches!(parser, ChainParser::LibdeflateLazy { .. });
                common.search.input_tail = if fast || dual_greedy {
                    InputTailPolicy::AtLeastFiveBytes
                } else {
                    InputTailPolicy::HashMinimum
                };
                if let ChainDistancePolicy::Window { bounds, .. } = &mut common.distance {
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

    pub(crate) fn set_full_window(&mut self, full: bool) {
        let history = SourceHistorySettings {
            matches_to_start: self.permits_position_zero(),
        };
        if let Self::Chain { common, .. } = self {
            if full {
                common.distance = ChainDistancePolicy::Window {
                    history,
                    bounds: WindowBounds::Full,
                };
            } else if matches!(
                common.distance,
                ChainDistancePolicy::Window {
                    bounds: WindowBounds::Full | WindowBounds::ExcludeOldest,
                    ..
                }
            ) {
                common.distance = ChainDistancePolicy::Window {
                    history,
                    bounds: WindowBounds::Lookahead,
                };
            }
        }
        self.configure_estimated_match_policies();
    }
}
