//! Provides access to the dictionary, search budget, and parser settings of
//! chain-based, MiniZ, and dictionary-free reconstruction configurations.

use crate::{hash_algorithm::HashAlgorithm, reconstruction_parameters::*};

impl ReconstructionParameters {
    pub(crate) fn chain_parser(&self) -> Option<ChainParser> {
        match self.behavior {
            BehaviorSettings::Chain { parser, .. } => Some(parser),
            _ => None,
        }
    }

    pub(crate) fn hash_algorithm(self) -> HashAlgorithm {
        self.behavior
            .dictionary_and_budget()
            .map_or(HashAlgorithm::None, |(dictionary, _)| {
                dictionary.index.into_algorithm()
            })
    }
}

impl ChainParser {
    pub(crate) fn with_cutoff(mut self, cutoff: u32) -> Self {
        if let Some(current) = self.short_match_cutoff_mut() {
            *current = cutoff;
        }
        self
    }
}

impl BehaviorSettings {
    pub(crate) fn uses_full_window(self) -> bool {
        matches!(
            self,
            Self::Chain {
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

    pub(crate) fn permits_position_zero(self) -> bool {
        match self {
            Self::Chain {
                common:
                    ChainMatchSettings {
                        distance: ChainDistancePolicy::Window { history, .. },
                        ..
                    },
                ..
            }
            | Self::MiniZ {
                common:
                    MiniZMatchSettings {
                        distance: MiniZDistancePolicy::Enabled(history),
                        ..
                    },
                ..
            } => history.matches_to_start,
            _ => false,
        }
    }

    pub(crate) fn set_short_match_cutoff(&mut self, cutoff: u32) {
        match self {
            Self::Chain { parser, .. } => *parser = parser.with_cutoff(cutoff),
            Self::MiniZ {
                short_match_cutoff, ..
            } => *short_match_cutoff = cutoff,
            Self::NoDictionary { .. } => {}
        }
    }
}

impl ReconstructionParameters {
    pub(crate) fn dictionary(&self) -> Option<&DictionarySettings> {
        match &self.behavior {
            BehaviorSettings::NoDictionary { .. } => None,
            BehaviorSettings::Chain { common, .. } => Some(&common.dictionary),
            BehaviorSettings::MiniZ { common, .. } => Some(&common.dictionary),
        }
    }

    pub(crate) fn dictionary_mut(&mut self) -> Option<&mut DictionarySettings> {
        match &mut self.behavior {
            BehaviorSettings::NoDictionary { .. } => None,
            BehaviorSettings::Chain { common, .. } => Some(&mut common.dictionary),
            BehaviorSettings::MiniZ { common, .. } => Some(&mut common.dictionary),
        }
    }

    pub(crate) fn budget(&self) -> Option<SearchBudget> {
        self.behavior
            .dictionary_and_budget()
            .map(|(_, budget)| budget)
    }

    pub(crate) fn to_json(self) -> crate::Result<String> {
        serde_json::to_string(&self).map_err(|error| {
            crate::PreflateError::new(crate::ExitCode::GeneralFailure, error.to_string())
        })
    }
}
