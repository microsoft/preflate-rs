//! Parsing and validation of reconstruction-parameter JSON for diagnostic replay.
//! Checks search limits and compatible hash/parser combinations before predictor allocation.

use crate::{
    ExitCode, PreflateError, Result,
    parameters::{DictionaryAddPolicy, LazyBehavior},
    reconstruction_parameters::*,
};

fn invalid(message: impl ToString) -> PreflateError {
    PreflateError::new(ExitCode::InvalidParameter, message.to_string())
}

impl ReconstructionParameters {
    pub(crate) fn from_json(json: &str) -> Result<Self> {
        let parameters: Self = serde_json::from_str(json).map_err(invalid)?;
        parameters.validate()?;
        Ok(parameters)
    }

    fn validate(&self) -> Result<()> {
        if self.max_token_count == 0 {
            return Err(invalid("token-buffer capacity must be positive"));
        }
        let (dictionary, budget) = match self.behavior {
            BehaviorSettings::NoDictionary { .. } => return Ok(()),
            BehaviorSettings::Chain { common, parser } => {
                if !(3..=258).contains(&common.search.nice_length) {
                    return Err(invalid("invalid nice length"));
                }
                if common.distance != ChainDistancePolicy::Disabled
                    && common.search.budget.max_chain == 0
                {
                    return Err(invalid("active chain search requires a positive budget"));
                }
                match parser {
                    ChainParser::Lazy { lookahead, .. } => {
                        if lookahead.max_lazy > 258
                            || matches!(lookahead.behavior, LazyBehavior::Zlib { good_length } if good_length > 258)
                        {
                            return Err(invalid("invalid lazy lookahead"));
                        }
                    }
                    ChainParser::WindowsLazy { max_lazy, .. } if max_lazy > 258 => {
                        return Err(invalid("invalid Windows lookahead"));
                    }
                    ChainParser::LibdeflateLazy {
                        two_positions: true,
                        ..
                    } if common.dictionary.index != DictionaryIndex::LibdeflateDualHash => {
                        return Err(invalid(
                            "two-position libdeflate matching requires the dual-hash index",
                        ));
                    }
                    _ => {}
                }
                (common.dictionary, common.search.budget)
            }
            BehaviorSettings::MiniZ { common, .. } => {
                if !(1..=4096).contains(&common.search.max_probes)
                    || (common.distance != MiniZDistancePolicy::Disabled
                        && common.search.budget.max_chain == 0)
                {
                    return Err(invalid("invalid MiniZ search budget"));
                }
                (common.dictionary, common.search.budget)
            }
        };
        if !(9..=15).contains(&dictionary.window_bits)
            || budget.max_chain > 4096
            || self.behavior.short_match_cutoff() > 32768
            || matches!(dictionary.insertion, DictionaryAddPolicy::AddFirst(n) | DictionaryAddPolicy::AddFirstAndLast(n) if n > 258)
        {
            return Err(invalid(
                "invalid window, search, cutoff or insertion settings",
            ));
        }
        match dictionary.index {
            DictionaryIndex::Chain {
                hash:
                    HashFunction::Zlib {
                        hash_mask,
                        hash_shift,
                    },
            } if hash_mask == 0
                || !(u32::from(hash_mask) + 1).is_power_of_two()
                || !(1..=15).contains(&hash_shift) =>
            {
                return Err(invalid("invalid zlib hash mask or shift"));
            }
            DictionaryIndex::Chain {
                hash: HashFunction::Chromium { hash_mask },
            } if ![32767, 65535].contains(&hash_mask) => {
                return Err(invalid("invalid Chromium hash mask"));
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_is_strict_and_preserves_binary_settings() {
        let parameters = crate::token_predictor::tests::zlib_level_1_params();
        let json = parameters.to_json().unwrap();
        assert_eq!(
            ReconstructionParameters::from_json(&json).unwrap(),
            parameters
        );
        for invalid in ["not JSON", "null", "[]", "{}", r#"{"max_chain":4}"#] {
            assert!(ReconstructionParameters::from_json(invalid).is_err());
        }
        let mut value = serde_json::to_value(parameters).unwrap();
        value["strategy"] = serde_json::json!("Default");
        assert!(ReconstructionParameters::from_json(&value.to_string()).is_err());
        let mut value = serde_json::to_value(parameters).unwrap();
        value["behavior"]["Chain"]["common"]["dictionary"]["unexpected"] = true.into();
        assert!(ReconstructionParameters::from_json(&value.to_string()).is_err());
        let mut value = serde_json::to_value(parameters).unwrap();
        value["behavior"]["Chain"]["common"]["search"]["budget"]["max_chain"] = 4097.into();
        assert!(ReconstructionParameters::from_json(&value.to_string()).is_err());
        let wrapper = serde_json::json!({"reconstruction": parameters, "model": "custom"});
        assert!(ReconstructionParameters::from_json(&wrapper.to_string()).is_err());
    }

    #[test]
    fn canonical_runtime_bounds_are_checked_before_replay() {
        let parameters = crate::token_predictor::tests::zlib_level_1_params();
        let original = serde_json::to_value(parameters).unwrap();
        for (pointer, value) in [
            ("/max_token_count", serde_json::json!(0)),
            (
                "/behavior/Chain/common/dictionary/window_bits",
                serde_json::json!(8),
            ),
            (
                "/behavior/Chain/common/dictionary/window_bits",
                serde_json::json!(16),
            ),
            (
                "/behavior/Chain/common/dictionary/index/Chain/hash/Zlib/hash_mask",
                serde_json::json!(17),
            ),
            (
                "/behavior/Chain/common/dictionary/index/Chain/hash/Zlib/hash_shift",
                serde_json::json!(0),
            ),
            (
                "/behavior/Chain/common/search/budget/max_chain",
                serde_json::json!(0),
            ),
            (
                "/behavior/Chain/common/search/budget/max_chain",
                serde_json::json!(4097),
            ),
            (
                "/behavior/Chain/common/search/nice_length",
                serde_json::json!(2),
            ),
            (
                "/behavior/Chain/common/search/nice_length",
                serde_json::json!(259),
            ),
            (
                "/behavior/Chain/parser/Greedy/short_match_cutoff",
                serde_json::json!(32769),
            ),
        ] {
            let mut value_json = original.clone();
            *value_json.pointer_mut(pointer).unwrap() = value;
            assert!(
                ReconstructionParameters::from_json(&value_json.to_string()).is_err(),
                "{pointer}"
            );
        }
        let BehaviorSettings::Chain { common, .. } = parameters.behavior else {
            unreachable!()
        };
        let invalid_behaviors = [
            BehaviorSettings::Chain {
                common,
                parser: ChainParser::LibdeflateLazy {
                    two_positions: true,
                    short_match_cutoff: 0,
                },
            },
            BehaviorSettings::Chain {
                common,
                parser: ChainParser::Lazy {
                    lookahead: LazyLookaheadSettings {
                        max_lazy: 259,
                        behavior: LazyBehavior::RecomputeAfterLiteral,
                    },
                    minimum: LazyMinimum::FilteredSix,
                },
            },
            BehaviorSettings::MiniZ {
                common: MiniZMatchSettings {
                    dictionary: common.dictionary,
                    distance: MiniZDistancePolicy::Disabled,
                    search: MiniZSearchSettings {
                        input_tail: InputTailPolicy::HashMinimum,
                        max_probes: 0,
                        budget: common.search.budget,
                    },
                },
                greedy: true,
                short_match_cutoff: 0,
            },
        ];
        for behavior in invalid_behaviors {
            let settings = ReconstructionParameters {
                behavior,
                ..parameters
            };
            assert!(ReconstructionParameters::from_json(&settings.to_json().unwrap()).is_err());
        }
    }

    #[test]
    fn canonical_experimental_distance_modes_remain_available() {
        let mut parameters = crate::token_predictor::tests::zlib_level_1_params();
        parameters.chain_common_mut().unwrap().distance = ChainDistancePolicy::Disabled;
        parameters.budget_mut().unwrap().max_chain = 0;
        assert_eq!(
            ReconstructionParameters::from_json(&parameters.to_json().unwrap()).unwrap(),
            parameters
        );
        for strategy in [
            crate::parameters::PreflateStrategy::Store,
            crate::parameters::PreflateStrategy::HuffOnly,
            crate::parameters::PreflateStrategy::Default,
            crate::parameters::PreflateStrategy::RleOnly,
        ] {
            parameters.behavior = BehaviorSettings::NoDictionary { strategy };
            assert_eq!(
                ReconstructionParameters::from_json(&parameters.to_json().unwrap()).unwrap(),
                parameters
            );
        }
    }
}
