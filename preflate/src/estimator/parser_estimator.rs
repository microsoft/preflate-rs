/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

//! Greedy and lazy parser inference from bounded match observations.
//! Interprets repeated deferred matches and insertion constraints for profile selection.

use crate::parameters::DictionaryAddPolicy;

// Confidence thresholds for inference, not constraints imposed by DEFLATE.
const MIN_LAZY_OBSERVATIONS: u16 = 4;

/// Bounded observations from the existing depth walk, independent of profile selection.
#[derive(Clone, Copy, Debug, Default)]
pub struct ParserEvidence {
    pub lazy_matches: u16,
    pub longest_lazy_match: u16,
}

/// What the observations support, without choosing compressor-specific search settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParserInference {
    Unresolved,
    Greedy,
    Lazy { longest_deferred_match: u16 },
}

impl ParserEvidence {
    pub fn infer(self, greedy_parser_detected: bool) -> ParserInference {
        if greedy_parser_detected {
            // Preserve the established greedy fingerprint when the signals disagree.
            ParserInference::Greedy
        } else if self.lazy_matches >= MIN_LAZY_OBSERVATIONS
            // Short matches can be rejected by filtering rather than lazy search.
            && u32::from(self.longest_lazy_match) >= crate::compressors::zlib::FILTERED_MIN_MATCH_LENGTH
        {
            ParserInference::Lazy {
                longest_deferred_match: self.longest_lazy_match,
            }
        } else {
            ParserInference::Unresolved
        }
    }
}

/// Whether insertion evidence permits reconsidering the default matching policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertionConstraint {
    /// The observed cutoff never excludes a match, so it does not establish greedy parsing.
    Unresolved,
    /// Retain the existing interpretation of the inferred insertion policy.
    Constrained,
}

impl InsertionConstraint {
    pub fn observe(policy: DictionaryAddPolicy, longest_match: u32) -> Self {
        match policy {
            DictionaryAddPolicy::AddFirst(limit) if u32::from(limit) >= longest_match => {
                // This stream cannot distinguish the inferred cutoff from full insertion.
                Self::Unresolved
            }
            _ => Self::Constrained,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        estimator::models::generic::resolve_matching_policy, reconstruction_parameters::ChainParser,
    };

    #[test]
    fn parser_inference_requires_unfiltered_repeated_evidence() {
        for (count, length, expected) in [
            (0, 0, ParserInference::Unresolved),
            (3, 7, ParserInference::Unresolved),
            (4, 5, ParserInference::Unresolved),
            (
                4,
                6,
                ParserInference::Lazy {
                    longest_deferred_match: 6,
                },
            ),
        ] {
            let evidence = ParserEvidence {
                lazy_matches: count,
                longest_lazy_match: length,
            };
            assert_eq!(evidence.infer(false), expected);
            assert_eq!(evidence.infer(true), ParserInference::Greedy);
        }
    }

    #[test]
    fn insertion_cutoff_is_unresolved_until_it_excludes_an_observed_match() {
        for (policy, longest, expected) in [
            (
                DictionaryAddPolicy::AddFirst(6),
                5,
                InsertionConstraint::Unresolved,
            ),
            (
                DictionaryAddPolicy::AddFirst(6),
                6,
                InsertionConstraint::Unresolved,
            ),
            (
                DictionaryAddPolicy::AddFirst(6),
                7,
                InsertionConstraint::Constrained,
            ),
            (
                DictionaryAddPolicy::AddAll,
                6,
                InsertionConstraint::Constrained,
            ),
            (
                DictionaryAddPolicy::AddFirstAndLast(6),
                6,
                InsertionConstraint::Constrained,
            ),
        ] {
            assert_eq!(InsertionConstraint::observe(policy, longest), expected);
        }
    }

    #[test]
    fn lazy_policy_must_look_beyond_the_deferred_match() {
        for (length, expected) in [
            (6, Some(16)),
            (15, Some(16)),
            (16, Some(32)),
            (32, Some(128)),
            (128, Some(258)),
            (258, None),
        ] {
            let result = resolve_matching_policy(
                ChainParser::Greedy {
                    short_match_cutoff: 0,
                },
                InsertionConstraint::Unresolved,
                ParserInference::Lazy {
                    longest_deferred_match: length,
                },
            );
            match expected {
                Some(expected) => {
                    assert!(
                        matches!(result, ChainParser::Lazy { lookahead, .. } if lookahead.max_lazy == expected)
                    );
                }
                None => assert_eq!(
                    result,
                    ChainParser::Greedy {
                        short_match_cutoff: 0
                    }
                ),
            }
        }
    }
}
