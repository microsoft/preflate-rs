/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use super::zlib;
use crate::estimator::{
    CandidateEvidence, InsertionConstraint, ParserInference,
    preflate_parameter_estimator::TokenPredictorParameters, preflate_parse_config::MatchingType,
};

pub(crate) fn resolve_matching_policy(
    current: MatchingType,
    insertion: InsertionConstraint,
    inference: ParserInference,
) -> MatchingType {
    if current == MatchingType::Greedy
        && insertion == InsertionConstraint::Unresolved
        && let ParserInference::Lazy {
            longest_deferred_match,
        } = inference
    {
        return zlib::SLOW_PREFLATE_PARSER_SETTINGS
            .iter()
            .map(|config| config.match_type)
            .find(|policy| {
                matches!(policy, MatchingType::Lazy { max_lazy, .. }
                    if *max_lazy > longest_deferred_match)
            })
            .unwrap_or(current);
    }
    current
}

pub(crate) fn apply_defaults(
    mut parameters: TokenPredictorParameters,
    evidence: &CandidateEvidence,
    compatible: bool,
    observed_min_len: u32,
) -> TokenPredictorParameters {
    // Borrow zlib-shaped defaults without claiming identity or inflating observed depth.
    if let Some(config) = zlib::parser_settings(parameters.add_policy)
        .iter()
        .find(|config| evidence.required_chain <= config.max_chain)
    {
        parameters.matching_type = config.match_type;
        parameters.nice_length = config.nice_length;
    }
    zlib::project_lazy_behavior(parameters, compatible, observed_min_len)
}
