/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::hash_algorithm::HashAlgorithm;

/// Family-specific restrictions on what a generic collector may count as evidence.
/// Sampling bounds and inference confidence thresholds are not family policies.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ParserEvidencePolicy {
    deferred_match_floor: u32,
}

impl ParserEvidencePolicy {
    pub fn for_hash(hash_algorithm: HashAlgorithm) -> Self {
        crate::models::evidence_policy(hash_algorithm)
    }

    pub(crate) const fn with_deferred_match_floor(deferred_match_floor: u32) -> Self {
        Self {
            deferred_match_floor,
        }
    }

    pub fn minimum_deferred_match(self, observed_minimum: u32) -> u32 {
        observed_minimum.max(self.deferred_match_floor)
    }
}
