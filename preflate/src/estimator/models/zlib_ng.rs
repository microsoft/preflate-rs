//! Zlib-ng hash signatures and insertion-policy defaults.
//! Recognizes hash/insertion combinations and infers fast-search thresholds.
//! Execution of slide-boundary insertion lives in `compressors::zlib_ng`.

/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use crate::estimator::initial_estimate::InitialEstimate;
use crate::hash_algorithm::HashAlgorithm;
use crate::{parameters::DictionaryAddPolicy, reconstruction_parameters::ReconstructionParameters};

pub fn inferred(parameters: ReconstructionParameters) -> Option<ReconstructionParameters> {
    if !matches!(
        parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion,
        DictionaryAddPolicy::AddAll
            | DictionaryAddPolicy::AddFirstAndLast(_)
            | DictionaryAddPolicy::AddFirstWith32KBoundary
    ) {
        return None;
    }
    match parameters.hash_algorithm() {
        HashAlgorithm::ZlibNG | HashAlgorithm::Crc32cHash => Some(parameters),
        _ => None,
    }
}
// Both signatures must be tested, independently of this machine's CPU features.
pub const HASHES: [HashAlgorithm; 2] = [HashAlgorithm::ZlibNG, HashAlgorithm::Crc32cHash];

pub fn greedy_nice_length(initial: &InitialEstimate<'_>) -> Option<u32> {
    if !HASHES.contains(&initial.evidence.hash_algorithm) {
        return None;
    }
    // Observed insertion cutoffs are lower bounds on the family's fixed thresholds.
    match initial.insertion {
        DictionaryAddPolicy::AddFirstWith32KBoundary
        | DictionaryAddPolicy::AddFirstAndLast(0..=4) => Some(8),
        DictionaryAddPolicy::AddFirstAndLast(5..=96) => Some(16),
        DictionaryAddPolicy::AddFirstAndLast(97..=191) => Some(32),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::parameters::tests::MatchingType;

    #[test]
    fn verify_zlibng_recognition() {
        use crate::{
            PreflateConfig, deflate::deflate_reader::tests::parse_deflate_whole,
            estimator::preflate_parameter_estimator::tests::estimate_preflate_parameters,
            parameters::DictionaryAddPolicy, preflate_whole_deflate_stream,
            recreate_whole_deflate_stream, utils::read_file,
        };

        for (level, insertion) in [
            (1, DictionaryAddPolicy::AddFirstWith32KBoundary),
            (2, DictionaryAddPolicy::AddFirstAndLast(4)),
            (3, DictionaryAddPolicy::AddFirstAndLast(96)),
            (4, DictionaryAddPolicy::AddFirstAndLast(191)),
        ] {
            let compressed = read_file(&format!("compressed_zlibng_level{level}.deflate"));
            let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
            let parameters = estimate_preflate_parameters(&contents, &plain).unwrap();
            assert_eq!(parameters.hash_algorithm(), HashAlgorithm::Crc32cHash);
            assert_eq!(parameters.add_policy(), insertion);
            assert_eq!(parameters.matching_type(), MatchingType::Greedy);
            let (record, plaintext) =
                preflate_whole_deflate_stream(&compressed, &PreflateConfig::default()).unwrap();
            let recreated =
                recreate_whole_deflate_stream(plaintext.text(), &record.corrections).unwrap();
            assert_eq!(recreated, compressed);
        }
    }
}
