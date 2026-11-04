/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use crate::hash_algorithm::HashAlgorithm;
use crate::parameters::{DictionaryAddPolicy, TokenPredictorParameters};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Profile(pub(super) TokenPredictorParameters);

impl Profile {
    pub(super) fn parameters(self) -> TokenPredictorParameters {
        self.0
    }

    pub(super) fn parameters_mut(&mut self) -> &mut TokenPredictorParameters {
        &mut self.0
    }

    pub(super) fn inferred(parameters: TokenPredictorParameters) -> Option<Self> {
        if !matches!(
            parameters.add_policy,
            DictionaryAddPolicy::AddAll
                | DictionaryAddPolicy::AddFirstAndLast(_)
                | DictionaryAddPolicy::AddFirstWith32KBoundary
        ) {
            return None;
        }
        match parameters.hash_algorithm {
            HashAlgorithm::ZlibNG | HashAlgorithm::Crc32cHash => Some(Self(parameters)),
            _ => None,
        }
    }
}

// Both signatures must be tested, independently of this machine's CPU features.
pub(crate) const HASHES: [HashAlgorithm; 2] = [HashAlgorithm::ZlibNG, HashAlgorithm::Crc32cHash];
pub(super) const SLIDE_POINT: u32 = 32768 - crate::deflate::deflate_constants::MIN_LOOKAHEAD;

pub(crate) fn greedy_nice_length(parameters: &TokenPredictorParameters) -> Option<u32> {
    if !HASHES.contains(&parameters.hash_algorithm) {
        return None;
    }
    // Observed insertion cutoffs are lower bounds on the family's fixed thresholds.
    match parameters.add_policy {
        DictionaryAddPolicy::AddFirstWith32KBoundary
        | DictionaryAddPolicy::AddFirstAndLast(0..=4) => Some(8),
        DictionaryAddPolicy::AddFirstAndLast(5..=96) => Some(16),
        DictionaryAddPolicy::AddFirstAndLast(97..=191) => Some(32),
        _ => None,
    }
}

#[inline(always)]
pub(crate) fn is_at_32k_boundary(length: u32, pos: u32) -> bool {
    length > 1 && ((pos & 0x7fff) <= SLIDE_POINT) && (((pos + length) & 0x7fff) >= SLIDE_POINT)
}

#[test]
fn verify_zlibng_recognition() {
    use crate::{
        PreflateConfig,
        deflate::deflate_reader::parse_deflate_whole,
        estimator::preflate_parameter_estimator::estimate_preflate_parameters,
        parameters::{DictionaryAddPolicy, MatchingType},
        preflate_whole_deflate_stream, recreate_whole_deflate_stream,
        utils::read_file,
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
        assert_eq!(parameters.hash_algorithm, HashAlgorithm::Crc32cHash);
        assert_eq!(parameters.add_policy, insertion);
        assert_eq!(parameters.matching_type, MatchingType::Greedy);
        let (record, plaintext) =
            preflate_whole_deflate_stream(&compressed, &PreflateConfig::default()).unwrap();
        let recreated =
            recreate_whole_deflate_stream(plaintext.text(), &record.corrections).unwrap();
        assert_eq!(recreated, compressed);
    }
}

#[test]
fn boundary_insertion_adds_the_last_match_byte_only_when_crossing_the_slide_point() {
    use crate::parameters::DictionaryAddPolicy;

    let bytes = [b'a'; 8];
    for base in [0, 32768, 65536] {
        for (start, length, expected) in [
            (32501, 4, vec![(32501, 1)]),
            (32502, 4, vec![(32502, 1), (32505, 1)]),
            (32506, 4, vec![(32506, 1), (32509, 1)]),
            (32507, 4, vec![(32507, 1)]),
            (32506, 1, vec![(32506, 1)]),
        ] {
            let mut inserted = Vec::new();
            DictionaryAddPolicy::AddFirstWith32KBoundary.update_hash(
                &bytes,
                base + start,
                length,
                |_, position, length| inserted.push((position, length)),
            );
            let expected: Vec<_> = expected
                .into_iter()
                .map(|(position, length)| (base + position, length))
                .collect();
            assert_eq!(
                inserted, expected,
                "base={base}, start={start}, length={length}"
            );
        }
    }
}
