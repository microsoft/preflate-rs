/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use crate::hash_algorithm::HashAlgorithm;

// Both signatures must be tested, independently of this machine's CPU features.
pub(crate) const HASHES: [HashAlgorithm; 2] = [HashAlgorithm::ZlibNG, HashAlgorithm::Crc32cHash];

#[inline(always)]
pub(crate) fn is_at_32k_boundary(length: u32, pos: u32) -> bool {
    length > 1
        && ((pos & 0x7fff) <= (32768 - 0x106))
        && (((pos + length) & 0x7fff) >= (32768 - 0x106))
}

#[test]
fn verify_zlibng_recognition() {
    use crate::{
        PreflateConfig,
        deflate::deflate_reader::parse_deflate_whole,
        estimator::{
            add_policy_estimator::DictionaryAddPolicy,
            preflate_parameter_estimator::estimate_preflate_parameters,
            preflate_parse_config::MatchingType,
        },
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
    use crate::estimator::add_policy_estimator::DictionaryAddPolicy;

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
