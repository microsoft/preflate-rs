/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

/// This module is design to detect the appropriate overall parameters for the preflate compressor.
/// Getting the parameters correct means that the resulting diff between the deflate stream
/// and the predicted deflate stream will be as small as possible.
use crate::{
    deflate::deflate_reader::DeflateContents,
    hash_algorithm::HashAlgorithm,
    models::{self, zlib::refine_depth_candidate},
    preflate_error::{ExitCode, Result, err_exit_code},
    preflate_input::PlainText,
};

use super::{
    add_policy_estimator::DictionaryAddPolicy,
    depth_estimator::{
        DistancePolicy, HashTableDepthEstimator, new_depth_estimator, run_depth_candidates,
    },
    parser_estimator::{InsertionConstraint, ParserInference},
    preflate_stream_info::PreflateStreamInfo,
};

/// Snapshot the existing walk's evidence before assigning compressor defaults.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CandidateEvidence {
    pub hash_algorithm: HashAlgorithm,
    pub required_chain: u32,
    pub distance_policy: DistancePolicy,
    pub parser: ParserInference,
}

impl CandidateEvidence {
    fn collect(candidate: &dyn HashTableDepthEstimator, wsize: u32) -> Self {
        Self {
            hash_algorithm: candidate.hash_algorithm(),
            required_chain: candidate.max_chain_found() + 1,
            distance_policy: candidate.distance_policy(wsize),
            parser: candidate
                .parser_evidence()
                .infer(candidate.greedy_parser_detected()),
        }
    }
}

pub(crate) struct DepthEstimate {
    pub selected: CandidateEvidence,
    pub zlib_candidates: Vec<CandidateEvidence>,
    pub short_match_rejections: Vec<(HashAlgorithm, u16)>,
}

fn select_depth_candidate<'a>(
    candidates: &'a [Box<dyn HashTableDepthEstimator>],
    add_policy: DictionaryAddPolicy,
    info: &PreflateStreamInfo,
) -> Option<&'a dyn HashTableDepthEstimator> {
    let prefer_miniz_hash = models::miniz::prefer_rotating_hash(
        add_policy,
        info,
        candidates
            .iter()
            .any(|candidate| models::miniz::vetoes_rotating_hash(candidate.hash_algorithm())),
    );
    candidates
        .iter()
        .find(|candidate| {
            models::libdeflate::prefer_fingerprint(candidate.hash_algorithm())
                || info.chromium_short_matches.supports_chromium()
                    && matches!(candidate.hash_algorithm(), HashAlgorithm::Chromium { .. })
                || prefer_miniz_hash && candidate.hash_algorithm() == models::zlib::DEFAULT_HASH
        })
        .or_else(|| {
            // Without a stronger fingerprint, prefer the shallowest surviving chain.
            // Observed depth is a lower bound on search effort, not an exact level identifier.
            candidates
                .iter()
                .min_by(|&a, &b| a.max_chain_found().cmp(&b.max_chain_found()))
        })
        .map(|candidate| candidate.as_ref())
}

pub(super) fn estimate_preflate_depth(
    wbits: u32,
    mem_level: u32,
    info: &PreflateStreamInfo,
    deflate_contents: &DeflateContents,
    plain_text: &PlainText,
    add_policy: DictionaryAddPolicy,
) -> Result<DepthEstimate> {
    let wsize = 1 << wbits;

    let mut candidates: Vec<Box<dyn HashTableDepthEstimator>> = Vec::new();

    for algorithm in models::candidate_hashes(mem_level, info, add_policy) {
        candidates.push(new_depth_estimator(algorithm));
    }
    run_depth_candidates(
        if InsertionConstraint::observe(add_policy, info.max_len) == InsertionConstraint::Unresolved
        {
            DictionaryAddPolicy::AddAll
        } else {
            add_policy
        },
        deflate_contents,
        plain_text,
        &mut candidates,
        info.min_len,
        info.max_dist_3_matches,
        wsize,
    );
    #[cfg(test)]
    if std::env::var_os("PREFLATE_ESTIMATOR_TRACE").is_some() {
        for candidate in &candidates {
            println!(
                "HASH {:?} depth={} greedy={} evidence={:?} short_rejections={}",
                candidate.hash_algorithm(),
                candidate.max_chain_found(),
                candidate.greedy_parser_detected(),
                candidate.parser_evidence(),
                candidate.short_match_rejections(),
            );
        }
    }

    let zlib_candidates: Vec<_> = candidates
        .iter()
        .filter(|candidate| matches!(candidate.hash_algorithm(), HashAlgorithm::Zlib { .. }))
        .filter(|candidate| candidate.max_chain_found() < 4096)
        .map(|candidate| CandidateEvidence::collect(candidate.as_ref(), wsize))
        .collect();
    let Some(initial) = select_depth_candidate(&candidates, add_policy, info) else {
        return err_exit_code(ExitCode::NoCompressionCandidates, "no candidates found");
    };
    let candidate = refine_depth_candidate(&candidates, initial, add_policy, info);

    if candidate.max_chain_found() > 4096 {
        return err_exit_code(
            ExitCode::NoCompressionCandidates,
            "no candidate found with reasonable chain length",
        );
    }

    if candidate.max_chain_found() >= 4096 {
        return err_exit_code(
            ExitCode::NoCompressionCandidates,
            format!("max_chain_found too large: {}", candidate.max_chain_found()),
        );
    }

    Ok(DepthEstimate {
        selected: models::libdeflate::primary_chain_evidence(
            CandidateEvidence::collect(candidate, wsize),
            info,
            add_policy,
        ),
        zlib_candidates,
        short_match_rejections: candidates
            .iter()
            .filter_map(|candidate| {
                let count = candidate.short_match_rejections();
                (count > 0).then(|| (candidate.hash_algorithm(), count))
            })
            .collect(),
    })
}

#[test]
fn fast_hash_refinement_requires_a_real_cutoff_and_consistent_evidence() {
    use super::parser_estimator::ParserEvidence;
    struct Fingerprint(HashAlgorithm, u32, u16);
    impl HashTableDepthEstimator for Fingerprint {
        fn update_hash(
            &mut self,
            _: DictionaryAddPolicy,
            _: &crate::preflate_input::PreflateInput,
            _: u32,
        ) {
        }
        fn match_depth(
            &mut self,
            _: crate::deflate::deflate_token::DeflateTokenReference,
            _: &crate::preflate_input::PreflateInput,
        ) -> bool {
            true
        }
        fn max_chain_found(&self) -> u32 {
            self.1
        }
        fn distance_policy(&self, _: u32) -> DistancePolicy {
            DistancePolicy::ZlibWindow
        }
        fn hash_algorithm(&self) -> HashAlgorithm {
            self.0
        }
        fn parser_evidence(&self) -> ParserEvidence {
            ParserEvidence {
                lazy_matches: self.2,
                longest_lazy_match: 3,
            }
        }
    }
    let zlib = HashAlgorithm::Zlib {
        hash_mask: 32767,
        hash_shift: 5,
    };
    let fallback = HashAlgorithm::RandomVector;
    let mut candidates: Vec<Box<dyn HashTableDepthEstimator>> = vec![
        Box::new(Fingerprint(fallback, 3, 4)),
        Box::new(Fingerprint(zlib, 3, 0)),
    ];
    let mut info = super::preflate_stream_info::extract_preflate_info(&[]);
    for (policy, max_len, expected) in [
        (DictionaryAddPolicy::AddFirst(4), 258, zlib),
        (DictionaryAddPolicy::AddFirst(4), 4, fallback),
        (DictionaryAddPolicy::AddFirst(9), 258, fallback),
        (DictionaryAddPolicy::AddAll, 258, fallback),
    ] {
        info.max_len = max_len;
        assert_eq!(
            refine_depth_candidate(&candidates, candidates[0].as_ref(), policy, &info)
                .hash_algorithm(),
            expected
        );
    }
    info.max_len = 258;
    for (depth, lazy) in [(4, 0), (3, 1)] {
        candidates[1] = Box::new(Fingerprint(zlib, depth, lazy));
        assert_eq!(
            refine_depth_candidate(
                &candidates,
                candidates[0].as_ref(),
                DictionaryAddPolicy::AddFirst(4),
                &info
            )
            .hash_algorithm(),
            fallback
        );
    }
}

#[test]
fn miniz_fingerprint_preference_preserves_guards_and_fallback() {
    use super::preflate_stream_info::extract_preflate_info;

    let zlib = HashAlgorithm::Zlib {
        hash_mask: 32767,
        hash_shift: 5,
    };
    let fallback = HashAlgorithm::RandomVector;
    let mut candidates = vec![new_depth_estimator(fallback), new_depth_estimator(zlib)];
    let mut info = extract_preflate_info(&[]);
    for (add_policy, distance, matches_to_start, expected) in [
        (DictionaryAddPolicy::AddAll, 0, false, fallback),
        (DictionaryAddPolicy::AddAll, 4096, false, fallback),
        (DictionaryAddPolicy::AddAll, 4097, false, zlib),
        (DictionaryAddPolicy::AddAll, 4097, true, fallback),
        (DictionaryAddPolicy::AddFirst(4), 4097, false, fallback),
    ] {
        info.max_dist_3_matches = distance;
        info.matches_to_start_detected = matches_to_start;
        assert_eq!(
            select_depth_candidate(&candidates, add_policy, &info)
                .unwrap()
                .hash_algorithm(),
            expected
        );
    }
    candidates.push(new_depth_estimator(HashAlgorithm::Libdeflate4));
    assert_eq!(
        select_depth_candidate(&candidates, DictionaryAddPolicy::AddAll, &info)
            .unwrap()
            .hash_algorithm(),
        fallback
    );
}

// Candidate ranking should be driven by evidence, not the incidental candidate order.
// Verify minimum-depth fallback across reordered real estimators and explicit fingerprint priority.
#[test]
fn candidate_selection_uses_depth_independently_of_order() {
    use super::preflate_stream_info::extract_preflate_info;
    use crate::{deflate::deflate_token::DeflateTokenReference, preflate_input::PreflateInput};

    let zlib = HashAlgorithm::Zlib {
        hash_mask: 32767,
        hash_shift: 5,
    };
    let plain = PlainText::new_with_data(vec![b'a'; 16]);
    let mut input = PreflateInput::new(&plain);
    let mut candidates = Vec::new();
    for (algorithm, depth) in [
        (zlib, 3),
        (HashAlgorithm::RandomVector, 0),
        (HashAlgorithm::ZlibNG, 2),
        (HashAlgorithm::Crc32cHash, 1),
    ] {
        let mut estimator = new_depth_estimator(algorithm);
        estimator.update_hash(DictionaryAddPolicy::AddAll, &input, 8);
        candidates.push((estimator, depth));
    }
    input.advance(8);
    let mut candidates: Vec<_> = candidates
        .into_iter()
        .map(|(mut estimator, depth)| {
            assert!(estimator.match_depth(DeflateTokenReference::new(4, depth + 1), &input));
            assert_eq!(estimator.max_chain_found(), depth);
            estimator
        })
        .collect();
    let mut info = extract_preflate_info(&[]);
    for _ in 0..2 {
        for _ in 0..candidates.len() {
            assert_eq!(
                select_depth_candidate(&candidates, DictionaryAddPolicy::AddAll, &info)
                    .unwrap()
                    .hash_algorithm(),
                HashAlgorithm::RandomVector
            );
            info.max_dist_3_matches = 4097;
            assert_eq!(
                select_depth_candidate(&candidates, DictionaryAddPolicy::AddAll, &info)
                    .unwrap()
                    .hash_algorithm(),
                zlib
            );
            info.max_dist_3_matches = 0;
            candidates.rotate_left(1);
        }
        candidates.reverse();
    }
}

// Minimum depth alone can hide a valid 15-bit fastest signature behind the legacy hash.
// Verify explicit preference, legacy-only fallback and the empty-candidate outcome.
#[test]
fn fastest_fingerprint_preference_preserves_legacy_and_empty_cases() {
    use super::preflate_stream_info::extract_preflate_info;

    let info = extract_preflate_info(&[]);
    let mut candidates = vec![new_depth_estimator(HashAlgorithm::Libdeflate4Fast)];
    assert_eq!(
        select_depth_candidate(&candidates, DictionaryAddPolicy::AddAll, &info)
            .unwrap()
            .hash_algorithm(),
        HashAlgorithm::Libdeflate4Fast
    );
    candidates.push(new_depth_estimator(HashAlgorithm::Libdeflate4Fast15));
    assert_eq!(
        select_depth_candidate(&candidates, DictionaryAddPolicy::AddAll, &info)
            .unwrap()
            .hash_algorithm(),
        HashAlgorithm::Libdeflate4Fast15
    );
    assert!(select_depth_candidate(&[], DictionaryAddPolicy::AddAll, &info).is_none());
}
