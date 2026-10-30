/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use bitcode::{Decode, Encode};

use crate::estimator::add_policy_estimator::DictionaryAddPolicy;

// Retain the existing table paths for diagnostics, even when only tests consume them.
#[allow(unused_imports)]
pub use crate::models::zlib::{SLOW_PREFLATE_PARSER_SETTINGS, ZLIB_PREFLATE_PARSER_SETTINGS};

#[derive(Encode, Decode, Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum MatchingType {
    /// Immediate-match baseline: zlib's fast levels, miniz's special fastest mode,
    /// and libdeflate's primary-only level-1 profiles.
    #[default]
    Greedy,
    /// Zlib-style one-position lookahead, used as the default for full-insertion streams
    /// until a compressor-specific fingerprint justifies a different matching policy.
    Lazy {
        max_lazy: u16,
        filtered_matching: bool,
        behavior: LazyBehavior,
    },
    /// Miniz/miniz_oxide's normal chain parser: grouped suffix probes, optionally lazy.
    /// Separate from MiniZFast hashing; this parser shares zlib's usual rotating hash.
    MiniZ { max_probes: u16, greedy: bool },
    /// Libdeflate's modeled levels 5-9: distance-aware lazy matching on Libdeflate4.
    /// Two positions selects the lazy2 parser rather than changing the dictionary hash.
    LibdeflateLazy { two_positions: bool },
    /// Libdeflate's modeled levels 2-4, also using Libdeflate4:
    /// greedy matching with a block-local, alphabet-dependent minimum length.
    LibdeflateGreedy,
}

#[derive(Encode, Decode, Debug, Copy, Clone, PartialEq, Eq)]
pub enum LazyBehavior {
    /// Quarter the lookahead budget after a good match and reuse a deferred reference.
    Zlib { good_length: u16 },
    /// Use the full lookahead budget and search again after emitting the literal.
    RecomputeAfterLiteral,
}

pub struct PreflateParserConfig {
    pub match_type: MatchingType,

    // used for testing
    #[allow(dead_code)]
    pub dictionary_add_policy: DictionaryAddPolicy,

    /// if we get this length of a match we immediately stop searching for more
    pub nice_length: u32,
    pub max_chain: u32,
}
