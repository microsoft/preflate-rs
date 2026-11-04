//! Shared runtime compressor settings; estimation policy lives in `estimator`.

use crate::hash_algorithm::HashAlgorithm;
use bitcode::{Decode, Encode};

#[derive(Encode, Decode, Debug, Copy, Clone, Eq, PartialEq)]
pub struct TokenPredictorParameters {
    /// Zlib does not match to first byte of a file in order to reserve 0 for the end of chain
    pub matches_to_start_detected: bool,

    /// Permit full-window matches rather than reserving zlib's lookahead space.
    /// This can follow a compressor fingerprint as well as observed distances.
    pub very_far_matches_detected: bool,
    pub window_bits: u32,

    pub strategy: PreflateStrategy,
    pub nice_length: u32,

    /// if something, then we use the "fast" compressor, which only adds smaller substrings
    /// to the dictionary
    pub add_policy: DictionaryAddPolicy,

    pub max_token_count: u16,

    pub max_dist_3_matches: u32,
    pub matching_type: MatchingType,
    pub max_chain: u32,
    pub hash_algorithm: HashAlgorithm,

    pub block_type_strategy: BlockTypeStrategy,
}

impl TokenPredictorParameters {
    pub(crate) fn canonical_short_match_cutoff(&self, bounds: (u32, u32)) -> u32 {
        let original = self.max_dist_3_matches;
        debug_assert!(bounds.0 <= original && original <= bounds.1);
        // Bitcode packs this singleton u32 in one or two value bytes for DEFLATE distances.
        // Crossing 255 would grow the parameter record; no trial encoding is needed.
        let maximum = if original <= u32::from(u8::MAX) {
            u32::from(u8::MAX)
        } else {
            32768
        };
        let lower = bounds.0;
        let upper = bounds.1.min(maximum);
        if lower == 0 {
            return 0;
        }
        if lower > upper {
            return original;
        }
        // The highest differing bit identifies the coarsest grid crossing in the interval.
        let alignment = ((lower - 1) ^ upper).ilog2();
        upper & (u32::MAX << alignment)
    }
}

#[derive(Encode, Decode, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum BlockTypeStrategy {
    Dynamic,
    Mixed,
    Static,
    Uncompressed,
}

#[derive(Encode, Decode, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum PreflateStrategy {
    Default,
    RleOnly,
    HuffOnly,
    Store,
}

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
    /// Windows table-hash lazy matching, including its token-buffer and input-tail rules.
    WindowsLazy { max_lazy: u16 },
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

    pub dictionary_add_policy: DictionaryAddPolicy,

    /// if we get this length of a match we immediately stop searching for more
    pub nice_length: u32,
    pub max_chain: u32,
}

#[derive(Encode, Decode, Default, Eq, PartialEq, Debug, Clone, Copy)]
pub enum DictionaryAddPolicy {
    /// Add all substrings of a match to the dictionary
    #[default]
    AddAll,
    /// Add only the first substring of a match to the dictionary that are larger than the limit
    AddFirst(u16),
    /// Add only the first and last substring of a match to the dictionary that are larger than the limit
    AddFirstAndLast(u16),

    /// This policy is used by MiniZ in fastest mode. It adds all substrings of a match to the dictionary except
    /// literals that are 4 bytes away from the end of the block.
    ///
    /// In addition, we don't attempt to look for matches if we are within 3 bytes of the 4k boundary.
    AddFirstExcept4kBoundary,

    /// This policy is used by fast mode in zlibng, it is the same
    /// as AddFirst(0) but it also add the last character for the
    /// last match in the 32k window.
    ///
    /// This is due to the fact that
    /// each time the dictionary is reset, it explicitly adds the
    /// last character to the dictionary which ends up being the
    /// last chacacter of the previous match.
    AddFirstWith32KBoundary,
}
