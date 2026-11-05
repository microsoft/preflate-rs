//! Defines block selection, dictionary insertion, and lazy-search policies used
//! by reconstruction settings and compressor-model estimation.

use bitcode::{Decode, Encode};

#[derive(Encode, Decode, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum BlockTypeStrategy {
    Dynamic,
    Mixed,
    Static,
    Uncompressed,
}

#[derive(Encode, Decode, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum PreflateStrategy {
    Default,
    RleOnly,
    HuffOnly,
    Store,
}

#[derive(
    Encode, Decode, Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub enum LazyBehavior {
    /// Quarter the lookahead budget after a good match and reuse a deferred reference.
    Zlib { good_length: u16 },
    /// Use the full lookahead budget and search again after emitting the literal.
    RecomputeAfterLiteral,
}

pub struct PreflateParserConfig {
    pub parser: crate::reconstruction_parameters::ChainParser,

    pub dictionary_add_policy: DictionaryAddPolicy,

    /// if we get this length of a match we immediately stop searching for more
    pub nice_length: u32,
    pub max_chain: u32,
}

#[derive(
    Encode, Decode, Default, Eq, PartialEq, Debug, Clone, Copy, serde::Serialize, serde::Deserialize,
)]
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[derive(
        Encode,
        Decode,
        Debug,
        Copy,
        Clone,
        PartialEq,
        Eq,
        Default,
        serde::Serialize,
        serde::Deserialize,
    )]
    #[serde(deny_unknown_fields)]
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
}
