//! Deterministic compressor behavior shared by prediction and reconstruction.
//!
//! Family helpers implement matching, lookahead, and dictionary insertion from
//! typed executable settings. They do not recognize producers or select
//! candidates; those decisions belong to the estimator.

pub mod libdeflate;
pub mod miniz;
pub mod windows;
pub mod zlib;
pub mod zlib_ng;

pub use libdeflate::{LazyMinimum, predict_lazy as predict_libdeflate_lazy};
pub use miniz::{
    cross_4k_boundary, is_zero_chain_link, match_chain as match_miniz_chain, maximum_distance,
    predict_token as predict_miniz_token, probe_limit,
};
pub use windows::{
    TRAILING_LITERALS as WINDOWS_TRAILING_LITERALS, literal_at_buffer_edge,
    predict_lazy as predict_windows_lazy,
};
pub use zlib::{DeferredCutoff, WindowConstraint, predict_lazy as predict_zlib_lazy};

use crate::parameters::DictionaryAddPolicy;

pub enum MatchPrediction {
    Reference,
    Literal {
        pending_reference: Option<crate::deflate::deflate_token::DeflateTokenReference>,
        pending_literals: u8,
    },
}

pub fn block_minimum_match_length(
    parameters: &crate::reconstruction_parameters::BehaviorSettings,
    bytes: &[u8],
) -> u32 {
    use crate::reconstruction_parameters::{BehaviorSettings, ChainParser, LazyMinimum};
    match parameters {
        BehaviorSettings::Chain { common, parser } => match parser {
            ChainParser::LibdeflateGreedy { .. } | ChainParser::LibdeflateLazy { .. } => {
                libdeflate::minimum_match_length(
                    bytes,
                    common.search.budget.max_chain.saturating_sub(1),
                )
            }
            ChainParser::Lazy {
                minimum: LazyMinimum::FilteredSix,
                ..
            } => zlib::FILTERED_MIN_MATCH_LENGTH,
            ChainParser::Greedy { .. }
            | ChainParser::WindowsLazy { .. }
            | ChainParser::Lazy { .. } => crate::deflate::deflate_constants::MIN_MATCH,
        },
        BehaviorSettings::NoDictionary { strategy: _ } | BehaviorSettings::MiniZ { .. } => {
            crate::deflate::deflate_constants::MIN_MATCH
        }
    }
}

impl DictionaryAddPolicy {
    /// Updates the hash based on the dictionary add policy
    #[inline(always)]
    pub fn update_hash<U: FnMut(&[u8], u32, u32)>(
        self,
        input: &[u8],
        pos: u32,
        length: u32,
        mut update_fn: U,
    ) {
        if length == 1 {
            match self {
                DictionaryAddPolicy::AddFirstExcept4kBoundary => {
                    if !miniz::cross_4k_boundary(pos) {
                        update_fn(input, pos, 1);
                    }
                }

                _ => {
                    update_fn(input, pos, 1);
                }
            }
        } else {
            match self {
                DictionaryAddPolicy::AddAll => update_fn(input, pos, length),
                DictionaryAddPolicy::AddFirst(limit) => {
                    if length <= u32::from(limit) {
                        update_fn(input, pos, length);
                    } else {
                        update_fn(input, pos, 1);
                    }
                }
                DictionaryAddPolicy::AddFirstAndLast(limit) => {
                    if length <= u32::from(limit) {
                        update_fn(input, pos, length);
                    } else {
                        update_fn(input, pos, 1);
                        update_fn(&input[length as usize - 1..], pos + length - 1, 1);
                    }
                }
                DictionaryAddPolicy::AddFirstExcept4kBoundary => {
                    if !miniz::cross_4k_boundary(pos) {
                        update_fn(input, pos, 1);
                    }
                }
                DictionaryAddPolicy::AddFirstWith32KBoundary => {
                    update_fn(input, pos, 1);
                    if zlib_ng::is_at_32k_boundary(length, pos) {
                        update_fn(&input[length as usize - 1..], pos + length - 1, 1);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_insertion_skips_only_the_final_three_positions_of_each_4k_region() {
        let bytes = [b'a'; 8];
        for base in [0, 4096, 32768] {
            let mut inserted = Vec::new();
            for offset in 4092..=4096 {
                DictionaryAddPolicy::AddFirstExcept4kBoundary.update_hash(
                    &bytes,
                    base + offset,
                    1,
                    |_, position, length| inserted.push((position, length)),
                );
            }
            assert_eq!(inserted, [(base + 4092, 1), (base + 4096, 1)]);
        }
    }

    #[test]
    fn boundary_insertion_adds_the_last_match_byte_only_when_crossing_the_slide_point() {
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
}
