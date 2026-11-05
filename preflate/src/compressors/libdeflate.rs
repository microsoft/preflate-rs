//! Libdeflate adaptive match minima and greedy/lazy reference decisions.
//!
//! The chained lazy parser compares references at one or two future positions,
//! accounting for length and distance cost. Its minimum match length changes
//! with the block's byte distribution and observed literal frequencies.

use super::MatchPrediction;
use crate::{
    deflate::{deflate_constants::MIN_MATCH, deflate_token::DeflateTokenReference},
    hash_algorithm::HashAlgorithm,
    hash_chain_holder::{HashChainHolder, MatchResult, SearchPurpose},
    preflate_input::PreflateInput,
};

pub fn minimum_match_length(bytes: &[u8], depth: u32) -> u32 {
    if bytes.len() < 512 {
        return MIN_MATCH;
    }
    let mut seen = [false; 256];
    let mut distinct = 0;
    for &byte in bytes.iter().take(4096) {
        if !seen[usize::from(byte)] {
            seen[usize::from(byte)] = true;
            distinct += 1;
            if distinct >= 80 {
                return MIN_MATCH;
            }
        }
    }
    minimum_for_alphabet(distinct, depth)
}

fn minimum_for_alphabet(distinct: u32, depth: u32) -> u32 {
    let length = match distinct {
        0..=5 => 9,
        6..=7 => 8,
        8..=9 => 7,
        10..=15 => 6,
        16..=44 => 5,
        45..=79 => 4,
        _ => 3,
    };
    let cap = match depth {
        0..=4 => 4,
        5..=9 => 5,
        10..=15 => 7,
        _ => 9,
    };
    length.min(cap)
}

pub struct LazyMinimum {
    block_start: u32,
    next_recalculation: u32,
}

impl LazyMinimum {
    pub fn new(position: u32, remaining: u32) -> Self {
        Self {
            block_start: position,
            next_recalculation: position + remaining.min(10000),
        }
    }

    pub fn update(
        &mut self,
        position: u32,
        end: u32,
        literal_frequencies: &[u16],
        depth: u32,
    ) -> Option<u32> {
        if position < self.next_recalculation || position == end {
            return None;
        }
        let total: u32 = literal_frequencies
            .iter()
            .map(|&count| u32::from(count))
            .sum();
        let cutoff = total >> 10;
        let distinct = literal_frequencies
            .iter()
            .filter(|&&count| u32::from(count) > cutoff)
            .count() as u32;
        self.next_recalculation += (end - self.next_recalculation).min(position - self.block_start);
        Some(minimum_for_alphabet(distinct, depth))
    }
}

#[inline(always)]
fn prefer_match(
    current: DeflateTokenReference,
    next: DeflateTokenReference,
    literal_cost: i32,
) -> bool {
    next.len() >= current.len()
        && 4 * (next.len() as i32 - current.len() as i32) + current.dist().ilog2() as i32
            - next.dist().ilog2() as i32
            > literal_cost
}

#[inline(always)]
pub fn predict_lazy(
    input: &PreflateInput,
    state: &dyn HashChainHolder,
    current: DeflateTokenReference,
    search: crate::reconstruction_parameters::ChainSettings,
    two_positions: bool,
) -> MatchPrediction {
    if current.len() < search.nice_length && input.remaining() > current.len() {
        let depth = search.budget.max_chain.saturating_sub(1);
        if let MatchResult::Success(next) = state.match_token_1(
            current.len() - 1,
            (depth >> 1).max(1),
            input,
            SearchPurpose::Prediction,
        ) && prefer_match(current, next, 2)
        {
            return MatchPrediction::Literal {
                pending_reference: Some(next),
                pending_literals: 0,
            };
        }
        if two_positions
            && input.remaining() > current.len() + 1
            && let MatchResult::Success(next) = state.match_token_2(
                current.len() - 1,
                (depth >> 2).max(1),
                input,
                SearchPurpose::Prediction,
            )
            && prefer_match(current, next, 6)
        {
            return MatchPrediction::Literal {
                pending_reference: Some(next),
                pending_literals: 1,
            };
        }
    }
    MatchPrediction::Reference
}

pub const CHAIN_HASH: HashAlgorithm = HashAlgorithm::Libdeflate4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_match_length_is_bounded_and_depth_aware() {
        for (distinct, expected) in [
            (1, 9),
            (5, 9),
            (6, 8),
            (7, 8),
            (8, 7),
            (9, 7),
            (10, 6),
            (15, 6),
            (16, 5),
            (44, 5),
            (45, 4),
            (79, 4),
            (80, 3),
            (256, 3),
        ] {
            let bytes: Vec<_> = (0..4096).map(|i| (i % distinct) as u8).collect();
            assert_eq!(minimum_match_length(&bytes, 16), expected);
            assert_eq!(minimum_match_length(&bytes, 12), expected.min(7));
            assert_eq!(minimum_match_length(&bytes, 6), expected.min(5));
            assert_eq!(minimum_match_length(&bytes, 4), expected.min(4));
            assert_eq!(minimum_match_length(&bytes[..511], 16), 3);
        }
        let mut bytes = vec![b'a'; 4096];
        bytes.extend(0..=255);
        assert_eq!(minimum_match_length(&bytes, 16), 9);
    }

    #[test]
    fn minimum_is_monotonic_and_alphabet_invariant() {
        for length in [511, 512, 4095, 4096, 4352] {
            let mut previous_alphabet = [9; 8];
            for alphabet in 1..=256 {
                let bytes: Vec<_> = (0..length).map(|i| (i % alphabet) as u8).collect();
                let relabeled: Vec<_> = bytes
                    .iter()
                    .map(|byte| byte.wrapping_mul(129) ^ 0xa5)
                    .collect();
                let mut previous_depth = 3;
                for (index, depth) in [0, 4, 5, 9, 10, 15, 16, 600].into_iter().enumerate() {
                    let minimum = minimum_match_length(&bytes, depth);
                    assert!((3..=9).contains(&minimum));
                    assert_eq!(minimum, minimum_match_length(&relabeled, depth));
                    assert!(minimum >= previous_depth);
                    assert!(minimum <= previous_alphabet[index]);
                    previous_depth = minimum;
                    previous_alphabet[index] = minimum;
                }
            }
        }
    }

    #[test]
    fn lazy_minimum_uses_literal_frequencies_and_progressive_positions() {
        let mut frequencies = [0; 256];
        frequencies[..80].fill(2);
        let mut minimum = LazyMinimum::new(700, 50000);
        assert_eq!(minimum.update(10699, 50700, &frequencies, 100), None);
        assert_eq!(minimum.update(10700, 50700, &frequencies, 100), Some(3));
        assert_eq!(minimum.next_recalculation, 20700);

        frequencies.fill(1);
        frequencies[0] = 1024;
        assert_eq!(minimum.update(20703, 50700, &frequencies, 100), Some(9));
        assert_eq!(minimum.next_recalculation, 40703);
        assert_eq!(minimum.update(40704, 50700, &frequencies, 4), Some(4));
        assert_eq!(minimum.next_recalculation, 50700);
        assert_eq!(minimum.update(50700, 50700, &frequencies, 100), None);
        assert_eq!(LazyMinimum::new(700, 511).next_recalculation, 1211);
    }

    #[test]
    fn lazy_prefers_a_nearer_equal_length_match() {
        let current = DeflateTokenReference::new(3, 136);
        assert!(prefer_match(current, DeflateTokenReference::new(3, 5), 2));
        assert!(!prefer_match(current, DeflateTokenReference::new(3, 32), 2));
        assert!(!prefer_match(current, DeflateTokenReference::new(3, 5), 6));
        assert!(!prefer_match(
            DeflateTokenReference::new(4, 136),
            DeflateTokenReference::new(3, 1),
            2,
        ));
    }
}
