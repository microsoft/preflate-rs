//! MiniZ dictionary probing and greedy/lazy token decisions.
//!
//! Searches inspect suffixes in three-probe groups before verifying full
//! matches, and long current matches reduce the probe budget. Lazy prediction
//! applies MiniZ's distance and short-reference rules rather than zlib's.
//! Fast insertion also skips the final three positions of each 4 KiB region.

use super::MatchPrediction;
use crate::{
    deflate::deflate_token::DeflateTokenReference,
    hash_chain_holder::{HashChainHolder, MatchResult, SearchPurpose, prefix_compare, read_u16_le},
    preflate_input::PreflateInput,
};

#[inline(always)]
pub fn cross_4k_boundary(pos: u32) -> bool {
    (pos & 4095) >= 4093
}

#[inline(always)]
pub fn maximum_distance(window: u32, history: u32, available: u32) -> u32 {
    history.min(window.saturating_sub(available))
}

#[inline(always)]
pub fn is_zero_chain_link(position: u32, distance: u32) -> bool {
    // Normal miniz chains reserve zero in their wrapping 16-bit position links.
    position.wrapping_sub(distance) & 65535 == 0
}

#[inline(always)]
pub fn probe_limit(
    depth: u32,
    search: crate::reconstruction_parameters::MiniZSearchSettings,
    normal_prediction: bool,
) -> u32 {
    if normal_prediction {
        u32::from(search.max_probes)
    } else {
        depth
    }
}

#[inline(always)]
pub fn predict_token(
    input: &PreflateInput,
    state: &dyn HashChainHolder,
    current: DeflateTokenReference,
    greedy: bool,
    budget: crate::reconstruction_parameters::SearchBudget,
) -> MatchPrediction {
    if current.dist() == input.pos() & 32767 {
        return MatchPrediction::Literal {
            pending_reference: None,
            pending_literals: 0,
        };
    }
    if !greedy
        && current.len() < 128
        && input.remaining() > current.len()
        && let MatchResult::Success(next) = state.match_token_1(
            current.len(),
            budget.max_chain,
            input,
            SearchPurpose::Prediction,
        )
        && next.len() > current.len()
        && !(next.len() == 3 && next.dist() >= 8192)
        && next.dist() != (input.pos() + 1) & 32767
    {
        return MatchPrediction::Literal {
            pending_reference: Some(next),
            pending_literals: 0,
        };
    }
    MatchPrediction::Reference
}

#[inline]
pub fn match_chain<const OFFSET: u32>(
    input: &PreflateInput<'_>,
    max_len: u32,
    max_dist: u32,
    max_probes: u32,
    mut best_len: u32,
    mut iter: impl Iterator<Item = u32>,
) -> MatchResult {
    let bytes = input.cur_chars(OFFSET as i32);
    let probes = if best_len < 32 {
        max_probes
    } else {
        max_probes >> 2
    };
    // The first suffix hit consumes its three-probe group even when the prefix fails.
    let mut groups = probes.div_ceil(3);
    let mut best = MatchResult::NoMoreMatchesFound;
    while groups > 0 {
        groups -= 1;
        let suffix = read_u16_le(bytes, (best_len - 1) as usize);
        let mut candidate = None;
        for _ in 0..3 {
            let Some(dist) = iter.next() else { return best };
            if dist > max_dist {
                return best;
            }
            let source = input.cur_chars(OFFSET as i32 - dist as i32);
            if read_u16_le(source, (best_len - 1) as usize) == suffix {
                candidate = Some((dist, source));
                break;
            }
        }
        if let Some((dist, source)) = candidate {
            if read_u16_le(source, 0) != read_u16_le(bytes, 0) {
                continue;
            }
            let length = prefix_compare(source, bytes, max_len);
            if length > best_len {
                best_len = length;
                best = MatchResult::Success(DeflateTokenReference::new(length, dist));
                if length == max_len {
                    return best;
                }
            }
        }
    }
    best
}
