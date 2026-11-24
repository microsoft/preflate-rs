//! Windows DEFLATE lazy matching and token-buffer edge behavior.
//!
//! Lazy searches reuse zlib-style lookahead with the Windows good-length
//! threshold. The final token slot can instead require a literal when no
//! deferred reference is waiting, preserving the original block boundary.

use crate::{
    hash_algorithm::HashAlgorithm, hash_chain_holder::HashChainHolder, parameters::LazyBehavior,
    preflate_input::PreflateInput,
};

// Windows DEFLATE uses fixed table-XOR hashing rather than zlib's rotating hash.
pub const HASH: HashAlgorithm = HashAlgorithm::RandomVector;

pub const TRAILING_LITERALS: u32 = 2;

#[inline(always)]
pub fn literal_at_buffer_edge(
    token_count: u32,
    capacity: u32,
    has_pending_reference: bool,
) -> bool {
    token_count + 1 == capacity && !has_pending_reference
}

pub fn predict_lazy(
    input: &PreflateInput,
    state: &dyn HashChainHolder,
    current: crate::deflate::deflate_token::DeflateTokenReference,
    max_lazy: u16,
    budget: crate::reconstruction_parameters::SearchBudget,
) -> super::MatchPrediction {
    // Keep the deferred reference as a token-buffer marker; prediction searches again.
    super::zlib::predict_lazy(
        input,
        state,
        current,
        crate::reconstruction_parameters::LazyLookaheadSettings {
            max_lazy,
            behavior: LazyBehavior::Zlib { good_length: 258 },
        },
        budget,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_edge_literal_requires_an_unused_deferred_match_slot() {
        for (count, capacity, pending, expected) in [
            (0, 128, false, false),
            (126, 128, false, false),
            (127, 128, false, true),
            (127, 128, true, false),
            (128, 128, false, false),
            (0, 1, false, true),
        ] {
            assert_eq!(
                literal_at_buffer_edge(count, capacity, pending),
                expected,
                "count={count}, capacity={capacity}, pending={pending}"
            );
        }
    }
}
