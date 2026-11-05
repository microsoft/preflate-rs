//! Zlib-compatible lazy matching and bounds for exact prediction replay.
//!
//! Lazy searches may defer a reference by one literal and retain the next
//! reference, with search depth reduced after a sufficiently long match.
//! Window and deferred-cutoff observations track only changes that preserve
//! those decisions; reconstruction uses the finalized settings and the same
//! matching rules without repeating estimation.

use super::MatchPrediction;
use crate::{
    deflate::{deflate_constants::MIN_LOOKAHEAD, deflate_token::DeflateTokenReference},
    hash_algorithm::HashAlgorithm,
    hash_chain_holder::{HashChainHolder, MatchResult, SearchPurpose},
    parameters::LazyBehavior,
    preflate_input::PreflateInput,
    reconstruction_parameters::{
        ChainDistancePolicy, DictionaryIndex, DictionarySettings, HashFunction,
        LazyLookaheadSettings, SearchBudget, WindowBounds,
    },
};

#[derive(Default)]
pub struct WindowConstraint {
    ceiling: std::cell::Cell<Option<u32>>,
}

impl WindowConstraint {
    pub fn is_enabled(&self) -> bool {
        self.ceiling.get().is_some()
    }

    pub fn enable(
        &mut self,
        dictionary: &DictionarySettings,
        distance: ChainDistancePolicy,
        eligible_parser: bool,
    ) {
        if matches!(
            dictionary.index,
            DictionaryIndex::Chain {
                hash: HashFunction::Zlib { .. }
            }
        ) && eligible_parser
            && matches!(
                distance,
                ChainDistancePolicy::Window {
                    history: _,
                    bounds: WindowBounds::Lookahead
                }
            )
            && (9..15).contains(&dictionary.window_bits)
        {
            self.ceiling.set(Some(32768));
        }
    }

    pub fn exclude(&self, distance: u32, first_hop: bool) {
        if let Some(ceiling) = self.ceiling.get() {
            // Hop zero admits window - MIN_LOOKAHEAD + 1; later hops admit one less.
            let maximum = distance.saturating_add(MIN_LOOKAHEAD - if first_hop { 2 } else { 1 });
            self.ceiling.set(Some(ceiling.min(maximum)));
        }
    }

    pub fn window_bits(&self, original: u32) -> Option<u32> {
        self.ceiling.get().map(|ceiling| {
            debug_assert!(ceiling >= 1 << original);
            if ceiling >= 32768 { 15 } else { original }
        })
    }
}

#[derive(Clone, Copy)]
pub struct DeferredCutoff {
    distance: u32,
    position: u32,
    end: u32,
}

impl DeferredCutoff {
    pub fn new(input: &PreflateInput, distance: u32) -> Option<Self> {
        // Stay before hash-table reshift and exclude prefixed/continuation history.
        (input.pos() < 32768 && input.bytes_before() == input.pos() && input.remaining() >= 5)
            .then_some(Self {
                distance,
                position: input.pos(),
                end: input.total_length(),
            })
    }

    pub fn upper_bound(self) -> u32 {
        self.distance - 1
    }

    pub fn resolved_by(self, input: &PreflateInput, found: MatchResult) -> bool {
        // Default chains virtually insert the current literal in OFFSET=1 searches.
        // With identical budgets and nice_length > 3, a fresh result longer than
        // three is also the previous position's lazy result. Its cached and fresh
        // paths therefore converge before making this position's prediction.
        input.pos() == self.position + 1
            && input.total_length() == self.end
            && matches!(found, MatchResult::Success(reference) if reference.len() > 3)
    }
}

#[inline(always)]
pub fn predict_lazy(
    input: &PreflateInput,
    state: &dyn HashChainHolder,
    current: DeflateTokenReference,
    lookahead: LazyLookaheadSettings,
    budget: SearchBudget,
) -> MatchPrediction {
    if current.len() < u32::from(lookahead.max_lazy) && input.remaining() >= current.len() + 2 {
        let mut max_depth = budget.max_chain;
        if let LazyBehavior::Zlib { good_length } = lookahead.behavior
            && current.len() >= u32::from(good_length)
        {
            max_depth >>= 2;
        }
        if let MatchResult::Success(next) =
            state.match_token_1(current.len(), max_depth, input, SearchPurpose::Prediction)
            && next.len() > current.len()
        {
            return MatchPrediction::Literal {
                pending_reference: match lookahead.behavior {
                    LazyBehavior::Zlib { .. } => Some(next),
                    LazyBehavior::RecomputeAfterLiteral => None,
                },
                pending_literals: 0,
            };
        }
    }
    MatchPrediction::Reference
}

pub const FILTERED_MIN_MATCH_LENGTH: u32 = 6;

pub const SHORT_MATCH_CUTOFF: u32 = 4096;

pub const DEFAULT_HASH: HashAlgorithm = HashAlgorithm::Zlib {
    hash_mask: 32767,
    hash_shift: 5,
};

pub fn memory_hash(mem_level: u32) -> HashAlgorithm {
    let bits = mem_level + 7;
    HashAlgorithm::Zlib {
        hash_mask: ((1u32 << bits) - 1) as u16,
        hash_shift: bits.div_ceil(3),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        parameters::{DictionaryAddPolicy, tests::MatchingType},
        preflate_input::PlainText,
        reconstruction_parameters::ReconstructionParameters,
    };

    fn supports_deferred_cutoff(parameters: &ReconstructionParameters) -> bool {
        parameters.behavior.supports_deferred_cutoff()
    }

    #[test]
    fn deferred_cutoff_proofs_reject_unsupported_search_policies() {
        let parameters = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_matching_type(MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: false,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            });
            canonical_configuration
        };
        assert!(supports_deferred_cutoff(&parameters));
        for parameters in [
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_nice_length(3);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration
                    .set_insertion(DictionaryAddPolicy::AddFirstExcept4kBoundary);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_matching_type(MatchingType::Greedy);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_matching_type(MatchingType::Lazy {
                    max_lazy: 16,
                    filtered_matching: false,
                    behavior: LazyBehavior::Zlib { good_length: 3 },
                });
                canonical_configuration
            },
        ] {
            assert!(!supports_deferred_cutoff(&parameters));
        }
        let plain = PlainText::new_with_data(vec![b'a'; 32780]);
        let mut input = PreflateInput::new(&plain);
        input.advance(32767);
        let proof = DeferredCutoff::new(&input, 4).unwrap();
        assert!(!proof.resolved_by(
            &input,
            MatchResult::Success(DeflateTokenReference::new(4, 1))
        ));
        input.advance(1);
        assert!(DeferredCutoff::new(&input, 4).is_none());
        assert!(proof.resolved_by(
            &input,
            MatchResult::Success(DeflateTokenReference::new(4, 1))
        ));
        assert!(!proof.resolved_by(
            &input,
            MatchResult::Success(DeflateTokenReference::new(3, 1))
        ));
        assert!(!proof.resolved_by(&input, MatchResult::NoMoreMatchesFound));
    }
}
