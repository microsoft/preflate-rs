/// Different versions of Zlib use some length criterea to decide whether to add all the substrings of
/// a large match to the hash table. For example, zlib level 1 will only add all the substrings of matches
/// of length 4 in order to save on CPU.
///
/// What we do here is walk through all the matches and record how long the matching
/// substrings are. The we see what the largest string was that we fully added to the
/// dictionary.
///
/// This will be the limit that we use when we decide whether to
/// use skip_hash or update_hash.
use crate::{
    hash_chain::DictionaryAddPolicy,
    preflate_token::{PreflateToken, PreflateTokenBlock},
};

pub fn estimate_skip_length(token_blocks: &[PreflateTokenBlock]) -> DictionaryAddPolicy {
    let mut current_window = vec![0u16; 32768];
    let mut max_distance: u32 = 0;
    let mut max_distance_last_add = 0;
    let mut current_offset: u32 = 0;
    let mut counters = [0u32; 259];
    let mut counters_b = [0u32; 259];

    for i in 0..token_blocks.len() {
        let token_block = &token_blocks[i];
        for token in token_block.tokens.iter() {
            match token {
                PreflateToken::Literal => {
                    current_window[(current_offset & 0x7fff) as usize] = 0;
                    current_offset += 1;
                }
                PreflateToken::Reference(r) => {
                    let match_length =
                        u32::from(current_window[((current_offset - r.dist()) & 0x7fff) as usize]);

                    counters[(match_length & 0x7fff) as usize] += 1;

                    max_distance = std::cmp::max(max_distance, match_length & 0x7fff);
                    if (match_length & 0x8000) == 0 {
                        counters_b[(match_length & 0x7fff) as usize] += 1;

                        max_distance_last_add =
                            std::cmp::max(max_distance_last_add, match_length & 0x7fff);
                    }

                    current_window[(current_offset & 0x7fff) as usize] = 0;
                    current_offset += 1;

                    for i in 1..r.len() {
                        current_window[(current_offset & 0x7fff) as usize] =
                            r.len() as u16 | if i == r.len() - 1 { 0x8000 } else { 0 };
                        current_offset += 1;
                    }
                }
            }
        }
    }

    if max_distance_last_add < max_distance {
        DictionaryAddPolicy::AddFirstAndLast(max_distance_last_add as u16)
    } else if max_distance < 258 {
        DictionaryAddPolicy::AddFirst(max_distance as u16)
    } else {
        DictionaryAddPolicy::AddAll
    }
}
