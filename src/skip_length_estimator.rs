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
use default_boxed::DefaultBoxed;

use crate::preflate_token::{PreflateToken, PreflateTokenBlock};

#[derive(DefaultBoxed)]
pub struct SkipLengthEstimator {
    pub current_window: [u8; 32768],
    pub current_offset: u32,
    pub max_distance: u32,
}

pub fn estimate_skip_length(token_blocks: &[PreflateTokenBlock]) -> u32 {
    let mut current_window = vec![0u8; 32768];
    let mut max_distance: u32 = 0;
    let mut current_offset: u32 = 0;

    for token_block in token_blocks {
        for token in token_block.tokens.iter() {
            match token {
                PreflateToken::Literal => {
                    current_window[(current_offset & 0x7fff) as usize] = 0;
                    current_offset += 1;
                }
                PreflateToken::Reference(r) => {
                    let match_length =
                        u32::from(current_window[((current_offset - r.dist()) & 0x7fff) as usize]);

                    max_distance = std::cmp::max(max_distance, match_length);

                    let l = std::cmp::min(r.len(), 255);
                    current_window[(current_offset & 0x7fff) as usize] = 0;
                    current_offset += 1;

                    for _i in 1..r.len() {
                        current_window[(current_offset & 0x7fff) as usize] = l as u8;
                        current_offset += 1;
                    }
                }
            }
        }
    }
    max_distance
}
