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

pub fn estimate_add_policy(token_blocks: &[PreflateTokenBlock]) -> DictionaryAddPolicy {
    const WINDOW_MASK: usize = 0x7fff;

    // used to see if we have the special case of not adding matches on the edge
    // of the 4k boundary. This is used by miniz.
    let mut block_4k = true;

    let mut current_window = vec![0u16; WINDOW_MASK + 1];

    // tracks the maximum length that we've see that was added to the dictionary
    let mut max_distance: u32 = 0;

    // tracks the maximum length that we've seen that was added to the dictionary if the last match was also added
    let mut max_distance_last_add = 0;
    let mut current_offset: u32 = 0;

    const LAST_ADDED: u16 = 0x8000;

    for i in 0..token_blocks.len() {
        let token_block = &token_blocks[i];
        for token in token_block.tokens.iter() {
            match token {
                PreflateToken::Literal => {
                    current_window[current_offset as usize & WINDOW_MASK] = 0;
                    current_offset += 1;
                }
                PreflateToken::Reference(r) => {
                    // track if we saw something  on the of the 4k boundary
                    if (current_offset & 4095) >= 4093 {
                        block_4k = false;
                    }

                    let previous_match =
                        current_window[(current_offset - r.dist()) as usize & WINDOW_MASK];

                    let match_length = u32::from(previous_match & !LAST_ADDED);

                    max_distance = std::cmp::max(max_distance, match_length);
                    if (previous_match & LAST_ADDED) == 0 {
                        max_distance_last_add = std::cmp::max(max_distance_last_add, match_length);
                    }

                    current_window[current_offset as usize & WINDOW_MASK] = 0;
                    current_offset += 1;

                    for i in 1..r.len() {
                        current_window[current_offset as usize & WINDOW_MASK] =
                            r.len() as u16 | if i == r.len() - 1 { LAST_ADDED } else { 0 };
                        current_offset += 1;
                    }
                }
            }
        }
    }

    if max_distance == 0 && block_4k {
        DictionaryAddPolicy::AddFirstExcept4kBoundary
    } else if max_distance_last_add < max_distance {
        DictionaryAddPolicy::AddFirstAndLast(max_distance_last_add as u16)
    } else if max_distance < 258 {
        DictionaryAddPolicy::AddFirst(max_distance as u16)
    } else {
        DictionaryAddPolicy::AddAll
    }
}

#[test]
fn verify_miniz1_recognition() {
    let f = crate::process::read_file("sample1.bin");
    let v = miniz_oxide::deflate::compress_to_vec(&f, 1);

    let contents = crate::process::parse_deflate(&v, 1).unwrap();

    let add_policy = estimate_add_policy(&contents.blocks);

    assert_eq!(add_policy, DictionaryAddPolicy::AddFirstExcept4kBoundary);
}

#[test]
fn verify_zlib_level_recognition() {
    let levels = [
        DictionaryAddPolicy::AddFirst(4),
        DictionaryAddPolicy::AddFirst(5),
        DictionaryAddPolicy::AddFirst(6),
        DictionaryAddPolicy::AddAll,
    ];

    for i in 1..=4 {
        let v = crate::process::read_file(&format!("compressed_zlib_level{}.deflate", i));

        let contents = crate::process::parse_deflate(&v, 1).unwrap();
        let add_policy = estimate_add_policy(&contents.blocks);

        assert_eq!(add_policy, levels[i - 1]);
    }
}

#[test]
fn verify_zlibng_level_recognition() {
    let levels = [
        DictionaryAddPolicy::AddFirstAndLast(0),   // 1 quick
        DictionaryAddPolicy::AddFirstAndLast(4),   // 2 fast
        DictionaryAddPolicy::AddFirstAndLast(96),  // 3 medium
        DictionaryAddPolicy::AddFirstAndLast(191), // 4 medium
    ];

    for i in 1..=4 {
        let v = crate::process::read_file(&format!("compressed_zlibng_level{}.deflate", i));

        let contents = crate::process::parse_deflate(&v, 1).unwrap();
        let add_policy = estimate_add_policy(&contents.blocks);

        assert_eq!(add_policy, levels[i - 1]);
    }
}
