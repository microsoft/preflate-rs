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
    preflate_token::{BlockType, PreflateToken, PreflateTokenBlock},
};

pub fn estimate_add_policy(token_blocks: &[PreflateTokenBlock]) -> DictionaryAddPolicy {
    const WINDOW_MASK: usize = 0x7fff;

    // used to see if we have the special case of not adding matches on the edge
    // of the 4k boundary. This is used by miniz.
    let mut block_4k = true;

    let mut current_window = vec![0u16; WINDOW_MASK + 1];

    // tracks the maximum length that we've see that was added to the dictionary
    let mut max_length: u32 = 0;

    // tracks the maximum length that we've seen that was added to the dictionary if the last match was also added
    let mut max_length_last_add = 0;
    let mut current_offset: u32 = 0;

    const LAST_ADDED: u16 = 0x8000;

    let mut min_len = u32::MAX;

    for i in 0..token_blocks.len() {
        let token_block = &token_blocks[i];

        match token_block.block_type {
            BlockType::Stored => {
                // we assume for stored blocks everything was added to the dictionary
                for _i in 0..token_block.uncompressed.len() {
                    current_window[current_offset as usize & WINDOW_MASK] = 0;
                    current_offset += 1;
                }
            }
            BlockType::StaticHuff | BlockType::DynamicHuff => {
                for token in token_block.tokens.iter() {
                    match token {
                        PreflateToken::Literal(_) => {
                            current_window[current_offset as usize & WINDOW_MASK] = 0;
                            current_offset += 1;
                        }
                        PreflateToken::Reference(r) => {
                            // track if we saw something  on the of the 4k boundary
                            if (current_offset & 4095) >= 4093 {
                                block_4k = false;
                            }

                            min_len = std::cmp::min(min_len, r.len());

                            let previous_match =
                                current_window[(current_offset - r.dist()) as usize & WINDOW_MASK];

                            let match_length = u32::from(previous_match & !LAST_ADDED);

                            max_length = std::cmp::max(max_length, match_length);
                            if (previous_match & LAST_ADDED) == 0 {
                                max_length_last_add =
                                    std::cmp::max(max_length_last_add, match_length);
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
        }
    }

    if max_length == 0 && block_4k {
        DictionaryAddPolicy::AddFirstExcept4kBoundary
    } else if max_length_last_add < max_length {
        DictionaryAddPolicy::AddFirstAndLast(max_length_last_add as u16)
    } else if max_length < 258 {
        DictionaryAddPolicy::AddFirst(max_length as u16)
    } else {
        DictionaryAddPolicy::AddAll
    }
}

#[test]
fn verify_miniz1_recognition() {
    let v = crate::process::read_file("compressed_minizoxide_level1.deflate");

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

/// libflate always adds all matches to the dictionary
#[test]
fn verify_libflate_level_recognition() {
    for i in 1..=9 {
        let v = crate::process::read_file(&format!("compressed_libdeflate_level{}.deflate", i));

        let contents = crate::process::parse_deflate(&v, 1).unwrap();
        let add_policy = estimate_add_policy(&contents.blocks);

        assert_eq!(add_policy, DictionaryAddPolicy::AddAll);
    }
}
