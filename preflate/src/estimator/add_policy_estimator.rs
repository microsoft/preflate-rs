//! Observe references into earlier match interiors and derive dictionary insertion policies.
use crate::deflate::deflate_token::{DeflateToken, DeflateTokenBlock, DeflateTokenBlockType};
use crate::models::{miniz::cross_4k_boundary, zlib_ng::is_at_32k_boundary};

use crate::parameters::DictionaryAddPolicy;

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct InsertionEvidence {
    max_interior_match_length: u32,
    max_nonfinal_interior_match_length: u32,
    references_cross_4k_boundary: bool,
    interior_reference_outside_32k_boundary: bool,
}

impl InsertionEvidence {
    pub(super) fn inferred_policy(&self) -> DictionaryAddPolicy {
        if self.max_interior_match_length == 0 && !self.references_cross_4k_boundary {
            DictionaryAddPolicy::AddFirstExcept4kBoundary
        } else if self.max_interior_match_length != 0
            && !self.interior_reference_outside_32k_boundary
        {
            DictionaryAddPolicy::AddFirstWith32KBoundary
        } else if self.max_nonfinal_interior_match_length < self.max_interior_match_length {
            DictionaryAddPolicy::AddFirstAndLast(self.max_nonfinal_interior_match_length as u16)
        } else if self.max_interior_match_length < 258 {
            DictionaryAddPolicy::AddFirst(self.max_interior_match_length as u16)
        } else {
            DictionaryAddPolicy::AddAll
        }
    }
}

/// Observe references into earlier matches without choosing an insertion policy.
pub(super) fn observe_insertion(token_blocks: &[DeflateTokenBlock]) -> InsertionEvidence {
    const WINDOW_MASK: usize = 0x7fff;

    let mut evidence = InsertionEvidence::default();
    let mut current_window = vec![0u16; WINDOW_MASK + 1];

    let mut current_offset: u32 = 0;

    const LAST_ADDED: u16 = 0x8000;
    const LAST_32K: u16 = 0x4000;

    const MASK: u16 = 0x0fff;

    for token_block in token_blocks {
        match &token_block.block_type {
            DeflateTokenBlockType::Stored { uncompressed, .. } => {
                // we assume for stored blocks everything was added to the dictionary
                for _i in 0..uncompressed.len() {
                    current_window[current_offset as usize & WINDOW_MASK] = 0;
                    current_offset += 1;
                }
            }
            DeflateTokenBlockType::Huffman { tokens, .. } => {
                for token in tokens.iter() {
                    match token {
                        DeflateToken::Literal(_) => {
                            current_window[current_offset as usize & WINDOW_MASK] = 0;
                            current_offset += 1;
                        }
                        DeflateToken::Reference(r) => {
                            // Track if we saw something crossing the 4k boundary
                            // MiniZ in fast mode doesn't process the last 3 bytes
                            // before the 4k boundary for optimization reasons.
                            //
                            // These bytes are neither added to the dictionary
                            // nor are matches looked for in this region.
                            if cross_4k_boundary(current_offset)
                                || cross_4k_boundary(current_offset - r.dist())
                            {
                                evidence.references_cross_4k_boundary = true;
                            }

                            let previous_match =
                                current_window[(current_offset - r.dist()) as usize & WINDOW_MASK];

                            let match_length = u32::from(previous_match & MASK);

                            evidence.max_interior_match_length =
                                evidence.max_interior_match_length.max(match_length);
                            if (previous_match & LAST_ADDED) == 0 {
                                evidence.max_nonfinal_interior_match_length = evidence
                                    .max_nonfinal_interior_match_length
                                    .max(match_length);
                            }

                            if match_length != 0 && (previous_match & LAST_32K) == 0 {
                                evidence.interior_reference_outside_32k_boundary = true;
                            }

                            let last = LAST_ADDED
                                | if is_at_32k_boundary(r.len(), current_offset) {
                                    LAST_32K
                                } else {
                                    0
                                };

                            current_window[current_offset as usize & WINDOW_MASK] = 0;
                            current_offset += 1;

                            for i in 1..r.len() {
                                current_window[current_offset as usize & WINDOW_MASK] =
                                    r.len() as u16 | if i == r.len() - 1 { last } else { 0 };
                                current_offset += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    evidence
}

#[cfg(test)]
pub(super) fn estimate_add_policy(token_blocks: &[DeflateTokenBlock]) -> DictionaryAddPolicy {
    observe_insertion(token_blocks).inferred_policy()
}

#[test]
fn insertion_observations_distinguish_interior_and_final_positions() {
    use crate::deflate::deflate_token::DeflateHuffmanType;

    for (distance, nonfinal_length, expected) in [
        (3, 4, DictionaryAddPolicy::AddFirst(4)),
        (1, 0, DictionaryAddPolicy::AddFirstAndLast(0)),
    ] {
        let blocks = [DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens: vec![
                    DeflateToken::Literal(b'a'),
                    DeflateToken::Literal(b'b'),
                    DeflateToken::new_ref(4, 2),
                    DeflateToken::new_ref(3, distance),
                ],
                huffman_type: DeflateHuffmanType::Static,
            },
            last: true,
        }];
        let evidence = observe_insertion(&blocks);
        assert_eq!(
            evidence,
            InsertionEvidence {
                max_interior_match_length: 4,
                max_nonfinal_interior_match_length: nonfinal_length,
                references_cross_4k_boundary: false,
                interior_reference_outside_32k_boundary: true,
            }
        );
        assert_eq!(evidence.inferred_policy(), expected);
    }
}

#[test]
fn insertion_policy_preserves_existing_interpretation_and_precedence() {
    for (max_length, nonfinal_length, crosses_4k, outside_32k, expected) in [
        (
            0,
            0,
            false,
            false,
            DictionaryAddPolicy::AddFirstExcept4kBoundary,
        ),
        (0, 0, true, false, DictionaryAddPolicy::AddFirst(0)),
        (
            258,
            0,
            true,
            false,
            DictionaryAddPolicy::AddFirstWith32KBoundary,
        ),
        (258, 4, true, true, DictionaryAddPolicy::AddFirstAndLast(4)),
        (6, 6, true, true, DictionaryAddPolicy::AddFirst(6)),
        (258, 258, true, true, DictionaryAddPolicy::AddAll),
    ] {
        let evidence = InsertionEvidence {
            max_interior_match_length: max_length,
            max_nonfinal_interior_match_length: nonfinal_length,
            references_cross_4k_boundary: crosses_4k,
            interior_reference_outside_32k_boundary: outside_32k,
        };
        assert_eq!(evidence.inferred_policy(), expected);
    }
}

#[test]
fn boundary_insertion_requires_an_observed_reference_into_a_boundary_match() {
    use crate::deflate::deflate_token::{DeflateHuffmanType, DeflateTokenBlockType};
    for (boundary_insertions, expected) in [
        (false, DictionaryAddPolicy::AddFirst(0)),
        (true, DictionaryAddPolicy::AddFirstWith32KBoundary),
    ] {
        let mut tokens = vec![DeflateToken::Literal(b'@'), DeflateToken::Literal(b'a')];
        let mut position = 2;
        let mut distance = 1;
        for _ in 0..300 {
            tokens.push(DeflateToken::new_ref(258, distance));
            distance = if boundary_insertions && is_at_32k_boundary(258, position) {
                1
            } else {
                258
            };
            position += 258;
        }
        let blocks = [DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type: DeflateHuffmanType::Static,
            },
            last: true,
        }];
        assert_eq!(estimate_add_policy(&blocks), expected);
    }
}

#[test]
fn verify_miniz1_recognition() {
    use crate::deflate::deflate_reader::parse_deflate_whole;

    let v = crate::utils::read_file("compressed_minizoxide_level1.deflate");

    let (contents, _) = parse_deflate_whole(&v).unwrap();

    let add_policy = estimate_add_policy(&contents.blocks);

    assert_eq!(add_policy, DictionaryAddPolicy::AddFirstExcept4kBoundary);
}

#[test]
fn verify_zlib_level_recognition() {
    use crate::deflate::deflate_reader::parse_deflate_whole;

    let levels = [
        DictionaryAddPolicy::AddFirst(4),
        DictionaryAddPolicy::AddFirst(5),
        DictionaryAddPolicy::AddFirst(6),
        DictionaryAddPolicy::AddAll,
    ];

    for i in 1..=4 {
        let v = crate::utils::read_file(&format!("compressed_zlib_level{}.deflate", i));

        let (contents, _plain_text) = parse_deflate_whole(&v).unwrap();
        let add_policy = estimate_add_policy(&contents.blocks);

        assert_eq!(add_policy, levels[i - 1]);
    }
}

#[test]
fn verify_zlibng_level_recognition() {
    use crate::deflate::deflate_reader::parse_deflate_whole;
    let levels = [
        DictionaryAddPolicy::AddFirstWith32KBoundary, // 1 quick
        DictionaryAddPolicy::AddFirstAndLast(4),      // 2 fast
        DictionaryAddPolicy::AddFirstAndLast(96),     // 3 medium
        DictionaryAddPolicy::AddFirstAndLast(191),    // 4 medium
    ];

    for i in 1..=4 {
        let v = crate::utils::read_file(&format!("compressed_zlibng_level{}.deflate", i));

        let (contents, _) = parse_deflate_whole(&v).unwrap();
        let add_policy = estimate_add_policy(&contents.blocks);

        assert_eq!(add_policy, levels[i - 1]);
    }
}

/// libflate always adds all matches to the dictionary
#[test]
fn verify_libdeflate_level_recognition() {
    use crate::deflate::deflate_reader::parse_deflate_whole;

    for i in 1..=9 {
        let v = crate::utils::read_file(&format!("compressed_libdeflate_level{}.deflate", i));

        let (contents, _) = parse_deflate_whole(&v).unwrap();
        let add_policy = estimate_add_policy(&contents.blocks);

        assert_eq!(add_policy, DictionaryAddPolicy::AddAll);
    }
}
