/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

//! Observations about DEFLATE tokens, block boundaries, and source references.
//! Collects evidence shared by hash, insertion-policy, and compressor-profile estimation.

use super::add_policy_estimator::{InsertionEvidence, observe_insertion};
use crate::{
    deflate::deflate_token::{
        DeflateHuffmanType, DeflateToken, DeflateTokenBlock, DeflateTokenBlockType,
    },
    estimator::models::chromium::ShortMatchEvidence,
    preflate_input::PlainText,
};

/// Candidate-independent observations; inferred settings are derived by consumers.
pub struct PreflateStreamInfo {
    pub token_count: u32,
    pub literal_count: u32,
    pub reference_count: u32,
    pub short_reference_count: u32,
    pub max_dist: u32,
    pub min_len: u32,
    pub max_len: u32,
    pub max_tokens_per_block: u32,
    pub max_huffman_block_bytes: u32,
    pub max_unflushed_tokens_per_block: u32,
    pub max_unflushed_huffman_block_bytes: u32,
    pub count_blocks: u32,
    pub ends_with_final_block: bool,
    pub count_stored_blocks: u32,
    pub stored_bytes: u32,
    pub count_static_huff_tree_blocks: u32,
    pub max_dist_3_matches: u32,
    pub matches_to_start_detected: bool,
    pub chromium_short_matches: ShortMatchEvidence,
    pub insertion_evidence: InsertionEvidence,
}

fn process_tokens(
    tokens: &[DeflateToken],
    result: &mut PreflateStreamInfo,
    position: &mut u32,
    plain: Option<&PlainText>,
) {
    result.token_count += tokens.len() as u32;
    result.max_tokens_per_block = std::cmp::max(result.max_tokens_per_block, tokens.len() as u32);
    let mut block_max_dist = 0;
    let mut block_min_len = u32::MAX;

    for token in tokens {
        match token {
            DeflateToken::Literal(_) => {
                result.literal_count += 1;
                *position += 1;
            }
            DeflateToken::Reference(t) => {
                if t.dist() == *position {
                    result.matches_to_start_detected = true;
                }

                result.reference_count += 1;
                block_max_dist = std::cmp::max(block_max_dist, t.dist());
                block_min_len = std::cmp::min(block_min_len, t.len());
                result.max_len = result.max_len.max(t.len());
                *position += t.len();

                if t.len() == 3 {
                    if let Some(plain) = plain {
                        result
                            .chromium_short_matches
                            .observe(plain, *position - 3, t.dist());
                    }
                    result.short_reference_count += 1;
                    result.max_dist_3_matches = std::cmp::max(result.max_dist_3_matches, t.dist());
                }
            }
        }
    }
    result.max_dist = std::cmp::max(result.max_dist, block_max_dist);
    result.min_len = std::cmp::min(result.min_len, block_min_len);
}

pub fn extract_preflate_info_with_plaintext(
    blocks: &[DeflateTokenBlock],
    plain: &PlainText,
) -> PreflateStreamInfo {
    extract_preflate_info_inner(blocks, Some(plain))
}

fn extract_preflate_info_inner(
    blocks: &[DeflateTokenBlock],
    plain: Option<&PlainText>,
) -> PreflateStreamInfo {
    let mut result: PreflateStreamInfo = PreflateStreamInfo {
        count_blocks: blocks.len() as u32,
        ends_with_final_block: blocks.last().is_some_and(|block| block.last),
        count_stored_blocks: 0,
        count_static_huff_tree_blocks: 0,
        token_count: 0,
        max_tokens_per_block: 0,
        max_huffman_block_bytes: 0,
        max_unflushed_tokens_per_block: 0,
        max_unflushed_huffman_block_bytes: 0,
        literal_count: 0,
        reference_count: 0,
        short_reference_count: 0,
        min_len: u32::MAX,
        max_len: 0,
        max_dist: 0,
        stored_bytes: 0,
        max_dist_3_matches: 0,
        matches_to_start_detected: false,
        chromium_short_matches: ShortMatchEvidence::default(),
        insertion_evidence: InsertionEvidence::default(),
    };

    let mut position = 0;
    let mut pending_huffman_size = None;
    for block in blocks {
        match &block.block_type {
            DeflateTokenBlockType::Stored { uncompressed, .. } => {
                // Empty fixed blocks may intervene before a stored flush marker.
                pending_huffman_size = None;
                result.count_stored_blocks += 1;
                result.stored_bytes += uncompressed.len() as u32;
                position += uncompressed.len() as u32;
            }
            DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type,
                ..
            } => {
                if !tokens.is_empty()
                    && let Some((count, bytes)) = pending_huffman_size.take()
                {
                    result.max_unflushed_tokens_per_block =
                        result.max_unflushed_tokens_per_block.max(count);
                    result.max_unflushed_huffman_block_bytes =
                        result.max_unflushed_huffman_block_bytes.max(bytes);
                }
                if let DeflateHuffmanType::Static = huffman_type {
                    result.count_static_huff_tree_blocks += 1;
                }
                let start = position;
                process_tokens(tokens, &mut result, &mut position, plain);
                result.max_huffman_block_bytes =
                    result.max_huffman_block_bytes.max(position - start);
                if !tokens.is_empty() {
                    pending_huffman_size = Some((tokens.len() as u32, position - start));
                }
            }
        }
        if block.last {
            pending_huffman_size = None;
        }
    }
    // Mixed stored/Huffman payloads retain insertion analysis even without references.
    if result.reference_count != 0 || (result.stored_bytes != 0 && result.token_count != 0) {
        result.insertion_evidence = observe_insertion(blocks);
    }
    result
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn extract_preflate_info(blocks: &[DeflateTokenBlock]) -> PreflateStreamInfo {
        extract_preflate_info_inner(blocks, None)
    }

    #[test]
    fn final_block_observation_distinguishes_empty_partial_and_final_chunks() {
        let block = |last| DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Stored {
                uncompressed: Vec::new(),
            },
            last,
        };
        for (blocks, expected) in [
            (vec![], false),
            (vec![block(false)], false),
            (vec![block(true)], true),
            (vec![block(false), block(false)], false),
            (vec![block(false), block(true)], true),
        ] {
            assert_eq!(
                extract_preflate_info(&blocks).ends_with_final_block,
                expected
            );
        }
    }

    #[test]
    fn shared_insertion_evidence_matches_the_standalone_observation_pass() {
        use crate::deflate::deflate_reader::tests::parse_deflate_whole;

        for (family, levels) in [
            ("zlib", 9),
            ("zlibng", 4),
            ("libdeflate", 9),
            ("minizoxide", 1),
        ] {
            for level in 1..=levels {
                let compressed =
                    crate::utils::read_file(&format!("compressed_{family}_level{level}.deflate"));
                let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
                let info = extract_preflate_info_with_plaintext(&contents.blocks, &plain);
                assert_ne!(info.reference_count, 0);
                assert_eq!(
                    info.insertion_evidence,
                    observe_insertion(&contents.blocks),
                    "{family} level {level}"
                );
                assert_eq!(
                    info.insertion_evidence,
                    extract_preflate_info(&contents.blocks).insertion_evidence,
                    "{family} level {level}"
                );
            }
        }
    }

    #[test]
    fn dictionary_free_and_mixed_literal_streams_have_empty_insertion_evidence() {
        let stored = || DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Stored {
                uncompressed: vec![b'a'; 32],
            },
            last: false,
        };
        let literals = || DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens: vec![DeflateToken::Literal(b'b'); 32],
                huffman_type: DeflateHuffmanType::Static,
            },
            last: true,
        };
        for blocks in [
            vec![],
            vec![stored()],
            vec![literals()],
            vec![stored(), literals()],
        ] {
            let info = extract_preflate_info(&blocks);
            assert_eq!(info.reference_count, 0);
            assert_eq!(info.insertion_evidence, InsertionEvidence::default());
            assert_eq!(info.insertion_evidence, observe_insertion(&blocks));
        }
    }

    #[test]
    fn huffman_block_byte_limit_counts_expanded_references_and_resets_after_stored_blocks() {
        let blocks = [
            DeflateTokenBlock {
                block_type: DeflateTokenBlockType::Huffman {
                    tokens: vec![DeflateToken::Literal(b'a'), DeflateToken::new_ref(258, 1)],
                    huffman_type: DeflateHuffmanType::Static,
                },
                last: false,
            },
            DeflateTokenBlock {
                block_type: DeflateTokenBlockType::Stored {
                    uncompressed: vec![0; 4096],
                },
                last: false,
            },
            DeflateTokenBlock {
                block_type: DeflateTokenBlockType::Huffman {
                    tokens: vec![DeflateToken::Literal(b'b'); 2],
                    huffman_type: DeflateHuffmanType::Static,
                },
                last: true,
            },
        ];
        let info = extract_preflate_info(&blocks);
        assert_eq!(info.max_huffman_block_bytes, 259);
        assert_eq!(info.max_tokens_per_block, 2);
        assert_eq!(info.max_unflushed_tokens_per_block, 0);
        assert_eq!(info.max_unflushed_huffman_block_bytes, 0);
    }

    #[test]
    fn block_capacity_evidence_excludes_flushes_terminal_data_and_partial_tails() {
        let data = |count, last| DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens: vec![DeflateToken::Literal(b'x'); count],
                huffman_type: DeflateHuffmanType::Static,
            },
            last,
        };
        let stored = |length| DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Stored {
                uncompressed: vec![0; length],
            },
            last: false,
        };
        for blocks in [
            vec![data(8191, true)],
            vec![data(8191, false)],
            vec![data(8191, false), data(0, true)],
            vec![data(8191, false), stored(0), data(5, true)],
            vec![data(8191, false), data(0, false), stored(0), data(5, true)],
            vec![data(8191, false), stored(10), data(5, true)],
        ] {
            let info = extract_preflate_info(&blocks);
            assert_eq!(info.max_tokens_per_block, 8191);
            assert_eq!(info.max_huffman_block_bytes, 8191);
            assert_eq!(info.max_unflushed_tokens_per_block, 0);
            assert_eq!(info.max_unflushed_huffman_block_bytes, 0);
            assert_eq!(
                crate::estimator::models::zlib::supported_memory_hash(&info),
                None
            );
        }
        let blocks = [
            data(8191, false),
            data(10, false),
            stored(0),
            data(16383, true),
        ];
        let info = extract_preflate_info(&blocks);
        assert_eq!(info.max_unflushed_tokens_per_block, 8191);
        assert_eq!(info.max_unflushed_huffman_block_bytes, 8191);
        assert_eq!(info.max_tokens_per_block, 16383);
        assert_eq!(
            crate::estimator::models::zlib::supported_memory_hash(&info),
            None
        );
        let blocks = [data(8191, false), data(10, true)];
        let info = extract_preflate_info(&blocks);
        assert_eq!(
            crate::estimator::models::zlib::supported_memory_hash(&info),
            Some(crate::hash_algorithm::HashAlgorithm::Zlib {
                hash_mask: 16383,
                hash_shift: 5
            })
        );
        let info = extract_preflate_info(&[data(8000, false), data(10, true)]);
        assert_eq!(
            crate::estimator::models::zlib::supported_memory_hash(&info),
            None
        );
        let info = extract_preflate_info(&[
            DeflateTokenBlock {
                block_type: DeflateTokenBlockType::Huffman {
                    tokens: vec![DeflateToken::Literal(b'x'), DeflateToken::new_ref(258, 1)],
                    huffman_type: DeflateHuffmanType::Static,
                },
                last: false,
            },
            data(1, true),
        ]);
        assert_eq!(info.max_unflushed_tokens_per_block, 2);
        assert_eq!(info.max_unflushed_huffman_block_bytes, 259);
    }
}
