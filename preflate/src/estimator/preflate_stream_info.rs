/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::deflate::deflate_token::{
    DeflateHuffmanType, DeflateToken, DeflateTokenBlock, DeflateTokenBlockType,
};
use crate::{models::chromium::ShortMatchEvidence, preflate_input::PlainText};

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
    pub count_blocks: u32,
    pub count_stored_blocks: u32,
    pub stored_bytes: u32,
    pub count_static_huff_tree_blocks: u32,
    pub max_dist_3_matches: u32,
    pub matches_to_start_detected: bool,
    pub(crate) chromium_short_matches: ShortMatchEvidence,
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

    for j in 0..tokens.len() {
        match &tokens[j] {
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

#[cfg(test)]
pub(crate) fn extract_preflate_info(blocks: &[DeflateTokenBlock]) -> PreflateStreamInfo {
    extract_preflate_info_inner(blocks, None)
}

pub(crate) fn extract_preflate_info_with_plaintext(
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
        count_stored_blocks: 0,
        count_static_huff_tree_blocks: 0,
        token_count: 0,
        max_tokens_per_block: 0,
        max_huffman_block_bytes: 0,
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
    };

    let mut position = 0;
    for i in 0..blocks.len() {
        match &blocks[i].block_type {
            DeflateTokenBlockType::Stored { uncompressed, .. } => {
                result.count_stored_blocks += 1;
                result.stored_bytes += uncompressed.len() as u32;
                position += uncompressed.len() as u32;
            }
            DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type,
                ..
            } => {
                if let DeflateHuffmanType::Static { .. } = huffman_type {
                    result.count_static_huff_tree_blocks += 1;
                }
                let start = position;
                process_tokens(&tokens, &mut result, &mut position, plain);
                result.max_huffman_block_bytes =
                    result.max_huffman_block_bytes.max(position - start);
            }
        }
    }
    result
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
}
