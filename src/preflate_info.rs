/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

 struct PreflateStreamInfo {
    token_count: usize,
    literal_count: usize,
    reference_count: usize,
    max_dist: usize,
    max_tokens_per_block: usize,
    count_blocks: usize,
    count_stored_blocks: usize,
    count_huff_blocks: usize,
    count_rle_blocks: usize,
    count_static_huff_tree_blocks: usize,
}

fn extract_preflate_info(blocks: &Vec<PreflateTokenBlock>) -> PreflateStreamInfo {
    let mut result = PreflateStreamInfo::default();
    result.count_blocks = blocks.len() as u32;
    for (i, b) in blocks.iter().enumerate() {
        if b.block_type == TokenBlockType::Stored {
            result.count_stored_blocks += 1;
            continue;
        }
        if b.block_type == TokenBlockType::StaticHuff {
            result.count_static_huff_tree_blocks += 1;
        }
        result.token_count += b.tokens.len() as u32;
        result.max_tokens_per_block = cmp::max(result.max_tokens_per_block, b.tokens.len() as u32);
        let mut block_max_dist = 0;
        for (j, t) in b.tokens.iter().enumerate() {
            if t.len == 1 {
                result.literal_count += 1;
            } else {
                result.reference_count += 1;
                block_max_dist = cmp::max(block_max_dist, t.dist as u32);
            }
        }
        result.max_dist = cmp::max(result.max_dist, block_max_dist);
        if block_max_dist == 0 {
            result.count_huff_blocks += 1;
        } else if block_max_dist == 1 {
            result.count_rle_blocks += 1;
        }
    }
    return result;
}