use crate::preflate_token::{BlockType, PreflateTokenBlock};

pub struct PreflateStreamInfo {
    pub token_count: u32,
    pub literal_count: u32,
    pub reference_count: u32,
    pub max_dist: u32,
    pub max_tokens_per_block: u32,
    pub count_blocks: u32,
    pub count_stored_blocks: u32,
    pub count_huff_blocks: u32,
    pub count_rle_blocks: u32,
    pub count_static_huff_tree_blocks: u32,
}

pub fn extract_preflate_info(blocks: &Vec<PreflateTokenBlock>) -> PreflateStreamInfo {
    let mut result: PreflateStreamInfo = PreflateStreamInfo {
        count_blocks: blocks.len() as u32,
        count_stored_blocks: 0,
        count_static_huff_tree_blocks: 0,
        token_count: 0,
        max_tokens_per_block: 0,
        literal_count: 0,
        reference_count: 0,
        max_dist: 0,
        count_huff_blocks: 0,
        count_rle_blocks: 0,
    };

    for i in 0..blocks.len() {
        let b = &blocks[i];
        if b.block_type == BlockType::Stored {
            result.count_stored_blocks += 1;
            continue;
        }
        if b.block_type == BlockType::StaticHuff {
            result.count_static_huff_tree_blocks += 1;
        }
        result.token_count += b.tokens.len() as u32;
        result.max_tokens_per_block =
            std::cmp::max(result.max_tokens_per_block, b.tokens.len() as u32);
        let mut block_max_dist = 0;
        for j in 0..b.tokens.len() {
            let t = &b.tokens[j];
            if t.len() == 1 {
                result.literal_count += 1;
            } else {
                result.reference_count += 1;
                block_max_dist = std::cmp::max(block_max_dist, t.dist().into());
            }
        }
        result.max_dist = std::cmp::max(result.max_dist, block_max_dist);
        if block_max_dist == 0 {
            result.count_huff_blocks += 1;
        } else if block_max_dist == 1 {
            result.count_rle_blocks += 1;
        }
    }
    result
}
