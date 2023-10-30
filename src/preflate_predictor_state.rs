use crate::preflate_constants::{self, MAX_MATCH, MIN_LOOKAHEAD, MIN_MATCH};
use crate::preflate_hash_chain::{PreflateHashChainExt, PreflateHashIterator};
use crate::preflate_parameter_estimator::PreflateParameters;
use crate::preflate_parse_config::PreflateParserConfig;
use crate::preflate_seq_chain::PreflateSeqChain;
use crate::preflate_token::{PreflateToken, TOKEN_NONE};
use std::cmp;

#[derive(Default)]
pub struct PreflateRematchInfo {
    pub first_match_depth: u32,
    pub first_match_dist: u32,
    pub requested_match_depth: u32,
    pub condensed_hops: u32,
}

pub struct PreflatePredictorState<'a> {
    hash: PreflateHashChainExt<'a>,
    seq: PreflateSeqChain<'a>,
    params: PreflateParameters,
    window_bytes: u32,
}

impl<'a> PreflatePredictorState<'a> {
    pub fn new(uncompressed: &'a [u8], params: PreflateParameters) -> Self {
        Self {
            hash: PreflateHashChainExt::new(uncompressed, params.mem_level),
            seq: PreflateSeqChain::new(uncompressed),
            window_bytes: 1 << params.window_bits,
            params: params,
        }
    }

    pub fn update_running_hash(&mut self, b: u8) {
        self.hash.update_running_hash(b);
    }

    pub fn update_hash(&mut self, pos: u32) {
        self.hash.update_hash(pos);
    }

    pub fn skip_hash(&mut self, pos: u32) {
        self.hash.skip_hash(pos);
    }

    pub fn hash_mask(&self) -> u32 {
        self.hash.hash_mask()
    }

    pub fn update_seq(&mut self, pos: u32) {
        self.seq.update_seq(pos);
    }

    pub fn seq_valid(&self, pos: u32) -> bool {
        self.seq.valid(pos)
    }

    pub fn current_input_pos(&self) -> u32 {
        self.hash.input().pos()
    }

    pub fn input_cursor(&self) -> &[u8] {
        self.hash.input().cur_chars(0)
    }

    pub fn input_cursor_offset(&self, offset: i32) -> &[u8] {
        self.hash.input().cur_chars(offset)
    }

    pub fn window_size(&self) -> u32 {
        self.window_bytes.into()
    }

    fn total_input_size(&self) -> u32 {
        self.hash.input().size()
    }

    pub fn available_input_size(&self) -> u32 {
        self.hash.input().remaining()
    }

    pub fn calculate_hash(&self) -> u32 {
        self.hash.cur_hash()
    }

    pub fn calculate_hash_next(&self) -> u32 {
        self.hash.cur_plus_1_hash()
    }

    pub fn get_current_hash_head(&self, hash_next: u32) -> u32 {
        self.hash.get_head(hash_next)
    }

    fn iterate_from_dist(&self, dist_: u32, ref_pos: u32, max_dist: u32) -> PreflateHashIterator {
        self.hash
            .iterate_from_pos(ref_pos - dist_, ref_pos, max_dist)
    }

    fn prefix_compare(s1: &[u8], s2: &[u8], best_len: u32, max_len: u32) -> u32 {
        assert!(max_len >= 3 && s1.len() >= max_len as usize && s2.len() >= max_len as usize);

        if s1[best_len as usize] != s2[best_len as usize] {
            return 0;
        }
        if s1[0] != s2[0] || s1[1] != s2[1] || s1[2] != s2[2] {
            return 0;
        }

        let mut match_len = 3; // Initialize with the length of the fixed prefix
        for i in 3..max_len {
            if s1[i as usize] != s2[i as usize] {
                break;
            }
            match_len = i + 1;
        }

        match_len
    }

    fn suffix_compare(s1: &[u8], s2: &[u8], best_len: u32, max_len: u32) -> u32 {
        if s1[best_len as usize] != s2[best_len as usize] {
            return 0;
        }

        let mut len = 0;
        while len < max_len && s1[len as usize] == s2[len as usize] {
            len += 1;
        }

        len
    }

    pub fn first_match(&mut self, len: u32) -> u32 {
        let max_len = std::cmp::min(self.available_input_size(), MAX_MATCH);
        if max_len < std::cmp::max(len, MIN_MATCH) {
            return 0;
        }

        let cur_pos = self.current_input_pos();
        let cur_max_dist = std::cmp::min(cur_pos, self.window_size());

        let hash = self.calculate_hash();

        let mut chain_it = self.hash.iterate_from_head(hash, cur_pos, cur_max_dist);
        if !chain_it.valid() {
            return 0;
        }

        loop {
            let match_length = Self::prefix_compare(
                self.input_cursor_offset(-(chain_it.dist() as i32)),
                self.input_cursor(),
                len - 1,
                len,
            );
            if match_length >= len {
                return chain_it.dist();
            }

            if !chain_it.next() {
                return 0;
            }
        }
    }

    pub fn match_token(
        &self,
        hash_head: u32,
        prev_len: u32,
        offset: u32,
        very_far_matches: bool,
        matches_to_start: bool,
        max_depth: u32,
    ) -> PreflateToken {
        if let Some(mut h) = self.create_match_helper(
            prev_len,
            self.current_input_pos() + offset,
            very_far_matches,
            matches_to_start,
            max_depth,
        ) {
            let mut chain_it =
                self.hash
                    .iterate_from_node(hash_head, h.start_pos, h.cur_max_dist_hop1_plus);
            // Handle ZLIB quirk: the very first entry in the hash chain can have a larger
            // distance than all following entries
            if chain_it.dist() > h.cur_max_dist_hop0 {
                return TOKEN_NONE;
            }

            let mut best_len = prev_len;
            let mut best_match = TOKEN_NONE;
            let input = self.hash.input().cur_chars(offset as i32);
            loop {
                let match_start = self
                    .hash
                    .input()
                    .cur_chars(offset as i32 - chain_it.dist() as i32);

                let match_length = Self::prefix_compare(match_start, input, best_len, h.max_len);
                if match_length > best_len {
                    best_len = match_length;
                    best_match = PreflateToken::new_reference(match_length, chain_it.dist(), false);
                    if best_len >= h.nice_len {
                        break;
                    }
                }

                if !(chain_it.next() && h.max_chain > 1) {
                    break;
                }

                h.max_chain -= 1;
                h.chain_explored += 1;
                if h.chain_explored > 900 {
                    println!("chain_explored: {}", h.chain_explored);
                }
            }
            best_match
        } else {
            TOKEN_NONE
        }
    }

    pub fn seq_match(
        &self,
        start_pos: u32,
        hash_head: u32,
        prev_len: u32,
        very_far_matches: bool,
        matches_to_start: bool,
        max_depth: u32,
    ) -> PreflateToken {
        if let Some(h) = self.create_match_helper(
            prev_len,
            start_pos,
            very_far_matches,
            matches_to_start,
            max_depth,
        ) {
            let mut chain_it = self.seq.iterate_from_pos(start_pos);
            if !chain_it.valid() {
                return TOKEN_NONE;
            }

            let mut cur_seq_len = std::cmp::min(self.seq.len(start_pos) as u32, h.max_len);
            let mut cur_max_dist = h.cur_max_dist_hop1_plus;
            let mut best_len = prev_len;
            let mut best_match = TOKEN_NONE;

            if cur_seq_len < preflate_constants::MIN_MATCH as u32 {
                cur_seq_len = std::cmp::min(chain_it.len() - chain_it.dist(), h.max_len);

                if cur_seq_len > prev_len && 1 <= h.cur_max_dist_hop0 {
                    best_len = cur_seq_len;
                    best_match = PreflateToken::new_reference(cur_seq_len, 1, false);
                }

                if best_len >= h.nice_len || !chain_it.next() {
                    return best_match;
                }

                if chain_it.dist()
                    > h.cur_max_dist_hop1_plus + chain_it.len() - preflate_constants::MIN_MATCH
                {
                    return best_match;
                }
            } else {
                let min_dist_off = chain_it.len() - preflate_constants::MIN_MATCH;

                if chain_it.dist() > h.cur_max_dist_hop1_plus + min_dist_off {
                    if chain_it.dist() > h.cur_max_dist_hop0 + min_dist_off {
                        return best_match;
                    }

                    // Handle ZLIB quirk: the very first entry in the hash chain can have a larger
                    // distance than all following entries
                    let latest_pos = h.start_pos - chain_it.dist() + min_dist_off;
                    let depth = self.hash.get_rel_pos_depth(latest_pos, hash_head);

                    if depth == 0 {
                        cur_max_dist = h.cur_max_dist_hop0;
                    }
                }
            }

            //let input = self.hash.input().cur_chars(start_pos as i32);
            let mut best_seq_len = cmp::min(cur_seq_len, best_len);

            loop {
                if chain_it.len() >= best_seq_len {
                    let old_best_seq_len = best_seq_len;
                    best_seq_len =
                        std::cmp::min(cmp::min(cur_seq_len, chain_it.len().into()), h.nice_len);
                    let best_dist = chain_it.dist() - chain_it.len() + best_seq_len;
                    let mut error = 0;

                    if best_dist > cur_max_dist {
                        error = best_dist - cur_max_dist;

                        if error > chain_it.len() - preflate_constants::MIN_MATCH {
                            break;
                        }
                    }

                    let best_chain_depth = self
                        .hash
                        .get_rel_pos_depth(h.start_pos - best_dist + error, hash_head);

                    if best_chain_depth >= h.max_chain {
                        error += best_chain_depth - h.max_chain + 1;

                        if error > chain_it.len() - preflate_constants::MIN_MATCH {
                            break;
                        }
                    }

                    if error > 0 {
                        if best_seq_len
                            > cmp::max(old_best_seq_len, preflate_constants::MIN_MATCH - 1) + error
                        {
                            best_match = PreflateToken::new_reference(
                                best_seq_len - error,
                                best_dist - error,
                                false,
                            );
                        }
                        break;
                    }

                    if best_seq_len == h.max_len {
                        best_match = PreflateToken::new_reference(best_seq_len, best_dist, false);
                        break;
                    } else {
                        let diff = start_pos as i32 - self.current_input_pos() as i32;

                        let match_length = best_seq_len
                            + Self::suffix_compare(
                                self.hash
                                    .input()
                                    .cur_chars(diff - best_dist as i32 + best_seq_len as i32),
                                self.hash.input().cur_chars(diff + best_seq_len as i32),
                                std::cmp::max(best_len, best_seq_len) - best_seq_len,
                                h.max_len - best_seq_len,
                            );

                        if match_length > best_len {
                            best_len = match_length;
                            best_match =
                                PreflateToken::new_reference(match_length, best_dist, false);
                            if best_len >= h.nice_len {
                                break;
                            }
                        }
                    }

                    cur_max_dist = h.cur_max_dist_hop1_plus;
                }

                if !chain_it.next() {
                    break;
                }
            }

            best_match
        } else {
            TOKEN_NONE
        }
    }

    fn create_match_helper(
        &self,
        prev_len: u32,
        start_pos: u32,
        very_far_matches: bool,
        matches_to_start: bool,
        max_depth: u32,
    ) -> Option<MatchHelper> {
        let max_len = std::cmp::min(self.total_input_size() - start_pos, MAX_MATCH as u32);
        if max_len < std::cmp::max(prev_len + 1, MIN_MATCH as u32) {
            return None;
        }

        let mut helper = MatchHelper {
            start_pos,
            max_len,
            cur_max_dist_hop0: 0,
            cur_max_dist_hop1_plus: 0,
            max_chain: 0,
            nice_len: 0,
            chain_explored: 0,
        };

        let max_dist_to_start = start_pos - if matches_to_start { 0 } else { 1 };

        if very_far_matches {
            helper.cur_max_dist_hop0 = cmp::min(max_dist_to_start, self.window_size());
            helper.cur_max_dist_hop1_plus = helper.cur_max_dist_hop0;
        } else {
            let max_dist: u32 = (self.window_size() - MIN_LOOKAHEAD).into();
            helper.cur_max_dist_hop0 = cmp::min(max_dist_to_start, max_dist);
            helper.cur_max_dist_hop1_plus = cmp::min(max_dist_to_start, max_dist - 1);
        }

        if max_depth > 0 {
            helper.max_chain = max_depth;
            helper.nice_len = helper.max_len;
        } else {
            helper.max_chain = self.params.max_chain; // max hash chain length
            helper.nice_len = std::cmp::min(self.params.nice_length, helper.max_len);

            if prev_len >= self.params.good_length {
                helper.max_chain >>= 2;
            }
        }

        Some(helper)
    }

    pub fn rematch_info(
        &self,
        hash_head: u32,
        target_reference: &PreflateToken,
    ) -> PreflateRematchInfo {
        let mut result = PreflateRematchInfo {
            first_match_dist: 0,
            first_match_depth: 0xffff,
            requested_match_depth: 0xffff,
            condensed_hops: 0,
        };

        let max_len = std::cmp::min(self.available_input_size(), MAX_MATCH);

        if max_len < target_reference.len() {
            return result;
        }

        let max_dist = self.window_size();
        let cur_pos = self.current_input_pos();
        let cur_max_dist = std::cmp::min(cur_pos, max_dist);

        let mut chain_it = self
            .hash
            .iterate_from_node(hash_head, cur_pos, cur_max_dist);
        if !chain_it.valid() {
            return result;
        }

        let max_chain_org = 0xffff; // max hash chain length
        let mut max_chain = max_chain_org; // max hash chain length
        let best_len = target_reference.len();

        loop {
            let match_pos = self.input_cursor_offset(-(chain_it.dist() as i32));
            let match_length =
                Self::prefix_compare(match_pos, self.input_cursor(), best_len - 1, best_len);

            if match_length >= best_len {
                result.first_match_depth =
                    std::cmp::min(result.first_match_depth, max_chain_org - max_chain);
                result.condensed_hops += 1;
            }

            if chain_it.dist() >= target_reference.dist() {
                if chain_it.dist() == target_reference.dist() {
                    result.requested_match_depth = max_chain_org - max_chain;
                }
                return result;
            }

            if !chain_it.next() || max_chain <= 1 {
                break;
            }

            max_chain -= 1;
        }

        result
    }

    pub fn hop_match(&self, target_reference: &PreflateToken, hops: u32) -> u32 {
        if hops == 0 {
            return target_reference.dist();
        }

        let cur_pos = self.current_input_pos();
        let error_dist = 0;
        let max_len = std::cmp::min(self.available_input_size(), MAX_MATCH);

        if max_len < target_reference.len() {
            return error_dist;
        }

        let max_dist = self.window_size();
        let cur_max_dist = std::cmp::min(cur_pos, max_dist);

        let mut chain_it: PreflateHashIterator<'_> =
            self.iterate_from_dist(target_reference.dist(), cur_pos, cur_max_dist);
        if !chain_it.valid() {
            return error_dist;
        }

        let best_len = target_reference.len();

        let mut todo = hops;
        while todo > 0 {
            if !chain_it.next() {
                break;
            }

            let match_length = Self::prefix_compare(
                self.input_cursor_offset(-(chain_it.dist() as i32)),
                self.input_cursor_offset(-(target_reference.dist() as i32)),
                best_len - 1,
                best_len,
            );

            if match_length >= best_len {
                todo -= 1;
                if todo == 0 {
                    return chain_it.dist();
                }
            }
        }

        error_dist
    }
}

struct MatchHelper {
    start_pos: u32,
    max_len: u32,
    cur_max_dist_hop0: u32,
    cur_max_dist_hop1_plus: u32,
    max_chain: u32,
    nice_len: u32,
    chain_explored: u32,
}
