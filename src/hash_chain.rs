/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::cmp;

use default_boxed::DefaultBoxed;

use crate::{
    bit_helper::DebugHash, hash_algorithm::RotatingHashTrait, preflate_input::PreflateInput,
    preflate_token::PreflateTokenReference,
};

pub struct HashIterator<'a> {
    chain: &'a [u16],
    ref_pos: u32,
    max_dist: u32,
    cur_pos: u32,
    cur_dist: u32,
    is_valid: bool,
}

impl<'a> HashIterator<'a> {
    fn new(chain: &'a [u16], ref_pos: u32, max_dist: u32, start_pos: u32) -> Self {
        let cur_dist = Self::calc_dist(ref_pos, start_pos);
        let is_valid = cur_dist <= max_dist;
        Self {
            chain,
            ref_pos,
            max_dist,
            cur_pos: start_pos,
            cur_dist,
            is_valid,
        }
    }

    pub fn valid(&self) -> bool {
        self.is_valid
    }

    fn calc_dist(p1: u32, p2: u32) -> u32 {
        p1 - p2
    }

    pub fn dist(&self) -> u32 {
        self.cur_dist
    }

    pub fn next(&mut self) -> bool {
        self.cur_pos = self.chain[self.cur_pos as usize].into();
        self.cur_dist = Self::calc_dist(self.ref_pos, self.cur_pos);
        self.is_valid = self.cur_pos > 0 && self.cur_dist <= self.max_dist;
        self.is_valid
    }
}

#[derive(DefaultBoxed)]
struct HashTable {
    /// Represents the head of the hash chain for a given hash value. In order
    /// to find additional matches, you follow the prev chain from the head.
    head: [u16; 65536],

    /// Represents the number of following nodes in the chain for a given
    /// position. For example, if chainDepth[100] == 5, then there are 5 more
    /// matches if we follow the prev chain from position 100 back to 0. The value goes back
    /// all the way to be beginning of the compressed data (not readjusted when we shift
    /// the compression window), so in order to calculate the number of chain positions,
    /// you need to subtract the value from the head position.
    ///
    /// This is used during estimation only to figure out how deep we need to match
    /// into the hash chain, which allows us to estimate which parameters were used
    /// to generate the deflate data.
    chain_depth: [i32; 65536],

    /// Represents the prev chain for a given position. This is used to find
    /// all the potential matches for a given hash. The value points to previous
    /// position in the chain, or 0 if there are no more matches. (We start
    /// with an offset of 8 to avoid confusion with the end of the chain)
    prev: [u16; 65536],
}

pub struct HashChain<H: RotatingHashTrait> {
    hash_table: Box<HashTable>,
    hash_shift: u32,
    running_hash: H,
    hash_mask: u16,
    total_shift: i32,
}

impl<H: RotatingHashTrait> HashChain<H> {
    pub fn new(hash_shift: u32, hash_mask: u16, input: &PreflateInput) -> Self {
        // Important: total_shift starts at -8 since 0 indicates the end of the hash chain
        // so this means that all valid values will be >= 8, otherwise the very first hash
        // offset would be zero and so it would get missed
        let mut c = HashChain {
            total_shift: -8,
            hash_shift,
            hash_mask,
            hash_table: HashTable::default_boxed(),
            running_hash: H::default(),
        };

        for i in 0..H::num_hash_bytes() - 1 {
            c.update_running_hash(input.cur_char(i as i32));
        }
        c
    }

    #[allow(dead_code)]
    pub fn checksum(&self, checksum: &mut DebugHash) {
        checksum.update_slice(&self.hash_table.chain_depth);
        checksum.update_slice(&self.hash_table.head);
        checksum.update_slice(&self.hash_table.prev);
        checksum.update(self.hash_shift);
        checksum.update(self.running_hash.hash(self.hash_mask));
        checksum.update(self.total_shift);
    }

    pub fn update_running_hash(&mut self, b: u8) {
        self.running_hash = self.running_hash.append(b, self.hash_shift);
    }

    fn reshift_if_necessary<const MAINTAIN_DEPTH: bool>(&mut self, input: &PreflateInput) {
        if input.pos() as i32 - self.total_shift >= 0xfe00 {
            const DELTA: usize = 0x7e00;
            for i in 0..=self.hash_mask as usize {
                self.hash_table.head[i] = self.hash_table.head[i].saturating_sub(DELTA as u16);
            }

            for i in DELTA..=65535 {
                self.hash_table.prev[i - DELTA] =
                    self.hash_table.prev[i].saturating_sub(DELTA as u16);
            }

            if MAINTAIN_DEPTH {
                self.hash_table.chain_depth.copy_within(DELTA..=65535, 0);
            }
            self.total_shift += DELTA as i32;
        }
    }

    /// construct a hash chain from scratch and verify that we match the existing hash chain
    /// used for debugging only
    #[allow(dead_code)]
    pub fn verify_hash(&self, dist: Option<PreflateTokenReference>, input: &PreflateInput) {
        let mut hash = H::default();
        let mut start_pos = self.total_shift as i32;

        let mut chains: Vec<Vec<u16>> = Vec::new();
        chains.resize(self.hash_mask as usize + 1, Vec::new());

        let mut start_delay = 2;

        while start_pos - 1 <= input.pos() as i32 {
            hash = hash.append(
                input.cur_char(start_pos - input.pos() as i32),
                self.hash_shift,
            );

            if start_delay > 0 {
                start_delay -= 1;
            } else {
                chains[hash.hash(self.hash_mask) as usize]
                    .push((start_pos - 2 - self.total_shift as i32) as u16);
            }

            start_pos += 1;
        }

        let distance = dist.map_or(0, |d| d.dist() as i32);

        println!(
            "MATCH t={:?} a={:?} b={:?} d={}",
            dist,
            &input.cur_chars(-distance)[0..10],
            &input.cur_chars(0)[0..10],
            input.pos() - self.total_shift as u32 - distance as u32
        );

        //println!("MATCH pos = {}, total_shift = {}", self.input.pos(), self.total_shift);
        let mut mismatch = false;
        for i in 0..=self.hash_mask {
            let current_chain = &chains[i as usize];

            let mut hash_table_chain = Vec::new();
            hash_table_chain.reserve(current_chain.len());

            let mut curr_pos = self.hash_table.head[i as usize];
            while curr_pos != 0 {
                hash_table_chain.push(curr_pos);
                curr_pos = self.hash_table.prev[curr_pos as usize];
            }
            hash_table_chain.reverse();

            if hash_table_chain[..] != current_chain[..] {
                mismatch = true;
                println!(
                    "HASH {i} MISMATCH a={:?} b={:?}",
                    hash_table_chain, current_chain
                );
            }

            //assert_eq!(0, chains[i as usize].len());
        }
        assert!(!mismatch);
    }

    pub fn get_head(&self, hash: H) -> u32 {
        self.hash_table.head[hash.hash(self.hash_mask) as usize].into()
    }

    pub fn get_node_depth(&self, node: u32) -> i32 {
        self.hash_table.chain_depth[node as usize]
    }

    pub fn iterate_from_head(&self, hash: H, ref_pos: u32, max_dist: u32) -> HashIterator {
        let head = self.get_head(hash);
        HashIterator::new(
            &self.hash_table.prev,
            (ref_pos as i32 - self.total_shift) as u32,
            max_dist,
            head,
        )
    }

    /// calculate the hash for the current byte in the input stream, which
    /// consists of the running hash plus the current character
    pub fn calculate_hash(&self, input: &PreflateInput) -> H {
        self.running_hash.append(
            input.cur_char(H::num_hash_bytes() as i32 - 1),
            self.hash_shift,
        )
    }

    /// calculate the hash for the next byte in the input stream which
    /// consists of the running hash plus the next 2 characters
    pub fn calculate_hash_next(&self, input: &PreflateInput) -> H {
        self.calculate_hash(input)
            .append(input.cur_char(H::num_hash_bytes() as i32), self.hash_shift)
    }

    pub fn hash_equal(&self, a: H, b: H) -> bool {
        a.hash(self.hash_mask) == b.hash(self.hash_mask)
    }

    pub fn update_hash<const MAINTAIN_DEPTH: bool>(
        &mut self,
        mut length: u32,
        input: &PreflateInput,
    ) {
        if length > 0x180 {
            while length > 0 {
                let blk = std::cmp::min(length, 0x180);
                self.update_hash::<MAINTAIN_DEPTH>(blk, input);
                length -= blk;
            }
            return;
        }

        self.reshift_if_necessary::<MAINTAIN_DEPTH>(input);

        let pos = (input.pos() as i32 - self.total_shift) as u16;

        let hash_limit = H::num_hash_bytes() - 1;

        let limit = std::cmp::min(length + u32::from(hash_limit), input.remaining()) as u16;

        for i in hash_limit..limit {
            self.update_running_hash(input.cur_char(i as i32));
            let h = self.running_hash.hash(self.hash_mask);
            let p = pos + i - hash_limit;

            if MAINTAIN_DEPTH {
                self.hash_table.chain_depth[usize::from(p)] = self.hash_table.chain_depth
                    [usize::from(self.hash_table.head[usize::from(h)])]
                    + 1;
            }

            self.hash_table.prev[usize::from(p)] = self.hash_table.head[usize::from(h)];
            self.hash_table.head[usize::from(h)] = p;
        }

        //let c = self.checksum_whole_struct();
        //println!("u {} = {}", length, c);
    }

    pub fn skip_hash<const MAINTAIN_DEPTH: bool>(&mut self, length: u32, input: &PreflateInput) {
        self.reshift_if_necessary::<MAINTAIN_DEPTH>(input);

        let pos = input.pos() as i32;

        let hash_limit = H::num_hash_bytes() - 1;

        let remaining = input.remaining();
        if remaining > u32::from(hash_limit) {
            self.update_running_hash(input.cur_char(i32::from(hash_limit)));
            let h = self.running_hash.hash(self.hash_mask);
            let p = pos - self.total_shift;

            if MAINTAIN_DEPTH {
                self.hash_table.chain_depth[p as usize] =
                    self.hash_table.chain_depth[self.hash_table.head[h as usize] as usize] + 1;

                // Skipped data is not inserted into the hash chain,
                // but we must still update the chainDepth, to avoid
                // bad analysis results
                // --------------------
                for i in 1..length {
                    let p = (pos + i as i32) - self.total_shift;
                    self.hash_table.chain_depth[p as usize] = -65536;
                }
            }

            self.hash_table.prev[p as usize] = self.hash_table.head[h as usize];
            self.hash_table.head[h as usize] = p as u16;

            for i in length..cmp::min(remaining, length + u32::from(hash_limit)) {
                self.update_running_hash(input.cur_char(i as i32));
            }
        }

        //let c = self.checksum_whole_struct();
        //println!("s {} = {}", l, c);
    }

    pub fn match_depth(
        &self,
        target_reference: &PreflateTokenReference,
        window_size: u32,
        input: &PreflateInput,
    ) -> u32 {
        let cur_pos = input.pos();
        let cur_max_dist = std::cmp::min(cur_pos, window_size);

        let head = self.get_head(self.calculate_hash(input));
        let start_depth = self.get_node_depth(head);

        if target_reference.dist() > cur_max_dist {
            return 0xffff;
        }

        let end_depth = self.get_node_depth(
            (cur_pos as i32 - target_reference.dist() as i32 - self.total_shift) as u32,
        );

        if start_depth < end_depth {
            return 0xffff;
        }

        std::cmp::min(start_depth.wrapping_sub(end_depth) as u32, 0xffff)
    }
}
