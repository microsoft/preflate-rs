/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use default_boxed::DefaultBoxed;

use crate::{
    bit_helper::DebugHash, hash_algorithm::RotatingHashTrait, preflate_input::PreflateInput,
    preflate_token::PreflateTokenReference,
};

pub const MAX_UPDATE_HASH_BATCH: u32 = 0x180;

pub trait HashChainTrait {}

#[derive(Default, Copy, Clone, Eq, PartialEq, Debug)]
struct InternalPosition {
    pos: u16,
}

impl InternalPosition {
    fn saturating_sub(&self, other: u16) -> Self {
        Self {
            pos: self.pos.saturating_sub(other),
        }
    }

    fn to_index(&self) -> usize {
        usize::from(self.pos)
    }

    fn add_offset(&self, offset: u32) -> Self {
        Self {
            pos: self.pos + u16::try_from(offset).unwrap(),
        }
    }

    fn from_absolute(pos: u32, total_shift: i32) -> Self {
        Self {
            pos: u16::try_from(pos as i32 - total_shift).unwrap(),
        }
    }

    fn is_valid(&self) -> bool {
        self.pos > 0
    }
}

pub struct HashIterator<'a> {
    chain: &'a [InternalPosition],
    ref_pos: InternalPosition,
    max_dist: u32,
    cur_pos: InternalPosition,
    state: IteratorState,
}

enum IteratorState {
    Nothing,
    Valid,
    ValidDist1Match,
}

impl<'a> HashIterator<'a> {
    fn new(
        chain: &'a [InternalPosition],
        ref_pos: InternalPosition,
        max_dist: u32,
        start_pos: InternalPosition,
        state: IteratorState,
    ) -> Self {
        Self {
            chain,
            ref_pos,
            max_dist,
            cur_pos: start_pos,
            state,
        }
    }

    fn calc_dist(p1: InternalPosition, p2: InternalPosition) -> u32 {
        u32::from(p1.pos - p2.pos)
    }

    pub fn next(&mut self) -> Option<u32> {
        match self.state {
            IteratorState::Nothing => None,
            IteratorState::Valid => {
                let d = Self::calc_dist(self.ref_pos, self.cur_pos);
                if d > self.max_dist {
                    self.state = IteratorState::Nothing;
                    return None;
                }

                let next = self.chain[self.cur_pos.to_index()];
                if next.is_valid() {
                    self.cur_pos = next;
                    self.state = IteratorState::Valid;
                } else {
                    self.state = IteratorState::Nothing;
                }

                Some(d)
            }
            IteratorState::ValidDist1Match => {
                self.state = IteratorState::Valid;
                Some(1)
            }
        }
    }
}

#[derive(DefaultBoxed)]
struct HashTable {
    /// Represents the head of the hash chain for a given hash value. In order
    /// to find additional matches, you follow the prev chain from the head.
    head: [InternalPosition; 65536],

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

    chain_depth_v: [usize; 65536],

    /// Represents the prev chain for a given position. This is used to find
    /// all the potential matches for a given hash. The value points to previous
    /// position in the chain, or 0 if there are no more matches. (We start
    /// with an offset of 8 to avoid confusion with the end of the chain)
    prev: [InternalPosition; 65536],
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

        // initialize running hash so that it has one minus the number of bytes it needs
        // to calculate the hash (we add the current byte when we calculate the hash)
        for i in 0..H::num_hash_bytes() - 1 {
            c.update_running_hash(input.cur_char(i as i32));
        }

        c
    }

    #[allow(dead_code)]
    pub fn checksum(&self, checksum: &mut DebugHash) {
        checksum.update_slice(&self.hash_table.chain_depth);
        //checksum.update_slice(&self.hash_table.head);
        //checksum.update_slice(&self.hash_table.prev);
        checksum.update(self.hash_shift);
        //checksum.update(self.running_hash.hash(self.hash_mask));
        checksum.update(self.total_shift);
    }

    fn update_running_hash(&mut self, b: u8) {
        self.running_hash = self.running_hash.append(b, self.hash_shift);
    }

    fn reshift_if_necessary<const MAINTAIN_DEPTH: bool>(&mut self, input: &PreflateInput) {
        if input.pos() as i32 - self.total_shift >= 0xfe08 {
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
                self.hash_table.chain_depth_v.copy_within(DELTA..=65535, 0);
            }
            self.total_shift += DELTA as i32;

            if MAINTAIN_DEPTH {
                //self.validate_hash_chains(input);
            }
        }
    }

    #[cfg(bad)]
    pub fn validate_hash_chains(&self, input: &PreflateInput) {
        /*
        let window_start = cmp::min(32768, input.pos());

        let hash_calc = H::default();
        for i in (1..window_start).rev()
        {
            hash_calc.append(input.cur_char(-(i as i32)), self.hash_shift);

            if i >= window_start - H::num_hash_bytes() as u32 {
                continue;
            }

            let pos = InternalPosition::from_absolute(input.pos() - i, self.total_shift);

            let h = hash_calc.hash(self.hash_mask);
            assert_eq!(self.hash_table.chain_depth_v[pos.to_index()], h);
        }*/

        for i in 0..=self.hash_mask as usize {
            let mut h = self.hash_table.head[i];
            while h.is_valid() {
                assert_eq!(self.hash_table.chain_depth_v[h.to_index()], i);
                h = self.hash_table.prev[h.to_index()];
            }
        }
    }

    /// construct a hash chain from scratch and verify that we match the existing hash chain
    /// used for debugging only
    #[allow(dead_code)]
    #[cfg(bad)]
    pub fn verify_hash(&self, dist: Option<PreflateTokenReference>, input: &PreflateInput) {
        let mut hash = H::default();
        let mut start_pos = self.total_shift;

        let mut chains: Vec<Vec<InternalPosition>> = Vec::new();
        chains.resize(self.hash_mask as usize + 1, Vec::new());

        let mut start_delay = H::num_hash_bytes() - 1;

        let window_size = cmp::min(input.pos(), 0x8000);

        while start_pos - 1 <= input.pos() as i32 {
            hash = hash.append(
                input.cur_char(start_pos - input.pos() as i32),
                self.hash_shift,
            );

            if start_delay > 0 {
                start_delay -= 1;
            } else {
                chains[hash.hash(self.hash_mask) as usize].push(
                    InternalPosition::from_absolute(start_pos, self.total_shift).sub_offset(2),
                );
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
            while curr_pos.is_valid() {
                hash_table_chain.push(curr_pos);
                curr_pos = self.hash_table.prev[curr_pos.to_index()];
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

    fn get_head(&self, hash: H) -> InternalPosition {
        let h = hash.hash(self.hash_mask);
        self.hash_table.head[h]
    }

    fn get_node_depth(&self, node: InternalPosition) -> i32 {
        self.hash_table.chain_depth[node.to_index()]
    }

    pub fn iterate_from_current(&self, input: &PreflateInput, max_dist: u32) -> HashIterator {
        let head = self.get_head(self.calculate_hash(input));

        HashIterator::new(
            &self.hash_table.prev,
            InternalPosition::from_absolute(input.pos(), self.total_shift),
            max_dist,
            head,
            if head.is_valid() {
                IteratorState::Valid
            } else {
                IteratorState::Nothing
            },
        )
    }

    pub fn iterate_from_next(&self, input: &PreflateInput, max_dist: u32) -> HashIterator {
        let curr_hash = self.calculate_hash(input);
        let next_hash = self.calculate_hash_next(input);

        let head = self.get_head(next_hash);
        HashIterator::new(
            &self.hash_table.prev,
            InternalPosition::from_absolute(input.pos() + 1, self.total_shift),
            max_dist,
            head,
            if self.hash_equal(curr_hash, next_hash) {
                IteratorState::ValidDist1Match
            } else {
                if head.is_valid() {
                    IteratorState::Valid
                } else {
                    IteratorState::Nothing
                }
            },
        )
    }

    /// calculate the hash for the current byte in the input stream, which
    /// consists of the running hash plus the current character
    fn calculate_hash(&self, input: &PreflateInput) -> H {
        self.running_hash.append(
            input.cur_char(H::num_hash_bytes() as i32 - 1),
            self.hash_shift,
        )
    }

    /// calculate the hash for the next byte in the input stream which
    /// consists of the running hash plus the next 2 characters
    fn calculate_hash_next(&self, input: &PreflateInput) -> H {
        self.calculate_hash(input)
            .append(input.cur_char(H::num_hash_bytes() as i32), self.hash_shift)
    }

    fn hash_equal(&self, a: H, b: H) -> bool {
        a.hash(self.hash_mask) == b.hash(self.hash_mask)
    }

    pub fn update_hash<const MAINTAIN_DEPTH: bool>(&mut self, length: u32, input: &PreflateInput) {
        assert!(length <= MAX_UPDATE_HASH_BATCH);

        self.reshift_if_necessary::<MAINTAIN_DEPTH>(input);

        let hash_limit = H::num_hash_bytes() - 1;
        let limit = std::cmp::min(
            length,
            input.remaining().saturating_sub(u32::from(hash_limit)),
        ) as u16;

        let mut pos = InternalPosition::from_absolute(input.pos(), self.total_shift);
        for i in 0..limit {
            self.update_running_hash(input.cur_char((i + hash_limit) as i32));

            let h = self.running_hash.hash(self.hash_mask);

            if MAINTAIN_DEPTH {
                self.hash_table.chain_depth[pos.to_index()] =
                    self.hash_table.chain_depth[self.hash_table.head[h].to_index()] + 1;
                self.hash_table.chain_depth_v[pos.to_index()] = h;
            }

            self.hash_table.prev[pos.to_index()] = self.hash_table.head[h];
            self.hash_table.head[h] = pos;

            pos = pos.add_offset(1);
        }

        //let c = self.checksum_whole_struct();
        //println!("u {} = {}", length, c);
    }

    pub fn skip_hash<const MAINTAIN_DEPTH: bool>(&mut self, length: u32, input: &PreflateInput) {
        assert!(length <= MAX_UPDATE_HASH_BATCH);

        self.reshift_if_necessary::<MAINTAIN_DEPTH>(input);

        let hash_limit = H::num_hash_bytes() - 1;
        let limit = std::cmp::min(
            length,
            input.remaining().saturating_sub(u32::from(hash_limit)),
        ) as u16;

        let mut pos: InternalPosition =
            InternalPosition::from_absolute(input.pos(), self.total_shift);
        for i in 0..limit {
            self.update_running_hash(input.cur_char((i + hash_limit) as i32));

            if i == 0 {
                let h = self.running_hash.hash(self.hash_mask);

                if MAINTAIN_DEPTH {
                    self.hash_table.chain_depth[pos.to_index()] =
                        self.hash_table.chain_depth[self.hash_table.head[h].to_index()] + 1;
                    self.hash_table.chain_depth_v[pos.to_index()] = h;
                }

                self.hash_table.prev[pos.to_index()] = self.hash_table.head[h];
                self.hash_table.head[h] = pos;
            } else {
                if MAINTAIN_DEPTH {
                    self.hash_table.chain_depth[pos.to_index()] = -65535;
                }
            }

            pos = pos.add_offset(1);
        }
    }

    pub fn match_depth(
        &self,
        target_reference: &PreflateTokenReference,
        window_size: u32,
        input: &PreflateInput,
    ) -> u32 {
        let cur_pos = input.pos();
        let cur_max_dist = std::cmp::min(cur_pos, window_size);

        let hash = self.calculate_hash(input);
        let head = self.get_head(hash);

        let start_depth = self.get_node_depth(head);

        if target_reference.dist() > cur_max_dist {
            println!("dtl {:?} > {}", target_reference, cur_max_dist);
            return 0xffff;
        }

        let end_pos =
            InternalPosition::from_absolute(cur_pos - target_reference.dist(), self.total_shift);

        let end_depth = self.get_node_depth(end_pos);

        if start_depth < end_depth {
            /*assert_eq!(
                self.hash_table.chain_depth_v[end_pos.to_index()],
                self.hash_table.chain_depth_v[head.to_index()]
            );
            println!("dtl {:?} {} > {}", target_reference, start_depth, end_depth);*/
            return 0xffff;
        }

        std::cmp::min(start_depth.wrapping_sub(end_depth) as u32, 0xffff)
    }
}
