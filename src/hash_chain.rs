/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::cmp;

use default_boxed::DefaultBoxed;

use crate::{
    bit_helper::DebugHash,
    hash_algorithm::{HashAlgorithm, LibdeflateRotatingHash3, RotatingHashTrait},
    preflate_input::PreflateInput,
    preflate_token::PreflateTokenReference,
};

pub const MAX_UPDATE_HASH_BATCH: u32 = 0x180;

pub trait HashChainTrait: Default {}

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

    fn inc(&self) -> Self {
        Self { pos: self.pos + 1 }
    }

    fn from_absolute(pos: u32, total_shift: i32) -> Self {
        Self {
            pos: u16::try_from(pos as i32 - total_shift).unwrap(),
        }
    }

    fn is_valid(&self) -> bool {
        self.pos > 0
    }

    fn dist(&self, pos: InternalPosition) -> u32 {
        u32::from(self.pos - pos.pos)
    }
}

enum HashIterator<'a> {
    Nothing,
    Single {
        dist: u32,
    },
    Chain {
        chain: &'a [InternalPosition],
        ref_pos: InternalPosition,
        max_dist: u32,
        cur_pos: InternalPosition,
    },
}

impl<'a> HashIterator<'a> {
    fn new(
        chain: &'a [InternalPosition],
        ref_pos: InternalPosition,
        max_dist: u32,
        start_pos: InternalPosition,
    ) -> Self {
        if start_pos.is_valid() {
            Self::Chain {
                chain,
                ref_pos,
                max_dist,
                cur_pos: start_pos,
            }
        } else {
            Self::Nothing
        }
    }
}

impl Iterator for HashIterator<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        match self {
            HashIterator::Nothing => None,
            HashIterator::Single { dist } => {
                let d = *dist;
                *self = HashIterator::Nothing;
                Some(d)
            }
            HashIterator::Chain {
                chain,
                ref_pos,
                max_dist,
                cur_pos,
            } => {
                let d = ref_pos.dist(*cur_pos);
                if d > *max_dist {
                    *self = HashIterator::Nothing;
                    return None;
                }

                let next = chain[cur_pos.to_index()];
                if next.is_valid() {
                    *cur_pos = next;
                } else {
                    *self = HashIterator::Nothing;
                }

                Some(d)
            }
        }
    }
}

#[derive(DefaultBoxed)]
struct HashTable<H: RotatingHashTrait> {
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

    hash_shift: u32,
    running_hash: H,
    hash_mask: u16,
}

impl<H: RotatingHashTrait> HashTable<H> {
    fn get_head(&self, hash: H) -> InternalPosition {
        let h = hash.hash(self.hash_mask);
        self.head[h]
    }

    fn get_running_hash(&self) -> usize {
        self.running_hash.hash(self.hash_mask)
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

    fn get_node_depth(&self, node: InternalPosition) -> i32 {
        self.chain_depth[node.to_index()]
    }

    fn init_running_hash(&mut self, input: &PreflateInput) {
        self.running_hash = H::default();
        for i in 0..H::num_hash_bytes() - 1 {
            self.update_running_hash(input.cur_char(i as i32));
        }
    }

    fn update_running_hash(&mut self, b: u8) {
        self.running_hash = self.running_hash.append(b, self.hash_shift);
    }

    fn update_chain<const MAINTAIN_DEPTH: bool, const IS_FAST_COMPRESSOR: bool>(
        &mut self,
        chars: &[u8],
        mut pos: InternalPosition,
        length: u32,
    ) {
        let offset = H::num_hash_bytes() as usize - 1;

        if chars.len() <= offset {
            // nothing to update
            return;
        }

        for i in 0..cmp::min(length as usize, chars.len() - offset) {
            self.update_running_hash(chars[i + offset]);

            if !IS_FAST_COMPRESSOR || i == 0 {
                let h = self.get_running_hash();

                if MAINTAIN_DEPTH {
                    self.chain_depth[pos.to_index()] =
                        self.chain_depth[self.head[h].to_index()] + 1;
                    self.chain_depth_v[pos.to_index()] = h;
                }

                self.prev[pos.to_index()] = self.head[h];
                self.head[h] = pos;
            } else {
                if MAINTAIN_DEPTH {
                    self.chain_depth[pos.to_index()] = -65535;
                }
            }

            pos = pos.inc();
        }
    }

    fn reshift<const MAINTAIN_DEPTH: bool, const DELTA: usize>(&mut self) {
        for i in 0..=usize::from(self.hash_mask) as usize {
            self.head[i] = self.head[i].saturating_sub(DELTA as u16);
        }

        for i in DELTA..=65535 {
            self.prev[i - DELTA] = self.prev[i].saturating_sub(DELTA as u16);
        }

        if MAINTAIN_DEPTH {
            self.chain_depth.copy_within(DELTA..=65535, 0);
            self.chain_depth_v.copy_within(DELTA..=65535, 0);
        }
    }

    pub fn match_depth(&self, end_pos: InternalPosition, input: &PreflateInput) -> u32 {
        let hash = self.calculate_hash(input);
        let head = self.get_head(hash);

        let start_depth = self.get_node_depth(head);

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

pub struct HashChain<H: RotatingHashTrait> {
    hash_table: Box<HashTable<H>>,
    hash_table_3_len: Option<Box<HashTable<LibdeflateRotatingHash3>>>,
    total_shift: i32,
}

impl<H: RotatingHashTrait> HashChain<H> {
    pub fn new(hash_shift: u32, hash_mask: u16, input: &PreflateInput) -> Self {
        // Important: total_shift starts at -8 since 0 indicates the end of the hash chain
        // so this means that all valid values will be >= 8, otherwise the very first hash
        // offset would be zero and so it would get missed
        let mut c = HashChain {
            total_shift: -8,
            hash_table: HashTable::default_boxed(),
            hash_table_3_len: None,
        };

        c.hash_table.hash_shift = hash_shift;
        c.hash_table.hash_mask = hash_mask;

        // initialize running hash so that it has the first bytes in it to start working
        c.hash_table.init_running_hash(input);

        // Libflate4 uses a 4 byte hash to find 4 byte matches, and if it doesn't
        // find anything, it uses a 3 byte hash to find 3 byte matches within the
        // first 4096 bytes.
        if H::hash_algorithm() == HashAlgorithm::Libdeflate4 {
            let mut libdeflate3 = HashTable::<LibdeflateRotatingHash3>::default_boxed();

            libdeflate3.hash_shift = 0; // shift is hardcoded for this hash
            libdeflate3.hash_mask = 0x7fff;
            libdeflate3.init_running_hash(input);

            c.hash_table_3_len = Some(libdeflate3);
        }

        c
    }

    #[allow(dead_code)]
    pub fn checksum(&self, checksum: &mut DebugHash) {
        checksum.update_slice(&self.hash_table.chain_depth);
        //checksum.update_slice(&self.hash_table.head);
        //checksum.update_slice(&self.hash_table.prev);
        //checksum.update(self.hash_shift);
        //checksum.update(self.running_hash.hash(self.hash_mask));
        //checksum.update(self.total_shift);
    }

    fn reshift_if_necessary<const MAINTAIN_DEPTH: bool>(&mut self, input: &PreflateInput) {
        if input.pos() as i32 - self.total_shift >= 0xfe08 {
            const DELTA: usize = 0x7e00;

            self.hash_table.reshift::<MAINTAIN_DEPTH, DELTA>();
            if let Some(x) = self.hash_table_3_len.as_mut() {
                x.reshift::<MAINTAIN_DEPTH, DELTA>();
            }

            self.total_shift += DELTA as i32;
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

    pub fn iterate<'a>(
        &'a self,
        input: &PreflateInput,
        offset: u32,
        max_dist: u32,
    ) -> impl Iterator<Item = u32> + 'a {
        let ref_pos = InternalPosition::from_absolute(input.pos() + offset, self.total_shift);

        let offset = offset;
        let first_match;
        let start_pos;

        if offset == 0 {
            let curr_hash = self.hash_table.calculate_hash(input);
            start_pos = self.hash_table.get_head(curr_hash);

            first_match = if let Some(x) = &self.hash_table_3_len {
                let curr_hash = x.calculate_hash(input);
                let start_pos = x.get_head(curr_hash);

                if start_pos.is_valid() {
                    HashIterator::Single {
                        dist: ref_pos.dist(start_pos),
                    }
                } else {
                    HashIterator::Nothing
                }
            } else {
                HashIterator::Nothing
            };
        } else {
            assert_eq!(offset, 1);

            let curr_hash = self.hash_table.calculate_hash(input);
            let next_hash = self.hash_table.calculate_hash_next(input);

            start_pos = self.hash_table.get_head(next_hash);

            first_match = if self.hash_table.hash_equal(curr_hash, next_hash) {
                HashIterator::Single { dist: 1 }
            } else {
                HashIterator::Nothing
            }
        }

        first_match.chain(HashIterator::new(
            &self.hash_table.prev,
            ref_pos,
            max_dist,
            start_pos,
        ))
    }

    pub fn update_hash<const MAINTAIN_DEPTH: bool>(&mut self, length: u32, input: &PreflateInput) {
        assert!(length <= MAX_UPDATE_HASH_BATCH);

        self.reshift_if_necessary::<MAINTAIN_DEPTH>(input);

        let pos = InternalPosition::from_absolute(input.pos(), self.total_shift);
        let chars = input.cur_chars(0);

        self.hash_table
            .update_chain::<MAINTAIN_DEPTH, false>(chars, pos, length);

        // maintain the extra 3 length chain if we have it
        if let Some(x) = self.hash_table_3_len.as_mut() {
            x.update_chain::<MAINTAIN_DEPTH, false>(chars, pos, length);
        }

        //let c = self.checksum_whole_struct();
        //println!("u {} = {}", length, c);
    }

    pub fn skip_hash<const MAINTAIN_DEPTH: bool>(&mut self, length: u32, input: &PreflateInput) {
        assert!(length <= MAX_UPDATE_HASH_BATCH);

        self.reshift_if_necessary::<MAINTAIN_DEPTH>(input);

        let pos = InternalPosition::from_absolute(input.pos(), self.total_shift);
        let chars = input.cur_chars(0);

        self.hash_table
            .update_chain::<MAINTAIN_DEPTH, true>(chars, pos, length);

        // maintain the extra 3 length chain if we have it
        if let Some(x) = self.hash_table_3_len.as_mut() {
            x.update_chain::<MAINTAIN_DEPTH, true>(chars, pos, length);
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

        if target_reference.dist() > cur_max_dist {
            println!("dtl {:?} > {}", target_reference, cur_max_dist);
            return 0xffff;
        }

        let end_pos =
            InternalPosition::from_absolute(cur_pos - target_reference.dist(), self.total_shift);

        if let Some(x) = &self.hash_table_3_len {
            if target_reference.len() == 3 {
                // libdeflate uses the 3 byte hash table only for a single match attempt
                // only legal location for the 3 byte hash is at the beginning of the chain, otherwise
                // we wouldn't find it using the libdeflate algorithm
                if x.match_depth(end_pos, input) == 0 {
                    return 0;
                } else {
                    return 0xffff;
                }
            } else {
                let d = self.hash_table.match_depth(end_pos, input);
                if d < 0xffff {
                    return d + 1;
                } else {
                    return d;
                }
            }
        }

        self.hash_table.match_depth(end_pos, input)
    }
}
