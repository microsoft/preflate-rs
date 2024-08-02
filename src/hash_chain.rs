/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use core::hash;
use std::cmp;

use default_boxed::DefaultBoxed;

use crate::{
    bit_helper::DebugHash,
    hash_algorithm::{
        HashAlgorithm, LibdeflateRotatingHash3, LibdeflateRotatingHash4, RotatingHashTrait,
    },
    preflate_input::PreflateInput,
    preflate_token::PreflateTokenReference,
};

pub const MAX_UPDATE_HASH_BATCH: u32 = 0x180;

pub const UPDATE_MODE_ALL: u32 = 0;
pub const UPDATE_MODE_FIRST: u32 = 1;
pub const UPDATE_MODE_FIRST_AND_LAST: u32 = 2;

#[derive(Default, Eq, PartialEq, Debug, Clone, Copy)]
pub enum DictionaryAddPolicy {
    /// Add all substrings of a match to the dictionary
    #[default]
    AddAll,
    /// Add only the first substring of a match to the dictionary that are larger than the limit
    AddFirst(u16),
    /// Add only the first and last substring of a match to the dictionary that are larger than the limit
    AddFirstAndLast(u16),
}
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

    fn to_index(self) -> usize {
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

    running_hash: H,
}

impl<H: RotatingHashTrait> HashTable<H> {
    fn get_head(&self, hash: H) -> InternalPosition {
        let h = hash.get_hash();
        self.head[h]
    }

    fn get_running_hash(&self) -> usize {
        self.running_hash.get_hash()
    }

    fn hash_equal(&self, a: H, b: H) -> bool {
        a.get_hash() == b.get_hash()
    }

    fn get_node_depth(&self, node: InternalPosition) -> i32 {
        self.chain_depth[node.to_index()]
    }

    fn init_running_hash(&mut self, hash_shift: u32, hash_mask: u16, input: &PreflateInput) {
        self.running_hash = H::init(input, hash_shift, hash_mask);
    }

    fn update_chain<const MAINTAIN_DEPTH: bool, const UPDATE_MODE: u32>(
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

        let last = cmp::min(length as usize, chars.len() - offset);
        for i in 0..last {
            self.running_hash.append(chars[i + offset]);

            if UPDATE_MODE == UPDATE_MODE_ALL
                || (UPDATE_MODE == UPDATE_MODE_FIRST && i == 0)
                || (UPDATE_MODE == UPDATE_MODE_FIRST_AND_LAST && (i == 0 || i == last - 1))
            {
                let h = self.get_running_hash();

                if MAINTAIN_DEPTH {
                    self.chain_depth[pos.to_index()] =
                        self.chain_depth[self.head[h].to_index()] + 1;
                    self.chain_depth_v[pos.to_index()] = h;
                }

                self.prev[pos.to_index()] = self.head[h];
                self.head[h] = pos;
            } else if MAINTAIN_DEPTH {
                self.chain_depth[pos.to_index()] = -65535;
            }

            pos = pos.inc();
        }
    }

    fn reshift<const MAINTAIN_DEPTH: bool, const DELTA: usize>(&mut self) {
        for i in 0..=65535 {
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
        let hash = self.running_hash.calculate_hash(input);
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

pub trait HashChain {
    fn new(hash_shift: u32, hash_mask: u16, input: &PreflateInput) -> Self;
    fn iterate<'a>(&'a self, input: &PreflateInput, offset: u32) -> impl Iterator<Item = u32> + 'a;

    fn update_hash<const MAINTAIN_DEPTH: bool, const UPDATE_MODE: u32>(
        &mut self,
        length: u32,
        input: &PreflateInput,
    );

    fn match_depth(
        &self,
        target_reference: &PreflateTokenReference,
        window_size: u32,
        input: &PreflateInput,
    ) -> u32;

    fn checksum(&self, checksum: &mut DebugHash);

    fn update_hash_with_policy<const MAINTAIN_DEPTH: bool>(
        &mut self,
        length: u32,
        input: &PreflateInput,
        add_policy: DictionaryAddPolicy,
    ) {
        match add_policy {
            DictionaryAddPolicy::AddAll => {
                self.update_hash::<MAINTAIN_DEPTH, UPDATE_MODE_ALL>(length, input);
            }
            DictionaryAddPolicy::AddFirst(limit) => {
                if length > limit.into() {
                    self.update_hash::<MAINTAIN_DEPTH, UPDATE_MODE_FIRST>(length, input);
                } else {
                    self.update_hash::<MAINTAIN_DEPTH, UPDATE_MODE_ALL>(length, input);
                }
            }
            DictionaryAddPolicy::AddFirstAndLast(limit) => {
                if length > limit.into() {
                    self.update_hash::<MAINTAIN_DEPTH, UPDATE_MODE_FIRST_AND_LAST>(length, input);
                } else {
                    self.update_hash::<MAINTAIN_DEPTH, UPDATE_MODE_ALL>(length, input);
                }
            }
        }
    }
}

/// This hash chain algorithm periodically normalizes the hash table
pub struct HashChainNormalize<H: RotatingHashTrait> {
    hash_table: Box<HashTable<H>>,
    total_shift: i32,
}

impl<H: RotatingHashTrait> HashChain for HashChainNormalize<H> {
    fn new(hash_shift: u32, hash_mask: u16, input: &PreflateInput) -> Self {
        // Important: total_shift starts at -8 since 0 indicates the end of the hash chain
        // so this means that all valid values will be >= 8, otherwise the very first hash
        // offset would be zero and so it would get missed
        let mut c = HashChainNormalize {
            total_shift: -8,
            hash_table: HashTable::default_boxed(),
        };

        // initialize running hash so that it has the first bytes in it to start working
        c.hash_table.init_running_hash(hash_shift, hash_mask, input);

        c
    }

    fn iterate<'a>(&'a self, input: &PreflateInput, offset: u32) -> impl Iterator<Item = u32> + 'a {
        let ref_pos = InternalPosition::from_absolute(input.pos() + offset, self.total_shift);

        // if we have a match that needs to be inserted at the head first before
        // we start walking the chain
        let mut first_match = None;

        let h1 = self.hash_table.running_hash.calculate_hash(input);

        let curr_hash;

        if offset == 0 {
            curr_hash = h1;
        } else {
            assert_eq!(offset, 1);

            // current hash is the next hash since we are starting at offset 1
            curr_hash = self.hash_table.running_hash.calculate_hash_next(input);

            // we are a lazy match, then we haven't added the last byte to the hash yet
            // which is a problem if that hash should have been part of this hash chain
            // (ie the same hash chain) and we have a limited number of enumerations
            // throught the hash chain.
            //
            // In order to fix this, we see if the hashes are the same, and then add
            // a distance 1 item to the iterator that we return.
            if h1.get_hash() == curr_hash.get_hash() {
                first_match = Some(1);
            }
        }

        let mut cur_pos = self.hash_table.get_head(curr_hash);

        std::iter::from_fn(move || {
            if let Some(d) = first_match {
                first_match = None;
                Some(d)
            } else {
                if cur_pos.is_valid() {
                    let d = ref_pos.dist(cur_pos);
                    cur_pos = self.hash_table.prev[cur_pos.to_index()];
                    Some(d)
                } else {
                    None
                }
            }
        })
    }

    fn match_depth(
        &self,
        target_reference: &PreflateTokenReference,
        window_size: u32,
        input: &PreflateInput,
    ) -> u32 {
        let cur_pos = input.pos();
        let cur_max_dist = std::cmp::min(cur_pos, window_size);

        if target_reference.dist() > cur_max_dist {
            //println!("dtl {:?} > {}", target_reference, cur_max_dist);
            return 0xffff;
        }

        let end_pos =
            InternalPosition::from_absolute(cur_pos - target_reference.dist(), self.total_shift);

        self.hash_table.match_depth(end_pos, input)
    }

    #[allow(dead_code)]
    fn checksum(&self, checksum: &mut DebugHash) {
        checksum.update_slice(&self.hash_table.chain_depth);
        //checksum.update_slice(&self.hash_table.head);
        //checksum.update_slice(&self.hash_table.prev);
        //checksum.update(self.hash_shift);
        //checksum.update(self.running_hash.hash(self.hash_mask));
        //checksum.update(self.total_shift);
    }

    fn update_hash<const MAINTAIN_DEPTH: bool, const UPDATE_MODE: u32>(
        &mut self,
        length: u32,
        input: &PreflateInput,
    ) {
        assert!(length <= MAX_UPDATE_HASH_BATCH);

        if input.pos() as i32 - self.total_shift >= 0xfe08 {
            const DELTA: usize = 0x7e00;

            self.hash_table.reshift::<MAINTAIN_DEPTH, DELTA>();

            self.total_shift += DELTA as i32;
        }

        let pos = InternalPosition::from_absolute(input.pos(), self.total_shift);
        let chars = input.cur_chars(0);

        self.hash_table
            .update_chain::<MAINTAIN_DEPTH, UPDATE_MODE>(chars, pos, length);
    }
}

/// implementation of the hash chain that uses the libdeflate rotating hash.
/// This consists of two hash tables, one for length 3 and one for length 4.
pub struct HashChainNormalizeLibflate4 {
    hash_table: Box<HashTable<LibdeflateRotatingHash4>>,
    hash_table_3: Box<HashTable<LibdeflateRotatingHash3>>,
    total_shift: i32,
}

impl HashChain for HashChainNormalizeLibflate4 {
    fn new(hash_shift: u32, hash_mask: u16, input: &PreflateInput) -> Self {
        assert_eq!(hash_shift, 0);
        assert_eq!(hash_mask, 0x7fff);

        // Important: total_shift starts at -8 since 0 indicates the end of the hash chain
        // so this means that all valid values will be >= 8, otherwise the very first hash
        // offset would be zero and so it would get missed
        let mut c = HashChainNormalizeLibflate4 {
            total_shift: -8,
            hash_table: HashTable::default_boxed(),
            hash_table_3: HashTable::default_boxed(),
        };

        // initialize running hash so that it has the first bytes in it to start working
        c.hash_table.init_running_hash(hash_shift, hash_mask, input);

        c.hash_table_3
            .init_running_hash(hash_shift, hash_mask, input);

        c
    }

    fn iterate<'a>(&'a self, input: &PreflateInput, offset: u32) -> impl Iterator<Item = u32> + 'a {
        let ref_pos = InternalPosition::from_absolute(input.pos() + offset, self.total_shift);

        // if we have a match that needs to be inserted at the head first before
        // we start walking the chain
        let mut first_match = None;

        let mut cur_pos;

        if offset == 0 {
            // for libflate, we look once at the 3 length hash table for a match
            // and then walk the length 4 hash table
            let curr_hash = self.hash_table_3.running_hash.calculate_hash(input);
            let start_pos = self.hash_table_3.get_head(curr_hash);

            if start_pos.is_valid() {
                first_match = Some(ref_pos.dist(start_pos));
            }

            let curr_hash = self.hash_table.running_hash.calculate_hash(input);
            cur_pos = self.hash_table.get_head(curr_hash);
        } else {
            assert_eq!(offset, 1);

            // current hash is the next hash since we are starting at offset 1
            let curr_hash = self.hash_table.running_hash.calculate_hash_next(input);

            // we are a lazy match, then we haven't added the last byte to the hash yet
            // which is a problem if that hash should have been part of this hash chain
            // (ie the same hash chain) and we have a limited number of enumerations
            // throught the hash chain.
            //
            // In order to fix this, we see if the hashes are the same, and then add
            // a distance 1 item to the iterator that we return.
            let prev_hash = self.hash_table.running_hash.calculate_hash(input);
            if self.hash_table.hash_equal(prev_hash, curr_hash) {
                first_match = Some(1);
            }

            cur_pos = self.hash_table.get_head(curr_hash);
        }

        std::iter::from_fn(move || {
            if let Some(d) = first_match {
                first_match = None;
                Some(d)
            } else {
                if cur_pos.is_valid() {
                    let d = ref_pos.dist(cur_pos);
                    cur_pos = self.hash_table.prev[cur_pos.to_index()];
                    Some(d)
                } else {
                    None
                }
            }
        })
    }

    fn match_depth(
        &self,
        target_reference: &PreflateTokenReference,
        window_size: u32,
        input: &PreflateInput,
    ) -> u32 {
        let cur_pos = input.pos();
        let cur_max_dist = std::cmp::min(cur_pos, window_size);

        if target_reference.dist() > cur_max_dist {
            //println!("dtl {:?} > {}", target_reference, cur_max_dist);
            return 0xffff;
        }

        let end_pos =
            InternalPosition::from_absolute(cur_pos - target_reference.dist(), self.total_shift);

        if target_reference.len() == 3 {
            // libdeflate uses the 3 byte hash table only for a single match attempt
            // only legal location for the 3 byte hash is at the beginning of the chain, otherwise
            // we wouldn't find it using the libdeflate algorithm
            if self.hash_table_3.match_depth(end_pos, input) == 0 {
                return 0;
            } else {
                return 0xffff;
            }
        } else {
            let mut d = self.hash_table.match_depth(end_pos, input);
            if d == 0xffff {
                return d;
            }

            // if there was a valid 3 byte match, then the hash chain will be one larger
            // than the 4 byte hash chain
            if self.hash_table_3.head[self
                .hash_table_3
                .running_hash
                .calculate_hash(input)
                .get_hash()]
            .is_valid()
            {
                d += 1;
            }

            return d;
        }
    }

    #[allow(dead_code)]
    fn checksum(&self, checksum: &mut DebugHash) {
        checksum.update_slice(&self.hash_table.chain_depth);
    }

    fn update_hash<const MAINTAIN_DEPTH: bool, const UPDATE_MODE: u32>(
        &mut self,
        length: u32,
        input: &PreflateInput,
    ) {
        assert!(length <= MAX_UPDATE_HASH_BATCH);

        if input.pos() as i32 - self.total_shift >= 0xfe08 {
            const DELTA: usize = 0x7e00;

            self.hash_table.reshift::<MAINTAIN_DEPTH, DELTA>();
            self.hash_table_3.reshift::<MAINTAIN_DEPTH, DELTA>();

            self.total_shift += DELTA as i32;
        }

        let pos = InternalPosition::from_absolute(input.pos(), self.total_shift);
        let chars = input.cur_chars(0);

        self.hash_table
            .update_chain::<MAINTAIN_DEPTH, UPDATE_MODE>(chars, pos, length);

        self.hash_table_3
            .update_chain::<MAINTAIN_DEPTH, UPDATE_MODE>(chars, pos, length);
    }
}

/*
/// This hash chain algorithm periodically normalizes the hash table
pub struct HashChainAbs<H: RotatingHashTrait> {

    head : [u32; 32768],

    prev : [u32; 32768],

    running_hash : H,
}

impl<H: RotatingHashTrait> HashChain for HashChainAbs<H> {
    fn new(_hash_shift: u32, _hash_mask: u16, input: &PreflateInput) -> Self {

        let mut c = HashChainAbs {
            head: [0; 32768],
            prev: [0; 32768],
            running_hash: H::default(),
        };

        // initialize running hash so that it has the first bytes in it to start working
        c.running_hash = H::init(input, 0);

        c
    }

    fn iterate<'a>(&'a self, input: &PreflateInput, offset: u32) -> impl Iterator<Item = u32> + 'a {
        // if we have a match that needs to be inserted at the head first before
        // we start walking the chain
        let mut first_match = None;

        let curr_hash;

        if offset == 0 {
            curr_hash = self.hash_table.calculate_hash(input);
        } else {
            assert_eq!(offset, 1);

            // current hash is the next hash since we are starting at offset 1
            curr_hash = self.hash_table.calculate_hash_next(input);

            // we are a lazy match, then we haven't added the last byte to the hash yet
            // which is a problem if that hash should have been part of this hash chain
            // (ie the same hash chain) and we have a limited number of enumerations
            // throught the hash chain.
            //
            // In order to fix this, we see if the hashes are the same, and then add
            // a distance 1 item to the iterator that we return.
            let prev_hash = self.hash_table.calculate_hash(input);
            if self.hash_table.hash_equal(prev_hash, curr_hash) {
                first_match = Some(1);
            }
        }

        let mut cur_pos = self.hash_table.get_head(curr_hash);

        std::iter::from_fn(move || {
            if let Some(d) = first_match {
                first_match = None;
                Some(d)
            } else {
                if cur_pos.is_valid() {
                    let d = ref_pos.dist(cur_pos);
                    cur_pos = self.hash_table.prev[cur_pos.to_index()];
                    Some(d)
                } else {
                    None
                }
            }
        })
    }

    fn match_depth(
        &self,
        target_reference: &PreflateTokenReference,
        window_size: u32,
        input: &PreflateInput,
    ) -> u32 {
        let cur_pos = input.pos();
        let cur_max_dist = std::cmp::min(cur_pos, window_size);

        if target_reference.dist() > cur_max_dist {
            //println!("dtl {:?} > {}", target_reference, cur_max_dist);
            return 0xffff;
        }

        let end_pos =
            InternalPosition::from_absolute(cur_pos - target_reference.dist(), self.total_shift);

        self.hash_table.match_depth(end_pos, input)
    }

    #[allow(dead_code)]
    fn checksum(&self, checksum: &mut DebugHash) {
        checksum.update_slice(&self.hash_table.chain_depth);
        //checksum.update_slice(&self.hash_table.head);
        //checksum.update_slice(&self.hash_table.prev);
        //checksum.update(self.hash_shift);
        //checksum.update(self.running_hash.hash(self.hash_mask));
        //checksum.update(self.total_shift);
    }

    fn update_hash<const MAINTAIN_DEPTH: bool, const UPDATE_MODE: u32>(
        &mut self,
        length: u32,
        input: &PreflateInput,
    ) {
        assert!(length <= MAX_UPDATE_HASH_BATCH);

        if input.pos() as i32 - self.total_shift >= 0xfe08 {
            const DELTA: usize = 0x7e00;

            self.hash_table.reshift::<MAINTAIN_DEPTH, DELTA>();

            self.total_shift += DELTA as i32;
        }

        let pos = InternalPosition::from_absolute(input.pos(), self.total_shift);
        let chars = input.cur_chars(0);

        self.hash_table
            .update_chain::<MAINTAIN_DEPTH, UPDATE_MODE>(chars, pos, length);
    }
}
*/
