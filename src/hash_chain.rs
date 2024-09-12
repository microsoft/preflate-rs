/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use default_boxed::DefaultBoxed;

use crate::{
    bit_helper::DebugHash,
    hash_algorithm::{HashImplementation, LibdeflateHash3Secondary, LibdeflateHash4},
    preflate_input::PreflateInput,
};

pub const MAX_UPDATE_HASH_BATCH: u32 = 0x180;

#[derive(Default, Copy, Clone, Eq, PartialEq, Debug)]
#[repr(C)]
struct InternalPosition {
    pos: u16,
}

impl InternalPosition {
    fn reshift(&self, other: u16) -> Self {
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

    fn is_valid(&self) -> bool {
        self.pos > 0
    }

    fn dist(&self, pos: InternalPosition) -> u32 {
        u32::from(self.pos - pos.pos)
    }
}

impl InternalPosition {
    fn from_absolute(pos: u32, total_shift: i32) -> Self {
        Self {
            pos: u16::try_from(pos as i32 - total_shift).unwrap(),
        }
    }
}

#[derive(DefaultBoxed)]
#[repr(C, align(64))]
struct HashTable<H: HashImplementation> {
    /// Represents the head of the hash chain for a given hash value. In order
    /// to find additional matches, you follow the prev chain from the head.
    head: [InternalPosition; 65536],

    /// Represents the prev chain for a given position. This is used to find
    /// all the potential matches for a given hash. The value points to previous
    /// position in the chain, or 0 if there are no more matches. (We start
    /// with an offset of 8 to avoid confusion with the end of the chain)
    prev: [InternalPosition; 65536],

    /// hash function used to calculate the hash
    hash: H,
}

impl<H: HashImplementation> HashTable<H> {
    #[inline]
    fn get_head(&self, h: u16) -> InternalPosition {
        self.head[usize::from(h)]
    }

    #[inline]
    fn update_chain(&mut self, chars: &[u8], mut pos: InternalPosition, length: u32) {
        debug_assert!(length as usize <= chars.len());
        if length as usize + H::num_hash_bytes() - 1 >= chars.len() {
            // reached on of the stream so there will be no more matches
            return;
        }

        for i in 0..length {
            {
                let h = self.hash.get_hash(&chars[i as usize..]);

                self.prev[pos.to_index()] = self.head[usize::from(h)];

                self.head[usize::from(h)] = pos;
            }

            pos = pos.inc();
        }
    }

    fn reshift<const DELTA: usize>(&mut self) {
        for i in 0..=65535 {
            self.head[i] = self.head[i].reshift(DELTA as u16);
        }

        for i in DELTA..=65535 {
            self.prev[i - DELTA] = self.prev[i].reshift(DELTA as u16);
        }
    }
}

pub trait HashChain {
    fn iterate<'a>(&'a self, input: &PreflateInput, offset: u32) -> impl Iterator<Item = u32> + 'a;

    fn update_hash(&mut self, input: &[u8], pos: u32, length: u32);

    fn checksum(&self, checksum: &mut DebugHash);
}

/// This hash chain algorithm periodically normalizes the hash table
pub struct HashChainNormalize<H: HashImplementation> {
    hash_table: Box<HashTable<H>>,
    total_shift: i32,
}

impl<H: HashImplementation> HashChainNormalize<H> {
    pub fn new(hash: H) -> Self {
        // Important: total_shift starts at -8 since 0 indicates the end of the hash chain
        // so this means that all valid values will be >= 8, otherwise the very first hash
        // offset would be zero and so it would get missed
        let mut c = HashChainNormalize {
            total_shift: -8,
            hash_table: HashTable::default_boxed(),
        };

        c.hash_table.hash = hash;

        c
    }

    fn reshift(&mut self) {
        const DELTA: usize = 0x7e00;

        self.hash_table.reshift::<DELTA>();

        self.total_shift += DELTA as i32;
    }
}

impl<H: HashImplementation> HashChain for HashChainNormalize<H> {
    #[inline]
    fn iterate<'a>(&'a self, input: &PreflateInput, offset: u32) -> impl Iterator<Item = u32> + 'a {
        let ref_pos = InternalPosition::from_absolute(input.pos() + offset, self.total_shift);

        // if we have a match that needs to be inserted at the head first before
        // we start walking the chain
        let mut first_match = None;

        let h1 = self.hash_table.hash.get_hash(input.cur_chars(0));

        let curr_hash;

        if offset == 0 {
            curr_hash = h1;
        } else {
            assert_eq!(offset, 1);

            // current hash is the next hash since we are starting at offset 1
            curr_hash = self.hash_table.hash.get_hash(input.cur_chars(1));

            // we are a lazy match, then we haven't added the last byte to the hash yet
            // which is a problem if that hash should have been part of this hash chain
            // (ie the same hash chain) and we have a limited number of enumerations
            // throught the hash chain.
            //
            // In order to fix this, we see if the hashes are the same, and then add
            // a distance 1 item to the iterator that we return.
            if h1 == curr_hash {
                first_match = Some(1);
            }
        }

        let mut cur_pos = self.hash_table.get_head(curr_hash);

        std::iter::from_fn(move || {
            if let Some(d) = first_match {
                first_match = None;
                Some(d)
            } else if cur_pos.is_valid() {
                let d = ref_pos.dist(cur_pos);
                cur_pos = self.hash_table.prev[cur_pos.to_index()];
                Some(d)
            } else {
                None
            }
        })
    }

    #[allow(dead_code)]
    fn checksum(&self, _checksum: &mut DebugHash) {
        //checksum.update_slice(&self.hash_table.chain_depth);
        //checksum.update_slice(&self.hash_table.head);
        //checksum.update_slice(&self.hash_table.prev);
        //checksum.update(self.hash_shift);
        //checksum.update(self.running_hash.hash(self.hash_mask));
        //checksum.update(self.total_shift);
    }

    #[inline]
    fn update_hash(&mut self, input: &[u8], pos: u32, length: u32) {
        assert!(length <= MAX_UPDATE_HASH_BATCH);

        if pos as i32 - self.total_shift >= 0xfe08 {
            self.reshift();
        }

        let pos = InternalPosition::from_absolute(pos, self.total_shift);

        self.hash_table.update_chain(input, pos, length);
    }
}

/// implementation of the hash chain that uses the libdeflate rotating hash.
/// This consists of two hash tables, one for length 3 and one for length 4.
pub struct HashChainNormalizeLibflate4 {
    hash_table: Box<HashTable<LibdeflateHash4>>,
    hash_table_3: Box<HashTable<LibdeflateHash3Secondary>>,
    total_shift: i32,
}

impl HashChainNormalizeLibflate4 {
    pub fn new() -> Self {
        // Important: total_shift starts at -8 since 0 indicates the end of the hash chain
        // so this means that all valid values will be >= 8, otherwise the very first hash
        // offset would be zero and so it would get missed
        HashChainNormalizeLibflate4 {
            total_shift: -8,
            hash_table: HashTable::default_boxed(),
            hash_table_3: HashTable::default_boxed(),
        }
    }
}

impl HashChain for HashChainNormalizeLibflate4 {
    fn iterate<'a>(&'a self, input: &PreflateInput, offset: u32) -> impl Iterator<Item = u32> + 'a {
        let ref_pos = InternalPosition::from_absolute(input.pos() + offset, self.total_shift);

        // if we have a match that needs to be inserted at the head first before
        // we start walking the chain
        let mut first_match = None;

        let mut cur_pos;

        if offset == 0 {
            // for libflate, we look once at the 3 length hash table for a match
            // and then walk the length 4 hash table
            let curr_hash = self.hash_table_3.hash.get_hash(input.cur_chars(0));
            let start_pos = self.hash_table_3.get_head(curr_hash);

            if start_pos.is_valid() {
                first_match = Some(ref_pos.dist(start_pos));
            }

            let curr_hash = self.hash_table.hash.get_hash(input.cur_chars(0));
            cur_pos = self.hash_table.get_head(curr_hash);
        } else {
            assert_eq!(offset, 1);

            // current hash is the next hash since we are starting at offset 1
            let curr_hash = self.hash_table.hash.get_hash(input.cur_chars(1));

            // we are a lazy match, then we haven't added the last byte to the hash yet
            // which is a problem if that hash should have been part of this hash chain
            // (ie the same hash chain) and we have a limited number of enumerations
            // throught the hash chain.
            //
            // In order to fix this, we see if the hashes are the same, and then add
            // a distance 1 item to the iterator that we return.
            let prev_hash = self.hash_table.hash.get_hash(input.cur_chars(0));
            if prev_hash == curr_hash {
                first_match = Some(1);
            }

            cur_pos = self.hash_table.get_head(curr_hash);
        }

        std::iter::from_fn(move || {
            if let Some(d) = first_match {
                first_match = None;
                Some(d)
            } else if cur_pos.is_valid() {
                let d = ref_pos.dist(cur_pos);
                cur_pos = self.hash_table.prev[cur_pos.to_index()];
                Some(d)
            } else {
                None
            }
        })
    }

    #[allow(dead_code)]
    fn checksum(&self, _checksum: &mut DebugHash) {
        //checksum.update_slice(&self.hash_table.chain_depth);
    }

    fn update_hash(&mut self, input: &[u8], pos: u32, length: u32) {
        assert!(length <= MAX_UPDATE_HASH_BATCH);

        if pos as i32 - self.total_shift >= 0xfe08 {
            const DELTA: usize = 0x7e00;

            self.hash_table.reshift::<DELTA>();
            self.hash_table_3.reshift::<DELTA>();

            self.total_shift += DELTA as i32;
        }

        let pos = InternalPosition::from_absolute(pos, self.total_shift);

        self.hash_table.update_chain(input, pos, length);

        self.hash_table_3.update_chain(input, pos, length);
    }
}
