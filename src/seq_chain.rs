use std::cmp;

use crate::{bit_helper::DebugHash, preflate_constants::MIN_MATCH, preflate_input::PreflateInput};

#[derive(Clone, Copy, Default)]
struct SeqChainEntry {
    dist_to_next: u16,
    length: u16,
}

/// This structure is used to find consecutive sequences of bytes of the same value
///
/// It is used to find sequences of bytes that can be compressed using a backreference
/// the structure is a hash table with 2^16 entries, each entry is a linked list of
/// sequences of bytes of the same value.
pub struct SeqChain<'a> {
    prev: Vec<SeqChainEntry>,
    total_shift: i32,
    cur_pos: u32,
    heads: [u16; 256],
    input: PreflateInput<'a>,
}

pub struct PreflateSeqIterator<'a> {
    chain: &'a [SeqChainEntry],
    ref_pos: u32,
    cur_dist: u32,
}

impl<'a> PreflateSeqIterator<'a> {
    fn new(chain: &'a [SeqChainEntry], ref_pos: u32) -> Self {
        let cur_dist = chain[ref_pos as usize].dist_to_next;
        Self {
            chain,
            ref_pos,
            cur_dist: cur_dist.into(),
        }
    }

    pub fn valid(&self) -> bool {
        (self.ref_pos - 8) > self.cur_dist
    }

    pub fn dist(&self) -> u32 {
        self.cur_dist.into()
    }

    pub fn len(&self) -> u32 {
        self.chain[(self.ref_pos - self.cur_dist) as usize]
            .length
            .into()
    }

    pub fn next(&mut self) -> bool {
        debug_assert!(self.valid());
        self.cur_dist += self.chain[(self.ref_pos - self.cur_dist) as usize].dist_to_next as u32;
        self.valid()
    }
}

impl<'a> SeqChain<'a> {
    pub fn new(i: &'a [u8]) -> Self {
        let mut r = Self {
            prev: vec![SeqChainEntry::default(); 1 << 16],
            total_shift: -8,
            cur_pos: 0,
            heads: [0; 256],
            input: PreflateInput::new(i),
        };

        r.build(8, cmp::min((1 << 16) - 8, r.input.remaining()));

        r
    }

    #[allow(dead_code)]
    pub fn checksum(&self, checksum: &mut DebugHash) {
        self.prev.iter().for_each(|x| {
            checksum.update(x.dist_to_next);
            checksum.update(x.length);
        });

        checksum.update_slice(&self.heads);
        checksum.update(self.total_shift);
        checksum.update(self.cur_pos);
    }

    pub fn valid(&self, ref_pos: u32) -> bool {
        let index = (ref_pos as i32 - self.total_shift) as usize;
        self.prev[index].dist_to_next != 0xffff
    }

    pub fn len(&self, ref_pos: u32) -> u32 {
        self.prev[(ref_pos as i32 - self.total_shift) as usize]
            .length
            .into()
    }

    pub fn update_seq(&mut self, l: u32) {
        self.cur_pos += l;
        while self.cur_pos as i32 - self.total_shift >= 0xfe08 {
            self.reshift();
        }
    }

    pub fn iterate_from_pos(&self, ref_pos: u32) -> PreflateSeqIterator {
        PreflateSeqIterator::new(&self.prev, (ref_pos as i32 - self.total_shift) as u32)
    }

    fn reshift(&mut self) {
        const DELTA: usize = 0x7e00;
        let remaining = (1 << 16) - (DELTA + 8);

        if self.prev[DELTA + 8].dist_to_next != 0xffff
            && (self.prev[DELTA + 8].length as u32) < MIN_MATCH
        {
            let d: u16 = self.prev[DELTA + 8].dist_to_next;

            self.prev[DELTA + 8].dist_to_next = 0xffff;
            self.prev[DELTA + 8].length = self.prev[DELTA + 8 - d as usize].length - d;
            for i in 3..self.prev[DELTA + 8].length as usize {
                self.prev[DELTA + 8 + i - 2].dist_to_next -= d;
            }

            let c = self.input.cur_char(-(remaining as i32));

            if self.heads[c as usize] == DELTA as u16 + 8 - d {
                self.heads[c as usize] += d;
            } else {
                for i in (self.prev[DELTA + 8].length as usize)..remaining {
                    if self.prev[DELTA + 8 + i].dist_to_next == (i as u16 + d) {
                        self.prev[DELTA + 8 + i].dist_to_next -= d;
                        break;
                    }
                }
            }
        }

        for i in 0..256 {
            self.heads[i] = cmp::max(self.heads[i], DELTA as u16) - DELTA as u16;
        }

        self.prev.copy_within(DELTA + 8..65536, 8);
        self.total_shift += DELTA as i32;
        self.build(
            8 + remaining as u32,
            cmp::min(DELTA as u32, self.input.remaining()),
        );
    }

    fn build(&mut self, off0: u32, size: u32) {
        if size == 0 {
            return;
        }

        let b = &mut self.input;
        let mut cur_char = b.cur_char(0);
        let start_of_seq = SeqChainEntry {
            dist_to_next: 0xffff,
            length: 0x0,
        };
        let mut start_off = off0;
        self.prev[off0 as usize] = start_of_seq;

        if off0 > 8 && cur_char == b.cur_char(-1) {
            start_off -= 1;
            // new block continues the old
            if cur_char == b.cur_char(-2) {
                start_off -= 1;
                // this is definitely a sequence
                if cur_char == b.cur_char(-3) {
                    // This was already a sequence in the previous block,
                    // just append
                    start_off = self.heads[cur_char as usize].into();
                    self.prev[off0 as usize - 2].dist_to_next = (off0 - start_off - 2) as u16;
                    self.prev[off0 as usize - 1].dist_to_next = (off0 - start_off - 1) as u16;
                    self.prev[off0 as usize].dist_to_next = (off0 - start_off) as u16;
                    self.prev[off0 as usize].length = 1;
                } else {
                    // Otherwise enter the sequence in the books
                    self.prev[start_off as usize].dist_to_next =
                        (start_off - self.heads[cur_char as usize] as u32) as u16;
                    self.prev[start_off as usize + 1].dist_to_next = 1;
                    self.prev[start_off as usize + 2].dist_to_next = 2;
                    self.prev[start_off as usize + 2].length = 1;
                    self.heads[cur_char as usize] = start_off as u16;
                }
            } else {
                self.prev[start_off as usize + 1].dist_to_next = 1;
                self.prev[start_off as usize + 1].length = 1;
            }
        }

        self.prev[start_off as usize].length += 1;

        let mut prev_char = cur_char;
        for i in 1..size {
            cur_char = b.cur_char(i as i32);
            if prev_char == cur_char {
                if self.prev[start_off as usize].length == 3 {
                    self.prev[start_off as usize].dist_to_next =
                        (start_off - self.heads[prev_char as usize] as u32) as u16;
                    self.heads[prev_char as usize] = start_off as u16;
                }
                self.prev[(off0 + i) as usize].dist_to_next = (off0 + i - start_off) as u16;
                self.prev[(off0 + i) as usize].length = 1;
                self.prev[start_off as usize].length += 1;
            } else {
                // Last two of a sequence are not a sequence themselves
                if self.prev[start_off as usize].length >= 2 {
                    if self.prev[start_off as usize].length >= 3 {
                        self.prev[(off0 + i - 2) as usize].dist_to_next = 0xffff;
                    }
                    self.prev[(off0 + i - 1) as usize].dist_to_next = 0xffff;
                }
                self.prev[(off0 + i) as usize] = start_of_seq;
                start_off = off0 + i;
                self.prev[start_off as usize].length += 1;
            }
            prev_char = cur_char;
        }

        // Last two of a sequence are not a sequence themselves
        if self.prev[start_off as usize].length >= 2 {
            if self.prev[start_off as usize].length >= 3 {
                self.prev[(off0 + size - 2) as usize].dist_to_next = 0xffff;
            }
            self.prev[(off0 + size - 1) as usize].dist_to_next = 0xffff;
        }

        b.advance(size);
    }
}
