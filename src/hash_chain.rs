use default_boxed::DefaultBoxed;

use crate::{bit_helper::DebugHash, preflate_constants::MIN_MATCH, preflate_input::PreflateInput};

pub struct HashIterator<'a> {
    chain: &'a [u16],
    chain_depth: &'a [u32],
    ref_pos: u32,
    max_dist: u32,
    cur_pos: u32,
    cur_dist: u32,
    is_valid: bool,
}

impl<'a> HashIterator<'a> {
    fn new(
        chain: &'a [u16],
        chain_depth: &'a [u32],
        ref_pos: u32,
        max_dist: u32,
        start_pos: u32,
    ) -> Self {
        let cur_dist = Self::calc_dist(ref_pos, start_pos);
        let is_valid = cur_dist <= max_dist;
        Self {
            chain,
            chain_depth,
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

    pub fn pos(&self) -> u32 {
        self.cur_pos
    }

    pub fn depth(&self) -> u32 {
        self.chain_depth[self.cur_pos as usize]
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
    head: [u16; 65536],
    chain_depth: [u32; 65536],
    prev: [u16; 65536],
}

pub struct HashChain<'a> {
    input: PreflateInput<'a>,
    hash_table: Box<HashTable>,
    hash_shift: u32,
    running_hash: RotatingHash,
    hash_mask: u16,
    total_shift: i32,
}

#[derive(Default, Debug, Copy, Clone)]
pub struct RotatingHash {
    hash: u16,
}

impl RotatingHash {
    pub fn hash(&self, mask: u16) -> u16 {
        self.hash & mask
    }

    pub fn append(&self, c: u8, hash_shift: u32) -> RotatingHash {
        RotatingHash {
            hash: (self.hash << hash_shift) ^ u16::from(c),
        }
    }
}

impl<'a> HashChain<'a> {
    pub fn new(i: &'a [u8], mem_level: u32) -> Self {
        let hash_bits = mem_level + 7;
        let hash_mask = ((1u32 << hash_bits) - 1) as u16;

        let mut hash_chain_ext = HashChain {
            input: PreflateInput::new(i),
            total_shift: -8,
            hash_shift: (hash_bits + MIN_MATCH - 1) / MIN_MATCH,
            hash_mask: hash_mask,
            hash_table: HashTable::default_boxed(),
            running_hash: RotatingHash::default(),
        };

        if i.len() > 2 {
            hash_chain_ext.update_running_hash(i[0]);
            hash_chain_ext.update_running_hash(i[1]);
        }

        hash_chain_ext
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

    fn next_hash(&self, b: u8) -> RotatingHash {
        self.running_hash.append(b, self.hash_shift)
    }

    fn next_hash_double(&self, b1: u8, b2: u8) -> RotatingHash {
        self.running_hash
            .append(b1, self.hash_shift)
            .append(b2, self.hash_shift)
    }

    pub fn update_running_hash(&mut self, b: u8) {
        self.running_hash = self.running_hash.append(b, self.hash_shift);
    }

    fn reshift_if_necessary(&mut self) {
        if self.input.pos() as i32 - self.total_shift >= 0xfe08 {
            const DELTA: usize = 0x7e00;
            for i in 0..=self.hash_mask as usize {
                self.hash_table.head[i] = self.hash_table.head[i].saturating_sub(DELTA as u16);
            }

            for i in (DELTA + 8)..(1 << 16) {
                self.hash_table.prev[i - DELTA] =
                    self.hash_table.prev[i].saturating_sub(DELTA as u16);
            }

            self.hash_table.chain_depth.copy_within(8 + DELTA..65536, 8);
            self.total_shift += DELTA as i32;
        }
    }

    pub fn get_head(&self, hash: RotatingHash) -> u32 {
        self.hash_table.head[hash.hash(self.hash_mask) as usize].into()
    }

    pub fn get_node_depth(&self, node: u32) -> u32 {
        self.hash_table.chain_depth[node as usize]
    }

    pub fn get_rel_pos_depth(&self, ref_pos: u32, head: u32) -> i32 {
        self.hash_table.chain_depth[head as usize] as i32
            - self.hash_table.chain_depth[(ref_pos as i32 - self.total_shift) as usize] as i32
    }

    pub fn iterate_from_head(
        &self,
        hash: RotatingHash,
        ref_pos: u32,
        max_dist: u32,
    ) -> HashIterator {
        let head = self.get_head(hash);
        HashIterator::new(
            &self.hash_table.prev,
            &self.hash_table.chain_depth,
            (ref_pos as i32 - self.total_shift) as u32,
            max_dist,
            head.into(),
        )
    }

    pub fn iterate_from_pos(&self, pos: u32, ref_pos: u32, max_dist: u32) -> HashIterator {
        HashIterator::new(
            &self.hash_table.prev,
            &self.hash_table.chain_depth,
            (ref_pos as i32 - self.total_shift) as u32,
            max_dist,
            (pos as i32 - self.total_shift) as u32,
        )
    }

    pub fn input(&self) -> &PreflateInput {
        &self.input
    }

    pub fn cur_hash(&self) -> RotatingHash {
        self.next_hash(self.input.cur_char(2))
    }

    pub fn cur_plus_1_hash(&self) -> RotatingHash {
        self.next_hash_double(self.input.cur_char(2), self.input.cur_char(3))
    }

    pub fn hash_equal(&self, a: RotatingHash, b: RotatingHash) -> bool {
        a.hash(self.hash_mask) == b.hash(self.hash_mask)
    }

    pub fn update_hash(&mut self, mut length: u32) {
        if length > 0x180 {
            while length > 0 {
                let blk = std::cmp::min(length, 0x180);
                self.update_hash(blk);
                length -= blk;
            }
            return;
        }

        self.reshift_if_necessary();

        let pos = (self.input.pos() as i32 - self.total_shift) as u16;

        let limit = std::cmp::min(length + 2, self.input.remaining()) as u16;

        for i in 2..limit {
            self.update_running_hash(self.input.cur_char(i as i32));
            let h = self.running_hash.hash(self.hash_mask);
            let p = pos + i - 2;
            self.hash_table.chain_depth[usize::from(p)] =
                self.hash_table.chain_depth[usize::from(self.hash_table.head[usize::from(h)])] + 1;
            self.hash_table.prev[usize::from(p)] = self.hash_table.head[usize::from(h)];
            self.hash_table.head[usize::from(h)] = p;
        }

        self.input.advance(length);

        //let c = self.checksum_whole_struct();
        //println!("u {} = {}", length, c);
    }

    pub fn skip_hash(&mut self, l: u32) {
        self.reshift_if_necessary();

        let pos = self.input.pos();

        let remaining = self.input.remaining();
        if remaining > 2 {
            self.update_running_hash(self.input.cur_char(2));
            let h = self.running_hash.hash(self.hash_mask);
            let p = pos as i32 - self.total_shift;
            self.hash_table.chain_depth[p as usize] =
                self.hash_table.chain_depth[self.hash_table.head[h as usize] as usize] + 1;
            self.hash_table.prev[p as usize] = self.hash_table.head[h as usize];
            self.hash_table.head[h as usize] = p as u16;

            // Skipped data is not inserted into the hash chain,
            // but we must still update the chainDepth, to avoid
            // bad analysis results
            // --------------------
            for i in 1..l {
                let p = (pos + i) as i32 - self.total_shift;
                self.hash_table.chain_depth[p as usize] = 0xffff8000;
            }

            if remaining > l {
                self.update_running_hash(self.input.cur_char(l as i32));
                if remaining > l + 1 {
                    self.update_running_hash(self.input.cur_char(l as i32 + 1));
                }
            }
        }

        self.input.advance(l);

        //let c = self.checksum_whole_struct();
        //println!("s {} = {}", l, c);
    }
}
