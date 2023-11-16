use crate::{bit_helper::DebugHash, preflate_constants::MIN_MATCH, preflate_input::PreflateInput};


pub struct HashChain {
    window: Vec<u8>,
    head: Vec<u16>,
    chain_depth: Vec<u32>,
    prev: Vec<u16>,
    hash_shift: u32,
    running_hash: RotatingHash,
    hash_mask: u32,
    total_shift: i32,
}

impl HashTable {
    pub fn new(mem_level: u32) -> Self {
        let hash_bits = mem_level + 7;
        let hash_mask = (1u32 << hash_bits) - 1;

        HashChain {
            window: vec![0; 1 << 16],
            total_shift: -8,
            hash_shift: (hash_bits + MIN_MATCH - 1) / MIN_MATCH,
            hash_mask: hash_mask,
            head: vec![0; hash_mask as usize + 1],
            prev: vec![0; 1 << 16],
            chain_depth: vec![0; 1 << 16],
            running_hash: RotatingHash::default(),
        }
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

    fn reshift(&mut self) {
        const DELTA: usize = 0x7e00;
        for i in 0..(self.hash_mask + 1) as usize {
            self.head[i] = std::cmp::max(self.head[i], DELTA as u16) - DELTA as u16;
        }

        for i in (DELTA + 8)..(1 << 16) {
            self.prev[i - DELTA] = std::cmp::max(self.prev[i], DELTA as u16) - DELTA as u16;
        }

        self.chain_depth.copy_within(8 + DELTA..65536, 8);
        self.total_shift += DELTA as i32;
    }

    pub fn get_head(&self, hash: RotatingHash) -> u32 {
        self.head[hash.hash(self.hash_mask) as usize].into()
    }

    pub fn get_node_depth(&self, node: u32) -> u32 {
        self.chain_depth[node as usize]
    }

    pub fn get_rel_pos_depth(&self, ref_pos: u32, head: u32) -> i32 {
        self.chain_depth[head as usize] as i32
            - self.chain_depth[(ref_pos as i32 - self.total_shift) as usize] as i32
    }

    pub fn iterate_from_head(
        &self,
        hash: RotatingHash,
        ref_pos: u32,
        max_dist: u32,
    ) -> HashIterator {
        let head = self.get_head(hash);
        HashIterator::new(
            &self.prev,
            &self.chain_depth,
            (ref_pos as i32 - self.total_shift) as u32,
            max_dist,
            head.into(),
        )
    }

    pub fn iterate_from_pos(&self, pos: u32, ref_pos: u32, max_dist: u32) -> HashIterator {
        HashIterator::new(
            &self.prev,
            &self.chain_depth,
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

        let pos = self.input.pos();
        if pos as i32 - self.total_shift >= 0xfe08 {
            self.reshift();
        }

        let limit = std::cmp::min(length + 2, self.input.remaining());

        for i in 2u32..limit {
            self.update_running_hash(self.input.cur_char(i as i32));
            let h = self.running_hash.hash(self.hash_mask);
            let p = (pos + i - 2) as i32 - self.total_shift;
            self.chain_depth[p as usize] = self.chain_depth[self.head[h as usize] as usize] + 1;
            self.prev[p as usize] = self.head[h as usize];
            self.head[h as usize] = p as u16;
        }

        self.input.advance(length);

        //let c = self.checksum_whole_struct();
        //println!("u {} = {}", length, c);
    }

    pub fn skip_hash(&mut self, l: u32) {
        let pos = self.input.pos();
        if pos as i32 - self.total_shift >= 0xfe08 {
            self.reshift();
        }

        let remaining = self.input.remaining();
        if remaining > 2 {
            self.update_running_hash(self.input.cur_char(2));
            let h = self.running_hash.hash(self.hash_mask);
            let p = pos as i32 - self.total_shift;
            self.chain_depth[p as usize] = self.chain_depth[self.head[h as usize] as usize] + 1;
            self.prev[p as usize] = self.head[h as usize];
            self.head[h as usize] = p as u16;

            // Skipped data is not inserted into the hash chain,
            // but we must still update the chainDepth, to avoid
            // bad analysis results
            // --------------------
            for i in 1..l {
                let p = (pos + i) as i32 - self.total_shift;
                self.chain_depth[p as usize] = 0xffff8000;
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
