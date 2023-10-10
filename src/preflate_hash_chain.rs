use crate::preflate_input::PreflateInput;

pub struct PreflateHashIterator<'a> {
    chain: &'a [u16],
    chain_depth: &'a [u32],
    ref_pos: u32,
    max_dist: u32,
    cur_pos: u32,
    cur_dist: u32,
    is_valid: bool,
}

impl<'a> PreflateHashIterator<'a> {
    fn new(
        chain: &'a [u16],
        chain_depth: &'a [u32],
        ref_pos: u32,
        max_dist: u32,
        start_pos: u32,
    ) -> Self {
        let cur_dist = Self::calcdist(ref_pos, start_pos);
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

    fn calcdist(p1: u32, p2: u32) -> u32 {
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
        self.cur_dist = Self::calcdist(self.ref_pos, self.cur_pos);
        self.is_valid = self.cur_pos > 0 && self.cur_dist <= self.max_dist;
        self.is_valid
    }
}

pub struct PreflateHashChainExt<'a> {
    _input: PreflateInput<'a>,
    head: Vec<u16>,
    chain_depth: Vec<u32>,
    prev: Vec<u16>,
    hash_bits: u32,
    hash_shift: u32,
    running_hash: u32,
    hash_mask: u32,
    total_shift: u32,
}

impl<'a> PreflateHashChainExt<'a> {
    pub fn new(i: &'a [u8], mem_level: u32) -> Self {
        let input = PreflateInput::new(i);
        let hash_bits = mem_level + 7;
        let hash_shift = (hash_bits + 1) - 3;
        let hash_mask = (1 << hash_bits) - 1;
        let total_shift = (hash_bits + 7) / 8;

        let head_size = 1 << hash_bits;
        let head = vec![0; head_size];
        let chain_depth = vec![0; head_size];
        let prev = vec![0; input.size() as usize];

        PreflateHashChainExt {
            _input: input,
            head,
            chain_depth,
            prev,
            hash_bits,
            hash_shift,
            running_hash: 0,
            hash_mask,
            total_shift: total_shift.into(),
        }
    }

    pub fn next_hash(&self, b: u8) -> u32 {
        (self.running_hash << self.hash_shift) ^ u32::from(b)
    }

    pub fn next_hash_double(&self, b1: u8, b2: u8) -> u32 {
        ((self.running_hash << self.hash_shift) ^ u32::from(b1) << self.hash_shift) ^ u32::from(b2)
    }

    pub fn update_running_hash(&mut self, b: u8) {
        self.running_hash = (self.running_hash << self.hash_shift) ^ u32::from(b);
    }

    pub fn reshift(&mut self) {
        // Implement reshift logic here
    }

    pub fn hash_mask(&self) -> u32 {
        self.hash_mask
    }

    pub fn get_head(&self, hash: u32) -> u32 {
        self.head[(hash & self.hash_mask as u32) as usize].into()
    }

    pub fn get_node_depth(&self, node: u32) -> u32 {
        self.chain_depth[node as usize]
    }

    pub fn get_rel_pos_depth(&self, ref_pos: u32, head: u32) -> u32 {
        self.chain_depth[head as usize]
            - self.chain_depth[(ref_pos - u32::from(self.total_shift)) as usize]
    }

    pub fn iterate_from_head(
        &self,
        hash: u32,
        ref_pos: u32,
        max_dist: u32,
    ) -> PreflateHashIterator {
        let head = self.get_head(hash);
        PreflateHashIterator::new(
            &self.prev,
            &self.chain_depth,
            ref_pos - u32::from(self.total_shift),
            max_dist,
            head.into(),
        )
    }

    pub fn iterate_from_node(
        &self,
        node: u32,
        ref_pos: u32,
        max_dist: u32,
    ) -> PreflateHashIterator {
        PreflateHashIterator::new(
            &self.prev,
            &self.chain_depth,
            ref_pos - self.total_shift,
            max_dist,
            node.into(),
        )
    }

    pub fn iterate_from_pos(&self, pos: u32, ref_pos: u32, max_dist: u32) -> PreflateHashIterator {
        PreflateHashIterator::new(
            &self.prev,
            &self.chain_depth,
            ref_pos - u32::from(self.total_shift),
            max_dist,
            pos - u32::from(self.total_shift),
        )
    }

    pub fn input(&self) -> &PreflateInput {
        &self._input
    }

    pub fn cur_hash(&self) -> u32 {
        self.next_hash(self._input.cur_char(2))
    }

    pub fn cur_plus_1_hash(&self) -> u32 {
        self.next_hash_double(self._input.cur_char(2), self._input.cur_char(3))
    }

    pub fn update_hash(&mut self, _l: u32) {
        // Implement update_hash logic here
    }

    pub fn update_hash_long(&mut self, _l: u32) {
        // Implement update_hash_long logic here
    }

    pub fn skip_hash(&mut self, _l: u32) {
        // Implement skip_hash logic here
    }
}
