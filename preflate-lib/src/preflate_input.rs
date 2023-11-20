pub struct PreflateInput<'a> {
    data: &'a [u8],
    pos: i32,
}

impl<'a> PreflateInput<'a> {
    pub fn new(v: &'a [u8]) -> Self {
        PreflateInput { data: v, pos: 0 }
    }

    pub fn pos(&self) -> u32 {
        self.pos as u32
    }

    pub fn size(&self) -> u32 {
        self.data.len() as u32
    }

    pub fn cur_chars(&self, offset: i32) -> &[u8] {
        &self.data[(self.pos + offset) as usize..]
    }

    pub fn cur_char(&self, offset: i32) -> u8 {
        self.data[(self.pos + offset) as usize]
    }

    pub fn advance(&mut self, l: u32) {
        self.pos += l as i32;
    }

    pub fn remaining(&self) -> u32 {
        self.data.len() as u32 - self.pos as u32
    }
}
