use crate::bit_helper::bit_length;

pub struct BitWriter {
    fill_register: u64,
    current_bit: u32,
}

impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}

// use to write varying sized bits
impl BitWriter {
    pub fn new() -> Self {
        return BitWriter {
            current_bit: 64,
            fill_register: 0,
        };
    }

    /// flushes whole bytes from the register
    pub fn flush_whole_bytes(&mut self, data_buffer: &mut Vec<u8>) {
        while self.current_bit <= 56 {
            let b = (self.fill_register >> 56) as u8;
            data_buffer.push(b);

            self.fill_register <<= 8;
            self.current_bit += 8;
        }
    }

    #[inline(always)]
    pub fn write(&mut self, val: u64, new_bits: u32, data_buffer: &mut Vec<u8>) {
        debug_assert!(
            val < (1 << new_bits),
            "value {0} should fit into the number of {1} bits provided",
            val,
            new_bits
        );

        // first see if everything fits in the current register
        if new_bits <= self.current_bit {
            self.fill_register |= val.wrapping_shl(self.current_bit - new_bits); // support corner case where new_bits is zero, we don't want to panic
            self.current_bit = self.current_bit - new_bits;
        } else {
            // if not, fill up the register so to the 64 bit boundary we can flush a whole 64 bit block
            let fill = self.fill_register | (val as u64).wrapping_shr(new_bits - self.current_bit);

            let leftover_new_bits = new_bits - self.current_bit;
            let leftover_val = val & (1 << leftover_new_bits) - 1;

            data_buffer.extend_from_slice(&fill.to_be_bytes());

            self.fill_register = (leftover_val as u64).wrapping_shl(64 - leftover_new_bits); // support corner case where new_bits is zero, we don't want to panic
            self.current_bit = 64 - leftover_new_bits;
        }
    }

    pub fn pad(&mut self, fillbit: u8, data_buffer: &mut Vec<u8>) {
        let mut offset = 1;
        while (self.current_bit & 7) != 0 {
            self.write(if (fillbit & offset) != 0 { 1 } else { 0 }, 1, data_buffer);
            offset <<= 1;
        }

        self.flush_whole_bytes(data_buffer);

        debug_assert!(
            self.current_bit == 64,
            "there should be no remainder after padding"
        );
    }

    pub fn reset_from_overhang_byte_and_num_bits(&mut self, overhang_byte: u8, num_bits: u32) {
        self.fill_register = 0;
        self.fill_register = overhang_byte as u64;
        self.fill_register <<= 56;
        self.current_bit = 64 - num_bits;
    }

    pub fn has_no_remainder(&self) -> bool {
        return self.current_bit == 64;
    }
}

// write a test pattern with an escape and see if it matches
#[test]
fn write_simple() {
    let arr = [0x12 as u8, 0x34, 0x45, 0x67, 0x89, 0xff, 0xee];

    let mut b = BitWriter::new();
    let mut data_buffer = Vec::new();

    b.write(1, 4, &mut data_buffer);
    b.write(2, 4, &mut data_buffer);
    b.write(3, 4, &mut data_buffer);
    b.write(4, 4, &mut data_buffer);
    b.write(4, 4, &mut data_buffer);
    b.write(0x56, 8, &mut data_buffer);
    b.write(0x78, 8, &mut data_buffer);
    b.write(0x9f, 8, &mut data_buffer);
    b.write(0xfe, 8, &mut data_buffer);
    b.write(0xe, 4, &mut data_buffer);

    b.flush_whole_bytes(&mut data_buffer);

    assert_eq!(data_buffer[..], arr);
}
