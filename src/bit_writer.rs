use crate::zip_bit_reader::ZipBitReader;

#[derive(Default)]
pub struct BitWriter {
    pub bit_buffer: u32,
    pub bits_in: u32,
}

// use to write varying sized bits
impl BitWriter {
    #[inline(always)]
    pub fn write(&mut self, bits: u32, len: u32, data_buffer: &mut Vec<u8>) {
        assert!(bits <= ((1u32 << len) - 1u32));
        self.bit_buffer |= bits << self.bits_in;
        self.bits_in += len;

        self.flush_whole_bytes(data_buffer);
    }

    pub fn pad(&mut self, fillbit: u8, data_buffer: &mut Vec<u8>) {
        let mut offset = 1;
        while (self.bits_in & 7) != 0 {
            self.write(if (fillbit & offset) != 0 { 1 } else { 0 }, 1, data_buffer);
            offset <<= 1;
        }
    }

    pub fn flush_whole_bytes(&mut self, data_buffer: &mut Vec<u8>) {
        while self.bits_in >= 8 {
            data_buffer.push(self.bit_buffer as u8);
            self.bit_buffer >>= 8;
            self.bits_in -= 8;
        }
    }
}

// write a test pattern with an escape and see if it matches
#[test]
fn write_simple() {
    let mut b = BitWriter::default();
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

    assert_eq!(data_buffer[..], [0x21, 0x43, 0x64, 0x85, 0xf7, 0xe9, 0xef]);

    let len = data_buffer.len() as i64;
    let mut cursor = std::io::Cursor::new(data_buffer);
    let mut reader = ZipBitReader::new(&mut cursor, len).unwrap();

    assert_eq!(reader.get(4).unwrap(), 1);
    assert_eq!(reader.get(4).unwrap(), 2);
    assert_eq!(reader.get(4).unwrap(), 3);
    assert_eq!(reader.get(4).unwrap(), 4);
    assert_eq!(reader.get(4).unwrap(), 4);
    assert_eq!(reader.get(8).unwrap(), 0x56);
    assert_eq!(reader.get(8).unwrap(), 0x78);
    assert_eq!(reader.get(8).unwrap(), 0x9f);
    assert_eq!(reader.get(8).unwrap(), 0xfe);
    assert_eq!(reader.get(4).unwrap(), 0xe);
}
