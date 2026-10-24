use std::{cmp, io::Result};

/// implementation of a context aware binary arithmetic encoder
pub trait CabacWriter<Context> {
    /// write using bypass bin for bits that aren't worth encoding
    fn put_bypass(&mut self, bin_value: bool) -> Result<()>;

    /// write bits using given context for probability
    fn put(&mut self, value: bool, cur_ctx: &mut Context) -> Result<()>;

    /// flush any remaining state
    fn finish(&mut self) -> Result<()>;

    /// default implementation to write num_bits of the lower bits
    fn put_n_bits<const A: usize>(
        &mut self,
        bits: u64,
        num_bits: usize,
        contexts: &mut [Context; A],
    ) -> Result<()> {
        let mut i: i32 = (num_bits - 1) as i32;
        while i >= 0 {
            self.put(
                (bits & (1 << i)) != 0,
                &mut contexts[cmp::min(A - 1, i as usize)],
            )?;
            i -= 1;
        }

        Ok(())
    }

    /// default implementation to write unary encoded value
    fn put_unary_encoded<const A: usize>(
        &mut self,
        v: usize,
        contexts: &mut [Context; A],
    ) -> Result<()> {
        for i in 0..=v {
            let cur_bit = v != i;

            self.put(cur_bit, &mut contexts[cmp::min(A - 1, i)])?;
            if !cur_bit {
                break;
            }
        }

        Ok(())
    }

    /// default implementation to write branched value, which consists of using
    /// a context for each bit, and the value is the index of the context as it is built up
    ///
    /// B must be a power of 2 and A must be log2(B)
    fn put_branched<const A: usize, const B: usize>(
        &mut self,
        v: u8,
        branches: &mut [[Context; B]; A],
    ) -> Result<()> {
        assert_eq!(1 << (A - 1), B, "1 << (A - 1), B");
        assert!(v < B as u8);

        let mut index = A - 1;
        let mut serialized_so_far = 0;

        loop {
            let cur_bit = (v & (1 << index)) != 0;
            self.put(cur_bit, &mut branches[index][serialized_so_far])?;
            serialized_so_far <<= 1;
            serialized_so_far |= cur_bit as usize;

            if index == 0 {
                break;
            }

            index -= 1;
        }

        Ok(())
    }
}

/// implementation of a context aware binary arithmetic decoder
pub trait CabacReader<Context> {
    /// read from bypass bin
    fn get_bypass(&mut self) -> Result<bool>;

    /// read using given context for probability
    fn get(&mut self, cur_ctx: &mut Context) -> Result<bool>;

    /// reads as unary encoded which mean that the number of true bits is equal to the value with
    /// a terminating false bit
    fn get_unary_encoded<const A: usize>(&mut self, contexts: &mut [Context; A]) -> Result<usize> {
        let mut value = 0;

        loop {
            let cur_bit = self.get(&mut contexts[cmp::min(A - 1, value)])?;
            if !cur_bit {
                break;
            }

            value += 1;
        }

        return Ok(value);
    }

    /// reads num_bits of the lower bits of a known size
    fn get_n_bits<const A: usize>(
        &mut self,
        num_bits: usize,
        contexts: &mut [Context; A],
    ) -> Result<u64> {
        let mut coef = 0;
        for i in (0..num_bits).rev() {
            coef |= (self.get(&mut contexts[cmp::min(A - 1, i)])? as u64) << i;
        }

        return Ok(coef);
    }

    /// reads branched value, which consists of using a context for each bit, and the value is the
    /// index of the context as it is built up
    fn get_branched<const A: usize, const B: usize>(
        &mut self,
        branches: &mut [[Context; B]; A],
    ) -> Result<u8> {
        assert_eq!(1 << (A - 1), B, "1 << (A - 1), B");

        let mut index = A - 1;
        let mut value = 0;
        let mut decoded_so_far = 0;

        loop {
            let cur_bit = self.get(&mut branches[index][decoded_so_far])? as u8;
            value |= cur_bit << index;
            decoded_so_far <<= 1;
            decoded_so_far |= cur_bit as usize;

            if index == 0 {
                break;
            }

            index -= 1;
        }

        Ok(value)
    }
}
