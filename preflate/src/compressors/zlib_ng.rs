//! Dictionary insertion at zlib-ng's sliding-window boundary.
//!
//! A match crossing the slide point inserts its final byte as well as its
//! first. The boundary repeats every 32 KiB and is evaluated from the match
//! position, not from an inferred compressor identity.

pub const SLIDE_POINT: u32 = 32768 - crate::deflate::deflate_constants::MIN_LOOKAHEAD;

#[inline(always)]
pub fn is_at_32k_boundary(length: u32, pos: u32) -> bool {
    length > 1 && ((pos & 0x7fff) <= SLIDE_POINT) && (((pos + length) & 0x7fff) >= SLIDE_POINT)
}
