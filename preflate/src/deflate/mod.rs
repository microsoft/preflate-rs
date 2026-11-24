//! DEFLATE parsing, token representation, and bitstream writing.
//! Retains block framing and Huffman encoding details so parsed streams can be
//! written back byte for byte.

mod bit_reader;
mod bit_writer;

pub mod deflate_constants;

pub mod deflate_reader;
pub mod deflate_token;
pub mod deflate_writer;
pub mod huffman_calc;
pub mod huffman_encoding;
