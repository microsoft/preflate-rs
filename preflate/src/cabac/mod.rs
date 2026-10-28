//! Minimal subset of the cabac crate (https://github.com/mcroomp/cabac) used by preflate.

#[cfg(test)]
pub mod debug;
mod traits;
pub mod vp8;

pub use traits::{CabacReader, CabacWriter};
