//! Context-adaptive binary arithmetic coding for prediction corrections.
//! Provides coder traits, a VP8 backend, and a context-checking test backend.
//!
//! Adapted from the cabac crate (<https://github.com/mcroomp/cabac>).

#[cfg(test)]
pub mod debug;
mod traits;
pub mod vp8;

pub use traits::{CabacReader, CabacWriter};
