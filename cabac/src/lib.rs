#![forbid(unsafe_code)]
#![forbid(trivial_numeric_casts)]
#![forbid(unused_qualifications)]
#![forbid(unused_results)]
#![forbid(unreachable_pub)]
#![forbid(deprecated_in_future)]

pub mod debug;
pub mod fpaq0;
pub mod fpaq0parallel;
pub mod perf;
pub mod rans32;
mod traits;
pub mod vp8;

pub use traits::{CabacReader, CabacWriter};
