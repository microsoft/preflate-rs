//! Estimator helpers exposed to prediction and diagnostic unit tests.
//! Re-exports candidate scoring, stream observations, and model constants used by fixtures.

pub use super::{
    complevel_estimator::CandidateEvidence,
    compressor_profile::CompressorProfile,
    depth_estimator::DistancePolicy,
    initial_estimate::tests::stream_info as initial_stream_info,
    models::zlib::compatible as zlib_compatible,
    parser_estimator::ParserInference,
    prediction_scoring::{
        refine_profile, score_predictions, score_refinement, tests::refine_ambiguous_profile,
    },
    preflate_parameter_estimator::{
        canonicalize_unobserved_insertion, estimate_preflate_window_bits,
    },
    preflate_stream_info::tests::extract_preflate_info,
};

pub mod zlib {
    //! Zlib hash and parser settings used by estimator test fixtures.

    pub use super::super::models::zlib::{
        SLOW_PREFLATE_PARSER_SETTINGS, ZLIB_PREFLATE_PARSER_SETTINGS, adjacent_memory_hash,
        candidate_hashes,
    };
    pub use crate::compressors::zlib::{DEFAULT_HASH, memory_hash};
}
