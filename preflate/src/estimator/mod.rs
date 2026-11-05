//! Estimation of the compressor settings behind a DEFLATE stream.
//! Combines token observations, compressor models, and bounded candidate scoring
//! to choose settings that minimize prediction corrections.

mod add_policy_estimator;
mod complevel_estimator;
mod compressor_profile;
mod depth_estimator;
mod estimation_result;
mod evidence_policy;
mod initial_estimate;
mod models;
mod parser_estimator;
mod prediction_encoding;
mod prediction_scoring;
mod preflate_parameter_estimator;
mod preflate_stream_info;

pub use estimation_result::EstimationResult;
pub use prediction_encoding::estimate_and_encode;

#[cfg(test)]
pub use preflate_parameter_estimator::tests::estimate_preflate_parameters;

#[cfg(feature = "diagnostics")]
pub use preflate_parameter_estimator::estimate_preflate_result;

#[cfg(test)]
pub mod test_support;
