//! This module is useed to estimate the parameters used to compress this DEFLATE stream. If we get these
//! parameters right, it will minimize or even eliminate the need to encode any corrections when we
//! recompress the stream.

mod complevel_estimator;
mod compressor_profile;
mod depth_estimator;
mod evidence_policy;
mod parser_estimator;
mod preflate_stream_info;

pub(crate) use complevel_estimator::{CandidateEvidence, DepthEstimate};
pub(crate) use compressor_profile::ParameterEstimate;
pub(crate) use depth_estimator::{DistancePolicy, HashTableDepthEstimator};
pub(crate) use evidence_policy::ParserEvidencePolicy;
pub(crate) use parser_estimator::{InsertionConstraint, ParserInference};
pub(crate) use preflate_stream_info::PreflateStreamInfo;

#[cfg(test)]
pub(crate) use compressor_profile::zlib_compatible;
#[cfg(test)]
pub(crate) use preflate_stream_info::extract_preflate_info;

pub mod add_policy_estimator;
pub mod preflate_parameter_estimator;
pub mod preflate_parse_config;
