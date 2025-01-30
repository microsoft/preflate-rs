//! This module is useed to estimate the parameters used to compress this DEFLATE stream. If we get these
//! parameters right, it will minimize or even eliminate the need to encode any corrections when we
//! recompress the stream.

pub mod add_policy_estimator;
pub mod complevel_estimator;
pub mod depth_estimator;
pub mod preflate_parameter_estimator;
pub mod preflate_parse_config;
pub mod preflate_stream_info;