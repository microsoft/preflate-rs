//! Pairs executable reconstruction settings with a selected compressor model
//! and serializes the combined estimation report as JSON.

use super::compressor_profile::CompressorProfile;
use crate::{Result, reconstruction_parameters::ReconstructionParameters};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct EstimationResult {
    pub reconstruction: ReconstructionParameters,
    /// Selected model hypothesis, not an identification of the original producer.
    pub model: CompressorProfile,
}

impl EstimationResult {
    pub fn new(model: CompressorProfile, reconstruction: ReconstructionParameters) -> Self {
        Self {
            reconstruction,
            model,
        }
    }

    pub fn to_json(self) -> Result<String> {
        serde_json::to_string(&self).map_err(|error| {
            crate::PreflateError::new(crate::ExitCode::GeneralFailure, error.to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        parameters::{BlockTypeStrategy, PreflateStrategy},
        reconstruction_parameters::BehaviorSettings,
    };

    #[test]
    fn estimator_report_json_preserves_model_labels_and_reconstruction() {
        let parameters = ReconstructionParameters {
            max_token_count: 2047,
            block_type_strategy: BlockTypeStrategy::Dynamic,
            behavior: BehaviorSettings::NoDictionary {
                strategy: PreflateStrategy::HuffOnly,
            },
        };
        for (model, label) in [
            (CompressorProfile::Zlib, "zlib"),
            (CompressorProfile::ZlibNg, "zlib_ng"),
            (CompressorProfile::MiniZ, "miniz"),
            (CompressorProfile::Libdeflate, "libdeflate"),
            (CompressorProfile::Windows, "windows"),
            (CompressorProfile::Chromium, "chromium"),
            (CompressorProfile::Custom, "custom"),
        ] {
            let result = model.with_parameters(parameters);
            let report: serde_json::Value =
                serde_json::from_str(&result.to_json().unwrap()).unwrap();
            assert_eq!(
                report,
                serde_json::json!({
                    "reconstruction": {
                        "max_token_count": 2047,
                        "block_type_strategy": "Dynamic",
                        "behavior": {"NoDictionary": {"strategy": "HuffOnly"}}
                    },
                    "model": label
                })
            );
        }
    }

    impl EstimationResult {
        pub fn test_fixture(reconstruction: ReconstructionParameters) -> Self {
            CompressorProfile::Custom.with_parameters(reconstruction)
        }
    }
}
