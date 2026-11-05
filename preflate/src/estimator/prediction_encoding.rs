//! Parameter estimation and prediction-correction encoding for the first chunk.
//! Returns the predictor for continuation chunks and the finalized settings for parameter reports.

use crate::{
    CountNonDefaultActions,
    deflate::deflate_reader::DeflateContents,
    preflate_error::{AddContext, ExitCode, PreflateError, Result},
    preflate_input::PlainText,
    token_predictor::TokenPredictor,
};

use super::estimation_result::EstimationResult;
use super::preflate_parameter_estimator::estimate_preflate_profile;

pub fn estimate_and_encode(
    contents: &DeflateContents,
    plain: &PlainText,
    complete: bool,
    max_chain: u32,
    counter: Option<&mut CountNonDefaultActions>,
    #[cfg(any(test, feature = "diagnostics"))] trace: &mut Option<
        crate::token_predictor::TokenPredictionTrace,
    >,
) -> Result<(Vec<u8>, TokenPredictor, EstimationResult)> {
    #[cfg(any(test, feature = "diagnostics"))]
    if let Some(trace) = trace {
        trace.stage = "estimate";
    }
    let mut result = estimate_preflate_profile(contents, plain).context()?;
    let parameters = result.reconstruction;
    #[cfg(any(test, feature = "diagnostics"))]
    if let Some(trace) = trace {
        trace.parameters = Some(result);
        trace.stage = "chain_limit";
    }
    let required_chain = parameters.budget().map_or(0, |budget| budget.max_chain);
    if required_chain > max_chain {
        return Err(PreflateError::new(
            ExitCode::NoCompressionCandidates,
            format!(
                "max_chain {} is larger than configured max_chain_length {}",
                required_chain, max_chain
            ),
        ));
    }
    let mut predictor = TokenPredictor::from_reconstruction_parameters(parameters);
    #[cfg(any(test, feature = "diagnostics"))]
    {
        if let Some(trace) = trace {
            trace.stage = "predict";
        }
        predictor.trace = trace.take();
    }
    let encoded = crate::stream_processor::encode_first_chunk(
        &mut predictor,
        contents,
        plain,
        complete,
        counter,
    );
    #[cfg(any(test, feature = "diagnostics"))]
    {
        *trace = predictor.trace.take();
    }
    let encoded = encoded?;
    result.reconstruction = predictor.reconstruction_parameters();
    #[cfg(any(test, feature = "diagnostics"))]
    if let Some(trace) = trace {
        trace.parameters = Some(result);
    }
    Ok((encoded, predictor, result))
}
