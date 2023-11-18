use std::io::Cursor;

use crate::{
    deflate_reader::DeflateReader,
    deflate_writer::DeflateWriter,
    huffman_calc::HufftreeBitCalc,
    preflate_error::PreflateError,
    preflate_parameter_estimator::{estimate_preflate_parameters, PreflateParameters},
    preflate_token::{BlockType, PreflateTokenBlock},
    statistical_codec::{CodecMisprediction, PredictionDecoder, PredictionEncoder},
    token_predictor::TokenPredictor,
    tree_predictor::{predict_tree_for_block, recreate_tree_for_block},
};

/// takes a deflate compressed stream, analyzes it, decoompresses it, and records
/// any differences in the encoder codec
pub fn read_deflate<E: PredictionEncoder>(
    compressed_data: &[u8],
    encoder: &mut E,
    deflate_info_dump_level: u32,
) -> Result<(usize, PreflateParameters, Vec<u8>, Vec<PreflateTokenBlock>), PreflateError> {
    let mut input_stream = Cursor::new(compressed_data);
    let mut block_decoder = DeflateReader::new(&mut input_stream, compressed_data.len() as i64);

    let mut blocks = Vec::new();
    let mut last = false;
    while !last {
        let block = block_decoder
            .read_block(&mut last)
            .map_err(|e| PreflateError::ReadBlock(blocks.len(), e))?;

        if deflate_info_dump_level > 0 {
            // Log information about this deflate compressed block
            println!("Block: tokens={}", block.tokens.len());
        }

        blocks.push(block);
    }

    let eof_padding = block_decoder.read_eof_padding();

    let params_e = estimate_preflate_parameters(block_decoder.get_plain_text(), &blocks);

    params_e.write(encoder);

    if deflate_info_dump_level > 0 {
        println!("prediction parameters: {:?}", params_e);
    }

    let mut token_predictor_in = TokenPredictor::new(&block_decoder.get_plain_text(), &params_e, 0);

    for i in 0..blocks.len() {
        if token_predictor_in.input_eof() {
            encoder.encode_misprediction(CodecMisprediction::EOFMisprediction, true);
        }

        token_predictor_in
            .predict_block(&blocks[i], encoder, i == blocks.len() - 1)
            .map_err(|e| PreflateError::PredictBlock(i, e))?;

        if blocks[i].block_type == BlockType::DynamicHuff {
            predict_tree_for_block(
                &blocks[i].huffman_encoding,
                &blocks[i].freq,
                encoder,
                HufftreeBitCalc::Zlib,
            )
            .map_err(|e| PreflateError::PredictTree(i, e))?;
        }
    }

    assert!(token_predictor_in.input_eof());

    encoder.encode_misprediction(CodecMisprediction::EOFMisprediction, false);

    encoder.encode_misprediction(CodecMisprediction::NonZeroPadding, eof_padding != 0);
    if eof_padding != 0 {
        encoder.encode_value(eof_padding.into(), 8);
    }

    let plain_text = block_decoder.move_plain_text();
    let amount_processed = input_stream.position() as usize;

    Ok((amount_processed, params_e, plain_text, blocks))
}

pub fn write_deflate<D: PredictionDecoder>(
    plain_text: &[u8],
    decoder: &mut D,
) -> Result<(Vec<u8>, Vec<PreflateTokenBlock>), PreflateError> {
    let params = PreflateParameters::read(decoder);
    let mut token_predictor = TokenPredictor::new(plain_text, &params, 0);

    let mut output_blocks = Vec::new();

    let mut deflate_encoder = DeflateWriter::new(&plain_text);

    let mut is_eof = token_predictor.input_eof()
        && !decoder.decode_misprediction(CodecMisprediction::EOFMisprediction);

    while !is_eof {
        let mut block = token_predictor
            .recreate_block(decoder)
            .map_err(|e| PreflateError::RecreateBlock(output_blocks.len(), e))?;

        if block.block_type == BlockType::DynamicHuff {
            block.huffman_encoding =
                recreate_tree_for_block(&block.freq, decoder, HufftreeBitCalc::Zlib)
                    .map_err(|e| PreflateError::RecreateTree(output_blocks.len(), e))?;
        }

        is_eof = token_predictor.input_eof()
            && !decoder.decode_misprediction(CodecMisprediction::EOFMisprediction);

        deflate_encoder
            .encode_block(&block, is_eof)
            .map_err(|e| PreflateError::EncodeBlock(output_blocks.len(), e))?;

        output_blocks.push(block);
    }

    // flush the last byte, which may be incomplete and normally
    // padded with zeros, but maybe not
    let padding = if decoder.decode_misprediction(CodecMisprediction::NonZeroPadding) {
        decoder.decode_value(8) as u8
    } else {
        0
    };
    deflate_encoder.flush_with_padding(padding);

    Ok((deflate_encoder.detach_output(), output_blocks))
}
