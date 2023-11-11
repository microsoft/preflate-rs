use std::io::Cursor;

use anyhow::{Context, Result};

use crate::{
    deflate_reader::DeflateReader,
    deflate_writer::DeflateWriter,
    preflate_parameter_estimator::{estimate_preflate_parameters, PreflateParameters},
    preflate_token::BlockType,
    statistical_codec::{PredictionDecoder, PredictionEncoder},
    token_predictor::TokenPredictor,
    tree_predictor::{predict_tree_for_block, recreate_tree_for_block},
};

/// takes a deflate compressed stream, analyzes it, decoompresses it, and records
/// any differences in the encoder codec
pub fn read_deflate<E: PredictionEncoder>(
    compressed_data: &[u8],
    encoder: &mut E,
    deflate_info_dump_level: u32,
) -> Result<(usize, PreflateParameters, Vec<u8>)> {
    let mut input_stream = Cursor::new(compressed_data);
    let mut block_decoder = DeflateReader::new(&mut input_stream, compressed_data.len() as i64)?;

    let mut blocks = Vec::new();
    let mut last = false;
    while !last {
        let block = block_decoder
            .read_block(&mut last)
            .with_context(|| "read block")?;

        if deflate_info_dump_level > 0 {
            // Log information about this deflate compressed block
            println!("Block: tokens={}", block.tokens.len());
        }

        blocks.push(block);
    }

    let eof_padding = block_decoder.read_eof_padding();

    let params_e = estimate_preflate_parameters(block_decoder.get_plain_text(), &blocks);

    if deflate_info_dump_level > 0 {
        println!("prediction parameters: {:?}", params_e);
    }

    let mut token_predictor_in = TokenPredictor::new(&block_decoder.get_plain_text(), &params_e, 0);

    for i in 0..blocks.len() {
        if token_predictor_in.input_eof() {
            encoder.encode_eof_misprediction(true);
        }

        token_predictor_in
            .predict_block(&blocks[i], encoder, i == blocks.len() - 1)
            .with_context(|| format!("encode_block {}", i))?;

        if blocks[i].block_type == BlockType::DynamicHuff {
            predict_tree_for_block(&blocks[i].huffman_encoding, &blocks[i].freq, encoder)?;
        }
    }

    assert!(token_predictor_in.input_eof());

    encoder.encode_eof_misprediction(false);

    encoder.encode_non_zero_padding(eof_padding != 0);
    if eof_padding != 0 {
        encoder.encode_value(eof_padding.into(), 8);
    }

    let plain_text = block_decoder.move_plain_text();
    let amount_processed = input_stream.position() as usize;

    Ok((amount_processed, params_e, plain_text))
}

pub fn write_deflate<D: PredictionDecoder>(
    plain_text: &[u8],
    params: &PreflateParameters,
    decoder: &mut D,
) -> Result<Vec<u8>> {
    let mut token_predictor = TokenPredictor::new(plain_text, params, 0);

    let mut output_blocks = Vec::new();

    let mut deflate_encoder = DeflateWriter::new(&plain_text);

    loop {
        if token_predictor.input_eof() && !decoder.decode_eof_misprediction() {
            break;
        }

        let mut block = token_predictor.recreate_block(decoder)?;

        if block.block_type == BlockType::DynamicHuff {
            block.huffman_encoding = recreate_tree_for_block(&block.freq, decoder)?;
        }

        deflate_encoder.encode_block(&block, token_predictor.input_eof())?;

        output_blocks.push(block);
    }

    // flush the last byte, which may be incomplete and normally
    // padded with zeros, but maybe not
    let padding = if decoder.decode_non_zero_padding() {
        decoder.decode_value(8) as u8
    } else {
        0
    };
    deflate_encoder.flush_with_padding(padding);

    Ok(deflate_encoder.detach_output())
}
