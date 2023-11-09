mod bit_helper;
mod bit_writer;
mod complevel_estimator;
mod deflate_decoder;
pub mod deflate_encoder;
mod hash_chain;
mod huffman_encoding;
mod huffman_helper;
mod predictor_state;
mod preflate_constants;
mod preflate_input;
mod preflate_parameter_estimator;
mod preflate_parse_config;
mod preflate_stream_info;
mod preflate_token;
mod seq_chain;
mod statistical_codec;
mod token_predictor;
mod tree_predictor;
mod zip_bit_reader;

use anyhow::{self, Context};
use deflate_decoder::DeflateDecoder;
use flate2::{read::GzEncoder, read::ZlibEncoder, Compression};
use std::{
    env,
    fs::File,
    io::{Cursor, Read, Write},
};

mod zip_structs;

use crate::{
    deflate_encoder::DeflateEncoder,
    preflate_parameter_estimator::estimate_preflate_parameters,
    preflate_token::BlockType,
    statistical_codec::{PredictionDecoder, PredictionEncoder, PreflatePredictionEncoder},
    token_predictor::TokenPredictor,
    tree_predictor::{predict_tree_for_block, recreate_tree_for_block},
};

fn analyze_compressed_data(
    compressed_data: &[u8],
    header_crc32: u32,
    deflate_info_dump_level: i32,
    uncompressed_size: &mut u64,
) -> anyhow::Result<()> {
    let mut output_data: Vec<u8> = vec![0; 4096];
    let output_stream = Cursor::new(&mut output_data);

    let mut input_stream = Cursor::new(compressed_data);
    let mut block_decoder = DeflateDecoder::new(&mut input_stream, compressed_data.len() as i64)?;

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

    println!("prediction parameters: {:?}", params_e);

    let mut token_predictor_in = TokenPredictor::new(&block_decoder.get_plain_text(), params_e, 0);

    let mut encoder = PreflatePredictionEncoder::default();

    for i in 0..blocks.len() {
        token_predictor_in
            .predict_block(&blocks[i], &mut encoder)
            .with_context(|| format!("encode_block {}", i))?;

        if blocks[i].block_type == BlockType::DynamicHuff {
            predict_tree_for_block(&blocks[i].huffman_encoding, &blocks[i].freq, &mut encoder)?;
        }
    }

    encoder.encode_non_zero_padding(eof_padding != 0);
    if eof_padding != 0 {
        encoder.encode_value(eof_padding.into(), 8);
    }

    encoder.print();

    let mut decoder = encoder.make_decoder();

    let mut token_predictor_out = TokenPredictor::new(block_decoder.get_plain_text(), params_e, 0);

    let mut output_blocks = Vec::new();

    let mut deflate_encoder = DeflateEncoder::new(block_decoder.get_plain_text());

    while !token_predictor_out.input_eof() {
        let mut block = token_predictor_out.recreate_block(&mut decoder)?;

        if block.block_type == BlockType::DynamicHuff {
            block.huffman_encoding = recreate_tree_for_block(&block.freq, &mut decoder)?;
        }

        deflate_encoder.encode_block(&block, token_predictor_out.input_eof())?;

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

    assert_eq!(blocks.len(), output_blocks.len());
    blocks.iter().zip(output_blocks).all(|(a, b)| {
        assert_eq!(a.block_type, b.block_type);
        //assert_eq!(a.uncompressed_len, b.uncompressed_len);
        assert_eq!(a.padding_bits, b.padding_bits);
        assert_eq!(a.tokens.len(), b.tokens.len());
        assert_eq!(a.freq.literal_codes, b.freq.literal_codes);
        assert_eq!(a.freq.distance_codes, b.freq.distance_codes);
        assert_eq!(a.huffman_encoding, b.huffman_encoding);
        assert_eq!(a.tokens, b.tokens);
        true
    });

    assert_eq!(
        deflate_encoder.get_output().len(),
        compressed_data.len(),
        "re-compressed version should be same"
    );
    assert_eq!(
        deflate_encoder.get_output(),
        compressed_data,
        "re-compressed version should be same"
    );

    let result_crc = crc32fast::hash(block_decoder.get_plain_text());

    if header_crc32 == 0 {
        if deflate_info_dump_level > 0 {
            println!("CRC: {:8X}", result_crc);
        }
    } else if result_crc != header_crc32 {
        println!(
            "Header CRC: {:8X} != Data CRC: {:8X}...Possible CORRUPT FILE.",
            header_crc32, result_crc
        );
    } else if deflate_info_dump_level > 0 {
        println!("Header CRC: {0:8X} == Data CRC: {:8X}", result_crc);
    }

    *uncompressed_size = output_stream.position();

    Ok(())
}

fn main_with_result() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    let mut v = Vec::new();
    {
        let mut file = File::open(&args[1])?;
        file.read_to_end(&mut v)?;
    }

    // Zlib compression with different compression levels
    for level in 1..10 {
        println!("zlib level: {}", level);

        let mut output = Vec::new();
        output.resize(v.len() + 1000, 0);

        let mut output_size = output.len() as u32;

        unsafe {
            let err = libz_sys::compress2(
                output.as_mut_ptr(),
                &mut output_size,
                v.as_ptr(),
                v.len() as u32,
                level,
            );

            output.set_len(output_size as usize);
            println!("output size: {}, err = {}", output.len(), err);
        }

        let minusheader = &output[2..output.len() - 4];

        // write output to file
        {
            let mut file = File::create(format!("zlib_level_{}.bin", level))?;
            file.write_all(minusheader)?;
        }

        if output.len() != 0 {
            do_analyze(&v, minusheader)?;
        }
    }

    // Zlib compression with different compression levels
    for level in 1..10 {
        println!("level: {}", level);
        let mut zlib_encoder: ZlibEncoder<Cursor<&Vec<u8>>> =
            ZlibEncoder::new(Cursor::new(&v), Compression::new(level));
        let mut output = Vec::new();
        zlib_encoder.read_to_end(&mut output).unwrap();

        // skip header and final crc
        do_analyze(&v, &output[2..output.len() - 4])?;
    }

    // Gzip compression with different compression levels
    for level in 3..10 {
        let mut gz_encoder = GzEncoder::new(Cursor::new(&v), Compression::new(level));

        let mut output = Vec::new();
        gz_encoder.read_to_end(&mut output).unwrap();
    }

    Ok(())
}

fn do_analyze(plain_text: &Vec<u8>, compressed_data: &[u8]) -> Result<(), anyhow::Error> {
    let crc = crc32fast::hash(plain_text);
    let mut uncompressed_size = 0;

    analyze_compressed_data(compressed_data, crc, 10, &mut uncompressed_size)
        .with_context(|| "analyze_compressed_data")?;
    Ok(())
}

fn main() {
    match main_with_result() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Error: {0:?}", e);
        }
    }
}
