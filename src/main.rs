mod bit_helper;
mod huffman_decoder;
mod huffman_helper;
mod minz_compress;
mod preflate_block_decoder;
mod preflate_complevel_estimator;
mod preflate_constants;
mod preflate_hash_chain;
mod preflate_input;
mod preflate_parameter_estimator;
mod preflate_parse_config;
mod preflate_predictor_state;
mod preflate_seq_chain;
mod preflate_statistical_codec;
mod preflate_statistical_model;
mod preflate_stream_info;
mod preflate_token;
mod preflate_token_predictor;
mod preflate_tree_predictor;
mod zip_bit_reader;

use anyhow::{self, Context};
use byteorder::{LittleEndian, ReadBytesExt};
use flate2::{read::GzEncoder, read::ZlibEncoder, Compression};
use preflate_block_decoder::PreflateBlockDecoder;
use std::{
    env,
    fs::File,
    io::{BufReader, Cursor, Read, Seek, SeekFrom, Write},
};

mod zip_structs;

use crate::{
    minz_compress::estimate_zlib_comp_level,
    preflate_parameter_estimator::estimate_preflate_parameters,
    preflate_statistical_codec::PreflatePredictionEncoder,
    preflate_statistical_model::PreflateStatisticsCounter,
    preflate_token_predictor::PreflateTokenPredictor,
    zip_structs::{
        Zip64ExtendedInformation, ZipCentralDirectoryFileHeader, ZipEndOfCentralDirectoryRecord,
        ZipExtendedInformationHeader, ZipLocalFileHeader,
    },
};

fn analyze_compressed_data<R: Read + Seek>(
    binary_reader: &mut R,
    compressed_size_in_bytes: u64,
    header_crc32: u32,
    deflate_info_dump_level: i32,
    uncompressed_size: &mut u64,
) -> anyhow::Result<()> {
    let mut output_data: Vec<u8> = vec![0; 4096];
    let output_stream = Cursor::new(&mut output_data);

    let mut block_decoder =
        PreflateBlockDecoder::new(binary_reader, compressed_size_in_bytes as i64)?;

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

    let params_e = estimate_preflate_parameters(&block_decoder.output, 0, &blocks);
    println!("prediction parameters: w {}, c {}, m {}, zlib {}, farL3M {}, very far M {}, M2S {}, log2CD {}",
            params_e.window_bits, params_e.comp_level, params_e.mem_level,
            params_e.zlib_compatible, params_e.far_len3_matches_detected,
            params_e.very_far_matches_detected, params_e.matches_to_start_detected,
            params_e.log2_of_max_chain_depth_m1);

    let mut counterE = PreflateStatisticsCounter::default();

    let mut tokenPredictorIn = PreflateTokenPredictor::new(&block_decoder.output, &params_e, 0);

    let mut tokenPredictorOut = PreflateTokenPredictor::new(&block_decoder.output, &params_e, 0);

    for i in 0..blocks.len() {
        let analysis = tokenPredictorIn
            .analyze_block(&blocks[i])
            .with_context(|| format!("analyze_block {}", i))?;
        analysis.update_counters(&mut counterE);

        let mut encoder = PreflatePredictionEncoder::new();
        analysis.encode_block(&mut encoder);

        let mut decoder = encoder.make_decoder();

        let outblock = tokenPredictorOut.decode_block(&mut decoder)?;

        // assert the decoded blocks are the same as the encoded ones
        assert_eq!(blocks[i].tokens, outblock.tokens, "block {}", i);
    }

    counterE.token.print();

    let result_crc = crc32fast::hash(&block_decoder.output);

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
    for level in 9..10 {
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

        let minusheader = &output[2..output.len()];

        // write output to file
        {
            let mut file = File::create(format!("zlib_level_{}.bin", level))?;
            file.write_all(minusheader)?;
        }

        if output.len() != 0 {
            do_analyze(&v, minusheader)?;
        }

        return Ok(());
    }

    // Zlib compression with different compression levels
    for level in 0..10 {
        println!("level: {}", level);
        let mut zlib_encoder: ZlibEncoder<Cursor<&Vec<u8>>> =
            ZlibEncoder::new(Cursor::new(&v), Compression::new(level));
        let mut output = Vec::new();
        zlib_encoder.read_to_end(&mut output).unwrap();

        do_analyze(&v, &output[2..])?;
    }

    // Gzip compression with different compression levels
    for level in 3..10 {
        let mut gz_encoder = GzEncoder::new(Cursor::new(&v), Compression::new(level));

        let mut output = Vec::new();
        gz_encoder.read_to_end(&mut output).unwrap();
    }

    Ok(())
}

fn do_analyze(v: &Vec<u8>, output: &[u8]) -> Result<(), anyhow::Error> {
    let crc = crc32fast::hash(v);
    let compressed_size = output.len() as u64;
    let mut uncompressed_size = 0;
    let mut reader = Cursor::new(&output);
    analyze_compressed_data(
        &mut reader,
        compressed_size - 2,
        crc,
        10,
        &mut uncompressed_size,
    )
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
