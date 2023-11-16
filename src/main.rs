mod bit_helper;
mod bit_writer;
mod cabac_codec;
mod complevel_estimator;
mod deflate_reader;
mod deflate_writer;
mod hash_chain;
mod huffman_calc;
mod huffman_encoding;
mod huffman_helper;
mod predictor_state;
mod preflate_constants;
mod preflate_input;
mod preflate_parameter_estimator;
mod preflate_parse_config;
mod preflate_stream_info;
mod preflate_token;
mod process;
mod seq_chain;
mod statistical_codec;
mod token_predictor;
mod tree_predictor;
mod zip_bit_reader;

use anyhow::{self, Context};
use flate2::{read::GzEncoder, read::ZlibEncoder, Compression};
use std::{
    env,
    fs::File,
    io::{Cursor, Read, Write},
};

mod zip_structs;

use crate::{
    cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
    process::{read_deflate, write_deflate},
    statistical_codec::PreflatePredictionEncoder,
};

fn analyze_compressed_data_old(
    compressed_data: &[u8],
    header_crc32: u32,
    deflate_info_dump_level: i32,
    uncompressed_size: &mut u64,
) -> anyhow::Result<()> {
    let mut encoder = PreflatePredictionEncoder::default();

    let (compressed_processed, params, plain_text, original_blocks) =
        read_deflate(compressed_data, &mut encoder, 1).with_context(|| "read_deflate")?;

    assert_eq!(compressed_processed, compressed_data.len());

    encoder.print();

    let mut decoder = encoder.make_decoder();

    let (recompressed, recreated_blocks) =
        write_deflate(&plain_text, &params, &mut decoder).with_context(|| "write_deflate")?;

    assert_eq!(original_blocks.len(), recreated_blocks.len());
    original_blocks
        .iter()
        .zip(recreated_blocks)
        .enumerate()
        .for_each(|(index, (a, b))| {
            assert_eq!(a.block_type, b.block_type, "block type differs {index}");
            //assert_eq!(a.uncompressed_len, b.uncompressed_len);
            assert_eq!(
                a.padding_bits, b.padding_bits,
                "padding bits differ {index}"
            );
            compare(&a.tokens, &b.tokens);
            assert_eq!(
                a.tokens.len(),
                b.tokens.len(),
                "token length differs {index}"
            );
            assert!(a.tokens == b.tokens, "tokens differ {index}");
            assert_eq!(
                a.freq.literal_codes, b.freq.literal_codes,
                "literal code freq differ {index}"
            );
            assert_eq!(
                a.freq.distance_codes, b.freq.distance_codes,
                "distance code freq differ {index}"
            );
            assert_eq!(
                a.huffman_encoding, b.huffman_encoding,
                "huffman_encoding differs {index}"
            );
        });

    assert_eq!(
        recompressed.len(),
        compressed_data.len(),
        "re-compressed version should be same (length)"
    );
    assert!(
        &recompressed[..] == compressed_data,
        "re-compressed version should be same (content)"
    );

    let result_crc = crc32fast::hash(&plain_text);

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

    *uncompressed_size = plain_text.len() as u64;

    Ok(())
}

fn analyze_compressed_data(
    compressed_data: &[u8],
    header_crc32: u32,
    deflate_info_dump_level: i32,
    uncompressed_size: &mut u64,
) -> anyhow::Result<()> {
    let mut buffer = Vec::new();

    let mut encoder = PredictionEncoderCabac::new(&mut buffer);

    let (compressed_processed, params, plain_text, original_blocks) =
        read_deflate(compressed_data, &mut encoder, 1).with_context(|| "read_deflate")?;

    assert_eq!(compressed_processed, compressed_data.len());

    encoder.finish();

    encoder.print();

    println!("buffer size: {}", buffer.len());

    let mut decoder = PredictionDecoderCabac::new(Cursor::new(&buffer));

    let (recompressed, recreated_blocks) =
        write_deflate(&plain_text, &params, &mut decoder).with_context(|| "write_deflate")?;

    assert_eq!(original_blocks.len(), recreated_blocks.len());
    original_blocks
        .iter()
        .zip(recreated_blocks)
        .enumerate()
        .for_each(|(index, (a, b))| {
            assert_eq!(a.block_type, b.block_type, "block type differs {index}");
            //assert_eq!(a.uncompressed_len, b.uncompressed_len);
            assert_eq!(
                a.padding_bits, b.padding_bits,
                "padding bits differ {index}"
            );
            compare(&a.tokens, &b.tokens);
            assert_eq!(
                a.tokens.len(),
                b.tokens.len(),
                "token length differs {index}"
            );
            assert!(a.tokens == b.tokens, "tokens differ {index}");
            assert_eq!(
                a.freq.literal_codes, b.freq.literal_codes,
                "literal code freq differ {index}"
            );
            assert_eq!(
                a.freq.distance_codes, b.freq.distance_codes,
                "distance code freq differ {index}"
            );
            assert_eq!(
                a.huffman_encoding, b.huffman_encoding,
                "huffman_encoding differs {index}"
            );
        });

    assert_eq!(
        recompressed.len(),
        compressed_data.len(),
        "re-compressed version should be same (length)"
    );
    assert!(
        &recompressed[..] == compressed_data,
        "re-compressed version should be same (content)"
    );

    let result_crc = crc32fast::hash(&plain_text);

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

    *uncompressed_size = plain_text.len() as u64;

    Ok(())
}

fn compare<T: PartialEq + std::fmt::Debug>(a: &[T], b: &[T]) {
    if a.len() != b.len() {
        panic!("lengths differ");
    }

    for i in 0..a.len() {
        if a[i] != b[i] {
            panic!("index {} differs ({:?},{:?})", i, a[i], b[i]);
        }
    }
}

fn main_with_result() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    let mut v = Vec::new();
    {
        let mut file = File::open(&args[1])?;
        file.read_to_end(&mut v)?;
    }

    let onlylevel: Option<u32> = None;

    // Zlib compression with different compression levels
    for level in 1..10 {
        if let Some(x) = onlylevel {
            if x != level {
                continue;
            }
        }

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
                level as i32,
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
        if let Some(x) = onlylevel {
            if x != level + 100 {
                continue;
            }
        }

        println!("Flate2 level: {}", level);
        let mut zlib_encoder: ZlibEncoder<Cursor<&Vec<u8>>> =
            ZlibEncoder::new(Cursor::new(&v), Compression::new(level));
        let mut output = Vec::new();
        zlib_encoder.read_to_end(&mut output).unwrap();

        // skip header and final crc
        do_analyze(&v, &output[2..output.len() - 4])?;
    }
    /*
        // Gzip compression with different compression levels
        for level in 3..10 {
            let mut gz_encoder = GzEncoder::new(Cursor::new(&v), Compression::new(level));

            let mut output = Vec::new();
            gz_encoder.read_to_end(&mut output).unwrap();
        }
    */
    Ok(())
}

fn do_analyze(plain_text: &Vec<u8>, compressed_data: &[u8]) -> Result<(), anyhow::Error> {
    let crc = crc32fast::hash(plain_text);
    let mut uncompressed_size = 0;

    analyze_compressed_data_old(compressed_data, crc, 10, &mut uncompressed_size)?;
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
