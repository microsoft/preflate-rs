


use anyhow::{self, Context};
use cabac::{
    debug::{DebugReader, DebugWriter},
    vp8::{VP8Reader, VP8Writer},
};
use flate2::{read::GzEncoder, read::ZlibEncoder, Compression};
use std::{
    env,
    fs::File,
    io::{Cursor, Read, Write}, path::Path,
};

use crate::{
    cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
    process::{read_deflate, write_deflate},
    statistical_codec::{PredictionEncoder, VerifyPredictionDecoder, VerifyPredictionEncoder},
};

#[cfg(test)]
fn analyze_compressed_data_fast(
    compressed_data: &[u8],
    header_crc32: Option<u32>,
    uncompressed_size: &mut u64,
)  {
    let mut buffer = Vec::new();

    let mut cabac_encoder = PredictionEncoderCabac::new(VP8Writer::new(&mut buffer).unwrap());

    let (compressed_processed, _params, plain_text, _original_blocks) =
        read_deflate(compressed_data, &mut cabac_encoder, 1).unwrap();

    if let Some(crc) = header_crc32 {
        let result_crc = crc32fast::hash(&plain_text);
        assert_eq!(result_crc, crc);
    }

    assert_eq!(compressed_processed, compressed_data.len());

    cabac_encoder.finish();

    cabac_encoder.print();

    println!("buffer size: {}", buffer.len());

    let mut cabac_decoder = PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&buffer)).unwrap());

    let (recompressed, _recreated_blocks) =
        write_deflate(&plain_text, &mut cabac_decoder).with_context(|| "write_deflate").unwrap();

    assert!(recompressed[..] == compressed_data[..]);

    *uncompressed_size = plain_text.len() as u64;

}

#[cfg(test)]
fn analyze_compressed_data_verify(
    compressed_data: &[u8],
    header_crc32: u32,
    deflate_info_dump_level: i32,
    uncompressed_size: &mut u64,
) {
    let mut buffer = Vec::new();

    let cabac_encoder = PredictionEncoderCabac::new(DebugWriter::new(&mut buffer).unwrap());
    let debug_encoder = VerifyPredictionEncoder::new(false);

    let mut combined_encoder = (cabac_encoder, debug_encoder);

    let (compressed_processed, _params, plain_text, original_blocks) =
        read_deflate(compressed_data, &mut combined_encoder, 1).with_context(|| "read_deflate").unwrap();

    assert_eq!(compressed_processed, compressed_data.len());

    combined_encoder.finish();

    combined_encoder.0.print();

    let actions = combined_encoder.1.actions();

    println!("buffer size: {}", buffer.len());

    let debug_encoder = VerifyPredictionDecoder::new(actions, false);
    let cabac_decoder = PredictionDecoderCabac::new(DebugReader::new(Cursor::new(&buffer)).unwrap());

    let (recompressed, recreated_blocks) =
        write_deflate(&plain_text, &mut (cabac_decoder, debug_encoder))
            .with_context(|| "write_deflate").unwrap();

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

#[cfg(test)]
fn do_analyze(
    plain_text: &Vec<u8>,
    compressed_data: &[u8],
    verify: bool,
)  {
    let crc = crc32fast::hash(plain_text);
    let mut uncompressed_size = 0;

    if verify {
        analyze_compressed_data_fast(compressed_data, Some(crc), &mut uncompressed_size);
    } else {
        analyze_compressed_data_verify(compressed_data, crc, 1, &mut uncompressed_size);
    }
}

#[cfg(test)]
fn read_file(filename: &str) -> Vec<u8> {
    let filename = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("samples")
        .join(filename.to_owned());
    println!("reading {0}", filename.to_str().unwrap());
    let mut f = File::open(filename).unwrap();

    let mut content = Vec::new();
    f.read_to_end(&mut content).unwrap();

    content
}

#[cfg(test)]
fn verify_zlib(level : usize, v : &Vec<u8>, verify : bool)
{
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

    do_analyze(&v, minusheader, verify);
}

#[cfg(test)]
fn verfify_minzoxide(level : usize, v : &Vec<u8>, verify : bool)
{
    println!("Flate2 level: {}", level);
    let mut zlib_encoder: ZlibEncoder<Cursor<&Vec<u8>>> =
        ZlibEncoder::new(Cursor::new(&v), Compression::new(level as u32));
    let mut output = Vec::new();
    zlib_encoder.read_to_end(&mut output).unwrap();

    let minusheader = &output[2..output.len() - 4];
    do_analyze(&v, minusheader, verify);
}

#[test]
fn test_zlib()
{
    let v = read_file("wrong", ".bin");

    // Zlib compression with different compression levels
    for level in 1..10 {
        verify_zlib(level, &v, true);
        verfify_minzoxide(level, &v, false);
    }
}