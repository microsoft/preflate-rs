use byteorder::ReadBytesExt;
use cabac::vp8::{VP8Reader, VP8Writer};
use std::io::{Cursor, Read, Write};

use crate::{
    cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
    idat_parse::{recreate_idat, IdatContents},
    preflate_error::PreflateError,
    preflate_input::PreflateInput,
    preflate_parameter_estimator::{estimate_preflate_parameters, PreflateParameters},
    process::{decode_mispredictions, encode_mispredictions, parse_deflate},
    scan_deflate::{split_into_deflate_streams, BlockChunk},
    statistical_codec::PredictionEncoder,
};

const COMPRESSED_WRAPPER_VERSION_1: u8 = 1;

/// literal chunks are just copied to the output
const LITERAL_CHUNK: u8 = 0;

/// zlib compressed chunks are zlib compressed
const DEFLATE_STREAM: u8 = 1;

/// PNG chunks are IDAT chunks that are zlib compressed
const PNG_COMPRESSED: u8 = 2;

pub fn write_varint(destination: &mut impl Write, value: u32) -> std::io::Result<()> {
    let mut value = value;
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        destination.write_all(&[byte])?;
        if value == 0 {
            break;
        }
    }

    Ok(())
}

pub fn read_varint(source: &mut impl Read) -> std::io::Result<u32> {
    let mut result = 0;
    let mut shift = 0;
    loop {
        let mut byte = [0u8; 1];
        source.read_exact(&mut byte)?;
        let byte = byte[0];
        result |= ((byte & 0x7F) as u32) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok(result)
}

#[test]
fn test_variant_roundtrip() {
    let values = [
        0, 1, 127, 128, 255, 256, 16383, 16384, 2097151, 2097152, 268435455, 268435456, 4294967295,
    ];

    let mut buffer = Vec::new();
    for &v in values.iter() {
        write_varint(&mut buffer, v).unwrap();
    }

    let mut buffer = &buffer[..];

    for &v in values.iter() {
        assert_eq!(v, read_varint(&mut buffer).unwrap());
    }
}

fn write_chunk_block(
    block: BlockChunk,
    literal_data: &[u8],
    destination: &mut impl Write,
) -> std::io::Result<usize> {
    match block {
        BlockChunk::Literal(content_size) => {
            destination.write_all(&[LITERAL_CHUNK])?;
            write_varint(destination, content_size as u32)?;
            destination.write_all(&literal_data[0..content_size])?;

            Ok(content_size)
        }

        BlockChunk::DeflateStream(res) => {
            destination.write_all(&[DEFLATE_STREAM])?;
            write_varint(destination, res.plain_text.len() as u32)?;
            destination.write_all(&res.plain_text)?;
            write_varint(destination, res.prediction_corrections.len() as u32)?;
            destination.write_all(&res.prediction_corrections)?;

            Ok(res.compressed_size)
        }

        BlockChunk::IDATDeflate(idat, res) => {
            destination.write_all(&[PNG_COMPRESSED])?;
            idat.write_to_bytestream(destination)?;
            write_varint(destination, res.plain_text.len() as u32)?;
            destination.write_all(&res.plain_text)?;
            write_varint(destination, res.prediction_corrections.len() as u32)?;
            destination.write_all(&res.prediction_corrections)?;

            Ok(idat.total_chunk_length)
        }
    }
}

fn read_chunk_block(
    source: &mut impl Read,
    destination: &mut impl Write,
) -> std::result::Result<bool, PreflateError> {
    let mut buffer = [0];
    if source.read(&mut buffer)? == 0 {
        return Ok(false);
    }

    match buffer[0] {
        LITERAL_CHUNK => {
            let mut length = read_varint(source)? as usize;
            while length > 0 {
                let mut buffer = [0; 65536];
                let amount_to_read = std::cmp::min(buffer.len(), length) as usize;

                source.read_exact(&mut buffer[0..amount_to_read])?;
                destination.write_all(&buffer[0..amount_to_read])?;

                length -= amount_to_read;
            }
        }
        DEFLATE_STREAM | PNG_COMPRESSED => {
            let idat = if buffer[0] == PNG_COMPRESSED {
                Some(IdatContents::read_from_bytestream(source)?)
            } else {
                None
            };

            let length = read_varint(source)?;
            let mut segment = vec![0; length as usize];
            source.read_exact(&mut segment)?;

            let corrections_length = read_varint(source)?;
            let mut corrections = vec![0; corrections_length as usize];
            source.read_exact(&mut corrections)?;

            let recompressed = recompress_deflate_stream(&segment, &corrections)?;

            if let Some(idat) = idat {
                recreate_idat(&idat, &recompressed[..], destination)
                    .map_err(|_e| PreflateError::InvalidCompressedWrapper)?;
            } else {
                destination.write_all(&recompressed)?;
            }
        }
        _ => return Err(PreflateError::InvalidCompressedWrapper),
    }
    Ok(true)
}

#[test]
fn roundtrip_chunk_block_literal() {
    let mut buffer = Vec::new();

    write_chunk_block(BlockChunk::Literal(5), b"hello", &mut buffer).unwrap();

    let mut read_cursor = std::io::Cursor::new(buffer);
    let mut destination = Vec::new();
    read_chunk_block(&mut read_cursor, &mut destination).unwrap();

    assert!(destination == b"hello");
}

#[test]
fn roundtrip_chunk_block_deflate() {
    let contents = crate::process::read_file("compressed_zlib_level1.deflate");
    let results = decompress_deflate_stream(&contents, true, 1).unwrap();

    let mut buffer = Vec::new();

    write_chunk_block(BlockChunk::DeflateStream(results), &[], &mut buffer).unwrap();

    let mut read_cursor = std::io::Cursor::new(buffer);
    let mut destination = Vec::new();
    read_chunk_block(&mut read_cursor, &mut destination).unwrap();

    assert!(destination == contents);
}

#[test]
fn roundtrip_chunk_block_png() {
    let f = crate::process::read_file("treegdi.png");

    // we know the first IDAT chunk starts at 83 (avoid testing the scan_deflate code in a unit teast)
    let (idat_contents, deflate_stream) = crate::idat_parse::parse_idat(&f[83..], 1).unwrap();
    let results = decompress_deflate_stream(&deflate_stream, true, 1).unwrap();

    let total_chunk_length = idat_contents.total_chunk_length;

    let mut buffer = Vec::new();

    write_chunk_block(
        BlockChunk::IDATDeflate(idat_contents, results),
        &[],
        &mut buffer,
    )
    .unwrap();

    let mut read_cursor = std::io::Cursor::new(buffer);
    let mut destination = Vec::new();
    read_chunk_block(&mut read_cursor, &mut destination).unwrap();

    assert!(destination == &f[83..83 + total_chunk_length]);
}

/// scans for deflate streams in a zlib compressed file, decompresses the streams and
/// returns an uncompressed file that can then be recompressed using a better algorithm.
/// This can then be passed back into recreated_zlib_chunks to recreate the exact original file.
pub fn expand_zlib_chunks(
    compressed_data: &[u8],
    loglevel: u32,
) -> std::result::Result<Vec<u8>, PreflateError> {
    let mut locations_found = Vec::new();

    split_into_deflate_streams(compressed_data, &mut locations_found, loglevel);
    if loglevel > 0 {
        println!("locations found: {:?}", locations_found);
    }

    let mut plain_text = Vec::new();
    plain_text.push(COMPRESSED_WRAPPER_VERSION_1); // version 1 of format. Definitely will improved.

    let mut index = 0;
    for loc in locations_found {
        index += write_chunk_block(loc, &compressed_data[index..], &mut plain_text)?;
    }

    Ok(plain_text)
}

/// takes a binary chunk of data that was created by expand_zlib_chunks and recompresses it back to its
/// original form.
pub fn recreated_zlib_chunks(
    source: &mut impl Read,
    destination: &mut impl Write,
) -> std::result::Result<(), PreflateError> {
    let version = source.read_u8()?;
    if version != COMPRESSED_WRAPPER_VERSION_1 {
        return Err(PreflateError::InvalidCompressedWrapper);
    }

    loop {
        if !read_chunk_block(source, destination)? {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
fn roundtrip_deflate_chunks(filename: &str) {
    let f = crate::process::read_file(filename);

    let expanded = expand_zlib_chunks(&f, 1).unwrap();

    let mut read_cursor = std::io::Cursor::new(expanded);

    let mut destination = Vec::new();
    recreated_zlib_chunks(&mut read_cursor, &mut destination).unwrap();

    assert_eq!(destination.len(), f.len());
    for i in 0..destination.len() {
        assert_eq!(destination[i], f[i], "Mismatch at index {}", i);
    }
    assert!(destination == f);
}

#[test]
fn roundtrip_skip_length_crash() {
    roundtrip_deflate_chunks("skiplengthcrash.bin");
}

#[test]
fn roundtrip_png_chunks() {
    roundtrip_deflate_chunks("treegdi.png");
}

#[test]
fn roundtrip_zip_chunks() {
    roundtrip_deflate_chunks("samplezip.zip");
}

#[test]
fn roundtrip_gz_chunks() {
    roundtrip_deflate_chunks("sample1.bin.gz");
}

#[test]
fn roundtrip_pdf_chunks() {
    roundtrip_deflate_chunks("starcontrol.samplesave");
}

/// result of decompress_deflate_stream
pub struct DecompressResult {
    /// the plaintext that was decompressed from the stream
    pub plain_text: Vec<u8>,

    /// the extra data that is needed to reconstruct the deflate stream exactly as it was written
    pub prediction_corrections: Vec<u8>,

    /// the number of bytes that were processed from the compressed stream (this will be exactly the
    /// data that will be recreated using the cabac_encoded data)
    pub compressed_size: usize,

    /// the parameters that were used to compress the stream (informational)
    pub parameters: PreflateParameters,
}

impl core::fmt::Debug for DecompressResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DecompressResult {{ plain_text: {}, prediction_corrections: {}, compressed_size: {} }}", self.plain_text.len(), self.prediction_corrections.len(), self.compressed_size)
    }
}

/// decompresses a deflate stream and returns the plaintext and cabac_encoded data that can be used to reconstruct it
pub fn decompress_deflate_stream(
    compressed_data: &[u8],
    verify: bool,
    loglevel: u32,
) -> Result<DecompressResult, PreflateError> {
    let mut cabac_encoded = Vec::new();

    let mut cabac_encoder =
        PredictionEncoderCabac::new(VP8Writer::new(&mut cabac_encoded).unwrap());

    let contents = parse_deflate(compressed_data, 0)?;

    //process::write_file("c:\\temp\\lastop.deflate", compressed_data);
    //process::write_file("c:\\temp\\lastop.bin", contents.plain_text.as_slice());

    let params = estimate_preflate_parameters(&contents.plain_text, &contents.blocks)
        .map_err(PreflateError::AnalyzeFailed)?;

    if loglevel > 0 {
        println!("params: {:?}", params);
    }

    params.write(&mut cabac_encoder);
    encode_mispredictions(&contents, &params, &mut cabac_encoder)?;

    cabac_encoder.finish();

    if verify {
        let mut cabac_decoder =
            PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&cabac_encoded[..])).unwrap());

        let reread_params = PreflateParameters::read(&mut cabac_decoder)
            .map_err(PreflateError::InvalidPredictionData)?;
        assert_eq!(params, reread_params);

        let (recompressed, _recreated_blocks) = decode_mispredictions(
            &reread_params,
            PreflateInput::new(&contents.plain_text),
            &mut cabac_decoder,
        )?;

        if recompressed[..] != compressed_data[..contents.compressed_size] {
            return Err(PreflateError::Mismatch(anyhow::anyhow!(
                "recompressed data does not match original"
            )));
        }
    }

    Ok(DecompressResult {
        plain_text: contents.plain_text,
        prediction_corrections: cabac_encoded,
        compressed_size: contents.compressed_size,
        parameters: params,
    })
}

/// recompresses a deflate stream using the cabac_encoded data that was returned from decompress_deflate_stream
pub fn recompress_deflate_stream(
    plain_text: &[u8],
    prediction_corrections: &[u8],
) -> Result<Vec<u8>, PreflateError> {
    let mut cabac_decoder =
        PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(prediction_corrections)).unwrap());

    let params = PreflateParameters::read(&mut cabac_decoder)
        .map_err(PreflateError::InvalidPredictionData)?;
    let (recompressed, _recreated_blocks) =
        decode_mispredictions(&params, PreflateInput::new(plain_text), &mut cabac_decoder)?;
    Ok(recompressed)
}

/// decompresses a deflate stream and returns the plaintext and cabac_encoded data that can be used to reconstruct it
/// This version uses DebugWriter and DebugReader, which are slower but can be used to debug the cabac encoding errors.
#[cfg(test)]
pub fn decompress_deflate_stream_assert(
    compressed_data: &[u8],
    verify: bool,
) -> Result<DecompressResult, PreflateError> {
    use cabac::debug::{DebugReader, DebugWriter};

    let mut cabac_encoded = Vec::new();

    let mut cabac_encoder =
        PredictionEncoderCabac::new(DebugWriter::new(&mut cabac_encoded).unwrap());

    let contents = parse_deflate(compressed_data, 0)?;

    let params = estimate_preflate_parameters(&contents.plain_text, &contents.blocks)
        .map_err(PreflateError::AnalyzeFailed)?;

    params.write(&mut cabac_encoder);
    encode_mispredictions(&contents, &params, &mut cabac_encoder)?;

    assert_eq!(contents.compressed_size, compressed_data.len());
    cabac_encoder.finish();

    if verify {
        let mut cabac_decoder =
            PredictionDecoderCabac::new(DebugReader::new(Cursor::new(&cabac_encoded)).unwrap());

        let params = PreflateParameters::read(&mut cabac_decoder)
            .map_err(PreflateError::InvalidPredictionData)?;
        let (recompressed, _recreated_blocks) = decode_mispredictions(
            &params,
            PreflateInput::new(&contents.plain_text),
            &mut cabac_decoder,
        )?;

        if recompressed[..] != compressed_data[..] {
            return Err(PreflateError::Mismatch(anyhow::anyhow!(
                "recompressed data does not match original"
            )));
        }
    }

    Ok(DecompressResult {
        plain_text: contents.plain_text,
        prediction_corrections: cabac_encoded,
        compressed_size: contents.compressed_size,
        parameters: params,
    })
}

/// recompresses a deflate stream using the cabac_encoded data that was returned from decompress_deflate_stream
/// This version uses DebugWriter and DebugReader, which are slower and don't compress but can be used to debug the cabac encoding errors.
#[cfg(test)]
pub fn recompress_deflate_stream_assert(
    plain_text: &[u8],
    prediction_corrections: &[u8],
) -> Result<Vec<u8>, PreflateError> {
    use cabac::debug::DebugReader;

    let mut cabac_decoder = PredictionDecoderCabac::new(
        DebugReader::new(Cursor::new(&prediction_corrections)).unwrap(),
    );

    let params = PreflateParameters::read(&mut cabac_decoder)
        .map_err(PreflateError::InvalidPredictionData)?;

    let (recompressed, _recreated_blocks) =
        decode_mispredictions(&params, PreflateInput::new(plain_text), &mut cabac_decoder)?;
    Ok(recompressed)
}

#[test]
fn verify_zip_compress() {
    use crate::process::read_file;
    let v = read_file("samplezip.zip");

    let expanded = expand_zlib_chunks(&v, 1).unwrap();

    let mut recompressed = Vec::new();
    recreated_zlib_chunks(&mut Cursor::new(expanded), &mut recompressed).unwrap();

    assert!(v == recompressed);
}

#[test]
fn verify_roundtrip_zlib() {
    for i in 0..9 {
        verify_file(&format!("compressed_zlib_level{}.deflate", i));
    }
}

#[test]
fn verify_roundtrip_flate2() {
    for i in 0..9 {
        verify_file(&format!("compressed_flate2_level{}.deflate", i));
    }
}

#[test]
fn verify_roundtrip_libdeflate() {
    for i in 0..9 {
        verify_file(&format!("compressed_libdeflate_level{}.deflate", i));
    }
}

#[cfg(test)]
fn verify_file(filename: &str) {
    use crate::process::read_file;
    let v = read_file(filename);

    let r = decompress_deflate_stream(&v, true, 1).unwrap();
    let recompressed = recompress_deflate_stream(&r.plain_text, &r.prediction_corrections).unwrap();
    assert!(v == recompressed);
}

/// expands the Zlib compressed streams in the data and then recompresses the result
/// with Zstd with the maximum level.
pub fn compress_zstd(zlib_compressed_data: &[u8], loglevel: u32) -> Result<Vec<u8>, PreflateError> {
    let plain_text = expand_zlib_chunks(zlib_compressed_data, loglevel)
        .map_err(|_| PreflateError::InvalidCompressedWrapper)?;
    zstd::bulk::compress(&plain_text, 9).map_err(PreflateError::ZstdError)
}

/// decompresses the Zstd compressed data and then recompresses the result back
/// to the original Zlib compressed streams.
pub fn decompress_zstd(compressed_data: &[u8], capacity: usize) -> Result<Vec<u8>, PreflateError> {
    let compressed_data =
        zstd::bulk::decompress(compressed_data, capacity).map_err(PreflateError::ZstdError)?;

    let mut result = Vec::new();
    recreated_zlib_chunks(&mut Cursor::new(compressed_data), &mut result)?;
    Ok(result)
}

#[test]
fn verify_zip_compress_zstd() {
    use crate::process::read_file;
    let v = read_file("samplezip.zip");

    let compressed = compress_zstd(&v, 1).unwrap();

    let recreated = decompress_zstd(&compressed, 256 * 1024 * 1024).unwrap();

    assert!(v == recreated);
    println!(
        "original zip = {} bytes, recompressed zip = {} bytes",
        v.len(),
        compressed.len()
    );
}

#[test]
fn verify_roundtrip_assert() {
    use crate::process::read_file;

    let v = read_file("compressed_zlib_level1.deflate");

    let r = decompress_deflate_stream_assert(&v, true).unwrap();
    let recompressed =
        recompress_deflate_stream_assert(&r.plain_text, &r.prediction_corrections).unwrap();
    assert!(v == recompressed);
}
