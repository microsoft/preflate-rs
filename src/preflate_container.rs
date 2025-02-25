use byteorder::ReadBytesExt;
use cabac::vp8::{VP8Reader, VP8Writer};
use std::{
    collections::VecDeque,
    io::{Cursor, Read, Write},
};

use crate::{
    cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
    estimator::preflate_parameter_estimator::PreflateParameters,
    hash_algorithm::HashAlgorithm,
    idat_parse::{recreate_idat, IdatContents},
    preflate_error::{err_exit_code, AddContext, ExitCode, PreflateError, Result},
    preflate_input::PreflateInput,
    process::{decode_mispredictions, encode_mispredictions, parse_deflate, ReconstructionData},
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
    compression_stats: &mut CompressionStats,
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

            compression_stats.overhead_bytes += res.prediction_corrections.len() as u64;
            compression_stats.hash_algorithm = res.parameters.predictor.hash_algorithm;
            Ok(res.compressed_size)
        }

        BlockChunk::IDATDeflate(idat, res) => {
            destination.write_all(&[PNG_COMPRESSED])?;
            idat.write_to_bytestream(destination)?;
            write_varint(destination, res.plain_text.len() as u32)?;
            destination.write_all(&res.plain_text)?;
            write_varint(destination, res.prediction_corrections.len() as u32)?;
            destination.write_all(&res.prediction_corrections)?;

            compression_stats.overhead_bytes += res.prediction_corrections.len() as u64;
            compression_stats.hash_algorithm = res.parameters.predictor.hash_algorithm;

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
                recreate_idat(&idat, &recompressed[..], destination).context()?;
            } else {
                destination.write_all(&recompressed)?;
            }
        }
        _ => {
            return Err(PreflateError::new(
                ExitCode::InvalidCompressedWrapper,
                "Invalid chunk",
            ))
        }
    }
    Ok(true)
}

#[test]
fn roundtrip_chunk_block_literal() {
    let mut buffer = Vec::new();

    let mut stats = CompressionStats::default();
    write_chunk_block(BlockChunk::Literal(5), b"hello", &mut stats, &mut buffer).unwrap();

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

    let mut stats = CompressionStats::default();
    write_chunk_block(
        BlockChunk::DeflateStream(results),
        &[],
        &mut stats,
        &mut buffer,
    )
    .unwrap();

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

    let mut stats = CompressionStats::default();
    write_chunk_block(
        BlockChunk::IDATDeflate(idat_contents, results),
        &[],
        &mut stats,
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
    compression_stats: &mut CompressionStats,
    write: &mut impl Write,
) -> Result<()> {
    let mut locations_found = Vec::new();

    split_into_deflate_streams(compressed_data, &mut locations_found, loglevel);
    if loglevel > 0 {
        println!("locations found: {:?}", locations_found);
    }

    write.write_all(&[COMPRESSED_WRAPPER_VERSION_1])?; // version 1 of format. Definitely will improved.

    let mut index = 0;
    for loc in locations_found {
        index += write_chunk_block(loc, &compressed_data[index..], compression_stats, write)?;
    }

    Ok(())
}

/// takes a binary chunk of data that was created by expand_zlib_chunks and recompresses it back to its
/// original form.
pub fn recreated_zlib_chunks(
    source: &mut impl Read,
    destination: &mut impl Write,
) -> std::result::Result<(), PreflateError> {
    let version = source.read_u8()?;
    if version != COMPRESSED_WRAPPER_VERSION_1 {
        return err_exit_code(
            ExitCode::InvalidCompressedWrapper,
            format!("Invalid version {version}"),
        );
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

    let mut stats = CompressionStats::default();
    let mut expanded = Vec::new();
    expand_zlib_chunks(&f, 1, &mut stats, &mut expanded).unwrap();

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
) -> Result<DecompressResult> {
    let mut cabac_encoded = Vec::new();

    let contents = parse_deflate(compressed_data, 0)?;

    //process::write_file("c:\\temp\\lastop.deflate", compressed_data);
    //process::write_file("c:\\temp\\lastop.bin", contents.plain_text.as_slice());

    let params =
        PreflateParameters::estimate_preflate_parameters(&contents.plain_text, &contents.blocks)
            .context()?;

    if loglevel > 0 {
        println!("params: {:?}", params);
    }

    let mut cabac_encoder =
        PredictionEncoderCabac::new(VP8Writer::new(&mut cabac_encoded).unwrap());

    encode_mispredictions(&contents, &params, &mut cabac_encoder)?;

    cabac_encoder.finish();

    if loglevel > 0 {
        cabac_encoder.print();
    }

    let reconstruction_data = bitcode::encode(&ReconstructionData {
        parameters: params,
        corrections: cabac_encoded,
    });

    if verify {
        let r: ReconstructionData = bitcode::decode(&reconstruction_data).map_err(|e| {
            PreflateError::new(ExitCode::InvalidCompressedWrapper, format!("{:?}", e))
        })?;

        let mut cabac_decoder =
            PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&r.corrections[..])).unwrap());

        let reread_params = r.parameters;

        assert_eq!(params, reread_params);

        let (recompressed, _recreated_blocks) = decode_mispredictions(
            &reread_params,
            PreflateInput::new(&contents.plain_text),
            &mut cabac_decoder,
        )?;

        if recompressed[..] != compressed_data[..contents.compressed_size] {
            return Err(PreflateError::new(
                ExitCode::RoundtripMismatch,
                "recompressed data does not match original",
            ));
        }
    }

    Ok(DecompressResult {
        plain_text: contents.plain_text,
        prediction_corrections: reconstruction_data,
        compressed_size: contents.compressed_size,
        parameters: params,
    })
}

/// recompresses a deflate stream using the cabac_encoded data that was returned from decompress_deflate_stream
pub fn recompress_deflate_stream(
    plain_text: &[u8],
    prediction_corrections: &[u8],
) -> Result<Vec<u8>> {
    let r = ReconstructionData::read(prediction_corrections)?;

    let mut cabac_decoder =
        PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(r.corrections)).unwrap());

    let (recompressed, _recreated_blocks) = decode_mispredictions(
        &r.parameters,
        PreflateInput::new(plain_text),
        &mut cabac_decoder,
    )?;
    Ok(recompressed)
}

/// decompresses a deflate stream and returns the plaintext and cabac_encoded data that can be used to reconstruct it
/// This version uses DebugWriter and DebugReader, which are slower but can be used to debug the cabac encoding errors.
#[cfg(test)]
pub fn decompress_deflate_stream_assert(
    compressed_data: &[u8],
    verify: bool,
) -> Result<DecompressResult> {
    use cabac::debug::{DebugReader, DebugWriter};

    use crate::preflate_error::AddContext;

    let mut cabac_encoded = Vec::new();

    let mut cabac_encoder =
        PredictionEncoderCabac::new(DebugWriter::new(&mut cabac_encoded).unwrap());

    let contents = parse_deflate(compressed_data, 0)?;

    let params =
        PreflateParameters::estimate_preflate_parameters(&contents.plain_text, &contents.blocks)
            .context()?;

    encode_mispredictions(&contents, &params, &mut cabac_encoder)?;
    assert_eq!(contents.compressed_size, compressed_data.len());
    cabac_encoder.finish();

    let reconstruction_data = bitcode::encode(&ReconstructionData {
        parameters: params,
        corrections: cabac_encoded,
    });

    if verify {
        let r = ReconstructionData::read(&reconstruction_data)?;

        let mut cabac_decoder =
            PredictionDecoderCabac::new(DebugReader::new(Cursor::new(&r.corrections)).unwrap());

        let params = r.parameters;
        let (recompressed, _recreated_blocks) = decode_mispredictions(
            &params,
            PreflateInput::new(&contents.plain_text),
            &mut cabac_decoder,
        )?;

        if recompressed[..] != compressed_data[..] {
            return Err(PreflateError::new(
                ExitCode::RoundtripMismatch,
                "recompressed data does not match original",
            ));
        }
    }

    Ok(DecompressResult {
        plain_text: contents.plain_text,
        prediction_corrections: reconstruction_data,
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
) -> Result<Vec<u8>> {
    use cabac::debug::DebugReader;

    let r = ReconstructionData::read(prediction_corrections)?;

    let mut cabac_decoder =
        PredictionDecoderCabac::new(DebugReader::new(Cursor::new(&r.corrections)).unwrap());

    let (recompressed, _recreated_blocks) = decode_mispredictions(
        &r.parameters,
        PreflateInput::new(plain_text),
        &mut cabac_decoder,
    )?;
    Ok(recompressed)
}

#[test]
fn verify_zip_compress() {
    use crate::process::read_file;
    let v = read_file("samplezip.zip");

    let mut stats = CompressionStats::default();
    let mut expanded = Vec::new();
    expand_zlib_chunks(&v, 1, &mut stats, &mut expanded).unwrap();

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
pub fn compress_zstd(
    zlib_compressed_data: &[u8],
    loglevel: u32,
    compression_stats: &mut CompressionStats,
) -> Result<Vec<u8>> {
    let mut ctx = PreflateCompressionContext::new(false, loglevel, 9);
    let r = ctx.process_vec(zlib_compressed_data)?;

    *compression_stats = ctx.stats();

    Ok(r)
}

/// decompresses the Zstd compressed data and then recompresses the result back
/// to the original Zlib compressed streams.
pub fn decompress_zstd(compressed_data: &[u8], capacity: usize) -> Result<Vec<u8>> {
    let mut ctx = PreflateDecompressionContext::new(capacity);

    Ok(ctx.process_vec(compressed_data)?)
}

#[test]
fn verify_zip_compress_zstd() {
    use crate::process::read_file;
    let v = read_file("samplezip.zip");

    let mut stats = CompressionStats::default();
    let compressed = compress_zstd(&v, 1, &mut stats).unwrap();

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

#[derive(Debug, Copy, Clone, Default)]
pub struct CompressionStats {
    pub deflate_compressed_size: u64,
    pub zstd_compressed_size: u64,
    pub uncompressed_size: u64,
    pub overhead_bytes: u64,
    pub hash_algorithm: HashAlgorithm,
    pub zstd_baseline_size: u64,
}

pub trait ProcessBuffer {
    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
        max_output_write: usize,
    ) -> Result<bool>;

    fn process_vec(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut writer = Vec::new();
        let mut done = self.process_buffer(input, true, &mut writer, usize::MAX)?;
        while !done {
            done = self.process_buffer(&[], true, &mut writer, usize::MAX)?;
        }
        Ok(writer)
    }

    /// reads everything from input and writes it to the output
    fn copy_to_end(&mut self, input: &mut impl Read, output: &mut impl Write) -> Result<()> {
        let mut buffer = [0; 65536];
        let mut input_complete = false;
        loop {
            let amount_read;

            if input_complete {
                amount_read = 0;
            } else {
                amount_read = input.read(&mut buffer).context()?;
                if amount_read == 0 {
                    input_complete = true
                }
            };

            let done = self
                .process_buffer(&buffer[0..amount_read], input_complete, output, usize::MAX)
                .context()?;
            if done {
                break;
            }
        }

        Ok(())
    }
}

pub struct PreflateCompressionContext {
    content: Vec<u8>,
    result: zstd::stream::write::Encoder<'static, VecDeque<u8>>,
    compression_stats: CompressionStats,

    /// if set, the encoder will write all the input to a null zstd encoder to see how much
    /// compression we would get if we just used Zstandard without any Preflate processing.
    ///
    /// This gives a fairer comparison of the compression ratio of Preflate + Zstandard vs. Zstandard
    /// since Zstd does compress the data a bit, especially if there is a lot of non-Deflate streams
    /// in the file.
    test_baseline: Option<zstd::stream::write::Encoder<'static, MeasureWriteSink>>,

    log_level: u32,

    compression_level: i32,

    input_complete: bool,
}

/// used to measure the length of the output without storing it anyway
struct MeasureWriteSink {
    pub length: usize,
}

impl Write for MeasureWriteSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.length += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl PreflateCompressionContext {
    pub fn new(test_baseline: bool, log_level: u32, compression_level: i32) -> Self {
        PreflateCompressionContext {
            content: Vec::new(),
            compression_stats: CompressionStats::default(),
            result: zstd::stream::write::Encoder::new(VecDeque::new(), compression_level).unwrap(),
            log_level,
            compression_level,
            input_complete: false,
            test_baseline: if test_baseline {
                Some(
                    zstd::stream::write::Encoder::new(
                        MeasureWriteSink { length: 0 },
                        compression_level,
                    )
                    .unwrap(),
                )
            } else {
                None
            },
        }
    }

    pub fn stats(&self) -> CompressionStats {
        self.compression_stats
    }
}

impl ProcessBuffer for PreflateCompressionContext {
    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
        max_output_write: usize,
    ) -> Result<bool> {
        if self.input_complete && (input.len() > 0 || !input_complete) {
            return Err(PreflateError::new(
                ExitCode::InvalidParameter,
                "more data provided after input_complete signaled",
            ));
        }

        if input.len() > 0 {
            if let Some(encoder) = &mut self.test_baseline {
                encoder.write_all(input).context()?;
            }

            self.content.extend_from_slice(input);
        }

        if input_complete && !self.input_complete {
            self.input_complete = true;

            if let Some(encoder) = &mut self.test_baseline {
                encoder.do_finish().context()?;
                self.compression_stats.zstd_baseline_size = encoder.get_ref().length as u64;
                self.test_baseline = None;
            }

            expand_zlib_chunks(
                &self.content,
                self.log_level,
                &mut self.compression_stats,
                &mut self.result,
            )
            .context()?;

            self.result.do_finish().context()?;
        }

        // write any output we have pending in the queue into the output buffer
        let pending_output = self.result.get_mut();
        if pending_output.len() > 0 {
            let slices = pending_output.as_mut_slices();

            let mut amount_written = 0;
            let len = slices.0.len().min(max_output_write);
            writer.write_all(&slices.0[..len])?;
            amount_written += len;

            if amount_written < max_output_write {
                let len = slices.1.len().min(max_output_write - amount_written);
                writer.write_all(&slices.1[..len])?;
                amount_written += len;
            }

            pending_output.drain(..amount_written);

            self.compression_stats.zstd_compressed_size += amount_written as u64;
        }
        Ok(self.input_complete && pending_output.len() == 0)
    }
}

pub struct PreflateDecompressionContext {
    capacity: usize,
    zstd_decompress: zstd::stream::write::Decoder<'static, Vec<u8>>,
    result: Option<Vec<u8>>,
    result_pos: usize,
    input_complete: bool,
}

impl PreflateDecompressionContext {
    pub fn new(capacity: usize) -> Self {
        PreflateDecompressionContext {
            zstd_decompress: zstd::stream::write::Decoder::new(Vec::new()).unwrap(),
            result: None,
            result_pos: 0,
            capacity,
            input_complete: false,
        }
    }
}

impl ProcessBuffer for PreflateDecompressionContext {
    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
        max_output_write: usize,
    ) -> Result<bool> {
        if self.input_complete && (input.len() > 0 || !input_complete) {
            return Err(PreflateError::new(
                ExitCode::InvalidParameter,
                "more data provided after input_complete signaled",
            ));
        }

        if input.len() > 0 {
            self.zstd_decompress.write_all(input).context()?;

            if self.zstd_decompress.get_ref().len() > self.capacity {
                return Err(PreflateError::new(
                    ExitCode::InvalidParameter,
                    "input data exceeds capacity",
                ));
            }
        }

        if input_complete {
            self.input_complete = true;
            self.zstd_decompress.flush().context()?;

            let mut result = Vec::new();
            recreated_zlib_chunks(
                &mut Cursor::new(&self.zstd_decompress.get_ref()),
                &mut result,
            )
            .context()?;

            self.result = Some(result);
        }

        if let Some(result) = &mut self.result {
            let amount_to_write = std::cmp::min(max_output_write, result.len() - self.result_pos);

            writer.write(&result[self.result_pos..self.result_pos + amount_to_write])?;
            self.result_pos += amount_to_write;
            Ok(self.result_pos == result.len())
        } else {
            Ok(false)
        }
    }
}

#[test]
fn test_baseline_calc() {
    use crate::process::read_file;

    let v = read_file("samplezip.zip");

    let mut context = PreflateCompressionContext::new(true, 0, 9);

    let r = context.process_vec(&v).unwrap();

    let stats = context.stats();

    println!("stats: {:?}", stats);

    // these change if the compression algorithm is altered, update them
    assert!(stats.zstd_baseline_size == 13661);
    assert!(stats.zstd_compressed_size == 12452);
    assert!(stats.overhead_bytes == 466);
}

#[test]
fn roundtrip_contexts() {
    use crate::process::read_file;

    let v = read_file("samplezip.zip");

    let mut context = PreflateCompressionContext::new(true, 1, 9);

    let mut buffer = Vec::new();
    let mut pos = 0;
    loop {
        let amount_to_write = std::cmp::min(1024, v.len() - pos);
        let input = &v[pos..pos + amount_to_write];
        pos += amount_to_write;

        let done = context
            .process_buffer(input, pos == v.len(), &mut buffer, 333)
            .unwrap();
        if done {
            break;
        }
    }

    let stats = context.stats();
    println!("stats: {:?}", stats);
    println!(
        "zstd baseline size: {} -> comp {}",
        stats.zstd_baseline_size,
        buffer.len()
    );

    let mut context = PreflateDecompressionContext::new(256 * 1024 * 1024);
    let mut buffer2 = Vec::new();
    let mut pos = 0;
    loop {
        let amount_to_write = std::cmp::min(1024, buffer.len() - pos);
        let input = &buffer[pos..pos + amount_to_write];
        pos += amount_to_write;

        let done = context
            .process_buffer(input, pos == buffer.len(), &mut buffer2, 517)
            .unwrap();
        if done {
            break;
        }
    }

    assert!(v == buffer2);
}
