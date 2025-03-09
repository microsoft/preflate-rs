use byteorder::ReadBytesExt;
use cabac::vp8::{VP8Reader, VP8Writer};
use std::{
    collections::VecDeque,
    io::{Cursor, Read, Write},
    usize,
};

use crate::{
    cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
    deflate::{deflate_reader::parse_deflate, deflate_writer::DeflateWriter},
    estimator::preflate_parameter_estimator::PreflateParameters,
    hash_algorithm::HashAlgorithm,
    idat_parse::{recreate_idat, IdatContents},
    preflate_error::{err_exit_code, AddContext, ExitCode, PreflateError, Result},
    preflate_input::PreflateInput,
    process::{decode_mispredictions, encode_mispredictions, recreate_blocks, ReconstructionData},
    scan_deflate::{find_deflate_stream, BlockChunk},
    scoped_read::ScopedRead,
    statistical_codec::PredictionEncoder,
    token_predictor::TokenPredictor,
    zstd_compression::{ZstdCompressContext, ZstdDecompressContext},
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

fn write_literal_block(content: &[u8], destination: &mut impl Write) -> Result<()> {
    destination.write_all(&[LITERAL_CHUNK])?;
    write_varint(destination, content.len() as u32)?;
    destination.write_all(content)?;
    Ok(())
}

fn write_chunk_block(
    block: BlockChunk,
    compression_stats: &mut CompressionStats,
    destination: &mut impl Write,
) -> std::io::Result<usize> {
    match block {
        BlockChunk::DeflateStream(res) => {
            destination.write_all(&[DEFLATE_STREAM, 0])?;

            write_varint(destination, res.prediction_corrections.len() as u32)?;
            write_varint(destination, res.plain_text.len() as u32)?;

            destination.write_all(&res.prediction_corrections)?;
            destination.write_all(&res.plain_text)?;

            compression_stats.overhead_bytes += res.prediction_corrections.len() as u64;
            compression_stats.hash_algorithm = res.parameters.predictor.hash_algorithm;
            Ok(res.compressed_size)
        }

        BlockChunk::IDATDeflate(idat, res) => {
            destination.write_all(&[PNG_COMPRESSED])?;
            write_varint(destination, res.prediction_corrections.len() as u32)?;
            write_varint(destination, res.plain_text.len() as u32)?;

            idat.write_to_bytestream(destination)?;

            destination.write_all(&res.prediction_corrections)?;
            destination.write_all(&res.plain_text)?;

            compression_stats.overhead_bytes += res.prediction_corrections.len() as u64;
            compression_stats.hash_algorithm = res.parameters.predictor.hash_algorithm;

            Ok(idat.total_chunk_length)
        }
    }
}

#[cfg(test)]
fn read_chunk_block(
    source: &mut impl Read,
    destination: &mut impl Write,
) -> std::result::Result<(), PreflateError> {
    let mut p = RecreateFromChunksContext::new_single_chunk(usize::MAX);
    p.copy_to_end_slow(source, destination).context()
}

#[test]
fn roundtrip_chunk_block_literal() {
    let mut buffer = Vec::new();

    write_literal_block(b"hello", &mut buffer).unwrap();

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
    write_chunk_block(BlockChunk::DeflateStream(results), &mut stats, &mut buffer).unwrap();

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
    let mut context = PreflateCompressionContext::new(loglevel);
    context
        .copy_to_end(&mut Cursor::new(compressed_data), write)
        .unwrap();

    Ok(())
}

/// takes a binary chunk of data that was created by expand_zlib_chunks and recompresses it back to its
/// original form.
pub fn recreated_zlib_chunks(
    source: &mut impl Read,
    destination: &mut impl Write,
) -> std::result::Result<(), PreflateError> {
    let mut recreate = RecreateFromChunksContext::new(usize::MAX);
    recreate.copy_to_end(source, destination)
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

    let contents = parse_deflate(compressed_data)?;

    //process::write_file("c:\\temp\\lastop.deflate", compressed_data);
    //process::write_file("c:\\temp\\lastop.bin", contents.plain_text.as_slice());

    let params = PreflateParameters::estimate_preflate_parameters(&contents).context()?;

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

        let mut input = PreflateInput::new(&contents.plain_text);
        let (recompressed, _recreated_blocks) =
            decode_mispredictions(&reread_params, &mut input, &mut cabac_decoder)?;

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

    let mut input = PreflateInput::new(plain_text);
    let (recompressed, _recreated_blocks) =
        decode_mispredictions(&r.parameters, &mut input, &mut cabac_decoder)?;
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

    let contents = parse_deflate(compressed_data)?;

    let params = PreflateParameters::estimate_preflate_parameters(&contents).context()?;

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
        let mut input = PreflateInput::new(&contents.plain_text);
        let (recompressed, _recreated_blocks) =
            decode_mispredictions(&params, &mut input, &mut cabac_decoder)?;

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

    let mut input = PreflateInput::new(plain_text);
    let (recompressed, _recreated_blocks) =
        decode_mispredictions(&r.parameters, &mut input, &mut cabac_decoder)?;
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

    /// reads everything from input and writes it to the output, but one byte a time to test worst case parsing
    #[cfg(test)]
    fn copy_to_end_slow(&mut self, input: &mut impl Read, output: &mut impl Write) -> Result<()> {
        let mut buffer = [0; 1];
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
                .process_buffer(&buffer[0..amount_read], input_complete, output, 1)
                .context()?;
            if done {
                break;
            }
        }

        Ok(())
    }

    fn stats(&self) -> CompressionStats {
        CompressionStats::default()
    }
}

pub struct PreflateCompressionContext {
    content: Vec<u8>,
    result: VecDeque<u8>,
    compression_stats: CompressionStats,

    log_level: u32,

    input_complete: bool,
}

impl PreflateCompressionContext {
    pub fn new(log_level: u32) -> Self {
        PreflateCompressionContext {
            content: Vec::new(),
            compression_stats: CompressionStats::default(),
            result: VecDeque::new(),
            log_level,
            input_complete: false,
        }
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
            self.content.extend_from_slice(input);
        }

        if input_complete && !self.input_complete {
            self.input_complete = true;

            self.result.write_all(&[COMPRESSED_WRAPPER_VERSION_1])?;

            let mut offset = 0;

            while let Some((next, chunk)) =
                find_deflate_stream(&self.content[offset..], self.log_level)
            {
                if next.start != 0 {
                    write_literal_block(
                        &self.content[offset..offset + next.start],
                        &mut self.result,
                    )?;
                }

                write_chunk_block(chunk, &mut self.compression_stats, &mut self.result)?;

                offset += next.end;
            }

            if offset < self.content.len() {
                write_literal_block(&self.content[offset..], &mut self.result)?;
            }
        }

        // write any output we have pending in the queue into the output buffer
        write_dequeue(&mut self.result, writer, max_output_write).context()?;

        Ok(self.input_complete && self.result.len() == 0)
    }

    fn stats(&self) -> CompressionStats {
        self.compression_stats
    }
}

/// writes the pending output to the writer
pub fn write_dequeue(
    pending_output: &mut VecDeque<u8>,
    writer: &mut impl Write,
    max_output_write: usize,
) -> Result<usize> {
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
        Ok(amount_written)
    } else {
        Ok(0)
    }
}

#[cfg(test)]
pub struct NopProcessBuffer {
    result: VecDeque<u8>,
}

#[cfg(test)]
impl ProcessBuffer for NopProcessBuffer {
    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
        max_output_write: usize,
    ) -> Result<bool> {
        self.result.extend(input);

        write_dequeue(&mut self.result, writer, max_output_write).context()?;

        Ok(input_complete && self.result.len() == 0)
    }
}

enum DecompressionState {
    Start,
    StartSegment,
    LiteralBlock(usize),
    DeflateBlock(usize, usize, bool),
    DeflateBlockContinue(Vec<u8>, TokenPredictor),
    PNGBlock(usize, usize, IdatContents),
}

/// recreates the orignal content from the chunked data
pub struct RecreateFromChunksContext {
    capacity: usize,
    input: VecDeque<u8>,
    result: VecDeque<u8>,
    input_complete: bool,
    state: DecompressionState,
}

impl RecreateFromChunksContext {
    pub fn new(capacity: usize) -> Self {
        RecreateFromChunksContext {
            input: VecDeque::new(),
            result: VecDeque::new(),
            capacity,
            input_complete: false,
            state: DecompressionState::Start,
        }
    }

    /// for testing reading a single chunk (skip header)
    pub fn new_single_chunk(capacity: usize) -> Self {
        RecreateFromChunksContext {
            input: VecDeque::new(),
            result: VecDeque::new(),
            capacity,
            input_complete: false,
            state: DecompressionState::StartSegment,
        }
    }

    fn reconstruct_deflate(
        plain_text: &[u8],
        corrections: &[u8],
        predictor: &mut TokenPredictor,
        partial: bool,
    ) -> Result<Vec<u8>> {
        let mut cabac_decoder =
            PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(corrections)).unwrap());
        let mut input = PreflateInput::new(plain_text);
        let mut deflate_writer = DeflateWriter::new();
        loop {
            let block = predictor.recreate_block(&mut cabac_decoder, &mut input)?;

            deflate_writer.encode_block(&block)?;

            let last = block.last;
            if last {
                break;
            }
        }
        deflate_writer.flush();
        Ok(deflate_writer.detach_output())
    }
}

impl ProcessBuffer for RecreateFromChunksContext {
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
            self.input.write_all(input).context()?;

            if self.input.len() > self.capacity {
                return Err(PreflateError::new(
                    ExitCode::InvalidParameter,
                    "input data exceeds capacity",
                ));
            }
        }

        if input_complete {
            self.input_complete = true;
        }

        loop {
            match &mut self.state {
                DecompressionState::Start => {
                    if !self.input_complete && self.input.len() == 0 {
                        break;
                    }

                    let version = self.input.read_u8()?;

                    if version != COMPRESSED_WRAPPER_VERSION_1 {
                        return err_exit_code(
                            ExitCode::InvalidCompressedWrapper,
                            format!("Invalid version {version}"),
                        );
                    }

                    self.state = DecompressionState::StartSegment;
                }
                DecompressionState::StartSegment => {
                    // here's a good place to stop if we run out of input
                    if self.input.len() == 0 {
                        break;
                    }

                    // use scoped read so that if we run out of bytes we can undo the read and wait for more input
                    self.state = match self.input.scoped_read(|r| match r.read_u8()? {
                        LITERAL_CHUNK => {
                            let length = read_varint(r)? as usize;

                            Ok(DecompressionState::LiteralBlock(length))
                        }
                        DEFLATE_STREAM => {
                            let partial = r.read_u8()? != 0;
                            let correction_length = read_varint(r)? as usize;
                            let uncompressed_length = read_varint(r)? as usize;

                            Ok(DecompressionState::DeflateBlock(
                                correction_length,
                                uncompressed_length,
                                partial,
                            ))
                        }
                        PNG_COMPRESSED => {
                            let correction_length = read_varint(r)? as usize;
                            let uncompressed_length = read_varint(r)? as usize;
                            let idat = IdatContents::read_from_bytestream(r)?;

                            Ok(DecompressionState::PNGBlock(
                                correction_length,
                                uncompressed_length,
                                idat,
                            ))
                        }
                        _ => Err(PreflateError::new(
                            ExitCode::InvalidCompressedWrapper,
                            "Invalid chunk",
                        )),
                    }) {
                        Ok(s) => s,
                        Err(e) => {
                            if !self.input_complete && e.exit_code() == ExitCode::ShortRead {
                                // wait for more input if we ran out of bytes here
                                break;
                            } else {
                                return Err(e);
                            }
                        }
                    }
                }

                DecompressionState::LiteralBlock(length) => {
                    let source_size = self.input.len();
                    if source_size < *length {
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input",
                            ));
                        }
                        self.result.extend(self.input.drain(..));
                        *length -= source_size;
                        break;
                    }

                    self.result.extend(self.input.drain(0..*length));
                    self.state = DecompressionState::StartSegment;
                }

                DecompressionState::DeflateBlock(
                    correction_length,
                    uncompressed_length,
                    partial,
                ) => {
                    let source_size = self.input.len();
                    let total_length = *correction_length + *uncompressed_length;

                    if source_size < total_length {
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input",
                            ));
                        }
                        break;
                    }

                    self.input.make_contiguous();
                    let source_slice = self.input.as_slices().0;

                    let plain_text: &[u8] = &source_slice[*correction_length..total_length];
                    let prediction_corrections: &[u8] = &source_slice[0..*correction_length];
                    let r = ReconstructionData::read(prediction_corrections)?;
                    let mut predictor = TokenPredictor::new(&r.parameters.predictor);

                    self.result.extend(Self::reconstruct_deflate(
                        plain_text,
                        &r.corrections,
                        &mut predictor,
                        *partial,
                    )?);

                    let tail_plain_text = plain_text.to_vec();

                    self.input.drain(0..total_length);

                    if *partial {
                        self.state =
                            DecompressionState::DeflateBlockContinue(tail_plain_text, predictor);
                    } else {
                        self.state = DecompressionState::StartSegment;
                    }
                }

                DecompressionState::DeflateBlockContinue(plain_text, predictor) => {
                    let (partial, correction_length, uncompressed_length) =
                        self.input.scoped_read(|r| {
                            Ok((
                                r.read_u8()? != 0,
                                read_varint(r)? as usize,
                                read_varint(r)? as usize,
                            ))
                        })?;

                    let source_size = self.input.len();
                    let total_length = correction_length + uncompressed_length;

                    if source_size < total_length {
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input",
                            ));
                        }
                        break;
                    }

                    self.input.make_contiguous();
                    let source_slice = self.input.as_slices().0;

                    plain_text.extend_from_slice(&source_slice[correction_length..total_length]);
                    let prediction_corrections: &[u8] = &source_slice[0..correction_length];

                    self.result.extend(Self::reconstruct_deflate(
                        plain_text,
                        prediction_corrections,
                        predictor,
                        partial,
                    )?);

                    self.input.drain(0..total_length);

                    if !partial {
                        self.state = DecompressionState::StartSegment;
                    }
                }

                DecompressionState::PNGBlock(correction_length, uncompressed_length, idat) => {
                    let source_size = self.input.len();
                    let total_length = *correction_length + *uncompressed_length;
                    if source_size < total_length {
                        // wait till we have the full block
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input",
                            ));
                        }
                        break;
                    }

                    self.input.make_contiguous();
                    let source_slice = self.input.as_slices().0;

                    let recompressed = recompress_deflate_stream(
                        &source_slice[*correction_length..total_length],
                        &source_slice[0..*correction_length],
                    )
                    .context()?;

                    self.input.drain(0..total_length);

                    recreate_idat(&idat, &recompressed[..], &mut self.result).context()?;

                    self.state = DecompressionState::StartSegment;
                }
            }
        }

        write_dequeue(&mut self.result, writer, max_output_write).context()?;

        Ok(self.input_complete && self.result.len() == 0)
    }
}

#[test]
fn test_baseline_calc() {
    use crate::process::read_file;

    let v = read_file("samplezip.zip");

    let mut context = ZstdCompressContext::new(PreflateCompressionContext::new(0), 9, true);

    let _r = context.process_vec(&v).unwrap();

    let stats = context.stats();

    println!("stats: {:?}", stats);

    // these change if the compression algorithm is altered, update them
    assert_eq!(stats.overhead_bytes, 466);
    assert_eq!(stats.zstd_compressed_size, 12445);
    assert_eq!(stats.zstd_baseline_size, 13661);
}

#[test]
fn roundtrip_contexts() {
    use crate::process::read_file;

    let v = read_file("samplezip.zip");

    let mut context = ZstdCompressContext::new(PreflateCompressionContext::new(0), 9, false);

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
    println!("stats: {:?} buffer:{}", stats, buffer.len());
    println!(
        "zstd baseline size: {} -> comp {}",
        stats.zstd_baseline_size,
        buffer.len()
    );

    let mut context = ZstdDecompressContext::new(RecreateFromChunksContext::new(usize::MAX));
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
