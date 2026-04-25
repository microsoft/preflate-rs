use crc32fast::Hasher as CrcHasher;

use std::io::Write;

use crate::{
    container_common::{
        BLOCK_COMPRESSION_NONE, BLOCK_COMPRESSION_ZSTD, BLOCK_TYPE_DEFLATE,
        BLOCK_TYPE_DEFLATE_CONTINUE, BLOCK_TYPE_JPEG_LEPTON, BLOCK_TYPE_LITERAL, BLOCK_TYPE_PNG,
        BLOCK_TYPE_WEBP, PreflateContainerConfig, PreflateStats, ProcessBuffer, write_varint,
    },
    idat_parse::{IdatContents, PngHeader},
    scan_deflate::{FindStreamResult, FoundStream, FoundStreamType, find_compressable_stream},
};

use preflate_rs::{AddContext, ExitCode, PreflateError, PreflateStreamProcessor, Result};

/// used to measure the length of the output without storing it
pub(crate) struct MeasureWriteSink {
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

#[derive(Debug)]
pub(crate) enum ChunkParseState {
    Start,
    /// we are looking for a deflate stream or PNG chunk. The data of the PNG file
    /// is stored later than the IHDR chunk that will tell us the dimensions of the image,
    /// so we need to keep track of the IHDR chunk so we can use it later to properly
    /// compress the PNG data.
    Searching(Option<PngHeader>),
    DeflateContinue(Box<PreflateStreamProcessor>),
}

/// V2 variant of write_chunk_block: block content goes through the persistent Zstd encoder.
/// JPEG blocks are written raw to writer (bypass encoder).
/// Returns (total compressed bytes written, optional continue state).
pub(crate) fn write_chunk_block_v2(
    encoder: &mut zstd::stream::write::Encoder<'static, Vec<u8>>,
    writer: &mut impl Write,
    chunk: FoundStream,
    stats: &mut PreflateStats,
) -> Result<(usize, Option<PreflateStreamProcessor>)> {
    match chunk.chunk_type {
        FoundStreamType::DeflateStream(parameters, state) => {
            write_varint(encoder, chunk.corrections.len() as u32)?;
            write_varint(encoder, state.plain_text().text().len() as u32)?;
            encoder.write_all(&chunk.corrections)?;
            encoder.write_all(state.plain_text().text())?;

            let compressed_size = emit_compressed_block(
                BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_DEFLATE,
                encoder,
                writer,
            )?;

            stats.overhead_bytes += chunk.corrections.len() as u64;
            stats.uncompressed_size += state.plain_text().len() as u64;
            stats.hash_algorithm = parameters.hash_algorithm;

            if !state.is_done() {
                return Ok((compressed_size, Some(*state)));
            }
            Ok((compressed_size, None))
        }

        FoundStreamType::IDATDeflate(parameters, mut idat, plain_text) => {
            log::debug!(
                "IDATDeflate param {:?} corrections {}",
                parameters,
                chunk.corrections.len()
            );

            let mut temp_vec = Vec::new();

            if webp_compress(&mut temp_vec, plain_text.text(), &chunk.corrections, &idat).is_ok() {
                // WebP is already compressed — write raw, bypassing the Zstd encoder.
                // temp_vec[0] is the BLOCK_TYPE_PNG placeholder byte; temp_vec[1..] is the payload.
                let payload = &temp_vec[1..];
                writer.write_all(&[BLOCK_COMPRESSION_NONE | BLOCK_TYPE_WEBP])?;
                write_varint(writer, payload.len() as u32)?;
                writer.write_all(payload)?;

                stats.uncompressed_size += plain_text.len() as u64;
                stats.hash_algorithm = parameters.hash_algorithm;
                stats.overhead_bytes += chunk.corrections.len() as u64;

                Ok((payload.len(), None))
            } else {
                // Non-WebP PNG: corrections + plaintext are compressible, send through Zstd.
                log::debug!("non-Webp compressed {}", idat.total_chunk_length);
                write_varint(encoder, chunk.corrections.len() as u32)?;
                write_varint(encoder, plain_text.text().len() as u32)?;
                idat.png_header = None;
                idat.write_to_bytestream(encoder)?;
                encoder.write_all(&chunk.corrections)?;
                encoder.write_all(plain_text.text())?;

                let compressed_size = emit_compressed_block(
                    BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_PNG,
                    encoder,
                    writer,
                )?;

                stats.uncompressed_size += plain_text.len() as u64;
                stats.hash_algorithm = parameters.hash_algorithm;
                stats.overhead_bytes += chunk.corrections.len() as u64;

                Ok((compressed_size, None))
            }
        }

        FoundStreamType::JPEGLepton(data) => {
            // JPEG is written raw (bypasses the encoder entirely)
            writer.write_all(&[BLOCK_COMPRESSION_NONE | BLOCK_TYPE_JPEG_LEPTON])?;
            write_varint(writer, data.len() as u32)?;
            writer.write_all(&data)?;

            stats.uncompressed_size += data.len() as u64;
            Ok((0, None))
        }
    }
}

/// Takes a sequence of bytes that may contain deflate streams, find
/// the streams, and emits a new stream that containus the decompressed
/// streams along with the corrections needed to recreate the original.
///
/// This output can then be compressed with a better algorithm, like Zstandard
/// and achieve much better compression than if we tried to compress the
/// deflate stream directlyh.
pub struct PreflateContainerProcessor {
    content: Vec<u8>,
    compression_stats: PreflateStats,
    input_complete: bool,
    total_plain_text_seen: u64,

    /// used to track the last attempted chunk size, in case we
    /// need more input to continue, we will collect at least min_chunk_size
    /// more input before trying to process again until we reach max_chunk_size
    last_attempt_chunk_size: usize,

    state: ChunkParseState,
    config: PreflateContainerConfig,

    /// running CRC-32 of all input bytes, written as the final block
    input_crc: CrcHasher,

    /// each block is individually compressed with this encoder (v2 format)
    encoder: Option<zstd::stream::write::Encoder<'static, Vec<u8>>>,

    /// when present, all raw input is also fed to this encoder so we can measure
    /// baseline Zstd compression (without preflate processing)
    baseline_encoder: Option<zstd::stream::write::Encoder<'static, MeasureWriteSink>>,
}

impl PreflateContainerProcessor {
    /// Creates a processor that uses v2 format with a persistent Zstd encoder shared
    /// across all non-JPEG blocks. JPEG blocks bypass the encoder entirely.
    pub fn new(config: &PreflateContainerConfig, level: i32, test_baseline: bool) -> Self {
        PreflateContainerProcessor {
            content: Vec::new(),
            compression_stats: PreflateStats::default(),
            input_complete: false,
            state: ChunkParseState::Start,
            total_plain_text_seen: 0,
            last_attempt_chunk_size: 0,
            config: config.clone(),
            input_crc: CrcHasher::new(),
            encoder: Some(zstd::stream::write::Encoder::new(Vec::new(), level).unwrap()),
            baseline_encoder: if test_baseline {
                Some(
                    zstd::stream::write::Encoder::new(MeasureWriteSink { length: 0 }, level)
                        .unwrap(),
                )
            } else {
                None
            },
        }
    }
}

impl ProcessBuffer for PreflateContainerProcessor {
    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
    ) -> Result<()> {
        use crate::container_common::COMPRESSED_WRAPPER_VERSION_2;

        if self.input_complete && (!input.is_empty() || !input_complete) {
            return Err(PreflateError::new(
                ExitCode::InvalidParameter,
                "more data provided after input_complete signaled",
            ));
        }

        if !input.is_empty() {
            self.compression_stats.deflate_compressed_size += input.len() as u64;
            self.input_crc.update(input);
            self.content.extend_from_slice(input);

            if let Some(encoder) = &mut self.baseline_encoder {
                encoder.write_all(input).context()?;
            }
        }

        loop {
            // wait until we have at least min_chunk_size before we start processing
            if self.content.is_empty()
                || (!input_complete
                    && (self.content.len() - self.last_attempt_chunk_size)
                        < self.config.min_chunk_size
                    && self.content.len() <= self.config.max_chunk_size)
            {
                break;
            }

            self.last_attempt_chunk_size = self.content.len();

            match &mut self.state {
                ChunkParseState::Start => {
                    writer.write_all(&[COMPRESSED_WRAPPER_VERSION_2])?;
                    self.state = ChunkParseState::Searching(None);
                }
                ChunkParseState::Searching(prev_ihdr) => {
                    if self.total_plain_text_seen > self.config.total_plain_text_limit {
                        // once we've exceeded our limit, we don't do any more compression
                        let encoder = self.encoder.as_mut().unwrap();
                        write_varint(encoder, self.content.len() as u32)?;
                        encoder.write_all(&self.content)?;
                        let sz = emit_compressed_block(
                            BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_LITERAL,
                            encoder,
                            writer,
                        )?;
                        self.compression_stats.zstd_compressed_size += sz as u64;

                        self.last_attempt_chunk_size = 0;
                        self.content.clear();
                        break;
                    }

                    // here we are looking for a deflate stream or PNG chunk
                    match find_compressable_stream(
                        &self.content,
                        prev_ihdr,
                        input_complete,
                        &self.config,
                    ) {
                        FindStreamResult::Found(next, chunk_box) => {
                            let chunk = *chunk_box;
                            // the gap between the start and the beginning of the deflate stream
                            // is written out as a literal block
                            if next.start != 0 {
                                let encoder = self.encoder.as_mut().unwrap();
                                write_varint(encoder, next.start as u32)?;
                                encoder.write_all(&self.content[..next.start])?;
                                let sz = emit_compressed_block(
                                    BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_LITERAL,
                                    encoder,
                                    writer,
                                )?;
                                self.compression_stats.zstd_compressed_size += sz as u64;
                            }

                            let (compressed_size, next_state) = write_chunk_block_v2(
                                self.encoder.as_mut().unwrap(),
                                writer,
                                chunk,
                                &mut self.compression_stats,
                            )
                            .context()?;
                            self.compression_stats.zstd_compressed_size += compressed_size as u64;

                            if let Some(mut state) = next_state {
                                self.total_plain_text_seen += state.plain_text().len() as u64;
                                state.shrink_to_dictionary();
                                self.state = ChunkParseState::DeflateContinue(Box::new(state));
                            }

                            self.content.drain(0..next.end);
                            self.last_attempt_chunk_size = self.content.len();
                        }
                        FindStreamResult::ShortRead => {
                            if input_complete || self.content.len() > self.config.max_chunk_size {
                                // if we have too much data or have no more data,
                                // we just write it out as a literal block with everything we have
                                let encoder = self.encoder.as_mut().unwrap();
                                write_varint(encoder, self.content.len() as u32)?;
                                encoder.write_all(&self.content)?;
                                let sz = emit_compressed_block(
                                    BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_LITERAL,
                                    encoder,
                                    writer,
                                )?;
                                self.compression_stats.zstd_compressed_size += sz as u64;

                                self.content.clear();
                                self.last_attempt_chunk_size = 0;
                            } else {
                                // we don't have enough data to process the stream, so we just
                                // wait for more data
                                break;
                            }
                        }
                        FindStreamResult::None => {
                            // couldn't find anything, just write the rest as a literal block
                            let encoder = self.encoder.as_mut().unwrap();
                            write_varint(encoder, self.content.len() as u32)?;
                            encoder.write_all(&self.content)?;
                            let sz = emit_compressed_block(
                                BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_LITERAL,
                                encoder,
                                writer,
                            )?;
                            self.compression_stats.zstd_compressed_size += sz as u64;

                            self.content.clear();
                            self.last_attempt_chunk_size = 0;
                        }
                    }
                }
                ChunkParseState::DeflateContinue(state) => {
                    // here we have a deflate stream that we need to continue
                    match state.decompress(&self.content) {
                        Err(ref e)
                            if e.exit_code() == ExitCode::ShortRead
                                && !input_complete
                                && self.content.len() <= self.config.max_chunk_size =>
                        {
                            // Not enough data to complete the next block yet; wait for more.
                            break;
                        }
                        Err(_e) => {
                            // Stream analysis diverged or no more data is coming; give up on
                            // continuation and fall back to treating the remaining bytes as raw.
                            self.state = ChunkParseState::Searching(None);

                            log::debug!("Error while trying to continue compression {:?}", _e);
                        }
                        Ok(res) => {
                            log::debug!(
                                "Deflate continue: {} -> {}",
                                state.plain_text().len(),
                                res.compressed_size
                            );

                            let encoder = self.encoder.as_mut().unwrap();
                            write_varint(encoder, res.corrections.len() as u32)?;
                            write_varint(encoder, state.plain_text().len() as u32)?;
                            encoder.write_all(&res.corrections)?;
                            encoder.write_all(state.plain_text().text())?;
                            let sz = emit_compressed_block(
                                BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_DEFLATE_CONTINUE,
                                encoder,
                                writer,
                            )?;
                            self.compression_stats.zstd_compressed_size += sz as u64;

                            self.total_plain_text_seen += state.plain_text().len() as u64;
                            self.compression_stats.overhead_bytes += res.corrections.len() as u64;
                            self.compression_stats.uncompressed_size +=
                                state.plain_text().len() as u64;

                            self.content.drain(0..res.compressed_size);
                            self.last_attempt_chunk_size = self.content.len();

                            if state.is_done() {
                                self.state = ChunkParseState::Searching(None);
                            } else {
                                state.shrink_to_dictionary();
                            }
                        }
                    }
                }
            }
        }

        if input_complete && !self.input_complete {
            self.input_complete = true;

            if !self.content.is_empty() {
                let encoder = self.encoder.as_mut().unwrap();
                write_varint(encoder, self.content.len() as u32)?;
                encoder.write_all(&self.content)?;
                let sz = emit_compressed_block(
                    BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_LITERAL,
                    encoder,
                    writer,
                )?;
                self.compression_stats.zstd_compressed_size += sz as u64;
            }
            self.content.clear();

            // Finalize the Zstd encoder; finish bytes are discarded since each block
            // was already flushed and the decoder relies on EOF as the stream terminator.
            let encoder = self.encoder.take().unwrap();
            let _ = encoder.finish();

            // Write the CRC-32 end block: 0xFF sentinel + 4-byte LE CRC of original input.
            let crc = self.input_crc.clone().finalize();
            writer.write_all(&[0xFF])?;
            writer.write_all(&crc.to_le_bytes())?;

            // Finalize baseline encoder for stats
            if let Some(mut encoder) = self.baseline_encoder.take() {
                encoder.flush().context()?;
                encoder.do_finish().context()?;
                self.compression_stats.zstd_baseline_size = encoder.get_mut().length as u64;
            }
        }

        Ok(())
    }

    fn stats(&self) -> PreflateStats {
        self.compression_stats
    }
}

/// Flushes the encoder, writes [block_type][varint(compressed_size)][compressed_bytes] to
/// destination, clears the encoder's inner buffer, and returns the compressed byte count.
fn emit_compressed_block(
    block_type: u8,
    encoder: &mut zstd::stream::write::Encoder<'static, Vec<u8>>,
    destination: &mut impl Write,
) -> Result<usize> {
    encoder.flush().context()?;
    let compressed = encoder.get_mut();
    let len = compressed.len();
    destination.write_all(&[block_type])?;
    write_varint(destination, len as u32)?;
    destination.write_all(compressed)?;
    compressed.clear();
    Ok(len)
}

fn webp_compress(
    result: &mut impl Write,
    plain_text: &[u8],
    corrections: &[u8],
    idat: &IdatContents,
) -> Result<()> {
    use crate::container_common::BLOCK_TYPE_PNG;
    log::debug!("{:?}", idat);

    #[cfg(feature = "webp")]
    if let Some(png_header) = idat.png_header {
        use crate::idat_parse::{PngColorType, undo_png_filters};
        use std::ops::Deref;

        let bbp = png_header.color_type.bytes_per_pixel();
        let w = png_header.width as usize;
        let h = png_header.height as usize;

        log::debug!(
            "plain text compressing {} bytes ({}x{}x{})",
            plain_text.len(),
            w,
            h,
            bbp
        );

        // see if the bitmap looks like the way with think it should (bits per pixel map + 1 height worth of filter bytes)
        if (bbp * w * h) + h == plain_text.len() {
            let (bitmap, filters) = undo_png_filters(plain_text, w, h, bbp);

            let enc = webp::Encoder::new(
                &bitmap,
                match png_header.color_type {
                    PngColorType::Rgb => webp::PixelLayout::Rgb,
                    PngColorType::Rgba => webp::PixelLayout::Rgba,
                },
                png_header.width,
                png_header.height,
            );

            let mut webpconfig = webp::WebPConfig::new().unwrap();
            webpconfig.lossless = 1;
            webpconfig.alpha_compression = 0;
            webpconfig.exact = 1; // undocumented option, but required to not throw away color if alpha channel is zero

            // this is the default quality setting for webp lossless, we could dial it up
            // but the quality gains are marginal for the CPU cost, although the
            // CPU decompression cost is the same.
            webpconfig.quality = 75.0; // 0..100 higher is slower but better compression
            webpconfig.method = 4; // 0..6 higher is slower but better compression

            let comp = match enc.encode_advanced(&webpconfig) {
                Ok(c) => c,
                Err(e) => {
                    return preflate_rs::err_exit_code(
                        ExitCode::WebPDecodeError,
                        format!("Webp encode failed: {:?}", e),
                    );
                }
            };

            result.write_all(&[BLOCK_TYPE_PNG])?; // placeholder — caller skips this byte

            write_varint(result, corrections.len() as u32)?;
            write_varint(result, comp.deref().len() as u32)?;

            log::debug!(
                "Webp compressed {} bytes (vs {})",
                comp.deref().len(),
                idat.total_chunk_length
            );

            idat.write_to_bytestream(result)?;
            result.write_all(&filters)?;

            result.write_all(corrections)?;
            result.write_all(comp.deref())?;

            return Ok(());
        }
    }

    preflate_rs::err_exit_code(
        ExitCode::InvalidCompressedWrapper,
        "Webp compression not supported",
    )
}
