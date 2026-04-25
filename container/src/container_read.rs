use byteorder::ReadBytesExt;
use crc32fast::Hasher as CrcHasher;
use lepton_jpeg::{DEFAULT_THREAD_POOL, EnabledFeatures};

use std::{
    collections::VecDeque,
    io::{Cursor, Read, Write},
};

use crate::{
    container_common::{
        BLOCK_COMPRESSION_MASK, BLOCK_COMPRESSION_NONE, BLOCK_COMPRESSION_ZSTD, BLOCK_TYPE_DEFLATE,
        BLOCK_TYPE_DEFLATE_CONTINUE, BLOCK_TYPE_JPEG_LEPTON, BLOCK_TYPE_LITERAL, BLOCK_TYPE_MASK,
        BLOCK_TYPE_PNG, BLOCK_TYPE_WEBP, COMPRESSED_WRAPPER_VERSION_2, ProcessBuffer, read_varint,
    },
    idat_parse::{IdatContents, recreate_idat},
    scoped_read::ScopedRead,
};

use preflate_rs::{
    AddContext, ExitCode, PreflateError, RecreateStreamProcessor, Result, err_exit_code,
    recreate_whole_deflate_stream,
};

/// Write wrapper that computes a running CRC-32 of every byte written.
struct CrcWriter<'a, W: Write> {
    inner: &'a mut W,
    hasher: &'a mut CrcHasher,
}

impl<W: Write> Write for CrcWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

enum DecompressionState {
    Start,
    StartSegment,
    /// accumulate compressed_size bytes then decode and process the block immediately.
    AccumulateBlock {
        block_type: u8,
        compressed_size: usize,
    },
    /// accumulate lepton bytes then decode the JPEG block immediately.
    JpegAccumulate {
        lepton_length: usize,
    },
    /// accumulate raw WebP-compressed PNG bytes then process the block immediately.
    WebpAccumulate {
        total_len: usize,
    },
    /// 0xFF end block was parsed; CRC check deferred to process_buffer.
    CrcCheck {
        expected: u32,
    },
}

/// recreates the orignal content from the chunked data
pub struct RecreateContainerProcessor {
    capacity: usize,
    input: VecDeque<u8>,
    input_complete: bool,
    state: DecompressionState,

    /// state of the predictor and plain text if we need to contiune a deflate stream
    /// if it was too big to complete in a single chunk
    deflate_continue_state: Option<RecreateStreamProcessor>,

    /// persistent Zstd decoder — maintains the streaming context across blocks
    zstd_decoder: zstd::stream::raw::Decoder<'static>,

    /// running CRC-32 of all output bytes, verified against the 0xFF end block
    output_crc: CrcHasher,
}

impl RecreateContainerProcessor {
    pub fn new(capacity: usize) -> Self {
        RecreateContainerProcessor {
            input: VecDeque::new(),
            capacity,
            input_complete: false,
            state: DecompressionState::Start,
            deflate_continue_state: None,
            zstd_decoder: zstd::stream::raw::Decoder::new().expect("failed to create zstd decoder"),
            output_crc: CrcHasher::new(),
        }
    }
}

impl ProcessBuffer for RecreateContainerProcessor {
    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
    ) -> Result<()> {
        if self.input_complete && (!input.is_empty() || !input_complete) {
            return Err(PreflateError::new(
                ExitCode::InvalidParameter,
                "more data provided after input_complete signaled",
            ));
        }

        // we could have been passed a big buffer, so we need to process it in chunks
        let mut amount_read = 0;
        loop {
            let amount_to_read = (input.len() - amount_read).min(self.capacity);

            // when we get to the end and we've read everything, we can signal that we are done
            if amount_read + amount_to_read == input.len() && input_complete {
                self.input_complete = true;
            }

            self.input
                .extend(&input[amount_read..amount_read + amount_to_read]);

            amount_read += amount_to_read;

            self.with_crc_writer(writer, |this, crc_writer| {
                this.process_buffer_internal(crc_writer)
            })?;

            // If process_buffer_internal parsed the 0xFF end block, verify the CRC now
            // that output_crc has been restored with all written bytes.
            if let DecompressionState::CrcCheck { expected } = self.state {
                let actual = self.output_crc.clone().finalize();
                if actual != expected {
                    return err_exit_code(
                        ExitCode::InvalidCompressedWrapper,
                        format!("CRC-32 mismatch: expected {expected:#010x}, got {actual:#010x}"),
                    );
                }
                self.state = DecompressionState::StartSegment;
            }

            if amount_read == input.len() {
                break;
            }
        }

        Ok(())
    }
}

impl RecreateContainerProcessor {
    /// Runs `f` with a `CrcWriter` wrapping `writer`, then restores `self.output_crc`.
    ///
    /// `self.output_crc` must be borrowed mutably through the `CrcWriter`, but
    /// `f` also needs `&mut self` to drive the state machine — a direct borrow
    /// conflict.  This helper resolves it by temporarily swapping `output_crc`
    /// out of `self` with `mem::replace`, so the field is no longer part of the
    /// active `&mut self` borrow while `f` runs.
    fn with_crc_writer<W: Write, F>(&mut self, writer: &mut W, f: F) -> Result<()>
    where
        F: FnOnce(&mut Self, &mut CrcWriter<'_, W>) -> Result<()>,
    {
        let mut hasher = std::mem::replace(&mut self.output_crc, CrcHasher::new());
        let result = {
            let mut crc_writer = CrcWriter {
                inner: writer,
                hasher: &mut hasher,
            };
            f(self, &mut crc_writer)
        };
        self.output_crc = hasher;
        result
    }

    fn process_buffer_internal(&mut self, writer: &mut impl Write) -> Result<()> {
        loop {
            match &mut self.state {
                DecompressionState::Start => {
                    if !self.input_complete && self.input.is_empty() {
                        break;
                    }

                    let version = self.input.read_u8()?;

                    match version {
                        COMPRESSED_WRAPPER_VERSION_2 => {
                            self.state = DecompressionState::StartSegment;
                        }
                        _ => {
                            return err_exit_code(
                                ExitCode::InvalidCompressedWrapper,
                                format!("Invalid version {version}"),
                            );
                        }
                    }
                }
                DecompressionState::StartSegment => {
                    // here's a good place to stop if we run out of input
                    if self.input.is_empty() {
                        break;
                    }

                    // read type byte, then dispatch
                    self.state = match self.input.scoped_read(|r| {
                        let type_byte = r.read_u8()?;

                        // 0xFF is the CRC end block: 4 raw bytes, no varint.
                        if type_byte == 0xFF {
                            let mut buf = [0u8; 4];
                            r.read_exact(&mut buf)?;
                            return Ok(DecompressionState::CrcCheck {
                                expected: u32::from_le_bytes(buf),
                            });
                        }

                        let compression = type_byte & BLOCK_COMPRESSION_MASK;
                        let block_type = type_byte & BLOCK_TYPE_MASK;
                        match compression {
                            BLOCK_COMPRESSION_NONE => match block_type {
                                BLOCK_TYPE_JPEG_LEPTON => {
                                    let lepton_length = read_varint(r)? as usize;
                                    Ok(DecompressionState::JpegAccumulate { lepton_length })
                                }
                                BLOCK_TYPE_WEBP => {
                                    let total_len = read_varint(r)? as usize;
                                    Ok(DecompressionState::WebpAccumulate { total_len })
                                }
                                _ => err_exit_code(
                                    ExitCode::InvalidCompressedWrapper,
                                    "unknown raw block type",
                                ),
                            },
                            BLOCK_COMPRESSION_ZSTD => {
                                let compressed_size = read_varint(r)? as usize;
                                Ok(DecompressionState::AccumulateBlock {
                                    block_type,
                                    compressed_size,
                                })
                            }
                            _ => err_exit_code(
                                ExitCode::InvalidCompressedWrapper,
                                "unknown compression algorithm",
                            ),
                        }
                    }) {
                        Ok(s) => s,
                        Err(e) => {
                            if !self.input_complete && e.exit_code() == ExitCode::ShortRead {
                                break;
                            } else {
                                return Err(e);
                            }
                        }
                    };
                }

                DecompressionState::AccumulateBlock {
                    block_type,
                    compressed_size,
                } => {
                    if self.input.len() < *compressed_size {
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input in block",
                            ));
                        }
                        break;
                    }

                    let block_type = *block_type;
                    let compressed_bytes: Vec<u8> = self.input.drain(0..*compressed_size).collect();
                    let decoded = drain_zstd_block(&mut self.zstd_decoder, &compressed_bytes)?;
                    process_compressed_block(
                        block_type,
                        &mut Cursor::new(decoded),
                        &mut self.deflate_continue_state,
                        writer,
                    )?;
                    self.state = DecompressionState::StartSegment;
                }

                DecompressionState::JpegAccumulate { lepton_length } => {
                    if self.input.len() < *lepton_length {
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input in jpeg block",
                            ));
                        }
                        break;
                    }

                    let lepton_bytes: Vec<u8> = self.input.drain(0..*lepton_length).collect();
                    if let Err(e) = lepton_jpeg::decode_lepton(
                        &mut Cursor::new(&lepton_bytes),
                        writer,
                        &EnabledFeatures::compat_lepton_vector_read(),
                        &DEFAULT_THREAD_POOL,
                    ) {
                        return Err(PreflateError::new(
                            ExitCode::InvalidCompressedWrapper,
                            format!("JPEG Lepton decode failed: {}", e),
                        ));
                    }
                    self.state = DecompressionState::StartSegment;
                }

                DecompressionState::WebpAccumulate { total_len } => {
                    if self.input.len() < *total_len {
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input in webp block",
                            ));
                        }
                        break;
                    }

                    let webp_bytes: Vec<u8> = self.input.drain(0..*total_len).collect();
                    // Payload is what webp_compress wrote after the BLOCK_TYPE_PNG type byte,
                    // so process_compressed_block can parse it directly.
                    process_compressed_block(
                        BLOCK_TYPE_PNG,
                        &mut Cursor::new(webp_bytes),
                        &mut self.deflate_continue_state,
                        writer,
                    )?;
                    self.state = DecompressionState::StartSegment;
                }

                DecompressionState::CrcCheck { .. } => {
                    // CRC verification is handled in process_buffer after this returns.
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Feeds `compressed` bytes into the persistent `decoder` and returns all decompressed output.
///
/// Each call corresponds to one Zstd flush frame (written by the encoder via `flush()`).
/// After consuming all input bytes the decoder is drained until it produces no more output,
/// which is guaranteed because `ZSTD_e_flush` ensures all data is available to the decoder
/// before the next block starts.
fn drain_zstd_block(
    decoder: &mut zstd::stream::raw::Decoder<'static>,
    compressed: &[u8],
) -> Result<Vec<u8>> {
    use zstd::stream::raw::{InBuffer, Operation, OutBuffer};

    let mut output = Vec::new();
    let mut scratch = vec![0u8; 65536];
    let mut in_buf = InBuffer::around(compressed);

    loop {
        let mut out_buf = OutBuffer::around(scratch.as_mut_slice());
        decoder.run(&mut in_buf, &mut out_buf).map_err(|e| {
            PreflateError::new(
                ExitCode::InvalidCompressedWrapper,
                format!("zstd decode failed: {e}"),
            )
        })?;
        let produced = out_buf.pos();
        output.extend_from_slice(&scratch[..produced]);

        // Stop when all input has been consumed and the decoder produced no more output.
        // zstd guarantees progress (either bytes_read > 0 or bytes_written > 0) so this
        // loop always terminates.
        if in_buf.pos() >= compressed.len() && produced == 0 {
            break;
        }
    }

    Ok(output)
}

/// Parses and processes a single non-JPEG/non-WebP block.
///
/// `cursor` wraps the output of `drain_zstd_block` for compressed blocks,
/// or the raw WebP payload for `BLOCK_TYPE_PNG` blocks stored outside Zstd.
///
/// Layout written by the encoder for each block type (block_type = lower 6 bits):
///   BLOCK_TYPE_LITERAL:          varint(len) + data
///   BLOCK_TYPE_DEFLATE:          varint(corrections_len) + varint(plaintext_len) + corrections + plaintext
///   BLOCK_TYPE_DEFLATE_CONTINUE: same as BLOCK_TYPE_DEFLATE
///   BLOCK_TYPE_PNG:              varint(correction_length) + varint(uncompressed_length) +
///                                IdatContents + [filters if png_header present] +
///                                corrections + (webp_data or raw_plaintext)
fn process_compressed_block(
    block_type: u8,
    cursor: &mut Cursor<Vec<u8>>,
    deflate_continue_state: &mut Option<RecreateStreamProcessor>,
    writer: &mut impl Write,
) -> Result<()> {
    match block_type {
        BLOCK_TYPE_LITERAL => {
            let length = read_varint(cursor)? as usize;
            let mut data = vec![0u8; length];
            cursor.read_exact(&mut data).map_err(|e| {
                PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
            })?;
            writer.write_all(&data)?;
        }
        BLOCK_TYPE_DEFLATE => {
            *deflate_continue_state = None;

            let correction_length = read_varint(cursor)? as usize;
            let uncompressed_length = read_varint(cursor)? as usize;

            let mut corrections = vec![0u8; correction_length];
            cursor.read_exact(&mut corrections).map_err(|e| {
                PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
            })?;

            let mut plain_text_buf = vec![0u8; uncompressed_length];
            cursor.read_exact(&mut plain_text_buf).map_err(|e| {
                PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
            })?;

            let mut reconstruct = RecreateStreamProcessor::new();
            let (comp, _) = reconstruct
                .recompress(&mut Cursor::new(&plain_text_buf), &corrections)
                .context()?;

            writer.write_all(&comp)?;
            *deflate_continue_state = Some(reconstruct);
        }
        BLOCK_TYPE_DEFLATE_CONTINUE => {
            let correction_length = read_varint(cursor)? as usize;
            let uncompressed_length = read_varint(cursor)? as usize;

            let mut corrections = vec![0u8; correction_length];
            cursor.read_exact(&mut corrections).map_err(|e| {
                PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
            })?;

            let mut plain_text_buf = vec![0u8; uncompressed_length];
            cursor.read_exact(&mut plain_text_buf).map_err(|e| {
                PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
            })?;

            let reconstruct = deflate_continue_state.as_mut().ok_or_else(|| {
                PreflateError::new(
                    ExitCode::InvalidCompressedWrapper,
                    "no deflate state to continue",
                )
            })?;

            let (comp, _) = reconstruct
                .recompress(&mut Cursor::new(&plain_text_buf), &corrections)
                .context()?;

            writer.write_all(&comp)?;
        }
        BLOCK_TYPE_PNG => {
            let correction_length = read_varint(cursor)? as usize;
            let uncompressed_length = read_varint(cursor)? as usize;
            let idat = IdatContents::read_from_bytestream(cursor)?;

            let mut filters = Vec::new();
            if let Some(png_header) = &idat.png_header {
                filters.resize(png_header.height as usize, 0);
                cursor.read_exact(&mut filters[..]).map_err(|e| {
                    PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
                })?;
            }

            let mut corrections = vec![0u8; correction_length];
            cursor.read_exact(&mut corrections).map_err(|e| {
                PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
            })?;

            let plain_text;
            if let Some(header) = &idat.png_header {
                let mut webp = vec![0u8; uncompressed_length];
                cursor.read_exact(&mut webp).map_err(|e| {
                    PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
                })?;
                plain_text = webp_decompress(&filters, webp, header).context()?;
            } else {
                let mut raw = vec![0u8; uncompressed_length];
                cursor.read_exact(&mut raw).map_err(|e| {
                    PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
                })?;
                plain_text = raw;
            }

            let recompressed =
                recreate_whole_deflate_stream(&plain_text, &corrections).context()?;

            recreate_idat(&idat, &recompressed[..], writer).context()?;
        }
        _ => {
            return err_exit_code(
                ExitCode::InvalidCompressedWrapper,
                format!("Unknown block type {block_type}"),
            );
        }
    }
    Ok(())
}

fn webp_decompress(
    filters: &[u8],
    webp: Vec<u8>,
    header: &crate::idat_parse::PngHeader,
) -> Result<Vec<u8>> {
    #[cfg(feature = "webp")]
    if let Some(result) = webp::Decoder::new(webp.as_slice()).decode() {
        use crate::idat_parse::apply_png_filters_with_types;
        use std::ops::Deref;

        let m = result.deref();

        return Ok(apply_png_filters_with_types(
            m,
            header.width as usize,
            header.height as usize,
            if result.is_alpha() { 4 } else { 3 },
            header.color_type.bytes_per_pixel(),
            filters,
        ));
    }
    err_exit_code(ExitCode::InvalidCompressedWrapper, "Webp decode failed")
}
