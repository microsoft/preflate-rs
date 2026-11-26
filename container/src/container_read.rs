use byteorder::ReadBytesExt;
use crc32fast::Hasher as CrcHasher;
use lepton_jpeg::{DEFAULT_THREAD_POOL, EnabledFeatures};

use std::{
    collections::VecDeque,
    io::{Cursor, Read, Write},
    num::Saturating,
};

use crate::{
    container_common::{
        BLOCK_COMPRESSION_MASK, BLOCK_COMPRESSION_NONE, BLOCK_COMPRESSION_ZSTD, BLOCK_TYPE_DEFLATE,
        BLOCK_TYPE_DEFLATE_CONTINUE, BLOCK_TYPE_JPEG_LEPTON, BLOCK_TYPE_LITERAL, BLOCK_TYPE_MASK,
        BLOCK_TYPE_PNG, BLOCK_TYPE_WEBP, COMPRESSED_WRAPPER_VERSION_3, PreflateContainerConfig,
        ProcessBuffer, SizeValue, check_size, read_varint,
    },
    idat_parse::{IdatContents, checked_image_size, recreate_idat},
    scoped_read::ScopedRead,
};

use preflate_rs::{
    AddContext, ExitCode, PreflateError, RecreateStreamProcessor, Result, err_exit_code,
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
    Done,
}

/// recreates the orignal content from the chunked data
pub struct RecreateContainerProcessor {
    capacity: usize,
    config: PreflateContainerConfig,
    input: VecDeque<u8>,
    input_complete: bool,
    failed: bool,
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
        Self::with_config(capacity, &PreflateContainerConfig::default())
    }

    pub fn with_config(capacity: usize, config: &PreflateContainerConfig) -> Self {
        RecreateContainerProcessor {
            input: VecDeque::new(),
            capacity,
            config: config.clone(),
            input_complete: false,
            failed: false,
            state: DecompressionState::Start,
            deflate_continue_state: None,
            zstd_decoder: zstd::stream::raw::Decoder::new().expect("failed to create zstd decoder"),
            output_crc: CrcHasher::new(),
        }
    }
}

impl ProcessBuffer for RecreateContainerProcessor {
    fn pending_output_limit(&self) -> usize {
        self.config.max_pending_output
    }

    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
    ) -> Result<()> {
        if self.failed {
            return err_exit_code(
                ExitCode::InvalidCompressedWrapper,
                "decoder cannot be reused after an error",
            );
        }
        self.failed = true;
        if matches!(self.state, DecompressionState::Done) && !input.is_empty() {
            return err_exit_code(
                ExitCode::InvalidCompressedWrapper,
                "data after CRC end block",
            );
        }
        if self.input_complete && (input.len() > 0 || !input_complete) {
            return Err(PreflateError::new(
                ExitCode::InvalidParameter,
                "more data provided after input_complete signaled",
            ));
        }

        // we could have been passed a big buffer, so we need to process it in chunks
        let mut amount_read = 0;
        loop {
            let available = self
                .config
                .compressed_block_limit
                .saturating_add(6)
                .saturating_sub(self.input.len());
            let amount_to_read = (input.len() - amount_read)
                .min(self.capacity.max(1))
                .min(available);
            if amount_to_read == 0 && amount_read < input.len() {
                return err_exit_code(
                    ExitCode::InvalidCompressedWrapper,
                    "Container input buffer limit exceeded",
                );
            }

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
                if !self.input.is_empty() || amount_read < input.len() {
                    return err_exit_code(
                        ExitCode::InvalidCompressedWrapper,
                        "data after CRC end block",
                    );
                }
                self.state = DecompressionState::Done;
            }

            if amount_read == input.len() {
                break;
            }
        }

        if self.input_complete && !matches!(self.state, DecompressionState::Done) {
            return err_exit_code(ExitCode::InvalidCompressedWrapper, "missing CRC end block");
        }

        self.failed = false;
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
                    if !self.input_complete && self.input.len() == 0 {
                        break;
                    }

                    let version = self.input.read_u8()?;

                    match version {
                        COMPRESSED_WRAPPER_VERSION_3 => {
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
                    if self.input.len() == 0 {
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
                                    let lepton_length = read_varint(r)?.to_usize()?;
                                    check_size(
                                        lepton_length,
                                        self.config.compressed_block_limit,
                                        "JPEG block",
                                    )?;
                                    Ok(DecompressionState::JpegAccumulate { lepton_length })
                                }
                                BLOCK_TYPE_WEBP => {
                                    let total_len = read_varint(r)?.to_usize()?;
                                    check_size(
                                        total_len,
                                        self.config.compressed_block_limit,
                                        "WebP block",
                                    )?;
                                    Ok(DecompressionState::WebpAccumulate { total_len })
                                }
                                _ => err_exit_code(
                                    ExitCode::InvalidCompressedWrapper,
                                    "unknown raw block type",
                                ),
                            },
                            BLOCK_COMPRESSION_ZSTD => {
                                let compressed_size = read_varint(r)?.to_usize()?;
                                check_size(
                                    compressed_size,
                                    self.config.compressed_block_limit,
                                    "Compressed block",
                                )?;
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
                    let decoded = drain_zstd_block(
                        &mut self.zstd_decoder,
                        &compressed_bytes,
                        self.config.decoded_block_limit,
                    )?;
                    process_compressed_block(
                        block_type,
                        &mut Cursor::new(decoded.as_slice()),
                        &mut self.deflate_continue_state,
                        writer,
                        &self.config,
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
                    match lepton_jpeg::decode_lepton(
                        &mut Cursor::new(&lepton_bytes),
                        writer,
                        &EnabledFeatures::compat_lepton_vector_read(),
                        &DEFAULT_THREAD_POOL,
                    ) {
                        Err(e) => {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                format!("JPEG Lepton decode failed: {}", e),
                            ));
                        }
                        Ok(_) => {}
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
                        &mut Cursor::new(webp_bytes.as_slice()),
                        &mut self.deflate_continue_state,
                        writer,
                        &self.config,
                    )?;
                    self.state = DecompressionState::StartSegment;
                }

                DecompressionState::CrcCheck { .. } => {
                    // CRC verification is handled in process_buffer after this returns.
                    break;
                }
                DecompressionState::Done => break,
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
    limit: usize,
) -> Result<Vec<u8>> {
    use zstd::stream::raw::{InBuffer, Operation, OutBuffer};

    let mut output = Vec::new();
    let mut scratch = vec![0u8; 65536];
    let mut in_buf = InBuffer::around(compressed);

    loop {
        let previous_position = in_buf.pos();
        let mut out_buf = OutBuffer::around(scratch.as_mut_slice());
        decoder.run(&mut in_buf, &mut out_buf).map_err(|e| {
            PreflateError::new(
                ExitCode::InvalidCompressedWrapper,
                format!("zstd decode failed: {e}"),
            )
        })?;
        let produced = out_buf.pos();
        check_size(
            produced,
            limit.saturating_sub(output.len()),
            "Decoded block",
        )?;
        if output.capacity() - output.len() < produced {
            let capacity = output
                .capacity()
                .saturating_mul(2)
                .max(output.len() + produced)
                .min(limit);
            output
                .try_reserve_exact(capacity - output.len())
                .map_err(|_| {
                    PreflateError::new(ExitCode::OutOfMemory, "Unable to reserve decoded block")
                })?;
        }
        output.extend_from_slice(&scratch[..produced]);

        // Stop when all input has been consumed and the decoder produced no more output.
        // zstd guarantees progress (either bytes_read > 0 or bytes_written > 0) so this
        // loop always terminates.
        if in_buf.pos() >= compressed.len() && produced == 0 {
            break;
        }
        if in_buf.pos() == previous_position && produced == 0 {
            return err_exit_code(
                ExitCode::InvalidCompressedWrapper,
                "Zstd decoder made no progress",
            );
        }
    }

    Ok(output)
}

fn read_payload<'a>(
    cursor: &mut Cursor<&'a [u8]>,
    length: usize,
    limit: usize,
) -> Result<&'a [u8]> {
    check_size(length, limit, "Payload")?;
    let start = cursor.position() as usize;
    let data = *cursor.get_ref();
    if start > data.len() || length > data.len().saturating_sub(start) {
        return err_exit_code(
            ExitCode::InvalidCompressedWrapper,
            "Payload exceeds remaining block",
        );
    }
    let end = start + length;
    cursor.set_position(end as u64);
    Ok(&data[start..end])
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
    cursor: &mut Cursor<&[u8]>,
    deflate_continue_state: &mut Option<RecreateStreamProcessor>,
    writer: &mut impl Write,
    limits: &PreflateContainerConfig,
) -> Result<()> {
    match block_type {
        BLOCK_TYPE_LITERAL => {
            let length = read_varint(cursor)?.to_usize()?;
            let data = read_payload(cursor, length, limits.decoded_block_limit)?;
            writer.write_all(data)?;
        }
        BLOCK_TYPE_DEFLATE => {
            *deflate_continue_state = None;

            let correction_length = read_varint(cursor)?.to_usize()?;
            let uncompressed_length = read_varint(cursor)?.to_usize()?;

            let corrections = read_payload(cursor, correction_length, limits.correction_limit)?;
            let plain_text_buf =
                read_payload(cursor, uncompressed_length, limits.chunk_plain_text_limit)?;

            let mut reconstruct = RecreateStreamProcessor::with_config(limits.preflate_config());
            let (comp, _) = reconstruct
                .recompress(&mut Cursor::new(plain_text_buf), corrections)
                .context()?;

            writer.write_all(&comp)?;
            *deflate_continue_state = Some(reconstruct);
        }
        BLOCK_TYPE_DEFLATE_CONTINUE => {
            let correction_length = read_varint(cursor)?.to_usize()?;
            let uncompressed_length = read_varint(cursor)?.to_usize()?;

            let corrections = read_payload(cursor, correction_length, limits.correction_limit)?;
            let plain_text_buf =
                read_payload(cursor, uncompressed_length, limits.chunk_plain_text_limit)?;

            let reconstruct = deflate_continue_state.as_mut().ok_or_else(|| {
                PreflateError::new(
                    ExitCode::InvalidCompressedWrapper,
                    "no deflate state to continue",
                )
            })?;

            let (comp, _) = reconstruct
                .recompress(&mut Cursor::new(plain_text_buf), corrections)
                .context()?;

            writer.write_all(&comp)?;
        }
        BLOCK_TYPE_PNG => {
            let correction_length = read_varint(cursor)?.to_usize()?;
            let uncompressed_length = read_varint(cursor)?.to_usize()?;
            let idat = IdatContents::read_from_bytestream(cursor, limits.max_chunk_size)?;

            let filters = if let Some(header) = &idat.png_header {
                let pixels = checked_image_size(
                    header.width as usize,
                    header.height as usize,
                    header.color_type.bytes_per_pixel(),
                    limits.image_limit,
                )?;
                check_size(
                    Saturating(pixels) + Saturating(header.height as usize),
                    limits.chunk_plain_text_limit,
                    "Filtered image",
                )?;
                read_payload(
                    cursor,
                    header.height as usize,
                    limits.chunk_plain_text_limit,
                )?
            } else {
                &[]
            };

            let corrections = read_payload(cursor, correction_length, limits.correction_limit)?;
            let payload = read_payload(
                cursor,
                uncompressed_length,
                if idat.png_header.is_some() {
                    limits.compressed_block_limit
                } else {
                    limits.chunk_plain_text_limit
                },
            )?;

            let decoded;
            let plain_text;
            if let Some(header) = &idat.png_header {
                if filters.iter().any(|&filter| filter > 4) {
                    return err_exit_code(ExitCode::InvalidIDat, "Invalid PNG filter");
                }
                decoded = webp_decompress(filters, payload, header, limits).context()?;
                plain_text = decoded.as_slice();
            } else {
                plain_text = payload;
            }

            let (recompressed, _) = RecreateStreamProcessor::with_config(limits.preflate_config())
                .recompress(&mut Cursor::new(plain_text), corrections)
                .context()?;

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
    webp: &[u8],
    header: &crate::idat_parse::PngHeader,
    limits: &PreflateContainerConfig,
) -> Result<Vec<u8>> {
    #[cfg(not(feature = "webp"))]
    let _ = (filters, webp, header, limits);
    #[cfg(feature = "webp")]
    {
        let features = webp::BitstreamFeatures::new(webp).ok_or_else(|| {
            PreflateError::new(ExitCode::InvalidCompressedWrapper, "Invalid WebP header")
        })?;
        if features.width() != header.width || features.height() != header.height {
            return err_exit_code(
                ExitCode::InvalidCompressedWrapper,
                "WebP and PNG dimensions differ",
            );
        }
        if features.has_alpha() && header.color_type.bytes_per_pixel() != 4 {
            return err_exit_code(
                ExitCode::InvalidCompressedWrapper,
                "WebP and PNG channel counts differ",
            );
        }
        checked_image_size(
            features.width() as usize,
            features.height() as usize,
            if features.has_alpha() { 4 } else { 3 },
            limits.image_limit,
        )?;
        match webp::Decoder::new(webp).decode() {
            Some(result) => {
                use crate::idat_parse::apply_png_filters_with_types;
                use std::ops::Deref;

                let m = result.deref();

                return Ok(apply_png_filters_with_types(
                    m,
                    header.width as usize,
                    header.height as usize,
                    if result.is_alpha() { 4 } else { 3 },
                    header.color_type.bytes_per_pixel(),
                    &filters,
                ));
            }
            _ => {}
        }
    }
    return err_exit_code(ExitCode::InvalidCompressedWrapper, "Webp decode failed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container_common::write_varint;
    use crate::container_write::PreflateContainerProcessor;
    use crate::idat_parse::{PngColorType, PngHeader};

    #[test]
    fn rejects_declared_payload_lengths_before_allocation() {
        for kind in [
            BLOCK_TYPE_LITERAL,
            BLOCK_TYPE_DEFLATE,
            BLOCK_TYPE_DEFLATE_CONTINUE,
            BLOCK_TYPE_PNG,
        ] {
            let mut payload = Vec::new();
            write_varint(&mut payload, u32::MAX).unwrap();
            if kind != BLOCK_TYPE_LITERAL {
                write_varint(&mut payload, 0).unwrap();
            }
            if kind == BLOCK_TYPE_PNG {
                payload.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 255]);
            }
            let error = process_compressed_block(
                kind,
                &mut Cursor::new(payload.as_slice()),
                &mut None,
                &mut Vec::new(),
                &PreflateContainerConfig::default(),
            )
            .unwrap_err();
            assert_eq!(error.exit_code(), ExitCode::InvalidCompressedWrapper);
        }
        let mut cursor = Cursor::new(b"abcd".as_slice());
        assert_eq!(read_payload(&mut cursor, 4, 4).unwrap(), b"abcd");
        assert!(read_payload(&mut Cursor::new(b"abc".as_slice()), 4, 4).is_err());
        assert!(read_payload(&mut Cursor::new(b"abcd".as_slice()), 4, 3).is_err());
    }

    #[test]
    fn bounds_zstd_expansion_at_exact_limit() {
        let plain = vec![0; 1024];
        let compressed = zstd::stream::encode_all(plain.as_slice(), 1).unwrap();
        assert_eq!(
            drain_zstd_block(
                &mut zstd::stream::raw::Decoder::new().unwrap(),
                &compressed,
                1024
            )
            .unwrap(),
            plain
        );
        let error = drain_zstd_block(
            &mut zstd::stream::raw::Decoder::new().unwrap(),
            &compressed,
            1023,
        )
        .unwrap_err();
        assert_eq!(error.exit_code(), ExitCode::InvalidCompressedWrapper);
    }

    #[test]
    fn decoder_cannot_resume_after_error() {
        let original = b"literal payload";
        let encoded =
            PreflateContainerProcessor::new(&PreflateContainerConfig::default(), 1, false)
                .process_vec(original)
                .unwrap();
        let mut malformed = vec![3];
        malformed.extend_from_slice(&encoded);

        let mut decoder = RecreateContainerProcessor::new(malformed.len());
        let mut output = Vec::new();
        assert!(
            decoder
                .process_buffer(&malformed, false, &mut output)
                .is_err()
        );
        assert!(decoder.process_buffer(&[], true, &mut output).is_err());
        assert!(output.is_empty());

        let mut decoder = RecreateContainerProcessor::new(encoded.len());
        decoder
            .process_buffer(&encoded[..2], false, &mut output)
            .unwrap();
        decoder
            .process_buffer(&encoded[2..], true, &mut output)
            .unwrap();
        assert_eq!(output, original);
    }

    #[test]
    fn rejects_data_after_verified_crc() {
        let original = b"literal payload";
        let encoded =
            PreflateContainerProcessor::new(&PreflateContainerConfig::default(), 1, false)
                .process_vec(original)
                .unwrap();
        let mut appended = encoded.clone();
        appended.extend_from_slice(&encoded[1..]);

        let mut decoder = RecreateContainerProcessor::new(1);
        let mut output = Vec::new();
        let error = decoder
            .process_buffer(&appended, true, &mut output)
            .unwrap_err();
        assert_eq!(error.exit_code(), ExitCode::InvalidCompressedWrapper);
        assert_eq!(output, original);

        let mut decoder = RecreateContainerProcessor::new(1);
        let mut output = Vec::new();
        decoder
            .process_buffer(&encoded, false, &mut output)
            .unwrap();
        decoder.process_buffer(&[], true, &mut output).unwrap();
        let error = decoder
            .process_buffer(&encoded[1..], true, &mut output)
            .unwrap_err();
        assert_eq!(error.exit_code(), ExitCode::InvalidCompressedWrapper);
        assert_eq!(output, original);
    }

    #[test]
    fn rejects_v2_frame_without_crc() {
        let original = b"literal payload";
        let encoded =
            PreflateContainerProcessor::new(&PreflateContainerConfig::default(), 1, false)
                .process_vec(original)
                .unwrap();
        assert_eq!(encoded[encoded.len() - 5], 0xff);
        for (length, expected) in [
            (1, ExitCode::InvalidCompressedWrapper),
            (encoded.len() - 5, ExitCode::InvalidCompressedWrapper),
            (encoded.len() - 1, ExitCode::ShortRead),
        ] {
            let mut decoder = RecreateContainerProcessor::new(1);
            let mut output = Vec::new();
            let error = decoder
                .process_buffer(&encoded[..length], true, &mut output)
                .unwrap_err();
            assert_eq!(error.exit_code(), expected);
        }
    }

    #[test]
    fn rejects_oversized_outer_blocks_and_varints() {
        let config = PreflateContainerConfig {
            compressed_block_limit: 8,
            ..PreflateContainerConfig::default()
        };
        for kind in [
            BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_LITERAL,
            BLOCK_TYPE_JPEG_LEPTON,
            BLOCK_TYPE_WEBP,
        ] {
            let mut decoder = RecreateContainerProcessor::with_config(1, &config);
            assert!(
                decoder
                    .process_buffer(&[2, kind], false, &mut Vec::new())
                    .is_ok()
            );
            let error = decoder
                .process_buffer(&[9], false, &mut Vec::new())
                .unwrap_err();
            assert_eq!(error.exit_code(), ExitCode::InvalidCompressedWrapper);
            assert!(decoder.input.len() <= 14);
        }
        let mut decoder = RecreateContainerProcessor::with_config(usize::MAX, &config);
        assert!(
            decoder
                .process_buffer(
                    &[2, 0x40, 0x80, 0x80, 0x80, 0x80, 0x80],
                    false,
                    &mut Vec::new()
                )
                .is_err()
        );
    }

    #[test]
    fn rejects_oversized_png_before_filter_allocation() {
        let mut payload = vec![0, 0];
        IdatContents {
            chunk_sizes: Vec::new(),
            zlib_header: [0; 2],
            total_chunk_length: 6,
            addler32: 0,
            png_header: Some(PngHeader {
                width: u32::MAX,
                height: u32::MAX,
                color_type: PngColorType::RGBA,
            }),
        }
        .write_to_bytestream(&mut payload)
        .unwrap();
        assert!(
            process_compressed_block(
                BLOCK_TYPE_PNG,
                &mut Cursor::new(payload.as_slice()),
                &mut None,
                &mut Vec::new(),
                &PreflateContainerConfig::default()
            )
            .is_err()
        );
        assert_eq!(checked_image_size(2, 2, 3, 12).unwrap(), 12);
        assert!(checked_image_size(2, 2, 3, 11).is_err());
        assert!(checked_image_size(usize::MAX, 2, 4, usize::MAX).is_err());
        assert!(checked_image_size(0, 2, 3, 12).is_err());
    }

    #[cfg(feature = "webp")]
    #[test]
    fn validates_webp_dimensions_and_pixel_budget_before_decode() {
        let encoded = webp::Encoder::from_rgb(&[0; 12], 2, 2).encode_lossless();
        let header = PngHeader {
            width: 2,
            height: 2,
            color_type: PngColorType::RGB,
        };
        let config = PreflateContainerConfig {
            image_limit: 12,
            ..PreflateContainerConfig::default()
        };
        assert_eq!(
            webp_decompress(&[0, 0], &encoded, &header, &config)
                .unwrap()
                .len(),
            14
        );
        assert!(
            webp_decompress(
                &[0, 0],
                &encoded,
                &header,
                &PreflateContainerConfig {
                    image_limit: 11,
                    ..config.clone()
                }
            )
            .is_err()
        );
        assert!(
            webp_decompress(
                &[0, 0],
                &encoded,
                &PngHeader {
                    width: 1000,
                    ..header
                },
                &config
            )
            .is_err()
        );
    }
}
