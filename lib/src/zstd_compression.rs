//! Implements processors for Zstandard compression and decompression using
//! the ProcessBuffer model. These are designed to be chained together with
//! the other ProcessBuffer implementations to create a full compression or
//! decompression pipeline.

use std::{
    collections::VecDeque,
    io::{BufRead, Write},
};

use crate::{
    ExitCode, PreflateContainerProcessor, PreflateError, PreflateStats, ProcessBuffer,
    RecreateContainerProcessor, Result, container_processor::PreflateConfig,
    preflate_error::AddContext, utils::write_dequeue,
};

/// processor that compresses the input using Zstandard
///
/// Designed to wrap around the PreflateChunkProcessor.
pub struct ZstdCompressContext<D: ProcessBuffer> {
    zstd_compress: zstd::stream::write::Encoder<'static, VecDeque<u8>>,
    input_complete: bool,
    internal: D,

    /// if set, the encoder will write all the input to a null zstd encoder to see how much
    /// compression we would get if we just used Zstandard without any Preflate processing.
    ///
    /// This gives a fairer comparison of the compression ratio of Preflate + Zstandard vs. Zstandard
    /// since Zstd does compress the data a bit, especially if there is a lot of non-Deflate streams
    /// in the file.
    test_baseline: Option<zstd::stream::write::Encoder<'static, MeasureWriteSink>>,

    zstd_baseline_size: u64,
    zstd_compressed_size: u64,

    done_write: bool,
}

impl<D: ProcessBuffer> ZstdCompressContext<D> {
    pub fn new(internal: D, compression_level: i32, test_baseline: bool) -> Self {
        ZstdCompressContext {
            zstd_compress: zstd::stream::write::Encoder::new(VecDeque::new(), compression_level)
                .unwrap(),
            input_complete: false,
            done_write: false,
            internal,
            zstd_baseline_size: 0,
            zstd_compressed_size: 0,
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
}

impl<D: ProcessBuffer> ProcessBuffer for ZstdCompressContext<D> {
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
        }

        if input_complete && !self.input_complete {
            self.input_complete = true;
        }

        let done_write = self
            .internal
            .process_buffer(input, input_complete, &mut self.zstd_compress, usize::MAX)
            .context()?;

        if done_write && !self.done_write {
            self.done_write = true;
            self.zstd_compress.flush().context()?;

            if let Some(encoder) = &mut self.test_baseline {
                encoder.do_finish()?;
                self.zstd_baseline_size = encoder.get_mut().length as u64;
            }
        }

        let output = self.zstd_compress.get_mut();
        let amount_written = write_dequeue(output, writer, max_output_write).context()?;
        self.zstd_compressed_size += amount_written as u64;

        Ok(done_write && output.len() == 0)
    }

    fn stats(&self) -> PreflateStats {
        PreflateStats {
            zstd_compressed_size: self.zstd_compressed_size,
            zstd_baseline_size: self.zstd_baseline_size,
            ..self.internal.stats()
        }
    }
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

/// Processor that decompresses the input using Zstandard
///
/// Designed to wrap around the RecreateContainerProcessor.
pub struct ZstdDecompressContext<D: ProcessBuffer> {
    zstd_decompress: zstd::stream::write::Decoder<'static, AcceptWrite<D, VecDeque<u8>>>,
}

/// used to accept the output from the Zstandard decoder and write it to the output buffer.
/// Since the plain text is significantly larger than the compressed version, we want
/// to avoid buffering the output in memory, so we send it directly to the recreator.
struct AcceptWrite<D: ProcessBuffer, O: Write> {
    internal: D,
    output: O,
    input_complete: bool,
    output_complete: bool,
}

impl<P: ProcessBuffer, O: Write> Write for AcceptWrite<P, O> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output_complete =
            self.internal
                .process_buffer(buf, self.input_complete, &mut self.output, usize::MAX)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<D: ProcessBuffer> ZstdDecompressContext<D> {
    pub fn new(internal: D) -> Self {
        ZstdDecompressContext {
            zstd_decompress: zstd::stream::write::Decoder::new(AcceptWrite {
                internal: internal,
                output: VecDeque::new(),
                input_complete: false,
                output_complete: false,
            })
            .unwrap(),
        }
    }
}

impl<D: ProcessBuffer> ProcessBuffer for ZstdDecompressContext<D> {
    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
        max_output_write: usize,
    ) -> Result<bool> {
        if self.zstd_decompress.get_mut().input_complete && (input.len() > 0 || !input_complete) {
            return Err(PreflateError::new(
                ExitCode::InvalidParameter,
                "more data provided after input_complete signaled",
            ));
        }

        if input.len() > 0 {
            self.zstd_decompress.write_all(input).context()?;
        }

        if input_complete && !self.zstd_decompress.get_mut().input_complete {
            self.zstd_decompress.flush().context()?;

            self.zstd_decompress.get_mut().input_complete = true;
        }

        let a = self.zstd_decompress.get_mut();

        let amount_written = write_dequeue(&mut a.output, writer, max_output_write).context()?;

        if input_complete
            && !a.output_complete
            && a.output.len() == 0
            && amount_written < max_output_write
        {
            a.output_complete =
                a.internal
                    .process_buffer(&[], true, writer, max_output_write - amount_written)?;
        }

        Ok(a.output_complete && a.output.len() == 0)
    }
}

/// Expands the Zlib compressed streams in the data and then recompresses the result
/// with Zstd with the given level.
pub fn zstd_preflate_whole_deflate_stream(
    config: PreflateConfig,
    input: &mut impl BufRead,
    output: &mut impl Write,
    compression_level: i32,
) -> Result<PreflateStats> {
    let mut ctx = ZstdCompressContext::new(
        PreflateContainerProcessor::new(config),
        compression_level,
        false,
    );

    ctx.copy_to_end(input, output).context()?;

    Ok(ctx.stats())
}

/// Decompresses the Zstd compressed data and then recompresses the result back
/// to the original Zlib compressed streams.
pub fn zstd_recreate_whole_deflate_stream(
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    let mut ctx = ZstdDecompressContext::<RecreateContainerProcessor>::new(
        RecreateContainerProcessor::new(1024 * 1024 * 128),
    );

    ctx.copy_to_end(input, output).context()?;

    Ok(())
}

#[test]
fn verify_zip_compress_zstd() {
    use crate::utils::read_file;
    let v = read_file("samplezip.zip");

    let mut compressed = Vec::new();
    let stats = zstd_preflate_whole_deflate_stream(
        PreflateConfig::default(),
        &mut std::io::Cursor::new(&v),
        &mut compressed,
        1, // for testing use a lower level to save CPU
    )
    .unwrap();

    let mut recreated = Vec::new();
    zstd_recreate_whole_deflate_stream(&mut std::io::Cursor::new(&compressed), &mut recreated)
        .unwrap();

    assert!(v == recreated);
    println!(
        "original zip = {} bytes, expanded = {} bytes recompressed zip = {} bytes",
        v.len(),
        stats.uncompressed_size,
        compressed.len()
    );
}

/// tests zstd compression buffer processing without involving preflate code
#[test]
fn roundtrip_zstd_only_contexts() {
    use crate::container_processor::NopProcessBuffer;
    use crate::utils::{assert_eq_array, read_file};
    use crate::zstd_compression::{ZstdCompressContext, ZstdDecompressContext};

    let original = read_file("samplezip.zip");

    let mut context = ZstdCompressContext::new(NopProcessBuffer::new(), 9, false);
    let compressed = context.process_vec_size(&original, 997, 997).unwrap();

    let mut context = ZstdDecompressContext::new(NopProcessBuffer::new());
    let recreated = context.process_vec_size(&compressed, 997, 997).unwrap();

    assert_eq_array(&original, &recreated);
}
