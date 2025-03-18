//! Implements processors for Zstandard compression and decompression using
//! the ProcessBuffer model. These are designed to be chained together with
//! the other ProcessBuffer implementations to create a full compression or
//! decompression pipeline.

use std::{collections::VecDeque, io::Write};

use crate::{
    preflate_error::AddContext, utils::write_dequeue, CompressionStats, ExitCode,
    PreflateCompressionContext, PreflateError, ProcessBuffer, RecreateFromChunksContext, Result,
};

pub struct ZstdDecompressContext<D: ProcessBuffer> {
    zstd_decompress: zstd::stream::write::Decoder<'static, VecDeque<u8>>,
    input_complete: bool,
    internal: D,
}

impl<D: ProcessBuffer> ZstdDecompressContext<D> {
    pub fn new(internal: D) -> Self {
        ZstdDecompressContext {
            zstd_decompress: zstd::stream::write::Decoder::new(VecDeque::new()).unwrap(),
            input_complete: false,
            internal,
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
        if self.input_complete && (input.len() > 0 || !input_complete) {
            return Err(PreflateError::new(
                ExitCode::InvalidParameter,
                "more data provided after input_complete signaled",
            ));
        }

        if input.len() > 0 {
            self.zstd_decompress.write_all(input).context()?;
        }

        if input_complete && !self.input_complete {
            self.input_complete = true;
            self.zstd_decompress.flush().context()?;
        }

        let output = self.zstd_decompress.get_mut();
        let slice0 = output.as_slices().0;
        let is_complete = input_complete && output.len() == slice0.len();

        let r = self.internal.process_buffer(
            output.as_slices().0,
            is_complete,
            writer,
            max_output_write,
        );

        output.drain(..slice0.len());

        r
    }
}

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

    fn stats(&self) -> CompressionStats {
        CompressionStats {
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

/// expands the Zlib compressed streams in the data and then recompresses the result
/// with Zstd with the maximum level.
pub fn compress_zstd(
    zlib_compressed_data: &[u8],
    loglevel: u32,
    compression_stats: &mut CompressionStats,
) -> Result<Vec<u8>> {
    let mut ctx = ZstdCompressContext::new(
        PreflateCompressionContext::new(loglevel, 1024 * 1024, 128 * 1024 * 1024),
        9,
        false,
    );

    let r = ctx.process_vec(zlib_compressed_data, usize::MAX, usize::MAX)?;

    *compression_stats = ctx.stats();

    Ok(r)
}

/// decompresses the Zstd compressed data and then recompresses the result back
/// to the original Zlib compressed streams.
pub fn decompress_zstd(compressed_data: &[u8], capacity: usize) -> Result<Vec<u8>> {
    let mut ctx = ZstdDecompressContext::<RecreateFromChunksContext>::new(
        RecreateFromChunksContext::new(capacity),
    );

    Ok(ctx.process_vec(compressed_data, usize::MAX, usize::MAX)?)
}

#[test]
fn verify_zip_compress_zstd() {
    use crate::utils::read_file;
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

/// tests zstd compression buffer processing without involving preflate code
#[test]
fn roundtrip_zstd_only_contexts() {
    use crate::preflate_container::NopProcessBuffer;
    use crate::utils::{assert_eq_array, read_file};
    use crate::zstd_compression::{ZstdCompressContext, ZstdDecompressContext};

    let original = read_file("samplezip.zip");

    let mut context = ZstdCompressContext::new(NopProcessBuffer::new(), 9, false);
    let compressed = context.process_vec(&original, 997, 997).unwrap();

    let mut context = ZstdDecompressContext::new(NopProcessBuffer::new());
    let recreated = context.process_vec(&compressed, 997, 997).unwrap();

    assert_eq_array(&original, &recreated);
}
