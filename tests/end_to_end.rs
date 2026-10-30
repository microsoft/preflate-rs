/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::ptr;

use libdeflate_sys::{
    libdeflate_alloc_compressor, libdeflate_deflate_compress, libdeflate_deflate_compress_bound,
    libdeflate_free_compressor,
};
use preflate_container::{
    PreflateContainerConfig, PreflateContainerProcessor, ProcessBuffer, RecreateContainerProcessor,
};
use preflate_rs::{
    PreflateConfig, PreflateStreamProcessor, RecreateStreamProcessor,
    preflate_whole_deflate_stream, recreate_whole_deflate_stream,
};

#[cfg(test)]
pub fn read_file(filename: &str) -> Vec<u8> {
    let filename = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("samples")
        .join(filename);
    println!("reading {0}", filename.to_str().unwrap());
    let mut f = File::open(filename).unwrap();

    let mut content = Vec::new();
    f.read_to_end(&mut content).unwrap();

    content
}

#[test]
fn end_to_end_compressed() {
    for i in 0..9 {
        let compressed_data = read_file(&format!("compressed_flate2_level{}.deflate", i));
        verifyresult(&compressed_data);

        let compressed_data = read_file(&format!("compressed_zlib_level{}.deflate", i));
        verifyresult(&compressed_data);
    }
}

#[test]
fn test_treepng() {
    test_container("treegdi.png");
}

#[test]
fn test_matchnotfound() {
    test_file("sample3.bin");
}

#[test]
fn test_pptxplaintext() {
    test_file("pptxplaintext.bin");
}

#[test]
fn test_nomatch() {
    test_file("sample2.bin");
}

#[test]
fn test_sample1() {
    test_file("sample1.bin");
}

#[test]
fn test_samplezip() {
    test_container("samplezip.zip");
}

#[test]
fn test_docx() {
    test_container("samplepptx.pptx");
}

fn test_container(filename: &str) {
    let v = read_file(filename);

    let mut c = Vec::new();
    let mut ctx = PreflateContainerProcessor::new(&PreflateContainerConfig::default(), 4, false);
    ctx.copy_to_end(&mut std::io::Cursor::new(&v), &mut c)
        .unwrap();
    let stats = ctx.stats();

    let mut r = Vec::new();
    let mut ctx = RecreateContainerProcessor::new(128 * 1024 * 1024);
    ctx.copy_to_end(&mut std::io::Cursor::new(&c), &mut r)
        .unwrap();
    assert!(v == r);

    println!(
        "file {} original size: {}, compressed size: {} (plaintext={})",
        filename,
        v.len(),
        c.len(),
        stats.uncompressed_size
    );
}

#[test]
fn libzng() {
    let level = 4;

    let v = read_file("pptxplaintext.bin");
    println!("zlibng level: {}", level);

    let output = libngzsys_compress(&v, level);

    let minusheader = &output[2..output.len() - 4];

    // write to file
    //let mut f = File::create(format!("c:\\temp\\compressed_zlib_level{}.bin", level)).unwrap();
    //.write_all(minusheader).unwrap();

    verifyresult(minusheader);
}

fn verifyresult(compressed_data: &[u8]) {
    let (result, plain_text) =
        preflate_whole_deflate_stream(compressed_data, &PreflateConfig::default()).unwrap();
    let recomp = recreate_whole_deflate_stream(&plain_text.text(), &result.corrections).unwrap();

    println!(
        "compressed size: {}, cabac: {}",
        compressed_data.len(),
        result.corrections.len()
    );
    println!("parameters: {:?}", result.parameters);

    assert_eq!(compressed_data, recomp);
}

fn test_file(filename: &str) {
    let v = read_file(filename);

    // Zlib compression with different compression levels
    for level in 1..=9 {
        println!("zlib level: {}", level);

        let output = libzsys_compress(&v, level, Strategy::Default);

        let minusheader = &output[2..output.len() - 4];

        // write to file
        //let mut f = File::create(format!("c:\\temp\\compressed_zlib_level{}.bin", level)).unwrap();
        //.write_all(minusheader).unwrap();

        verifyresult(minusheader);
    }

    for s in [Strategy::HuffmanOnly, Strategy::Rle, Strategy::Fixed].iter() {
        println!("zlib level: strategy {:?}", s);

        let output = libzsys_compress(&v, 1, *s);

        let minusheader = &output[2..output.len() - 4];

        // write to file
        //let mut f = File::create(format!("c:\\temp\\compressed_zlib_level{}.bin", level)).unwrap();
        //.write_all(minusheader).unwrap();

        verifyresult(minusheader);
    }

    for level in 0..=9 {
        println!("libdeflate level: {}", level);
        let output = libdeflate_compress(&v, level);

        // write to file
        /*let mut f = File::create(format!(
            "c:\\temp\\compressed_libdeflate_level{}.deflate",
            level
        ))
        .unwrap();
        f.write_all(&output).unwrap();*/

        verifyresult(&output);
    }

    // Zlibng compression with different compression levels
    for level in 1..=4 {
        println!("zlibng level: {}", level);

        let output = libngzsys_compress(&v, level);

        let minusheader = &output[2..output.len() - 4];

        // write to file
        /*let mut f = File::create(format!(
            "c:\\temp\\compressed_zlibng_level{}.deflate",
            level
        ))
        .unwrap();
        f.write_all(minusheader).unwrap();*/

        verifyresult(minusheader);
    }

    for level in 0..=9 {
        println!("miniz_oxide level: {}", level);
        let output = miniz_oxide::deflate::compress_to_vec(&v, level);
        verifyresult(&output);
    }
}

#[derive(Debug, Copy, Clone)]
enum Strategy {
    Default,
    Filtered,
    HuffmanOnly,
    Rle,
    Fixed,
}

// The bindings use non-null Rust function pointers, so null/default callbacks
// cannot be represented by transmuting a null C pointer.
unsafe extern "C" fn zlib_alloc(
    _opaque: *mut std::ffi::c_void,
    items: std::ffi::c_uint,
    size: std::ffi::c_uint,
) -> *mut std::ffi::c_void {
    unsafe { libc::calloc(items as usize, size as usize) }
}

unsafe extern "C" fn zlib_free(_opaque: *mut std::ffi::c_void, address: *mut std::ffi::c_void) {
    unsafe { libc::free(address) }
}

#[test]
fn zlib_allocator_callbacks_return_zeroed_memory() {
    unsafe {
        let address = zlib_alloc(ptr::null_mut(), 4, 8);
        assert!(!address.is_null());
        assert!(
            std::slice::from_raw_parts(address.cast::<u8>(), 32)
                .iter()
                .all(|&byte| byte == 0)
        );
        zlib_free(ptr::null_mut(), address);
    }
}

fn libzsys_compress(input_data: &[u8], level: i32, strategy: Strategy) -> Vec<u8> {
    libzsys_compress_options(input_data, level, strategy, 15, 8)
}

fn libzsys_compress_options(
    input_data: &[u8],
    level: i32,
    strategy: Strategy,
    window_bits: i32,
    mem_level: i32,
) -> Vec<u8> {
    libzsys_compress_with_flush(input_data, level, strategy, window_bits, mem_level, None)
}

fn libzsys_compress_with_flush(
    input_data: &[u8],
    level: i32,
    strategy: Strategy,
    window_bits: i32,
    mem_level: i32,
    flush: Option<i32>,
) -> Vec<u8> {
    let mut output = Vec::new();
    use libz_sys::*;
    unsafe {
        let mut z_stream = z_stream {
            next_in: input_data.as_ptr() as *mut _,
            avail_in: input_data.len() as u32,
            next_out: ptr::null_mut(),
            avail_out: 0,
            total_in: 0,
            total_out: 0,
            msg: std::ptr::null_mut(),
            state: std::ptr::null_mut(),
            zalloc: zlib_alloc,
            zfree: zlib_free,
            opaque: ptr::null_mut(),
            data_type: 0,
            adler: 0,
            reserved: 0,
        };

        // Additional options for deflateInit2_
        let version = zlibVersion(); // Use the zlib version defined in the library
        let stream_size = std::mem::size_of::<z_stream>() as i32;

        // Initialize the zlib stream for compression with deflateInit2_

        assert_eq!(
            deflateInit2_(
                &mut z_stream,
                level,
                Z_DEFLATED,
                window_bits,
                mem_level,
                match strategy {
                    Strategy::Default => Z_DEFAULT_STRATEGY,
                    Strategy::Filtered => Z_FILTERED,
                    Strategy::HuffmanOnly => Z_HUFFMAN_ONLY,
                    Strategy::Rle => Z_RLE,
                    Strategy::Fixed => Z_FIXED,
                },
                version,
                stream_size
            ),
            Z_OK
        );

        let bound = deflateBound(&mut z_stream, input_data.len().try_into().unwrap());
        output.resize(
            usize::try_from(bound).unwrap() + if flush.is_some() { 32 } else { 0 },
            0,
        );

        z_stream.next_out = output.as_mut_ptr() as *mut _;
        z_stream.avail_out = output.len() as u32;

        if let Some(flush) = flush {
            assert_eq!(Z_OK, deflate(&mut z_stream, flush));
            assert_eq!(z_stream.avail_in, 0);
            assert!(z_stream.avail_out > 0);
        }
        assert_eq!(Z_STREAM_END, deflate(&mut z_stream, Z_FINISH));
        let output_len = usize::try_from(z_stream.total_out).unwrap();
        assert!(
            output_len <= output.len(),
            "zlib exceeded its output buffer"
        );
        output.truncate(output_len);

        assert_eq!(Z_OK, deflateEnd(&mut z_stream));
    }
    output
}

#[test]
fn specialized_strategies_survive_empty_flush_tails() {
    for (strategy, plain) in [
        (Strategy::HuffmanOnly, b"abc".to_vec()),
        (Strategy::Rle, vec![b'A'; 200]),
    ] {
        let baseline = libzsys_compress(&plain, 6, strategy);
        let (baseline_result, _) = preflate_whole_deflate_stream(
            &baseline[2..baseline.len() - 4],
            &PreflateConfig::default(),
        )
        .unwrap();
        let expected = baseline_result.parameters.unwrap().strategy;
        for flush in [
            None,
            Some(libz_sys::Z_PARTIAL_FLUSH),
            Some(libz_sys::Z_SYNC_FLUSH),
            Some(libz_sys::Z_FULL_FLUSH),
        ] {
            let wrapped = libzsys_compress_with_flush(&plain, 6, strategy, 15, 8, flush);
            let compressed = &wrapped[2..wrapped.len() - 4];
            let (result, decoded) =
                preflate_whole_deflate_stream(compressed, &PreflateConfig::default()).unwrap();
            assert_eq!(decoded.text(), plain);
            assert_eq!(
                result.parameters.unwrap().strategy,
                expected,
                "{strategy:?}, {flush:?}"
            );
            assert_eq!(
                recreate_whole_deflate_stream(decoded.text(), &result.corrections).unwrap(),
                compressed
            );
        }
    }
}

#[test]
fn zlib_flush_tails_and_huffman_block_limits_roundtrip() {
    use preflate_rs::{
        CodecCorrection, CountNonDefaultActions, PreflateConfig, PreflateStreamProcessor,
    };

    let plain: Vec<_> = (0..40000)
        .map(|i| b'@' + ((i * 37 + i / 97) % 53) as u8)
        .collect();
    for level in [0, 1, 6, 9] {
        for mem_level in [1, 5, 8, 9] {
            for strategy in [Strategy::Default, Strategy::HuffmanOnly, Strategy::Fixed] {
                for flush in [
                    libz_sys::Z_PARTIAL_FLUSH,
                    libz_sys::Z_SYNC_FLUSH,
                    libz_sys::Z_FULL_FLUSH,
                ] {
                    let wrapped = libzsys_compress_with_flush(
                        &plain,
                        level,
                        strategy,
                        15,
                        mem_level,
                        Some(flush),
                    );
                    let compressed = &wrapped[2..wrapped.len() - 4];
                    let mut counts = CountNonDefaultActions::default();
                    let mut processor = PreflateStreamProcessor::new(&PreflateConfig::default());
                    let chunk = processor
                        .decompress_with_statistics(compressed, &mut counts)
                        .unwrap();
                    assert_eq!(chunk.compressed_size, compressed.len());
                    assert_eq!(processor.plain_text().text(), plain);
                    if level != 0 && matches!(strategy, Strategy::HuffmanOnly) {
                        assert_eq!(
                            counts.corrections_count[CodecCorrection::TokenCount as usize],
                            0,
                            "level={level} mem={mem_level} flush={flush}"
                        );
                    }
                }
            }
        }
    }
}

fn libdeflate_compress(in_data: &[u8], level: i32) -> Vec<u8> {
    unsafe {
        let compressor = libdeflate_alloc_compressor(level);
        assert!(!compressor.is_null());
        let bound = libdeflate_deflate_compress_bound(compressor, in_data.len());
        let mut out_data = vec![0; bound];
        let sz = libdeflate_deflate_compress(
            compressor,
            in_data.as_ptr() as *const core::ffi::c_void,
            in_data.len(),
            out_data.as_mut_ptr() as *mut core::ffi::c_void,
            out_data.len(),
        );
        libdeflate_free_compressor(compressor);

        assert_ne!(sz, 0);
        out_data.resize(sz, 0);
        out_data
    }
}

fn libngzsys_compress(input_data: &[u8], level: i32) -> Vec<u8> {
    let mut output = Vec::new();
    use libz_ng_sys::{
        Z_DEFAULT_STRATEGY, Z_DEFLATED, Z_FINISH, Z_OK, Z_STREAM_END, deflate, deflateBound,
        deflateEnd, deflateInit2_, z_stream, zlibVersion,
    };
    unsafe {
        let mut z_stream = z_stream {
            next_in: input_data.as_ptr() as *mut _,
            avail_in: input_data.len() as u32,
            next_out: ptr::null_mut(),
            avail_out: 0,
            total_in: 0,
            total_out: 0,
            msg: std::ptr::null_mut(),
            state: std::ptr::null_mut(),
            zalloc: zlib_alloc,
            zfree: zlib_free,
            opaque: ptr::null_mut(),
            data_type: 0,
            adler: 0,
            reserved: 0,
        };

        // Additional options for deflateInit2_
        let window_bits = 15; // Default window size
        let mem_level = 8; // Default memory level
        let version = zlibVersion(); // Use the zlib version defined in the library
        let stream_size = std::mem::size_of::<z_stream>() as i32;

        // Initialize the zlib stream for compression with deflateInit2_

        assert_eq!(
            deflateInit2_(
                &mut z_stream,
                level,
                Z_DEFLATED,
                window_bits,
                mem_level,
                Z_DEFAULT_STRATEGY,
                version,
                stream_size
            ),
            Z_OK
        );

        // Quick profiles can expand incompressible input beyond a fixed spare-byte allowance.
        let bound = deflateBound(&mut z_stream, input_data.len().try_into().unwrap());
        output.resize(bound.try_into().unwrap(), 0);

        z_stream.next_out = output.as_mut_ptr() as *mut _;
        z_stream.avail_out = output.len() as u32;

        assert_eq!(Z_STREAM_END, deflate(&mut z_stream, Z_FINISH));
        let output_len = usize::try_from(z_stream.total_out).unwrap();
        assert!(
            output_len <= output.len(),
            "zlib-ng exceeded its output buffer"
        );
        output.truncate(output_len);

        assert_eq!(Z_OK, deflateEnd(&mut z_stream));
    }
    output
}

/// Tests the overhead of matching each of popular DEFLATE
/// algorithms. The overhead is the size of the prediction
/// corrections that are needed to encode the data.
///
/// If this test fails, it means that there was a change in the
/// behavior of the prediction encoder/decoder, which should
/// be checked to make sure there isn't a regression in the efficiency
/// of the encoding.
#[test]
fn compression_benchmark_overhead_size() {
    let original = read_file("sample1.bin");

    fn zlib(v: &[u8], level: i32) -> Vec<u8> {
        let output = libzsys_compress(v, level, Strategy::Default);

        // remove header and trailer. Just testing pure deflate
        output[2..output.len() - 4].to_vec()
    }

    fn libdeflate(v: &[u8], level: i32) -> Vec<u8> {
        libdeflate_compress(v, level)
    }

    fn libngzsys(v: &[u8], level: i32) -> Vec<u8> {
        let output = libngzsys_compress(v, level);

        // remove header and trailer. Just testing pure deflate
        output[2..output.len() - 4].to_vec()
    }

    fn miniz_oxide(v: &[u8], level: i32) -> Vec<u8> {
        miniz_oxide::deflate::compress_to_vec(v, level as u8)
    }

    use preflate_rs::ExitCode;

    struct BenchmarkResult {
        name: &'static str,
        compress_fn: fn(&[u8], i32) -> Vec<u8>,
        overhead: [Result<usize, ExitCode>; 10],
    }

    // The expected overhead for each compression level.
    // The lower compression levels are more important since
    // they are better recompressed and give more bang-for-buck.
    // Each value includes the 1-byte RECONSTRUCTION_DATA_VERSION prefix.
    let bench = [
        BenchmarkResult {
            name: "libngzsys",
            compress_fn: libngzsys,
            overhead: [
                Ok(19),
                Ok(34),
                Ok(21),
                Ok(21),
                Ok(42),
                Ok(2501),
                Ok(1801),
                Ok(49),
                Ok(27),
                Err(ExitCode::NoCompressionCandidates),
            ],
        },
        BenchmarkResult {
            name: "zlib",
            compress_fn: zlib,
            overhead: [
                Ok(19),
                Ok(26),
                Ok(26),
                Ok(26),
                Ok(30),
                Ok(30),
                Ok(30),
                Ok(328),
                Ok(130),
                Ok(28),
            ],
        },
        BenchmarkResult {
            name: "libdeflate",
            compress_fn: libdeflate,
            overhead: [
                Ok(19),
                Ok(76),
                Ok(123),
                Ok(94),
                Ok(95),
                Ok(162),
                Ok(106),
                Ok(73),
                Ok(90),
                Ok(89),
            ],
        },
        BenchmarkResult {
            name: "miniz_oxide",
            compress_fn: miniz_oxide,
            overhead: [
                Ok(28),
                Ok(177),
                Ok(76),
                Ok(85),
                Ok(65),
                Ok(65),
                Ok(62),
                Ok(63),
                Ok(64),
                Ok(63),
            ],
        },
    ];

    struct LevelResult {
        compressed_size: usize,
        overhead: Result<usize, ExitCode>,
    }

    // Collect all results first so the table can be printed before asserting.
    let all_results: Vec<Vec<LevelResult>> = bench
        .iter()
        .map(|i| {
            (0..=9)
                .map(|level| {
                    let compressed = (i.compress_fn)(&original, level);
                    let compressed_size = compressed.len();
                    let overhead = match preflate_whole_deflate_stream(
                        &compressed,
                        &PreflateConfig::default(),
                    ) {
                        Ok((r, _)) => Ok(r.corrections.len()),
                        Err(e) => Err(e.exit_code()),
                    };
                    LevelResult {
                        compressed_size,
                        overhead,
                    }
                })
                .collect()
        })
        .collect();

    // Print a comparison table so regressions and improvements are visible at a glance.
    println!(
        "\nOverhead benchmark — original = {} bytes\n",
        original.len()
    );
    for (i, results) in bench.iter().zip(all_results.iter()) {
        println!("{}:", i.name);
        println!(
            "  {:>3}  {:>11}  {:>11}  {:>11}  {:>9}  {}",
            "Lv", "Compressed", "Expected", "Actual", "Delta", "Status"
        );
        for (level, (result, expected)) in results.iter().zip(i.overhead.iter()).enumerate() {
            let expected_str = match expected {
                Ok(v) => format!("{}", v),
                Err(e) => format!("{:?}", e),
            };
            let actual_str = match &result.overhead {
                Ok(v) => format!("{}", v),
                Err(e) => format!("{:?}", e),
            };
            let (delta_str, status) = match (expected, &result.overhead) {
                (Ok(exp), Ok(act)) => {
                    let delta = *act as i64 - *exp as i64;
                    let status = if delta < 0 {
                        "BETTER"
                    } else if delta > 0 {
                        "WORSE"
                    } else {
                        "ok"
                    };
                    (format!("{:+}", delta), status)
                }
                (exp, act) if exp == act => ("=".to_string(), "ok"),
                _ => ("?".to_string(), "CHANGED"),
            };
            println!(
                "  {:>3}  {:>11}  {:>11}  {:>11}  {:>9}  {}",
                level, result.compressed_size, expected_str, actual_str, delta_str, status
            );
        }
        println!();
    }

    // Now assert — failures will name the compressor and show the diff above.
    for (i, results) in bench.iter().zip(all_results.iter()) {
        let actual: Vec<_> = results.iter().map(|r| r.overhead.clone()).collect();
        assert_eq!(
            actual,
            i.overhead.as_ref(),
            "compression overhead mismatch for {}",
            i.name
        );
    }
}

// Keep native compressor setup outside the core prediction measurements.
// This manual harness exports raw compressor/level fixtures; it does not assert compression ratios.
#[test]
#[ignore = "exports generated streams for the core prediction diagnostic harness"]
fn export_compression_diagnostics() {
    let directory = std::env::var_os("PREFLATE_DIAGNOSTICS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("prediction-diagnostics")
        });
    std::fs::create_dir_all(&directory).unwrap();
    let original = match std::env::var_os("PREFLATE_DIAGNOSTICS_INPUT") {
        Some(path) => std::fs::read(path).unwrap(),
        None => read_file("sample1.bin"),
    };
    for level in 0..=9 {
        let streams = [
            (
                "miniz",
                miniz_oxide::deflate::compress_to_vec(&original, level as u8),
            ),
            ("libdeflate", libdeflate_compress(&original, level)),
            ("zlibng", {
                let stream = libngzsys_compress(&original, level);
                stream[2..stream.len() - 4].to_vec()
            }),
            ("zlib", {
                let stream = libzsys_compress(&original, level, Strategy::Default);
                stream[2..stream.len() - 4].to_vec()
            }),
        ];
        for (name, stream) in streams {
            let path = directory.join(format!("{name}_{level}.deflate"));
            println!("Exporting {} ({} bytes)", path.display(), stream.len());
            std::fs::write(path, stream).unwrap();
        }
    }
}

#[test]
#[ignore = "offline native recompression comparison; requires selected raw .deflate fixtures"]
fn compare_native_compressor_outputs() {
    let input = std::env::var_os("PREFLATE_NATIVE_INPUT")
        .expect("set PREFLATE_NATIVE_INPUT to a raw .deflate payload");
    let output = std::env::var_os("PREFLATE_NATIVE_OUTPUT")
        .expect("set PREFLATE_NATIVE_OUTPUT to a new fixture directory");
    let output = Path::new(&output);
    std::fs::create_dir(output).unwrap();
    let original = std::fs::read(input).unwrap();
    let plain = miniz_oxide::inflate::decompress_to_vec(&original).unwrap();
    println!("original={} plaintext={}", original.len(), plain.len());
    std::fs::write(output.join("original.deflate"), &original).unwrap();
    for level in [5, 6, 7, 8, 9, 10, 11, 12] {
        let compressed = libdeflate_compress(&plain, level);
        assert_eq!(
            miniz_oxide::inflate::decompress_to_vec(&compressed).unwrap(),
            plain
        );
        println!(
            "libdeflate_{level}: bytes={} exact={}",
            compressed.len(),
            compressed == original
        );
        std::fs::write(
            output.join(format!("libdeflate_{level}.deflate")),
            compressed,
        )
        .unwrap();
    }
    for level in [6, 8, 9] {
        for (name, wrapped) in [
            ("zlib", libzsys_compress(&plain, level, Strategy::Default)),
            ("zlibng", libngzsys_compress(&plain, level)),
        ] {
            let compressed = &wrapped[2..wrapped.len() - 4];
            assert_eq!(
                miniz_oxide::inflate::decompress_to_vec(compressed).unwrap(),
                plain
            );
            println!(
                "{name}_{level}: bytes={} exact={}",
                compressed.len(),
                compressed == original
            );
            std::fs::write(output.join(format!("{name}_{level}.deflate")), compressed).unwrap();
        }
    }
}

fn seeded_test_bytes(mut seed: u32, length: usize) -> Vec<u8> {
    assert_ne!(seed, 0);
    (0..length)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        })
        .collect()
}

fn mixed_test_bytes(seed: u32, length: usize) -> Vec<u8> {
    let mut bytes = seeded_test_bytes(seed, length);
    let pattern = b"request completed status=200 path=/api/items\n";
    for (i, byte) in bytes.iter_mut().enumerate() {
        if (i / 4096) % 2 == 1 {
            *byte = pattern[i % pattern.len()];
        }
    }
    bytes
}

fn generated_prediction_inputs() -> Vec<(String, Vec<u8>)> {
    let mut inputs = Vec::new();
    for seed in [1, 0x5eed, 0xabcdef] {
        inputs.push((format!("random_{seed}"), seeded_test_bytes(seed, 32769)));
        let mutations = seeded_test_bytes(seed, 65);
        let periodic = (0..65537)
            .map(|i| {
                if i % 1024 == 0 {
                    mutations[i / 1024]
                } else {
                    ((i % 251) as u8).wrapping_add(seed as u8)
                }
            })
            .collect();
        inputs.push((format!("periodic_{seed}"), periodic));
        let mut records = String::new();
        for i in 0..512 {
            use std::fmt::Write;
            writeln!(
                records,
                "record={i:04} group={} status=200 payload={:08x}",
                i % 17,
                (i as u32).wrapping_mul(seed)
            )
            .unwrap();
        }
        inputs.push((format!("records_{seed}"), records.into_bytes()));
        inputs.push((format!("mixed_{seed}"), mixed_test_bytes(seed, 98305)));
    }
    inputs
}

fn pdf_style_test_bytes() -> Vec<u8> {
    let palette = seeded_test_bytes(0x5eed, 4096);
    let choices = seeded_test_bytes(0xabcdef, 32768);
    let mut original = Vec::new();
    for (index, pair) in choices.as_chunks::<2>().0.iter().enumerate() {
        let start = usize::from(pair[0]) * 16;
        original.extend_from_slice(&palette[start..start + 4]);
        original.push(pair[1]);
        original.extend_from_slice(&palette[start + 4..start + 12]);
        original.push((index >> 8) as u8);
    }
    original
}

#[test]
fn low_alphabet_libdeflate_profiles_reconstruct_without_token_corrections() {
    let noise = seeded_test_bytes(0x5eed, 100000);
    let mut original = Vec::new();
    for pair in noise.as_chunks::<2>().0 {
        original.extend_from_slice(b"aaaa");
        original.extend([pair[0] & 15, pair[1] & 15, 16]);
    }
    for level in 5..=9 {
        let compressed = libdeflate_compress(&original, level);
        let mut processor = PreflateStreamProcessor::new(&PreflateConfig::default());
        processor.enable_trace(4);
        let result = processor.decompress(&compressed).unwrap();
        assert!(processor.is_done(), "level {level}");
        assert_eq!(processor.plain_text().text(), original, "level {level}");
        assert_eq!(
            recreate_whole_deflate_stream(processor.plain_text().text(), &result.corrections)
                .unwrap(),
            compressed,
            "level {level}"
        );
        let trace = processor.prediction_trace().unwrap();
        assert_eq!(
            trace.mismatch_count, 0,
            "level {level}: {:?}; {:?}",
            result.parameters, trace.first_mismatches
        );
        assert!(
            result.corrections.len() <= 512,
            "level {level}: {} correction bytes",
            result.corrections.len()
        );
    }
}

#[test]
fn pdf_zlib_model_probe_reaches_long_match_prefix() {
    let mut original = vec![0; 131072];
    original.extend(pdf_style_test_bytes());
    let wrapped = libzsys_compress_options(&original, 6, Strategy::Default, 12, 5);
    let compressed = &wrapped[2..wrapped.len() - 4];
    let (result, plain) =
        preflate_whole_deflate_stream(compressed, &PreflateConfig::default()).unwrap();
    assert_eq!(plain.text(), original);
    assert_eq!(
        recreate_whole_deflate_stream(plain.text(), &result.corrections).unwrap(),
        compressed
    );
    assert!(
        result.corrections.len() * 100 < compressed.len(),
        "{} corrections / {} deflate bytes",
        result.corrections.len(),
        compressed.len()
    );
}

#[test]
fn pdf_zlib_profiles_have_low_correction_overhead() {
    let original = pdf_style_test_bytes();
    for strategy in [Strategy::Default, Strategy::Filtered] {
        for window in [12, 15] {
            for memory in [5, 8, 9] {
                for level in [4, 6, 9] {
                    let context =
                        format!("{strategy:?}, window={window}, memory={memory}, level={level}");
                    let wrapped =
                        libzsys_compress_options(&original, level, strategy, window, memory);
                    let compressed = &wrapped[2..wrapped.len() - 4];
                    let mut state =
                        preflate_rs::PreflateStreamProcessor::new(&PreflateConfig::default());
                    state.enable_trace(8);
                    let result = state
                        .decompress(compressed)
                        .unwrap_or_else(|error| panic!("{context}: {error:?}"));
                    assert!(state.is_done(), "{context}");
                    assert_eq!(state.plain_text().text(), original, "{context}");
                    if matches!(strategy, Strategy::Filtered) {
                        assert!(
                            matches!(
                                result.parameters.unwrap().hash_algorithm,
                                preflate_rs::HashAlgorithm::Zlib { .. }
                            ),
                            "{context}: {:?}",
                            result.parameters
                        );
                        assert!(
                            matches!(
                                result.parameters.unwrap().matching_type,
                                preflate_rs::MatchingType::Lazy {
                                    filtered_matching: true,
                                    ..
                                }
                            ),
                            "{context}"
                        );
                    }
                    let recreated = recreate_whole_deflate_stream(
                        state.plain_text().text(),
                        &result.corrections,
                    )
                    .unwrap();
                    assert_eq!(recreated, compressed, "{context}");
                    assert!(
                        result.corrections.len() * 100 < compressed.len(),
                        "{context}: {} corrections / {} deflate bytes; {:?}",
                        result.corrections.len(),
                        compressed.len(),
                        result.parameters
                    );
                }
            }
        }
    }
}

#[test]
fn native_compressor_bounds_roundtrip_incompressible_boundaries() {
    for length in [
        0, 1, 7, 8, 255, 256, 257, 32767, 32768, 32769, 65535, 65536, 65537, 1048577,
    ] {
        let original = seeded_test_bytes(0x5eed, length);
        for level in 0..=9 {
            for (name, compressed) in [
                (
                    "zlib",
                    libzsys_compress(&original, level, Strategy::Default),
                ),
                ("zlib-ng", libngzsys_compress(&original, level)),
            ] {
                let decoded = miniz_oxide::inflate::decompress_to_vec_zlib(&compressed)
                    .unwrap_or_else(|error| {
                        panic!("{name}, length={length}, level={level}: {error:?}")
                    });
                assert_eq!(decoded, original, "{name}, length={length}, level={level}");
            }
            let compressed = libdeflate_compress(&original, level);
            let decoded =
                miniz_oxide::inflate::decompress_to_vec(&compressed).unwrap_or_else(|error| {
                    panic!("libdeflate, length={length}, level={level}: {error:?}")
                });
            assert_eq!(
                decoded, original,
                "libdeflate, length={length}, level={level}"
            );
        }
    }
}

// Model state must survive different chunk boundaries, not just one fixture partition.
// Verify plaintext, first-chunk-only parameters and exact bitstreams across dictionary shrinking.
#[test]
fn compressor_models_roundtrip_across_chunks() {
    for (input_name, original) in [
        ("sample1", read_file("sample1.bin")),
        ("mixed", mixed_test_bytes(0x5eed, 524289)),
    ] {
        for (name, level) in (2..=9)
            .map(|level| ("miniz", level))
            .chain([("libdeflate", 1), ("zlib-filtered", 6)])
        {
            let compressed = match name {
                "miniz" => miniz_oxide::deflate::compress_to_vec(&original, level as u8),
                "libdeflate" => libdeflate_compress(&original, level),
                "zlib-filtered" => {
                    let wrapped =
                        libzsys_compress_options(&original, level, Strategy::Filtered, 15, 5);
                    wrapped[2..wrapped.len() - 4].to_vec()
                }
                _ => unreachable!("unknown generated compressor"),
            };
            // Limits must accommodate a complete Huffman block before the parser can checkpoint.
            for limit in [256 * 1024, 384 * 1024] {
                let context = format!("{input_name}, {name} level {level}, limit={limit}");
                let config = PreflateConfig {
                    plain_text_limit: limit,
                    verify_compression: false,
                    ..PreflateConfig::default()
                };
                let mut processor = PreflateStreamProcessor::new(&config);
                let mut traced = PreflateStreamProcessor::new(&config);
                traced.enable_trace(5);
                let mut recreate = RecreateStreamProcessor::new();
                let mut offset = 0;
                let mut chunks = 0;
                let mut tokens_seen = 0;
                let mut mismatches_seen = 0;
                let mut recreated = Vec::new();
                let mut decoded = Vec::new();
                while !processor.is_done() {
                    let chunk = processor
                        .decompress(&compressed[offset..])
                        .unwrap_or_else(|error| panic!("{context}, chunk {chunks}: {error:?}"));
                    let mut counts = preflate_rs::CountNonDefaultActions::default();
                    let trace_chunk = traced
                        .decompress_with_statistics(&compressed[offset..], &mut counts)
                        .unwrap_or_else(|error| {
                            panic!("{context}, traced chunk {chunks}: {error:?}")
                        });
                    assert_eq!(
                        trace_chunk.compressed_size, chunk.compressed_size,
                        "{context}"
                    );
                    assert_eq!(trace_chunk.parameters, chunk.parameters, "{context}");
                    assert_eq!(trace_chunk.corrections, chunk.corrections, "{context}");
                    assert_eq!(
                        traced.plain_text().text(),
                        processor.plain_text().text(),
                        "{context}"
                    );
                    tokens_seen += chunk
                        .blocks
                        .iter()
                        .map(|block| match &block.block_type {
                            preflate_rs::DeflateTokenBlockType::Huffman { tokens, .. } => {
                                tokens.len()
                            }
                            preflate_rs::DeflateTokenBlockType::Stored { .. } => 0,
                        })
                        .sum::<usize>();
                    let trace = traced.prediction_trace().unwrap();
                    assert_eq!(trace.token_count, tokens_seen, "{context}");
                    assert!(trace.mismatch_count >= mismatches_seen, "{context}");
                    assert_eq!(
                        trace.first_mismatches.len(),
                        trace.mismatch_count.min(5),
                        "{context}"
                    );
                    assert!(
                        trace
                            .first_mismatches
                            .windows(2)
                            .all(|pair| pair[0].0 < pair[1].0),
                        "{context}"
                    );
                    let plaintext_end = decoded.len() + processor.plain_text().len();
                    assert!(
                        trace
                            .first_mismatches
                            .iter()
                            .all(|&(position, actual, predicted)| {
                                (position as usize) < plaintext_end && actual != predicted
                            }),
                        "{context}"
                    );
                    mismatches_seen = trace.mismatch_count;
                    assert!(chunk.compressed_size > 0, "{context}");
                    assert_eq!(chunk.parameters.is_some(), chunks == 0, "{context}");
                    if let Some(params) = chunk.parameters {
                        assert!(params.max_chain <= config.max_chain_length, "{context}");
                    }
                    decoded.extend_from_slice(processor.plain_text().text());
                    let (bytes, _) = recreate
                        .recompress(
                            &mut std::io::Cursor::new(processor.plain_text().text()),
                            &chunk.corrections,
                        )
                        .unwrap_or_else(|error| panic!("{context}, chunk {chunks}: {error:?}"));
                    recreated.extend_from_slice(&bytes);
                    offset += chunk.compressed_size;
                    chunks += 1;
                    processor.shrink_to_dictionary();
                    traced.shrink_to_dictionary();
                }
                assert!(chunks > 1, "{context}: did not exercise continuation");
                assert_eq!(offset, compressed.len(), "{context}");
                assert_eq!(original, decoded, "{context}");
                assert_eq!(compressed, recreated, "{context}");
            }
        }
    }
}

// Model correctness must generalize across entropy, repetition and changing data distributions.
// Verify native-compressor round trips on seeded families, size boundaries and real documents.
#[test]
fn compressor_models_roundtrip_varied_inputs() {
    let mut inputs = generated_prediction_inputs();
    inputs.extend(
        ["sample2.bin", "sample3.bin", "pptxplaintext.bin"]
            .into_iter()
            .map(|name| (name.to_owned(), read_file(name))),
    );
    for length in [0, 1, 3, 4, 5, 511, 512, 32767, 32768, 32769, 65537, 98304] {
        let data = (0..length)
            .map(|i| i as u8 ^ ((i / 257) % 17) as u8)
            .collect();
        inputs.push((format!("structured_{length}"), data));
    }
    let config = PreflateConfig {
        verify_compression: false,
        ..PreflateConfig::default()
    };
    for (name, original) in inputs {
        for level in 1..=9 {
            for (compressor, compressed) in [
                (
                    "miniz",
                    miniz_oxide::deflate::compress_to_vec(&original, level as u8),
                ),
                ("libdeflate", libdeflate_compress(&original, level)),
            ] {
                let context = format!("{name}, {compressor} level {level}");
                let (result, plain) = preflate_whole_deflate_stream(&compressed, &config)
                    .unwrap_or_else(|error| panic!("{context}: {error:?}"));
                if name == "pptxplaintext.bin" && compressor == "libdeflate" && level <= 4 {
                    assert!(
                        result.corrections.len() < 1000,
                        "{context}: low-level corrections exceeded 1000 bytes: {}",
                        result.corrections.len()
                    );
                }
                assert_eq!(original, plain.text(), "{context}");
                let recreated = recreate_whole_deflate_stream(plain.text(), &result.corrections)
                    .unwrap_or_else(|error| panic!("{context}: {error:?}"));
                assert_eq!(compressed, recreated, "{context}");
            }
        }
    }
}

// New compressor fingerprints must not break other supported compressor implementations.
// Verify the same seeded corpus round-trips through zlib levels and zlib-ng's low-level parsers.
#[test]
fn compressor_models_roundtrip_other_compressors() {
    let config = PreflateConfig {
        verify_compression: false,
        ..PreflateConfig::default()
    };
    for (name, original) in generated_prediction_inputs() {
        for level in [1, 3, 6, 9] {
            let wrapped = libzsys_compress(&original, level, Strategy::Default);
            let compressed = &wrapped[2..wrapped.len() - 4];
            let context = format!("{name}, zlib level {level}");
            let (result, plain) = preflate_whole_deflate_stream(compressed, &config)
                .unwrap_or_else(|error| panic!("{context}: {error:?}"));
            assert_eq!(original, plain.text(), "{context}");
            let recreated = recreate_whole_deflate_stream(plain.text(), &result.corrections)
                .unwrap_or_else(|error| panic!("{context}: {error:?}"));
            assert_eq!(compressed, recreated, "{context}");
        }
        for level in 1..=4 {
            let wrapped = libngzsys_compress(&original, level);
            let compressed = &wrapped[2..wrapped.len() - 4];
            let context = format!("{name}, zlib-ng level {level}");
            let (result, plain) = preflate_whole_deflate_stream(compressed, &config)
                .unwrap_or_else(|error| panic!("{context}: {error:?}"));
            assert_eq!(original, plain.text(), "{context}");
            let recreated = recreate_whole_deflate_stream(plain.text(), &result.corrections)
                .unwrap_or_else(|error| panic!("{context}: {error:?}"));
            assert_eq!(compressed, recreated, "{context}");
        }
    }
}

// Pure periodic streams exercise valid one-symbol distance alphabets in real compressor output.
// Verify native inflate, decoded plaintext and exact reconstruction across lengths, shifts and levels.
#[test]
fn periodic_miniz_streams_roundtrip() {
    for length in [32769, 65537] {
        for shift in [0u8, 1, 127] {
            let original: Vec<_> = (0..length)
                .map(|i| ((i % 251) as u8).wrapping_add(shift))
                .collect();
            for level in [2, 3, 6, 9] {
                let context = format!("periodic length={length}, shift={shift}, miniz={level}");
                let compressed = miniz_oxide::deflate::compress_to_vec(&original, level);
                assert_eq!(
                    miniz_oxide::inflate::decompress_to_vec(&compressed).unwrap(),
                    original,
                    "{context}"
                );
                let (result, plain) =
                    preflate_whole_deflate_stream(&compressed, &PreflateConfig::default())
                        .unwrap_or_else(|error| panic!("{context}: {error:?}"));
                assert_eq!(original, plain.text(), "{context}");
                let recreated = recreate_whole_deflate_stream(plain.text(), &result.corrections)
                    .unwrap_or_else(|error| panic!("{context}: {error:?}"));
                assert_eq!(compressed, recreated, "{context}");
            }
        }
    }
}
