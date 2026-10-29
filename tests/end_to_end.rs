/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::{mem, ptr};

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
    HuffmanOnly,
    Rle,
    Fixed,
}

fn libzsys_compress(input_data: &[u8], level: i32, strategy: Strategy) -> Vec<u8> {
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
            zalloc: mem::transmute(ptr::null::<u8>()),
            zfree: mem::transmute(ptr::null::<u8>()),
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
                match strategy {
                    Strategy::Default => Z_DEFAULT_STRATEGY,
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
        output.resize(bound.try_into().unwrap(), 0);

        z_stream.next_out = output.as_mut_ptr() as *mut _;
        z_stream.avail_out = output.len() as u32;

        assert_eq!(Z_STREAM_END, deflate(&mut z_stream, Z_FINISH));
        output.set_len(z_stream.total_out as usize);

        assert_eq!(Z_OK, deflateEnd(&mut z_stream));
    }
    output
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
            zalloc: mem::transmute(ptr::null::<u8>()),
            zfree: mem::transmute(ptr::null::<u8>()),
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
        output.set_len(z_stream.total_out as usize);

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
                Ok(31),
                Ok(37),
                Ok(24),
                Ok(24),
                Ok(45),
                Ok(2504),
                Ok(1804),
                Ok(50),
                Ok(28),
                Err(ExitCode::NoCompressionCandidates),
            ],
        },
        BenchmarkResult {
            name: "zlib",
            compress_fn: zlib,
            overhead: [
                Ok(31),
                Ok(29),
                Ok(29),
                Ok(29),
                Ok(31),
                Ok(31),
                Ok(31),
                Ok(329),
                Ok(131),
                Ok(29),
            ],
        },
        BenchmarkResult {
            name: "libdeflate",
            compress_fn: libdeflate,
            overhead: [
                Ok(31),
                Ok(110),
                Ok(287),
                Ok(248),
                Ok(266),
                Ok(298),
                Ok(236),
                Ok(205),
                Ok(184),
                Ok(243),
            ],
        },
        BenchmarkResult {
            name: "miniz_oxide",
            compress_fn: miniz_oxide,
            overhead: [
                Ok(48),
                Ok(204),
                Ok(100),
                Ok(158),
                Ok(82),
                Ok(92),
                Ok(90),
                Ok(109),
                Ok(103),
                Ok(106),
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
            .chain([("libdeflate", 1)])
        {
            let compressed = if name == "miniz" {
                miniz_oxide::deflate::compress_to_vec(&original, level as u8)
            } else {
                libdeflate_compress(&original, level)
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
                let mut recreate = RecreateStreamProcessor::new();
                let mut offset = 0;
                let mut chunks = 0;
                let mut recreated = Vec::new();
                let mut decoded = Vec::new();
                while !processor.is_done() {
                    let chunk = processor
                        .decompress(&compressed[offset..])
                        .unwrap_or_else(|error| panic!("{context}, chunk {chunks}: {error:?}"));
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

// Pure periodic streams expose an existing reader failure before model estimation is reached.
// Verify native inflate accepts each stream, then require exact preflate round trips once fixed.
#[test]
#[ignore = "Known reader limitation: valid miniz streams with incomplete Huffman trees"]
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
