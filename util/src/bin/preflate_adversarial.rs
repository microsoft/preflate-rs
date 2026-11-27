use std::{
    fs,
    io::Cursor,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
};

use clap::Parser;
use preflate_container::{
    PreflateContainerConfig, PreflateContainerProcessor, ProcessBuffer, RecreateContainerProcessor,
};
use preflate_rs::{PreflateConfig, preflate_whole_deflate_stream, recreate_whole_deflate_stream};

#[derive(Parser)]
#[command(about = "Systematically exercise preflate on synthetic, adversarial inputs")]
struct Args {
    #[arg(long, default_value_t = 1)]
    seed: u64,
    #[arg(long, default_value_t = 1)]
    seeds: u64,
    #[arg(long, default_value_t = 8192)]
    max_size: usize,
    #[arg(long, default_value_t = 400)]
    max_cases: usize,
    #[arg(long, default_value_t = 256)]
    max_chain: u32,
    #[arg(long)]
    artifacts: Option<PathBuf>,
}

fn generated_bytes(kind: &str, len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.max(1);
    let mut data = Vec::with_capacity(len);
    for i in 0..len {
        let byte = match kind {
            "zero" => 0,
            "repeat" => b"abcabcab"[i % 8],
            "ramp" => i as u8,
            "signatures" => b"\x78\x9c\x1f\x8bPKIDAT\0"[i % 11],
            _ => {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            }
        };
        data.push(byte);
    }
    // JPEG/Lepton is intentionally outside this harness's scope.
    for i in 1..data.len() {
        if data[i - 1] == 0xff && data[i] == 0xd8 {
            data[i] = 0xd7;
        }
    }
    data
}

fn gzip_stream(zlib: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut output = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    output.extend_from_slice(&zlib[2..zlib.len() - 4]);
    output.extend_from_slice(&crc32fast::hash(plaintext).to_le_bytes());
    output.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    output
}

fn zip_stream(zlib: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let deflate = &zlib[2..zlib.len() - 4];
    let mut output = b"PK\x03\x04\x14\0\0\0\x08\0\0\0\0\0".to_vec();
    output.extend_from_slice(&crc32fast::hash(plaintext).to_le_bytes());
    output.extend_from_slice(&(deflate.len() as u32).to_le_bytes());
    output.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    output.extend_from_slice(&[0; 4]);
    output.extend_from_slice(deflate);
    output
}

fn png_chunks(zlib: &[u8]) -> Vec<u8> {
    let mut output = b"\x89PNG\r\n\x1a\n".to_vec();
    for part in zlib.chunks(3) {
        output.extend_from_slice(&(part.len() as u32).to_be_bytes());
        output.extend_from_slice(b"IDAT");
        output.extend_from_slice(part);
        let mut crc = crc32fast::Hasher::new();
        crc.update(b"IDAT");
        crc.update(part);
        output.extend_from_slice(&crc.finalize().to_be_bytes());
    }
    output.extend_from_slice(&[0, 0, 0, 0]);
    output.extend_from_slice(b"IEND");
    output.extend_from_slice(&crc32fast::hash(b"IEND").to_be_bytes());
    output
}

fn check_case(
    data: &[u8],
    raw_deflate: Option<&[u8]>,
    config: &PreflateContainerConfig,
) -> Result<bool, String> {
    let mut raw_supported = true;
    if let Some(deflate) = raw_deflate {
        match preflate_whole_deflate_stream(
            deflate,
            &PreflateConfig {
                max_chain_length: config.max_chain_length,
                ..PreflateConfig::default()
            },
        ) {
            Ok((chunk, plain_text)) => {
                let recreated =
                    recreate_whole_deflate_stream(plain_text.text(), &chunk.corrections)
                        .map_err(|e| format!("raw DEFLATE reconstruction failed: {e:?}"))?;
                if chunk.compressed_size != deflate.len() || recreated != deflate {
                    return Err("raw DEFLATE changed during reconstruction".into());
                }
            }
            Err(_) => raw_supported = false,
        }
    }

    for chunk_size in [1, 31, 4096] {
        let mut encoded = Vec::new();
        PreflateContainerProcessor::new(config, 1, false)
            .copy_to_end_size(&mut Cursor::new(data), &mut encoded, chunk_size)
            .map_err(|e| format!("container compression failed at chunk {chunk_size}: {e:?}"))?;
        let mut restored = Vec::new();
        RecreateContainerProcessor::with_config(4096, config)
            .copy_to_end_size(&mut Cursor::new(&encoded), &mut restored, chunk_size)
            .map_err(|e| format!("container reconstruction failed at chunk {chunk_size}: {e:?}"))?;
        if restored != data {
            return Err(format!(
                "container round trip differs at chunk {chunk_size}"
            ));
        }
    }
    Ok(raw_supported)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = PreflateContainerConfig {
        max_chain_length: args.max_chain,
        validate_compression: true,
        ..PreflateContainerConfig::default()
    };
    let artifacts = args
        .artifacts
        .unwrap_or_else(|| PathBuf::from("target").join("adversarial-failures"));
    let mut count = 0;
    let mut failures = 0;
    let mut unsupported_raw = 0;
    let sizes = [
        0, 1, 2, 3, 7, 31, 255, 256, 257, 258, 1023, 1024, 1025, 4095, 4096, 4097, 8191, 8192,
        8193, 65535, 65536,
    ];

    'cases: for seed_offset in 0..args.seeds {
        let seed = args.seed.wrapping_add(seed_offset);
        for len in sizes.into_iter().filter(|&len| len <= args.max_size) {
            for kind in ["zero", "repeat", "ramp", "random", "signatures"] {
                let data = generated_bytes(kind, len, seed);
                let mut variants = vec![(kind.to_owned(), data.clone(), None)];
                if len >= 1024 {
                    if kind == "signatures" {
                        let mut tiny_idat = Vec::new();
                        for _ in 0..len / 12 {
                            tiny_idat.extend_from_slice(&[0, 0, 0, 0]);
                            tiny_idat.extend_from_slice(b"IDAT");
                            tiny_idat.extend_from_slice(&crc32fast::hash(b"IDAT").to_be_bytes());
                        }
                        let run_end = tiny_idat.len();
                        tiny_idat.extend_from_slice(&[0, 0, 0, 0]);
                        tiny_idat.extend_from_slice(b"IEND");
                        tiny_idat.extend_from_slice(&crc32fast::hash(b"IEND").to_be_bytes());
                        variants.push(("tiny-idat".into(), tiny_idat.clone(), None));
                        tiny_idat.truncate(run_end);
                        variants.push(("truncated-tiny-idat".into(), tiny_idat.clone(), None));
                        tiny_idat[8] ^= 1;
                        variants.push(("bad-crc-tiny-idat".into(), tiny_idat, None));

                        let mut invalid_idat = Vec::new();
                        let payload = [0x78, 0x9c, 0, 0, 0, 0];
                        for _ in 0..len / 18 {
                            invalid_idat.extend_from_slice(&6u32.to_be_bytes());
                            invalid_idat.extend_from_slice(b"IDAT");
                            invalid_idat.extend_from_slice(&payload);
                            let mut crc = crc32fast::Hasher::new();
                            crc.update(b"IDAT");
                            crc.update(&payload);
                            invalid_idat.extend_from_slice(&crc.finalize().to_be_bytes());
                        }
                        invalid_idat.extend_from_slice(&[0, 0, 0, 0]);
                        invalid_idat.extend_from_slice(b"IEND");
                        invalid_idat.extend_from_slice(&crc32fast::hash(b"IEND").to_be_bytes());
                        variants.push(("invalid-idat-run".into(), invalid_idat, None));
                    }
                    let zlib = miniz_oxide::deflate::compress_to_vec_zlib(&data, 6);
                    let raw = zlib[2..zlib.len() - 4].to_vec();
                    let mut damaged_deflate = zlib.clone();
                    damaged_deflate[2 + raw.len() / 2] ^= 0x20;
                    let mut damaged_adler = zlib.clone();
                    *damaged_adler.last_mut().unwrap() ^= 1;
                    let mut damaged_png = png_chunks(&zlib);
                    damaged_png[19] ^= 1;
                    variants.push(("zlib".into(), zlib.clone(), Some(raw)));
                    variants.push(("gzip".into(), gzip_stream(&zlib, &data), None));
                    variants.push(("zip".into(), zip_stream(&zlib, &data), None));
                    variants.push(("png".into(), png_chunks(&zlib), None));
                    variants.push(("damaged-deflate".into(), damaged_deflate, None));
                    variants.push(("damaged-adler".into(), damaged_adler, None));
                    variants.push(("damaged-png-crc".into(), damaged_png, None));
                    variants.push(("truncated".into(), zlib[..zlib.len() / 2].to_vec(), None));
                    variants.push((
                        "two-streams".into(),
                        [zlib.as_slice(), zlib.as_slice()].concat(),
                        None,
                    ));
                }

                for (variant, bytes, raw) in variants {
                    if count >= args.max_cases {
                        break 'cases;
                    }
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        check_case(&bytes, raw.as_deref(), &config)
                    }));
                    match result.unwrap_or_else(|_| Err("panic".into())) {
                        Ok(false) => unsupported_raw += 1,
                        Ok(true) => {}
                        Err(reason) => {
                            failures += 1;
                            fs::create_dir_all(&artifacts)?;
                            let file = artifacts
                                .join(format!("{count:05}-{seed}-{len}-{kind}-{variant}.bin"));
                            fs::write(&file, &bytes)?;
                            eprintln!(
                                "FAIL case {count}: seed={seed} len={len} kind={kind} variant={variant}: {reason}; input={}",
                                file.display()
                            );
                        }
                    }
                    count += 1;
                    if count % 25 == 0 {
                        println!("Checked {count} cases ({failures} failures)");
                    }
                }
            }
        }
    }
    println!(
        "Checked {count} cases; {failures} failures, {unsupported_raw} raw streams unsupported (seed {}, {} seeds)",
        args.seed, args.seeds
    );
    if failures != 0 {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generators_are_deterministic_and_round_trip() {
        assert_eq!(
            generated_bytes("random", 257, 7),
            generated_bytes("random", 257, 7)
        );
        let data = generated_bytes("repeat", 2048, 1);
        let zlib = miniz_oxide::deflate::compress_to_vec_zlib(&data, 6);
        for input in [
            zlib.clone(),
            gzip_stream(&zlib, &data),
            zip_stream(&zlib, &data),
            png_chunks(&zlib),
        ] {
            check_case(&input, None, &PreflateContainerConfig::default()).unwrap();
        }
    }

    #[test]
    fn damaged_wrapper_inputs_round_trip() {
        for kind in ["zero", "repeat", "signatures", "random"] {
            let data = generated_bytes(kind, 1025, 17);
            let zlib = miniz_oxide::deflate::compress_to_vec_zlib(&data, 6);
            let mut damaged_deflate = zlib.clone();
            damaged_deflate[2 + (zlib.len() - 6) / 2] ^= 0x20;
            let mut damaged_adler = zlib.clone();
            *damaged_adler.last_mut().unwrap() ^= 1;
            let mut damaged_png = png_chunks(&zlib);
            damaged_png[19] ^= 1;
            for input in [damaged_deflate, damaged_adler, damaged_png] {
                check_case(&input, None, &PreflateContainerConfig::default()).unwrap();
            }
        }

        let data = generated_bytes("random", 4095, 1);
        let zlib = miniz_oxide::deflate::compress_to_vec_zlib(&data, 6);
        let mut damaged_png = png_chunks(&zlib);
        damaged_png[19] ^= 1;
        check_case(&damaged_png, None, &PreflateContainerConfig::default()).unwrap();
    }

    #[test]
    fn damaged_raw_deflate_never_panics_or_changes_accepted_streams() {
        let config = PreflateConfig {
            max_chain_length: 64,
            plain_text_limit: 4096,
            correction_limit: 4096,
            ..PreflateConfig::default()
        };
        for kind in ["zero", "repeat", "random"] {
            let data = generated_bytes(kind, 1025, 23);
            let zlib = miniz_oxide::deflate::compress_to_vec_zlib(&data, 6);
            let raw = &zlib[2..zlib.len() - 4];
            let positions = [
                0,
                1,
                2,
                3,
                raw.len() / 2,
                raw.len().saturating_sub(3),
                raw.len().saturating_sub(2),
                raw.len() - 1,
            ];
            for &position in &positions {
                for bit in 0..8 {
                    let mut mutated = raw.to_vec();
                    mutated[position] ^= 1 << bit;
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        preflate_whole_deflate_stream(&mutated, &config)
                    }))
                    .expect("raw DEFLATE parser panicked on mutated input");
                    if let Ok((chunk, plain_text)) = result {
                        let recreated =
                            recreate_whole_deflate_stream(plain_text.text(), &chunk.corrections)
                                .expect("accepted raw DEFLATE failed reconstruction");
                        assert_eq!(recreated, mutated[..chunk.compressed_size]);
                    }
                }
            }
        }
    }
}
