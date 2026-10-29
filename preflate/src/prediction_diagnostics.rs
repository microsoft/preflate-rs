/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use super::*;
use crate::{
    deflate::deflate_reader::{DeflateContents, parse_deflate_whole},
    deflate::deflate_token::{DeflateHuffmanType, DeflateToken, DeflateTokenBlockType},
    estimator::add_policy_estimator::DictionaryAddPolicy,
    estimator::preflate_parameter_estimator::BlockTypeStrategy,
    estimator::preflate_parse_config::{MatchingType, SLOW_PREFLATE_PARSER_SETTINGS},
    statistical_codec::CountNonDefaultActions,
    token_predictor::TokenPredictionTrace,
};
use std::path::{Path, PathBuf};

#[derive(Default)]
struct CorrectionCounter(CountNonDefaultActions);

impl PredictionEncoder for CorrectionCounter {
    fn encode_correction(&mut self, action: CodecCorrection, value: u32) {
        self.0.record_correction(action, value);
    }

    fn encode_verify_state(&mut self, _message: &'static str, _checksum: u64) {}

    fn finish(&mut self) {}
}

struct Measurement {
    corrections: Vec<u8>,
    cabac_size: usize,
    count: CountNonDefaultActions,
    trace: TokenPredictionTrace,
}

fn measure(
    contents: &DeflateContents,
    plain_text: &PlainText,
    params: &TokenPredictorParameters,
) -> Result<Measurement> {
    let mut buffer = Vec::new();
    let mut encoder = (
        CorrectionCounter::default(),
        PredictionEncoderCabac::new(VP8Writer::new(&mut buffer).unwrap()),
    );
    let mut predictor = TokenPredictor::new(params);
    predictor.trace = Some(TokenPredictionTrace::default());
    predict_blocks(
        &contents.blocks,
        &mut predictor,
        &mut encoder,
        &mut PreflateInput::new(plain_text),
    )?;
    encoder.finish();
    let (counter, cabac) = encoder;
    drop(cabac);
    let cabac_size = buffer.len();
    let corrections = ReconstructionData {
        parameters: *params,
        corrections: buffer,
    }
    .write();
    Ok(Measurement {
        corrections,
        cabac_size,
        count: counter.0,
        trace: predictor.trace.unwrap(),
    })
}

fn verify(measurement: &Measurement, plain_text: &PlainText, compressed: &[u8]) {
    let recreated = recreate_whole_deflate_stream(plain_text.text(), &measurement.corrections)
        .expect("diagnostic parameters must reconstruct successfully");
    crate::utils::assert_eq_array(compressed, &recreated);
}

fn print_measurement(label: &str, measurement: &Measurement, compressed_size: usize) {
    println!(
        "{label}: overhead={} ({:.3}% of deflate), cabac={}, tokens={}, token_mismatches={}, corrections={}",
        measurement.corrections.len(),
        100.0 * measurement.corrections.len() as f64 / compressed_size as f64,
        measurement.cabac_size,
        measurement.trace.token_count,
        measurement.trace.mismatch_count,
        measurement.count.total_non_default,
    );
}

fn print_details(measurement: &Measurement) {
    measurement.count.print();
    for (offset, actual, predicted) in &measurement.trace.first_mismatches {
        println!("  plaintext offset {offset}: actual={actual:?}, predicted={predicted:?}");
    }
}

fn parameter_variants(
    params: TokenPredictorParameters,
    combined: bool,
) -> Vec<TokenPredictorParameters> {
    let mut variants = Vec::new();
    let mut add = |candidate| {
        if candidate != params && !variants.contains(&candidate) {
            variants.push(candidate);
        }
    };
    let matching_types = std::iter::once(MatchingType::Greedy).chain(
        SLOW_PREFLATE_PARSER_SETTINGS
            .iter()
            .map(|config| config.match_type),
    );
    for matching_type in matching_types {
        add(TokenPredictorParameters {
            matching_type,
            ..params
        });
        if combined {
            for nice_length in [8, 10, 14, 16, 30, 32, 64, 65, 128, 130, 258] {
                for max_chain in [
                    params.max_chain,
                    params.max_chain.saturating_sub(1).max(1),
                    params.max_chain.next_power_of_two(),
                ] {
                    add(TokenPredictorParameters {
                        matching_type,
                        nice_length,
                        max_chain,
                        ..params
                    });
                }
            }
        }
    }
    for nice_length in [8, 10, 14, 16, 30, 32, 64, 65, 128, 130, 258] {
        add(TokenPredictorParameters {
            nice_length,
            ..params
        });
    }
    // A chain depth inferred from observed matches is a lower bound, not a search budget.
    for max_chain in [
        params.max_chain.saturating_sub(1).max(1),
        params.max_chain.next_power_of_two(),
    ] {
        add(TokenPredictorParameters {
            max_chain,
            ..params
        });
    }
    variants
}

fn fixture_directory() -> PathBuf {
    std::env::var_os("PREFLATE_DIAGNOSTICS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("target")
                .join("prediction-diagnostics")
        })
}

#[test]
#[ignore = "throughput measurement using exported fixtures; run in release mode"]
fn benchmark_prediction_throughput() {
    let names = [
        "zlib_6",
        "miniz_2",
        "miniz_3",
        "libdeflate_1",
        "libdeflate_2",
        "libdeflate_3",
        "libdeflate_4",
        "libdeflate_5",
    ];
    let config = PreflateConfig {
        verify_compression: false,
        ..PreflateConfig::default()
    };
    for name in names {
        let compressed =
            std::fs::read(fixture_directory().join(format!("{name}.deflate"))).unwrap();
        let (_, plain_text) = preflate_whole_deflate_stream(&compressed, &config).unwrap();
        let start = std::time::Instant::now();
        let mut iterations = 0;
        let mut corrections = 0;
        while start.elapsed().as_millis() < 1000 {
            let result =
                preflate_whole_deflate_stream(std::hint::black_box(&compressed), &config).unwrap();
            corrections = result.0.corrections.len();
            std::hint::black_box(result);
            iterations += 1;
        }
        let elapsed = start.elapsed().as_secs_f64();
        println!(
            "THROUGHPUT {name}: {:.2} MiB/s plaintext, {:.3} ms/stream, corrections={corrections}, iterations={iterations}",
            iterations as f64 * plain_text.len() as f64 / (1024.0 * 1024.0 * elapsed),
            elapsed * 1000.0 / iterations as f64
        );
    }
}

#[test]
#[ignore = "run export_compression_diagnostics first; optionally filter or sweep parameters"]
fn diagnose_compression() {
    let directory = fixture_directory();
    let filter = std::env::var("PREFLATE_DIAGNOSTICS_FILTER").unwrap_or_default();
    let sweep = std::env::var_os("PREFLATE_DIAGNOSTICS_SWEEP").is_some();
    let mut files: Vec<_> = std::fs::read_dir(&directory)
        .expect("run the root export_compression_diagnostics test first")
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "deflate")
                && path
                    .file_stem()
                    .unwrap()
                    .to_string_lossy()
                    .contains(&filter)
        })
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no .deflate fixtures matched in {}",
        directory.display()
    );
    let mut ranking = Vec::new();
    let mut unsupported = 0;
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy();
        let compressed = std::fs::read(&file).unwrap();
        let (contents, plain_text) = parse_deflate_whole(&compressed)
            .unwrap_or_else(|error| panic!("{}: {error:?}", file.display()));
        assert_eq!(contents.compressed_size, compressed.len());
        let params = match estimate_preflate_parameters(&contents, &plain_text) {
            Ok(params) => params,
            Err(error) if error.exit_code() == ExitCode::NoCompressionCandidates => {
                println!("UNSUPPORTED {name}: {error:?}");
                unsupported += 1;
                continue;
            }
            Err(error) => panic!("{name}: {error:?}"),
        };
        let baseline = measure(&contents, &plain_text, &params)
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        verify(&baseline, &plain_text, &compressed);
        println!(
            "\n{name}: plaintext={}, deflate={}, blocks={}, params={params:?}",
            plain_text.len(),
            compressed.len(),
            contents.blocks.len()
        );
        print_measurement("BASELINE", &baseline, compressed.len());
        print_details(&baseline);
        ranking.push((
            name.into_owned(),
            baseline.corrections.len(),
            compressed.len(),
        ));
        if !sweep || params.max_chain == 0 {
            continue;
        }
        let mut best = baseline;
        let mut best_params = params;
        for candidate in parameter_variants(params, false) {
            match measure(&contents, &plain_text, &candidate) {
                Ok(measurement) => {
                    verify(&measurement, &plain_text, &compressed);
                    println!(
                        "  ISOLATED match={:?} nice={} chain={}",
                        candidate.matching_type, candidate.nice_length, candidate.max_chain
                    );
                    print_measurement("  RESULT", &measurement, compressed.len());
                    if measurement.corrections.len() < best.corrections.len() {
                        best = measurement;
                        best_params = candidate;
                    }
                }
                Err(error) => println!("  REJECTED {candidate:?}: {error:?}"),
            }
        }
        for candidate in parameter_variants(params, true) {
            match measure(&contents, &plain_text, &candidate) {
                Ok(measurement) => {
                    if measurement.corrections.len() < best.corrections.len() {
                        verify(&measurement, &plain_text, &compressed);
                        best = measurement;
                        best_params = candidate;
                    }
                }
                Err(error) => println!("  REJECTED {candidate:?}: {error:?}"),
            }
        }
        println!("BEST TESTED params={best_params:?}");
        print_measurement("BEST TESTED", &best, compressed.len());
        print_details(&best);
    }
    ranking.sort_by(|a, b| (b.1 as u128 * a.2 as u128).cmp(&(a.1 as u128 * b.2 as u128)));
    println!("\nOverhead ranking (corrections / original deflate bytes):");
    for (name, corrections, compressed) in ranking {
        println!(
            "{name}: {corrections}/{compressed} = {:.3}%",
            100.0 * corrections as f64 / compressed as f64
        );
    }
    println!("Unsupported streams: {unsupported}");
}

#[test]
fn diagnostic_measurement_matches_production() {
    for name in [
        "compressed_zlib_level1.deflate",
        "compressed_libdeflate_level1.deflate",
        "compressed_libdeflate_level2.deflate",
        "compressed_libdeflate_level4.deflate",
        "compressed_zlib_level0.deflate",
    ] {
        let compressed = crate::utils::read_file(name);
        let (contents, plain_text) = parse_deflate_whole(&compressed).unwrap();
        let params = estimate_preflate_parameters(&contents, &plain_text).unwrap();
        let measurement = measure(&contents, &plain_text, &params).unwrap();
        if name == "compressed_libdeflate_level1.deflate" {
            assert_eq!(
                params.hash_algorithm,
                crate::HashAlgorithm::Libdeflate4Fast15
            );
            assert_eq!(measurement.trace.mismatch_count, 0);
        }
        verify(&measurement, &plain_text, &compressed);
        let (production, _) =
            preflate_whole_deflate_stream(&compressed, &PreflateConfig::default()).unwrap();
        assert_eq!(measurement.corrections, production.corrections);
        assert!(measurement.trace.first_mismatches.len() <= 8);
        assert!(measurement.trace.mismatch_count <= measurement.trace.token_count);
    }
}

#[test]
fn isolated_variants_change_one_parameter() {
    let compressed = crate::utils::read_file("compressed_zlib_level1.deflate");
    let (contents, plain_text) = parse_deflate_whole(&compressed).unwrap();
    let params = estimate_preflate_parameters(&contents, &plain_text).unwrap();
    let variants = parameter_variants(params, false);
    assert!(!variants.is_empty());
    for candidate in variants {
        let changes = usize::from(candidate.matching_type != params.matching_type)
            + usize::from(candidate.nice_length != params.nice_length)
            + usize::from(candidate.max_chain != params.max_chain);
        assert_eq!(changes, 1);
        assert_eq!(candidate.hash_algorithm, params.hash_algorithm);
        assert_eq!(candidate.add_policy, params.add_policy);
    }
}

fn synthetic_stream(tokens: Vec<DeflateToken>) -> (Vec<u8>, DeflateContents, PlainText) {
    let mut writer = DeflateWriter::new();
    writer
        .encode_block(&DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type: DeflateHuffmanType::Static,
            },
            last: true,
        })
        .unwrap();
    writer.flush();
    let compressed = writer.detach_output();
    let (contents, plain_text) = parse_deflate_whole(&compressed).unwrap();
    (compressed, contents, plain_text)
}

fn synthetic_params() -> TokenPredictorParameters {
    TokenPredictorParameters {
        add_policy: DictionaryAddPolicy::AddAll,
        nice_length: 258,
        max_chain: 32,
        block_type_strategy: BlockTypeStrategy::Static,
        ..crate::token_predictor::zlib_level_1_params()
    }
}

#[test]
fn diagnostic_isolates_greedy_from_lazy_matching() {
    let mut tokens: Vec<_> = b"@abcdX"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.push(DeflateToken::new_ref(3, 4));
    tokens.extend(b"efY".iter().copied().map(DeflateToken::Literal));
    tokens.push(DeflateToken::new_ref(4, 11));
    tokens.extend(b"ef".iter().copied().map(DeflateToken::Literal));
    let (compressed, contents, plain_text) = synthetic_stream(tokens);
    assert_eq!(plain_text.text(), b"@abcdXbcdefYabcdef");
    let params = synthetic_params();
    let greedy = measure(&contents, &plain_text, &params).unwrap();
    let lazy = measure(
        &contents,
        &plain_text,
        &TokenPredictorParameters {
            matching_type: MatchingType::Lazy {
                good_length: 32,
                max_lazy: 258,
            },
            ..params
        },
    )
    .unwrap();
    verify(&greedy, &plain_text, &compressed);
    verify(&lazy, &plain_text, &compressed);
    assert_eq!(greedy.trace.mismatch_count, 0);
    assert_eq!(lazy.trace.mismatch_count, 1);
    assert_eq!(
        lazy.trace.first_mismatches,
        vec![(
            12,
            DeflateToken::new_ref(4, 11),
            DeflateToken::Literal(b'a')
        )]
    );
    assert_eq!(
        lazy.count.corrections_count[CodecCorrection::LiteralPredictionWrong as usize],
        1
    );
}

#[test]
fn diagnostic_isolates_nice_length_cutoff() {
    let mut tokens: Vec<_> = b"@abcdefX"
        .iter()
        .copied()
        .map(DeflateToken::Literal)
        .collect();
    tokens.push(DeflateToken::new_ref(3, 7));
    tokens.push(DeflateToken::Literal(b'Y'));
    tokens.push(DeflateToken::new_ref(6, 11));
    let (compressed, contents, plain_text) = synthetic_stream(tokens);
    assert_eq!(plain_text.text(), b"@abcdefXabcYabcdef");
    let params = synthetic_params();
    let full_search = measure(&contents, &plain_text, &params).unwrap();
    let early_exit = measure(
        &contents,
        &plain_text,
        &TokenPredictorParameters {
            nice_length: 3,
            ..params
        },
    )
    .unwrap();
    verify(&full_search, &plain_text, &compressed);
    verify(&early_exit, &plain_text, &compressed);
    assert_eq!(full_search.trace.mismatch_count, 0);
    assert_eq!(early_exit.trace.mismatch_count, 1);
    assert_eq!(
        early_exit.trace.first_mismatches,
        vec![(
            12,
            DeflateToken::new_ref(6, 11),
            DeflateToken::new_ref(3, 4)
        )]
    );
    assert_eq!(
        early_exit.count.corrections_count[CodecCorrection::LenCorrection as usize],
        1
    );
}

#[test]
fn diagnostic_trace_bounds_samples_not_counts() {
    let tokens = b"abcd"
        .repeat(32)
        .into_iter()
        .map(DeflateToken::Literal)
        .collect();
    let (compressed, contents, plain_text) = synthetic_stream(tokens);
    let measurement = measure(&contents, &plain_text, &synthetic_params()).unwrap();
    verify(&measurement, &plain_text, &compressed);
    assert_eq!(measurement.trace.token_count, 128);
    assert!(measurement.trace.mismatch_count > 8);
    assert_eq!(measurement.trace.first_mismatches.len(), 8);
    for pair in measurement.trace.first_mismatches.windows(2) {
        assert!(pair[0].0 < pair[1].0);
    }
}
