//! Tests the JSON replay CLI with explicit settings, file ranges, and synthetic blocks.
//! Checks diagnostic output, execution limits, input rejection, and reconstruction verification.

use std::{
    fs,
    io::Write,
    process::{Command, Output, Stdio},
};

use serde_json::{Value, json};
use tempfile::tempdir;

fn request() -> Value {
    serde_json::from_slice(
        &fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("examples")
                .join("replay.json"),
        )
        .unwrap(),
    )
    .unwrap()
}

fn run(request: &Value) -> (Output, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_preflate_replay"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(request).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let result = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output, result)
}

#[test]
fn replay_reports_later_blocks_with_preceding_dictionary_context() {
    let (output, result) = run(&request());
    assert!(output.status.success(), "{result}");
    assert!(output.stderr.is_empty());
    let result = &result["result"];
    assert_eq!(result["verified"], true);
    assert_eq!(result["total_blocks"], 3);
    assert_eq!(result["total_tokens"], 6);
    assert_eq!(result["plaintext_bytes"], 28);
    assert_eq!(result["reported_tokens"], 1);
    assert_eq!(result["reported_mismatches"], 0);
    assert_eq!(result["blocks"].as_array().unwrap().len(), 1);
    assert_eq!(result["blocks"][0]["index"], 2);
    assert_eq!(result["blocks"][0]["plaintext_offset"], 16);
    assert_eq!(result["blocks"][0]["dictionary_reset"], false);
    assert!(result["reconstruction_bytes"].as_u64().unwrap() > 0);
    assert_eq!(
        result["effective_reconstruction_parameters"],
        result["reconstruction_parameters"]
    );
    assert_eq!(
        result["input_statistics"],
        json!({
            "literal_tokens":4,
            "reference_tokens":2,
            "reference_lengths":{"12":2},
            "maximum_reference_distance":3,
            "distance_one_maximum_matches":0,
            "max_tokens_per_block":5,
            "max_huffman_block_bytes":16
        })
    );
}

#[test]
fn replay_without_encoding_labels_unverified_results() {
    let mut input = request();
    input["options"]["encode"] = json!(false);
    let (output, result) = run(&input);
    assert!(output.status.success(), "{result}");
    assert!(result["result"]["verified"].is_null());
    assert!(result["result"]["reconstruction_bytes"].is_null());
    assert_eq!(result["result"]["reported_tokens"], 1);
}

#[test]
fn replay_rejects_bad_parameters_ranges_tokens_limits_and_unknown_fields() {
    let mut cases = Vec::new();
    let mut input = request();
    input["reconstruction_parameters"]["behavior"]["Chain"]["common"]["dictionary"]["window_bits"] =
        json!(32);
    cases.push(input);
    let mut input = request();
    input["reconstruction_parameters"]["behavior"]["Chain"]["common"]["dictionary"]["index"]["Chain"]
        ["hash"]["Zlib"]["hash_shift"] = json!(16);
    cases.push(input);
    let mut input = request();
    input["reconstruction_parameters"]["surprise"] = json!(true);
    cases.push(input);
    let mut input = request();
    input["options"]["block_start"] = json!(3);
    cases.push(input);
    let mut input = request();
    input["options"]["max_tokens"] = json!(1);
    cases.push(input);
    let mut input = request();
    input["options"]["max_blocks"] = json!(1);
    cases.push(input);
    let mut input = request();
    input["options"]["max_plaintext_bytes"] = json!(1);
    cases.push(input);
    let mut input = request();
    input["options"]["max_input_bytes"] = json!(1);
    cases.push(input);
    let mut input = request();
    input["source"]["blocks"][0]["tokens"][4]["length"] = json!(2);
    cases.push(input);
    let mut input = request();
    input["source"]["blocks"][0]["tokens"][4]["distance"] = json!(5);
    cases.push(input);
    let mut input = request();
    input["source"]["blocks"][0]["last"] = json!(true);
    cases.push(input);
    for input in cases {
        let (output, result) = run(&input);
        assert!(!output.status.success(), "{input}");
        assert_eq!(result["status"], "error", "{result}");
        assert_eq!(result["error"]["code"], "InvalidParameter", "{result}");
    }
}

#[test]
fn replay_reads_exact_file_ranges_and_never_overwrites_output() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("wrapped.bin");
    // A final stored block containing "abc", surrounded by non-stream bytes.
    fs::write(&source, b"XX\x01\x03\x00\xfc\xffabcYY").unwrap();
    let mut input = request();
    input["source"] = json!({"type": "file", "path": source, "offset": 2, "length": 8});
    input["options"] = json!({});
    let (output, result) = run(&input);
    assert!(output.status.success(), "{result}");
    assert_eq!(result["result"]["compressed_bytes"], 8);
    assert_eq!(result["result"]["plaintext_bytes"], 3);
    assert_eq!(result["result"]["verified"], true);
    let request_path = directory.path().join("request.json");
    fs::write(&request_path, serde_json::to_vec(&input).unwrap()).unwrap();
    let output_path = directory.path().join("result.json");
    fs::write(&output_path, b"do not replace").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_preflate_replay"))
        .arg(request_path)
        .arg("--output")
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(&output_path).unwrap(), b"do not replace");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("cannot write replay result")
    );
}

#[test]
fn replay_preserves_parameters_and_bounds_mismatch_examples() {
    let mut input = request();
    input["source"] = json!({
        "type": "blocks",
        "blocks": [{
            "type": "huffman", "last": true,
            "tokens": (0..100).map(|_| json!({"type":"literal", "value":97})).collect::<Vec<_>>()
        }]
    });
    input["options"] = json!({"max_mismatches": 2});
    let (output, result) = run(&input);
    assert!(output.status.success(), "{result}");
    let result = &result["result"];
    assert_eq!(result["verified"], true);
    assert_eq!(
        result["reconstruction_parameters"],
        input["reconstruction_parameters"]
    );
    assert_eq!(
        result["effective_reconstruction_parameters"],
        input["reconstruction_parameters"]
    );
    assert!(result["total_mismatches"].as_u64().unwrap() > 2);
    assert_eq!(result["mismatches"].as_array().unwrap().len(), 2);
    assert_eq!(result["mismatches_truncated"], true);
    for mismatch in result["mismatches"].as_array().unwrap() {
        assert!(mismatch["actual"].get("value").is_none());
    }
}

#[test]
fn replay_enforces_raw_stream_limits_during_parsing() {
    let mut input = request();
    let blocks = serde_json::from_value(input["source"]["blocks"].clone()).unwrap();
    let bytes = preflate_rs::diagnostics::encode_replay_blocks(
        blocks,
        &preflate_rs::diagnostics::ReplayOptions::default(),
    )
    .unwrap();
    input["source"] = json!({"type":"deflate","bytes":bytes});
    input["options"] = json!({"max_tokens":6,"max_blocks":3});
    let (output, result) = run(&input);
    assert!(output.status.success(), "{result}");
    for (tokens, blocks) in [(5, 3), (6, 2)] {
        input["options"] = json!({"max_tokens":tokens,"max_blocks":blocks});
        let (output, result) = run(&input);
        assert!(!output.status.success());
        assert_eq!(result["error"]["code"], "InvalidParameter");
    }

    // Stop at the block budget rather than inspecting a malformed later block.
    input["source"] = json!({"type":"deflate","bytes":[0,0,0,255,255,7]});
    input["options"] = json!({"max_blocks":1});
    let (output, result) = run(&input);
    assert!(!output.status.success());
    assert_eq!(result["error"]["code"], "InvalidParameter");
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("max_blocks")
    );
}

#[test]
fn parameter_json_replays_all_supplied_variants() {
    let matching = [
        json!({"Greedy":{"short_match_cutoff":8192}}),
        json!({"Lazy":{
            "lookahead":{"max_lazy":16,"behavior":{"Zlib":{"good_length":8}}},
            "minimum":{"Three":{"short_match_cutoff":8192}}
        }}),
        json!({"Lazy":{
            "lookahead":{"max_lazy":16,"behavior":"RecomputeAfterLiteral"},
            "minimum":"FilteredSix"
        }}),
        json!({"LibdeflateLazy":{"two_positions":true,"short_match_cutoff":8192}}),
        json!({"LibdeflateGreedy":{"short_match_cutoff":8192}}),
        json!({"WindowsLazy":{"max_lazy":32,"short_match_cutoff":8192}}),
    ];
    for variant in matching {
        let mut input = request();
        if variant.get("LibdeflateLazy").is_some() {
            input["reconstruction_parameters"]["behavior"]["Chain"]["common"]["dictionary"]["index"] =
                json!("LibdeflateDualHash");
        }
        input["reconstruction_parameters"]["behavior"]["Chain"]["parser"] = variant;
        let (output, result) = run(&input);
        assert!(output.status.success(), "{result}");
        assert_eq!(
            result["result"]["reconstruction_parameters"],
            input["reconstruction_parameters"]
        );
    }
    let mut input = request();
    let mut common = input["reconstruction_parameters"]["behavior"]["Chain"]["common"].clone();
    common["distance"] = json!({"Enabled":{"matches_to_start":false}});
    common["search"] =
        json!({"max_probes":128,"budget":{"max_chain":128},"input_tail":"HashMinimum"});
    input["reconstruction_parameters"]["behavior"] =
        json!({"MiniZ":{"common":common,"greedy":false,"short_match_cutoff":8192}});
    let (output, result) = run(&input);
    assert!(output.status.success(), "{result}");
    assert_eq!(
        result["result"]["reconstruction_parameters"],
        input["reconstruction_parameters"]
    );
}

#[test]
fn replay_requires_reconstruction_json_not_estimator_or_flat_json() {
    let mut wrapped = request();
    wrapped["reconstruction_parameters"] = json!({
        "reconstruction": wrapped["reconstruction_parameters"].clone(),
        "model": "custom"
    });
    let mut flat = request();
    flat["reconstruction_parameters"] = json!({
        "max_chain": 128, "nice_length": 258, "window_bits": 15
    });
    let mut old_envelope = request();
    let settings = old_envelope
        .as_object_mut()
        .unwrap()
        .remove("reconstruction_parameters")
        .unwrap();
    old_envelope["parameters"] = settings;
    for input in [wrapped, flat, old_envelope] {
        let (output, result) = run(&input);
        assert!(!output.status.success(), "{result}");
        assert_eq!(result["error"]["code"], "InvalidParameter");
    }
}

#[test]
fn replay_reports_correction_failures_as_json_without_hiding_them() {
    let mut input = request();
    input["source"] = json!({
        "type":"blocks",
        "blocks":[{
            "type":"huffman", "last":true,
            "tokens":[
                {"type":"literal","value":64},
                {"type":"literal","value":97},
                {"type":"literal","value":98},
                {"type":"literal","value":99},
                {"type":"literal","value":88},
                {"type":"literal","value":155},
                {"type":"literal","value":17},
                {"type":"literal","value":0},
                {"type":"reference","length":3,"distance":7},
                {"type":"literal","value":90}
            ]
        }]
    });
    input["reconstruction_parameters"]["behavior"]["Chain"]["common"]["dictionary"]["index"] =
        json!("LibdeflateDualHash");
    input["options"] = json!({});
    let (output, result) = run(&input);
    assert!(!output.status.success());
    assert_eq!(result["status"], "error");
    assert!(matches!(
        result["error"]["code"].as_str(),
        Some("MatchNotFound" | "PredictionFailure")
    ));
    assert!(result.get("result").is_none());
}

#[test]
fn replay_only_normalizes_parameters_when_explicitly_requested() {
    let mut input = request();
    input["options"]["normalize_parameters"] = json!(true);
    let (output, result) = run(&input);
    assert!(output.status.success(), "{result}");
    assert_eq!(result["result"]["verified"], true);
    assert_eq!(
        result["result"]["reconstruction_parameters"],
        input["reconstruction_parameters"]
    );
    assert_ne!(
        result["result"]["effective_reconstruction_parameters"],
        input["reconstruction_parameters"]
    );
}

#[test]
fn replay_rejects_two_position_search_without_the_required_index() {
    for hash in [
        json!("Libdeflate4"),
        json!("Libdeflate4_15"),
        json!({"Zlib":{"hash_mask":32767,"hash_shift":5}}),
    ] {
        let mut input = request();
        input["reconstruction_parameters"]["behavior"]["Chain"]["common"]["dictionary"]["index"] =
            json!({"Chain":{"hash":hash}});
        input["reconstruction_parameters"]["behavior"]["Chain"]["parser"] =
            json!({"LibdeflateLazy":{"two_positions":true,"short_match_cutoff":8192}});
        let (output, result) = run(&input);
        assert!(!output.status.success());
        assert!(output.stderr.is_empty());
        assert_eq!(result["status"], "error");
        assert_eq!(result["error"]["code"], "InvalidParameter");
        assert!(
            result["error"]["message"]
                .as_str()
                .unwrap()
                .contains("requires the dual-hash index")
        );
    }
    let mut input = request();
    input["reconstruction_parameters"]["behavior"]["Chain"]["common"]["dictionary"]["index"] =
        json!("LibdeflateDualHash");
    input["reconstruction_parameters"]["behavior"]["Chain"]["parser"] =
        json!({"LibdeflateLazy":{"two_positions":true,"short_match_cutoff":8192}});
    let (output, result) = run(&input);
    assert!(output.status.success(), "{result}");
    assert_eq!(result["result"]["verified"], true);
}

#[test]
fn replay_input_statistics_count_stored_and_repetitive_input_correctly() {
    let mut input = request();
    input["source"] = json!({
        "type":"blocks",
        "blocks":[
            {"type":"stored","last":false,"bytes":[97]},
            {"type":"huffman","last":true,"tokens":[
                {"type":"literal","value":97},
                {"type":"reference","length":258,"distance":1},
                {"type":"reference","length":3,"distance":1}
            ]}
        ]
    });
    input["options"] = json!({"encode":false});
    let (output, result) = run(&input);
    assert!(output.status.success(), "{result}");
    assert_eq!(result["result"]["plaintext_bytes"], 263);
    assert_eq!(
        result["result"]["input_statistics"],
        json!({
            "literal_tokens":1,
            "reference_tokens":2,
            "reference_lengths":{"3":1,"258":1},
            "maximum_reference_distance":1,
            "distance_one_maximum_matches":1,
            "max_tokens_per_block":3,
            "max_huffman_block_bytes":262
        })
    );
}
